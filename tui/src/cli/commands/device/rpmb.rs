/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use log::info;
use penumbra::da::extensions::{KeyDeriveId, KeySize};
use penumbra::{Device, MtkPort, RpmbRegion, Storage, StorageType};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

const MAX_RPMB_TRANSFER_SECTORS: u32 = u32::MAX / 256;

#[derive(Debug, Args)]
pub struct RpmbReadArgs {
    /// RPMB region to use.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub region: u8,
    /// Starting sector to read from.
    #[arg(long, default_value_t = 0)]
    pub start_sector: u32,
    /// Number of sectors to read.
    #[arg(short, long)]
    pub num_sectors: Option<u32>,
    /// File to write the read data to.
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct RpmbWriteArgs {
    /// RPMB region to use.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub region: u8,
    /// Starting sector to write to.
    #[arg(long, default_value_t = 0)]
    pub start_sector: u32,
    /// Number of sectors to write.
    #[arg(short, long)]
    pub num_sectors: Option<u32>,
    /// RPMB authentication key in hex. If omitted, device-side derivation is used.
    #[arg(long)]
    pub key: Option<String>,
    /// File to read the data from.
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct RpmbAuthArgs {
    /// RPMB region to use.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub region: u8,
    /// The 32-byte authentication key in hex.
    pub key: String,
}

#[derive(Debug, Args)]
pub struct RpmbVerifyDerivedArgs {
    /// RPMB region to verify.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub region: u8,
}

#[derive(Debug, Args)]
pub struct RpmbEraseArgs {
    /// Erase one complete RPMB region.
    #[arg(
        long,
        value_parser = clap::value_parser!(u8).range(0..=3),
        conflicts_with = "all_regions",
        required_unless_present = "all_regions"
    )]
    pub region: Option<u8>,
    /// Erase every reported RPMB region; disabled regions require --force.
    #[arg(long, conflicts_with = "region", required_unless_present = "region")]
    pub all_regions: bool,
    /// Attempt erase even when the selected region is reported disabled.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RpmbInfoArgs {
    /// Show only one RPMB region; omit to display every region.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub region: Option<u8>,
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct RpmbArgs {
    #[command(subcommand)]
    pub command: RpmbCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum RpmbCommand {
    /// Read from RPMB.
    Read(RpmbReadArgs),
    /// Write to RPMB.
    Write(RpmbWriteArgs),
    /// Authenticate with RPMB.
    Auth(RpmbAuthArgs),
    /// Derive and authenticate the device RPMB key without writing data.
    VerifyDerived(RpmbVerifyDerivedArgs),
    /// Irreversibly overwrite an entire RPMB region with zeroes, without readback verification.
    Erase(RpmbEraseArgs),
    /// Display device-reported RPMB region capacities.
    Info(RpmbInfoArgs),
}

impl CommandMetadata for RpmbArgs {
    fn about() -> &'static str {
        "Perform RPMB operations."
    }

    fn long_about() -> &'static str {
        "Perform RPMB operations. DA Extensions must be loaded for this command to work."
    }
}

fn parse_region(value: u8) -> Result<RpmbRegion> {
    RpmbRegion::try_from(value)
        .map_err(|_| anyhow!("Invalid RPMB region {value}; expected 0 through 3"))
}

fn all_regions() -> [RpmbRegion; 4] {
    [RpmbRegion::R0, RpmbRegion::R1, RpmbRegion::R2, RpmbRegion::R3]
}

fn decode_rpmb_key(key: &str) -> Result<Vec<u8>> {
    let value = key.trim().strip_prefix("0x").unwrap_or(key.trim());
    let key = hex::decode(value)?;
    if key.len() != 32 {
        return Err(anyhow!("RPMB key must be exactly 32 bytes / 64 hex characters"));
    }
    Ok(key)
}

fn validate_sector_range(
    start_sector: u32,
    num_sectors: u32,
    max_sectors: Option<u32>,
) -> Result<()> {
    if num_sectors == 0 {
        return Err(anyhow!("RPMB sector count must be greater than 0"));
    }
    if num_sectors > MAX_RPMB_TRANSFER_SECTORS {
        return Err(anyhow!(
            "RPMB transfer is too large; maximum per command is {MAX_RPMB_TRANSFER_SECTORS} sectors"
        ));
    }

    let end = start_sector
        .checked_add(num_sectors)
        .ok_or_else(|| anyhow!("RPMB sector range overflows u32"))?;
    if max_sectors.is_some_and(|max| end > max) {
        return Err(anyhow!(
            "RPMB operation is out of bounds! Maximum sectors available: {}",
            max_sectors.unwrap()
        ));
    }

    Ok(())
}

fn perform_rpmb_io<P: MtkPort>(
    dev: &mut Device<P>,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: Option<u32>,
    file_path: &PathBuf,
    is_read: bool,
) -> Result<()> {
    let storage =
        dev.get_storage().ok_or_else(|| anyhow!("Failed to retrieve storage information"))?;

    let rpmb_size = storage.get_rpmb_size();
    let global_max_sectors = if rpmb_size == 0 {
        None
    } else {
        Some(
            u32::try_from(rpmb_size / 256)
                .map_err(|_| anyhow!("Reported RPMB capacity does not fit in u32 sectors"))?,
        )
    };
    let max_sectors = if storage.kind() == StorageType::Ufs {
        match dev.get_rpmb_region_info(region) {
            Ok((_, sectors)) if sectors != 0 => Some(sectors),
            Ok(_) if region == RpmbRegion::R0 => global_max_sectors,
            Ok(_) => Some(0),
            Err(_) if region == RpmbRegion::R0 => global_max_sectors,
            Err(error) => return Err(error.into()),
        }
    } else {
        global_max_sectors
    };
    let num_sectors = match (num_sectors, max_sectors) {
        (Some(count), _) => count,
        (None, Some(max)) => max.saturating_sub(start_sector),
        (None, None) => {
            return Err(anyhow!(
                "Device did not report RPMB size; pass --num-sectors/-n to specify how many sectors to {}",
                if is_read { "read" } else { "write" }
            ));
        }
    };

    validate_sector_range(start_sector, num_sectors, max_sectors).with_context(|| {
        format!("Invalid RPMB {} range", if is_read { "read" } else { "write" })
    })?;

    if max_sectors.is_none() {
        info!(
            "Device did not report RPMB size; using requested sector count without host-side bounds check"
        );
    }

    info!(
        "{} {} sectors from RPMB region {} starting at sector {} {} {}",
        if is_read { "Reading" } else { "Writing" },
        num_sectors,
        region as u32,
        start_sector,
        if is_read { "into" } else { "from" },
        file_path.display()
    );

    let pb = AntumbraProgress::new(num_sectors as u64 * 256);
    let mut progress = pb.get_callback(
        if is_read { "Reading RPMB..." } else { "Writing RPMB..." },
        if is_read { "RPMB Read Complete!" } else { "RPMB Write Complete!" },
    );

    if is_read {
        let file = File::create(file_path)?;
        let mut writer = BufWriter::new(file);
        dev.read_rpmb(region, start_sector, num_sectors, &mut writer, &mut progress)?;
        writer.flush()?;
    } else {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        dev.write_rpmb(region, start_sector, num_sectors, &mut reader, &mut progress)?;
    }

    Ok(())
}

fn verify_derived<P: MtkPort>(dev: &mut Device<P>, region: RpmbRegion) -> Result<()> {
    let key = dev.derive_key_by_id(KeyDeriveId::Rpmb, KeySize::Key256)?;
    dev.auth_rpmb(region, &key)?;
    Ok(())
}

fn erase_rpmb<P: MtkPort>(dev: &mut Device<P>, args: &RpmbEraseArgs) -> Result<()> {
    let storage =
        dev.get_storage().ok_or_else(|| anyhow!("Failed to retrieve storage information"))?;
    let is_ufs = storage.kind() == StorageType::Ufs;
    let requested: Vec<RpmbRegion> = if args.all_regions {
        if is_ufs { all_regions().to_vec() } else { vec![RpmbRegion::R0] }
    } else {
        vec![parse_region(args.region.expect("clap enforces an erase scope"))?]
    };

    let mut regions = Vec::new();
    for region in requested {
        let (enabled, sectors) = dev.get_rpmb_region_info(region)?;
        if sectors == 0 {
            if args.all_regions && region != RpmbRegion::R0 {
                info!("RPMB region {} has no configured capacity; skipping it", region as u32);
                continue;
            }
            return Err(anyhow!(
                "RPMB region {} capacity is unavailable; refusing whole-region erase",
                region as u32
            ));
        }

        if !enabled {
            if args.force {
                log::warn!(
                    "RPMB region {} is reported disabled; --force was supplied, attempting erase using its configured {} sectors",
                    region as u32,
                    sectors
                );
            } else if args.all_regions {
                info!(
                    "RPMB region {} is disabled; skipping it (use --force to attempt it)",
                    region as u32
                );
                continue;
            } else {
                return Err(anyhow!(
                    "RPMB region {} is disabled; pass --force to attempt erasing it anyway",
                    region as u32
                ));
            }
        }

        validate_sector_range(0, sectors, Some(sectors))?;
        regions.push((region, sectors));
    }

    if regions.is_empty() {
        return Err(anyhow!("No erasable RPMB regions were reported by the device"));
    }

    // Authenticate every target before modifying the first region. Advanced
    // UFS RPMB regions may have independent authentication state/counters.
    for (region, sectors) in &regions {
        info!(
            "Preflight authenticating RPMB region {} ({} sectors / {} bytes)",
            *region as u32,
            sectors,
            *sectors as u64 * 256
        );
        verify_derived(dev, *region)
            .with_context(|| format!("RPMB region {} authentication failed", *region as u32))?;
    }

    for (region, sectors) in regions {
        let byte_count = sectors as u64 * 256;
        info!(
            "ERASING RPMB region {}: authenticated zero-fill of {} sectors ({} bytes)",
            region as u32, sectors, byte_count
        );

        let pb = AntumbraProgress::new(byte_count);
        let mut progress = pb.get_callback("Erasing RPMB...", "RPMB Erase Complete!");
        let mut zeroes = std::io::repeat(0).take(byte_count);
        dev.write_rpmb(region, 0, sectors, &mut zeroes, &mut progress).with_context(|| {
            format!(
                "RPMB region {} erase failed; the region may be partially zero-filled",
                region as u32
            )
        })?;
    }

    info!(
        "RPMB erase completed without readback verification. OTP authentication keys and write counters cannot be reset by authenticated writes."
    );
    Ok(())
}

fn show_rpmb_info<P: MtkPort>(dev: &mut Device<P>, args: &RpmbInfoArgs) -> Result<()> {
    let storage =
        dev.get_storage().ok_or_else(|| anyhow!("Failed to retrieve storage information"))?;
    let is_ufs = storage.kind() == StorageType::Ufs;
    let regions: Vec<RpmbRegion> = match args.region {
        Some(region) => vec![parse_region(region)?],
        None if is_ufs => all_regions().to_vec(),
        None => vec![RpmbRegion::R0],
    };

    for region in regions {
        let (enabled, sectors) = dev.get_rpmb_region_info(region)?;
        let status = if enabled { "enabled" } else { "disabled" };
        if sectors == 0 {
            info!("RPMB region {}: {status}, capacity unavailable", region as u32);
        } else {
            info!(
                "RPMB region {}: {status}, {} sectors, {} bytes ({:.2} MiB)",
                region as u32,
                sectors,
                sectors as u64 * 256,
                sectors as f64 * 256.0 / (1024.0 * 1024.0)
            );
        }
    }
    Ok(())
}

impl DeviceCommand for RpmbArgs {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()> {
        dev.enter_da_mode()?;

        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        match &self.command {
            RpmbCommand::Read(args) => perform_rpmb_io(
                dev,
                parse_region(args.region)?,
                args.start_sector,
                args.num_sectors,
                &args.file,
                true,
            )?,
            RpmbCommand::Write(args) => {
                let region = parse_region(args.region)?;
                let storage = dev
                    .get_storage()
                    .ok_or_else(|| anyhow!("Failed to retrieve storage information"))?;

                if let Some(key) = &args.key {
                    info!("Authenticating RPMB using provided key before write...");
                    dev.auth_rpmb(region, &decode_rpmb_key(key)?)?;
                    info!("RPMB authentication was successful!");
                } else if storage.kind() == StorageType::Ufs {
                    info!(
                        "No RPMB key provided; trying device-side UFS RPMB key derivation before write"
                    );
                }

                perform_rpmb_io(
                    dev,
                    region,
                    args.start_sector,
                    args.num_sectors,
                    &args.file,
                    false,
                )?;
            }
            RpmbCommand::Auth(args) => {
                info!("Authenticating RPMB using provided key...");
                dev.auth_rpmb(parse_region(args.region)?, &decode_rpmb_key(&args.key)?)?;
                info!("Authentication was successful!");
            }
            RpmbCommand::VerifyDerived(args) => {
                info!("Deriving and verifying the device RPMB key without writing RPMB data...");
                verify_derived(dev, parse_region(args.region)?)?;
                info!("Device-derived RPMB key verification was successful!");
            }
            RpmbCommand::Erase(args) => erase_rpmb(dev, args)?,
            RpmbCommand::Info(args) => show_rpmb_info(dev, args)?,
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: RpmbCommand,
    }

    #[test]
    fn parses_read_sector_arguments_with_declared_types() {
        let cli = TestCli::try_parse_from([
            "test",
            "read",
            "--region",
            "3",
            "--start-sector",
            "256",
            "--num-sectors",
            "200",
            "rpmb.bin",
        ])
        .unwrap();

        let RpmbCommand::Read(args) = cli.command else { panic!("expected RPMB read") };
        assert_eq!(args.region, 3);
        assert_eq!(args.start_sector, 256);
        assert_eq!(args.num_sectors, Some(200));
    }

    #[test]
    fn rejects_out_of_range_region() {
        let error =
            TestCli::try_parse_from(["test", "read", "--region", "4", "rpmb.bin"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn parses_verify_derived_command() {
        let cli = TestCli::try_parse_from(["test", "verify-derived", "--region", "2"]).unwrap();
        let RpmbCommand::VerifyDerived(args) = cli.command else {
            panic!("expected RPMB verify-derived")
        };
        assert_eq!(args.region, 2);
    }

    #[test]
    fn erase_requires_exactly_one_scope_and_accepts_force() {
        assert!(TestCli::try_parse_from(["test", "erase"]).is_err());
        assert!(
            TestCli::try_parse_from(["test", "erase", "--region", "0", "--all-regions"]).is_err()
        );

        let cli = TestCli::try_parse_from(["test", "erase", "--region", "2", "--force"]).unwrap();
        let RpmbCommand::Erase(args) = cli.command else { panic!("expected RPMB erase") };
        assert_eq!(args.region, Some(2));
        assert!(args.force);
    }

    #[test]
    fn info_defaults_to_all_regions() {
        let cli = TestCli::try_parse_from(["test", "info"]).unwrap();
        let RpmbCommand::Info(args) = cli.command else { panic!("expected RPMB info") };
        assert_eq!(args.region, None);
    }

    #[test]
    fn validates_rpmb_key_length() {
        assert!(decode_rpmb_key(&"aa".repeat(32)).is_ok());
        assert!(decode_rpmb_key("aa").is_err());
    }
}
