/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/

use acon::{MMIO, SoC};
use hacc::DaEntry;
use log::{debug, info, warn};
use penumbra_macros::XmlCommand;
use wincode::SchemaWrite;

use crate::da::extensions::{KeyDeriveId, KeyDeriveParams, KeySize, SejParams};
use crate::da::xml::Xml;
use crate::da::xml::cmd::{XmlCmdLifetime, XmlCommand};
use crate::da::{DownloadProtocol, NOOP_PROGRESS};
use crate::error::{PenumbraError, ProtocolError, Result};
use crate::exploit::{DaEntryExt, get_v6_payload};
use crate::port::MtkPort;
use crate::storage::{RPMB_FRAME_DATA_SZ, RpmbRegion, Storage};
use crate::traits::{ProgressCallback, Reader, ToBytes, Writer};
use crate::utils::analysis::{Aarch64Analyzer, Analyzer, Arch, ArchAnalyzer, ArmAnalyzer};
use crate::utils::xml::{get_tag, get_tag_usize};

const DA_EXT: &[u8] = include_bytes!("../../../payloads/da_xml.bin");
const POINTER_TABLE_MAGIC: u32 = 0x54525450;
const MAX_RPMB_TRANSFER_SECTORS: u32 = u32::MAX / RPMB_FRAME_DATA_SZ as u32;

#[derive(SchemaWrite, ToBytes)]
#[repr(C)]
struct ExtPointerTable {
    magic: u32,
    uart_base: u32,
    reg_cmd: u32,
    clear_err_msg: u32,
    set_err_msg: u32,
    malloc: u32,
    free: u32,
    mmc_get_card: u32,
    ufs_get_lu: u32,
    ufs_get_tag: u32,
    ufs_queuecommand: u32,
    ufs_put_tag: u32,
    da_key_derive: u32,
    ufs_read_desc: u32,
}

#[derive(XmlCommand)]
pub struct ExtAck;

#[derive(XmlCommand)]
pub struct ExtDaCtx {
    #[xml(tag = "sej_base", fmt = "0x{sej_base:X}")]
    sej_base: u32,
    #[xml(tag = "tzcc_base", fmt = "0x{tzcc_base:X}")]
    tzcc_base: u32,
    #[xml(tag = "ssr_base", fmt = "0x{ssr_base:X}")]
    ssr_base: u32,
    #[xml(tag = "da2_base", fmt = "0x{da2_base:X}")]
    da2_base: u32,
    #[xml(tag = "da2_size", fmt = "0x{da2_size:X}")]
    da2_size: u32,
    #[xml(tag = "storage")]
    storage: String,
    #[xml(tag = "usb_log")]
    usb_log: String,
}

#[derive(XmlCommand)]
pub struct ExtReadMem {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u32,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: usize,
}

#[derive(XmlCommand)]
pub struct ExtWriteMem {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u32,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: usize,
}

#[derive(XmlCommand)]
pub struct ExtReadReg {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u64,
}

#[derive(XmlCommand)]
pub struct ExtWriteReg {
    #[xml(tag = "address", fmt = "0x{address:X}")]
    address: u64,
    #[xml(tag = "value", fmt = "0x{value:X}")]
    value: u32,
}

#[derive(XmlCommand)]
pub struct ExtKeyDerive {
    #[xml(tag = "key_type")]
    pub key_type: String,
    #[xml(tag = "key_length", fmt = "0x{key_length:X}")]
    pub key_length: u32,
    #[xml(tag = "label")]
    pub label: String,
    #[xml(tag = "salt")]
    pub salt: String,
}

#[derive(XmlCommand)]
pub struct ExtSej {
    #[xml(tag = "encrypt")]
    encrypt: String,
    #[xml(tag = "ac")]
    anti_clone: String,
    #[xml(tag = "length", fmt = "0x{length:X}")]
    length: u32,
    #[xml(tag = "cbc")]
    cbc: String,
    #[xml(tag = "key_id")]
    key_id: String,
    #[xml(tag = "key_size")]
    key_size: String,
}

#[derive(XmlCommand)]
pub struct ExtRpmbInit {
    #[xml(tag = "partition", fmt = "{partition}")]
    partition: u32,
    #[xml(tag = "key")]
    key: String,
}

#[derive(XmlCommand)]
pub struct ExtRpmbRead {
    #[xml(tag = "partition", fmt = "{partition}")]
    partition: u32,
    #[xml(tag = "start_sector", fmt = "{start_sector}")]
    start_sector: u32,
    #[xml(tag = "sectors_count", fmt = "{sectors_count}")]
    sectors_count: u32,
}

#[derive(XmlCommand)]
pub struct ExtRpmbWrite {
    #[xml(tag = "partition", fmt = "{partition}")]
    partition: u32,
    #[xml(tag = "start_sector", fmt = "{start_sector}")]
    start_sector: u32,
    #[xml(tag = "sectors_count", fmt = "{sectors_count}")]
    sectors_count: u32,
}

#[derive(XmlCommand)]
pub struct ExtRpmbInfo {
    #[xml(tag = "partition", fmt = "{partition}")]
    partition: u32,
}

pub fn boot_extensions<P: MtkPort>(xml: &mut Xml, port: &mut P, da: &DaEntry<'_>) -> Result<bool> {
    let Some(chip) = xml.get_devinfo().chip() else {
        warn!("Failed to get chip info, continuing without extensions");
        return Ok(false);
    };

    let Some(ext_data) = prepare_extensions(da, chip) else {
        warn!("Failed to prepare XML extensions. Continuing without.");
        return Ok(false);
    };

    debug!("Trying booting XML extensions...");

    let ext_addr = 0x68000000;
    let ext_size = DA_EXT.len() as u32;

    info!("Uploading XML DA extensions to 0x{:08X} (0x{:X} bytes)", ext_addr, ext_size);

    if xml.boot_to(port, ext_addr, &ext_data).is_err() {
        warn!("Failed to upload XML extensions, continuing without extensions");
        return Ok(false);
    }

    if xmlcmd!(xml, port, ExtAck).is_err() {
        warn!("Extensions did not reply, continuing without extensions");
        return Ok(false);
    }

    let response = xml.get_upload_file_resp(port);
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    if response.is_err() {
        warn!("Failed to get extension ack response, continuing without extensions");
        return Ok(false);
    };

    let ack: String = get_tag(&response?, "status")?;
    if ack != "OK" {
        warn!("DA extensions failed to start: {}", ack);
        return Ok(false);
    }

    let sej_base = chip.hacc();
    let tzcc_base = chip.tzcc().map(|n| n.get()).unwrap_or_default();
    let ssr_base = chip.ssr().map(|n| n.get()).unwrap_or_default();
    let da2_base = da.da2().addr();
    let da2_size = da.da2().region_length() as u32;
    let storage = xml.get_storage(port).map_or("Unknown", |s| s.as_str());
    let usb_log = if xml.usb_log_channel { "yes" } else { "no" };

    xmlcmd_e!(
        xml, port, ExtDaCtx, sej_base, tzcc_base, ssr_base, da2_base, da2_size, storage, usb_log
    )?;

    info!("Successfully booted XML extensions");

    Ok(true)
}

fn prepare_extensions(da: &DaEntry<'_>, chip: SoC) -> Option<Vec<u8>> {
    let da2address = da.da2().addr() as u64;
    let da2data = da.da2_code();

    let analyzer = match da.arch() {
        Arch::Aarch64 => Analyzer::Aarch64(Aarch64Analyzer::new(da2data.into(), da2address)),
        Arch::Arm => Analyzer::Arm(ArmAnalyzer::new(da2data.into(), da2address)),
        _ => unreachable!(),
    };

    let is_arm64 = matches!(da.arch(), Arch::Aarch64);
    let mut da_ext_data = get_v6_payload(DA_EXT, is_arm64).to_vec();

    let reg_cmd_addr = analyzer
        .fn_from_str("CMD:REBOOT")
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("Reg CMD function at VA 0x{:X}", reg_cmd_addr);

    let malloc_addr = analyzer
        .va_to_off(reg_cmd_addr as u64)
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("Malloc function at VA 0x{:X}", malloc_addr);

    let free_addr = analyzer
        .str_xref("Bad %s")
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|bl_off| analyzer.next_bl_from_off(bl_off + 4))
        .and_then(|bl_off| analyzer.bl_target(bl_off))? as u32;

    debug!("Free function at VA 0x{:X}", free_addr);

    // On newer devices, MMC is not compiled at all.
    let mmc_get_card = analyzer
        .fn_from_str("mmc_switch_part")
        .and_then(|off| analyzer.next_bl_from_off(off))
        .and_then(|bl_off| analyzer.bl_target(bl_off))
        .unwrap_or(0) as u32;

    debug!("mmc_get_card function at VA 0x{:X}", mmc_get_card);

    let unsup_cmd = analyzer.str_xref("Unsupported command.")?;

    let set_err_msg =
        analyzer.next_bl_from_off(unsup_cmd).and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("set_err_msg function at VA 0x{:X}", set_err_msg);

    let clear_err_msg =
        analyzer.next_bl_from_off(unsup_cmd - 0x10).and_then(|off| analyzer.bl_target(off))? as u32;

    debug!("clear_err_msg function at VA 0x{:X}", clear_err_msg);

    let (ufs_get_lu, ufs_get_tag, ufs_queuecommand, ufs_put_tag) = if is_arm64 {
        (0, 0, 0, 0)
    } else {
        find_ufs_rpmb_helpers(&analyzer).unwrap_or((0, 0, 0, 0))
    };

    if ufs_get_lu != 0 && ufs_get_tag != 0 && ufs_queuecommand != 0 && ufs_put_tag != 0 {
        debug!(
            "UFS RPMB helpers at get_lu=0x{:X}, get_tag=0x{:X}, queuecommand=0x{:X}, put_tag=0x{:X}",
            ufs_get_lu, ufs_get_tag, ufs_queuecommand, ufs_put_tag
        );
    } else {
        debug!("Could not locate UFS RPMB helper functions");
    }

    let da_key_derive =
        if is_arm64 { 0 } else { find_native_da_key_derive(&analyzer).unwrap_or(0) };
    if da_key_derive != 0 {
        info!("Using native DA key derivation helper at 0x{da_key_derive:08X}");
    } else {
        debug!("Could not locate native DA key derivation helper");
    }

    let ufs_read_desc = if is_arm64 { 0 } else { find_ufs_read_desc(&analyzer).unwrap_or(0) };
    if ufs_read_desc != 0 {
        info!("Using native UFS descriptor reader at 0x{ufs_read_desc:08X}");
    } else {
        debug!("Could not locate native UFS descriptor query helper");
    }

    let uart_base = chip.uart0();

    debug!("UART base address at 0x{:X}", uart_base);

    let table = ExtPointerTable {
        magic: POINTER_TABLE_MAGIC,
        uart_base,
        reg_cmd: reg_cmd_addr,
        clear_err_msg,
        set_err_msg,
        malloc: malloc_addr,
        free: free_addr,
        mmc_get_card,
        ufs_get_lu,
        ufs_get_tag,
        ufs_queuecommand,
        ufs_put_tag,
        da_key_derive,
        ufs_read_desc,
    };

    let off = da_ext_data.len() - ExtPointerTable::SIZE;

    da_ext_data[off..off + ExtPointerTable::SIZE].copy_from_slice(&table.to_bytes());

    Some(da_ext_data)
}

fn find_ufs_rpmb_helpers(analyzer: &Analyzer) -> Option<(u32, u32, u32, u32)> {
    let read_counter_off = analyzer.fn_from_str("rpmb_authen_read_counter")?;

    let get_lu_bl = analyzer.next_bl_from_off(read_counter_off)?;
    let ufs_get_lu = analyzer.bl_target(get_lu_bl)? as u32;

    let get_tag_bl = analyzer.next_bl_from_off(get_lu_bl + 4)?;
    let ufs_get_tag = analyzer.bl_target(get_tag_bl)? as u32;

    // ARM32 layout observed in MT6895-family DAs.
    let ufs_queuecommand = analyzer.bl_target(read_counter_off + 0x150)? as u32;
    let ufs_put_tag = analyzer.bl_target(read_counter_off + 0x2D4)? as u32;

    Some((ufs_get_lu, ufs_get_tag, ufs_queuecommand, ufs_put_tag))
}

fn find_native_da_key_derive(analyzer: &Analyzer) -> Option<u32> {
    let offset = analyzer.fn_from_str("key_derive fails")?;

    // Guard the string match with the ARM32 prologue used by the native
    // three-argument wrapper in the MT6895 DA.
    let expected = [0xE92D_48F0, 0xE28D_B010, 0xE24D_D030];
    for (index, instruction) in expected.into_iter().enumerate() {
        if analyzer.read_u32(offset + index * 4)? != instruction {
            return None;
        }
    }

    let address = analyzer.off_to_va(offset)?;
    if address > u32::MAX as u64 || address & 3 != 0 {
        return None;
    }

    Some(address as u32)
}

fn find_ufs_read_desc(analyzer: &Analyzer) -> Option<u32> {
    let offset =
        analyzer.fn_from_str("[UFS] failed reading descriptor. desc_id %d desc_len %d ret %d")?;

    let expected = [0xE92D_48F0, 0xE28D_B010, 0xE24D_D010, 0xE1A0_4001];
    for (index, instruction) in expected.into_iter().enumerate() {
        if analyzer.read_u32(offset + index * 4)? != instruction {
            return None;
        }
    }

    let address = analyzer.off_to_va(offset)?;
    if address > u32::MAX as u64 || address & 3 != 0 {
        return None;
    }

    Some(address as u32)
}

pub(super) fn peek<W: Writer, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    length: usize,
    writer: W,
    progress: F,
) -> Result<()> {
    xmlcmd!(xml, port, ExtReadMem, addr as u32, length)?;

    xml.upload_data(port, length, writer, progress)?;

    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn poke<R: Reader, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    length: usize,
    reader: R,
    progress: F,
) -> Result<()> {
    xmlcmd!(xml, port, ExtWriteMem, addr as u32, length)?;

    xml.download_data(port, length, reader, progress)?;

    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn read_register<P: MtkPort>(xml: &mut Xml, port: &mut P, addr: u64) -> Result<u32> {
    xmlcmd!(xml, port, ExtReadReg, addr)?;

    let response = xml.get_upload_file_resp(port);
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    let resp = response?;

    let value: u32 = get_tag_usize(&resp, "value")? as u32;

    Ok(value)
}

pub(super) fn write_register<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    addr: u64,
    value: u32,
) -> Result<()> {
    xmlcmd_e!(xml, port, ExtWriteReg, addr, value)
}

pub(super) fn derive_key<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    params: KeyDeriveParams,
) -> Result<Vec<u8>> {
    const MAX_DATA_LEN: usize = 0x20;

    let (key_type, key_length, label, salt) = match params {
        KeyDeriveParams::Id { id, len } => {
            (id.to_string(), len.to_bytes() as u32, String::new(), String::new())
        }
        KeyDeriveParams::Input { label, salt, len } => {
            if label.len() > MAX_DATA_LEN || salt.len() > MAX_DATA_LEN {
                return Err(PenumbraError::InvalidKeySourceLength.into());
            }

            (
                KeyDeriveId::Input.to_string(),
                len.to_bytes() as u32,
                hex::encode(label),
                hex::encode(salt),
            )
        }
    };

    xmlcmd!(xml, port, ExtKeyDerive, key_type, key_length, label, salt)?;

    let response = xml.get_upload_file_resp(port);
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    let resp = response?;

    let key_hex: String = get_tag(&resp, "result")?;

    let key = hex::decode(&key_hex).map_err(|_| ProtocolError::InvalidResponseFormat)?;

    Ok(key)
}

pub(super) fn sej_aes<R: Reader, W: Writer, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    params: &SejParams,
    reader: R,
    writer: W,
) -> Result<()> {
    let encrypt_str = if params.encrypt { "yes" } else { "no" };
    let ac_str = if params.anti_clone { "yes" } else { "no" };
    let cbc_str = if params.cbc { "yes" } else { "no" };

    xmlcmd!(
        xml,
        port,
        ExtSej,
        encrypt_str,
        ac_str,
        params.length,
        cbc_str,
        params.key_id.to_string(),
        params.key_sz.to_string()
    )?;

    xml.download_data(port, params.length as usize, reader, NOOP_PROGRESS)?;
    xml.upload_data(port, params.length as usize, writer, NOOP_PROGRESS)?;

    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

fn init_rpmb<P: MtkPort>(xml: &mut Xml, port: &mut P, region: RpmbRegion) -> Result<()> {
    let key =
        derive_key(xml, port, KeyDeriveParams::Id { id: KeyDeriveId::Rpmb, len: KeySize::Key256 })?;

    // If the RPMB is already initialized (even with another key), this will succeed
    // without actually changing the key.
    xmlcmd_e!(xml, port, ExtRpmbInit, region as u32, hex::encode(&key))?;
    xml.rpmb_authenticated_regions |= 1 << (region as u8);
    Ok(())
}

fn storage_sector_count(rpmb_size: u64) -> Result<Option<u32>> {
    if rpmb_size == 0 {
        return Ok(None);
    }

    let sectors = u32::try_from(rpmb_size / RPMB_FRAME_DATA_SZ as u64)
        .map_err(|_| PenumbraError::RpmbSectorOutOfBounds)?;
    Ok(Some(sectors))
}

fn checked_rpmb_data_len(
    start_sector: u32,
    num_sectors: u32,
    max_sectors: Option<u32>,
) -> Result<usize> {
    if num_sectors == 0 || num_sectors > MAX_RPMB_TRANSFER_SECTORS {
        return Err(PenumbraError::RpmbSectorOutOfBounds.into());
    }

    let end = start_sector.checked_add(num_sectors).ok_or(PenumbraError::RpmbSectorOutOfBounds)?;
    if max_sectors.is_some_and(|max| end > max) {
        return Err(PenumbraError::RpmbSectorOutOfBounds.into());
    }

    (num_sectors as usize)
        .checked_mul(RPMB_FRAME_DATA_SZ)
        .ok_or_else(|| PenumbraError::RpmbSectorOutOfBounds.into())
}

fn rpmb_max_sectors<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    storage_type: crate::storage::StorageType,
    global_rpmb_size: u64,
) -> Result<Option<u32>> {
    let global = storage_sector_count(global_rpmb_size)?;
    if storage_type != crate::storage::StorageType::Ufs {
        return Ok(global);
    }

    match get_rpmb_region_info(xml, port, region) {
        Ok((_, sectors)) if sectors != 0 => Ok(Some(sectors)),
        Ok(_) if region == RpmbRegion::R0 => Ok(global),
        Ok(_) => Ok(Some(0)),
        Err(error) => {
            warn!("Failed to retrieve RPMB region {} capacity: {error}", region as u32);
            if region == RpmbRegion::R0 { Ok(global) } else { Err(error) }
        }
    }
}

pub(super) fn get_rpmb_region_info<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
) -> Result<(bool, u32)> {
    let Some(storage) = xml.get_storage(port) else {
        return Err(ProtocolError::CannotGetStorageInfo.into());
    };
    let storage_type = storage.kind();
    let rpmb_size = storage.get_rpmb_size();

    if storage_type != crate::storage::StorageType::Ufs {
        if region != RpmbRegion::R0 {
            return Ok((false, 0));
        }

        let sectors = storage_sector_count(rpmb_size)?.unwrap_or(0);
        return Ok((sectors != 0, sectors));
    }

    xmlcmd!(xml, port, ExtRpmbInfo, region as u32)?;
    let response = xml.get_upload_file_resp(port);
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)?;

    let response = response?;
    let enabled = get_tag::<String>(&response, "enabled")? == "yes";
    let sectors = get_tag::<u32>(&response, "sector_count")?;
    Ok((enabled, sectors))
}

pub(super) fn read_rpmb<W: Writer, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    writer: W,
    progress: F,
) -> Result<()> {
    let Some(storage) = xml.get_storage(port) else {
        return Err(ProtocolError::CannotGetStorageInfo.into());
    };

    let storage_type = storage.kind();
    let rpmb_size = storage.get_rpmb_size();
    if storage_type == crate::storage::StorageType::Ufs {
        info!("Skipping RPMB key derivation/init for UFS RPMB read");
    } else if xml.rpmb_authenticated_regions & (1 << (region as u8)) != 0 {
        info!("Using the already authenticated RPMB key for RPMB read");
    } else {
        init_rpmb(xml, port, region)?;
    }

    let max_sectors = rpmb_max_sectors(xml, port, region, storage_type, rpmb_size)?;
    let data_len = checked_rpmb_data_len(start_sector, num_sectors, max_sectors)?;
    if max_sectors.is_none() {
        info!("Device reports unknown RPMB size; skipping RPMB bounds check");
    }

    xmlcmd!(xml, port, ExtRpmbRead, region as u32, start_sector, num_sectors)?;
    if let Err(error) = xml.upload_data(port, data_len, writer, progress) {
        let _ = xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd);
        return Err(error);
    }
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn write_rpmb<R: Reader, F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    reader: R,
    progress: F,
) -> Result<()> {
    let Some(storage) = xml.get_storage(port) else {
        return Err(ProtocolError::CannotGetStorageInfo.into());
    };

    let storage_type = storage.kind();
    let rpmb_size = storage.get_rpmb_size();
    if xml.rpmb_authenticated_regions & (1 << (region as u8)) != 0 {
        info!("Using the already authenticated RPMB key for RPMB write");
    } else {
        init_rpmb(xml, port, region)?;
    }

    let max_sectors = rpmb_max_sectors(xml, port, region, storage_type, rpmb_size)?;
    let data_len = checked_rpmb_data_len(start_sector, num_sectors, max_sectors)?;
    if max_sectors.is_none() {
        info!("Device reports unknown RPMB size; skipping RPMB bounds check");
    }

    xmlcmd!(xml, port, ExtRpmbWrite, region as u32, start_sector, num_sectors)?;
    if let Err(error) = xml.download_data(port, data_len, reader, progress) {
        let _ = xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd);
        return Err(error);
    }
    xml.lifetime_ack(port, XmlCmdLifetime::CmdEnd)
}

pub(super) fn erase_rpmb<F: ProgressCallback, P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    start_sector: u32,
    num_sectors: u32,
    progress: F,
) -> Result<()> {
    let total_bytes = num_sectors as u64 * RPMB_FRAME_DATA_SZ as u64;

    let zero_reader = std::io::repeat(0).take(total_bytes);

    write_rpmb(xml, port, region, start_sector, num_sectors, zero_reader, progress)
}

pub(super) fn auth_rpmb<P: MtkPort>(
    xml: &mut Xml,
    port: &mut P,
    region: RpmbRegion,
    key: &[u8],
) -> Result<()> {
    if key.len() != 32 {
        return Err(PenumbraError::InvalidRpmbKeyLength.into());
    }

    let key_hex = hex::encode(key);
    xmlcmd_e!(xml, port, ExtRpmbInit, region as u32, key_hex)?;
    xml.rpmb_authenticated_regions |= 1 << (region as u8);
    Ok(())
}
