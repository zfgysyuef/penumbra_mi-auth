/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Penumbra contributors
*/
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use log::info;
use penumbra::{Device, MtkPort};

use crate::cli::DeviceCommand;
use crate::cli::common::{CONN_DA, CommandMetadata};
use crate::cli::helpers::AntumbraProgress;
use crate::cli::state::PersistedDeviceState;

#[derive(Args, Debug)]
pub struct UfsFfuArgs {
    /// Raw UFS firmware update image matching the connected device.
    pub firmware: PathBuf,
}

impl CommandMetadata for UfsFfuArgs {
    fn visible_aliases() -> &'static [&'static str] {
        &["ffu"]
    }

    fn about() -> &'static str {
        "Update UFS firmware through an XML/V6 Download Agent."
    }

    fn long_about() -> &'static str {
        "Send a raw UFS field firmware update image to an XML/V6 Download Agent. \
         The DA must support CMD:DEBUG:UFS / UPDATE-FIRMWARE. Use an image intended for \
         the connected UFS device."
    }
}

impl DeviceCommand for UfsFfuArgs {
    fn run<P: MtkPort>(&self, dev: &mut Device<P>, state: &mut PersistedDeviceState) -> Result<()> {
        let file = File::open(&self.firmware).with_context(|| {
            format!("Cannot open UFS firmware image {}", self.firmware.display())
        })?;
        let file_size = file.metadata()?.len();
        if file_size == 0 {
            bail!("UFS firmware image is empty");
        }
        let size =
            usize::try_from(file_size).context("UFS firmware image is too large for this host")?;
        let mut reader = BufReader::new(file);

        dev.enter_da_mode()?;
        state.connection_type = CONN_DA;
        state.flash_mode = 1;

        info!("Updating UFS firmware from {} ({} bytes)...", self.firmware.display(), size);
        let pb = AntumbraProgress::new(file_size);
        let mut progress = pb.get_callback("Sending UFS firmware...", "UFS firmware sent.");
        if let Err(error) = dev.update_ufs_firmware(size, &mut reader, &mut progress) {
            pb.abandon("UFS firmware update failed!");
            return Err(error.into());
        }

        info!("DA reported successful UFS firmware update completion.");
        Ok(())
    }
}
