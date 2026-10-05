/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/

use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use log::info;
use penumbra::port::{ConnectionType, PortType};
use penumbra::{DevInfoData, Device, DeviceBuilder, MMIO, MtkPort, SoC};

use crate::cli::CliArgs;
use crate::cli::helpers::logging::setup_file_logger;
use crate::cli::state::PersistedDeviceState;
use crate::helpers::SoCExt;

const DA_LOG_FILE: &str = "da.log";

pub fn setup_device<'a>(
    args: &CliArgs,
    state: &mut PersistedDeviceState,
    da_data: Option<&'a [u8]>,
    pl_data: Option<&'a [u8]>,
    auth_data: Option<&'a [u8]>,
) -> Result<Device<'a, PortType>> {
    if args.mi_auth && auth_data.is_none() {
        bail!("--mi-auth requires a matching --auth file before requesting the one-time challenge");
    }

    let usb_log_channel = state.usb_log || args.usb_log;

    let mut last_seen = Instant::now();
    let timeout = Duration::from_millis(500);

    info!("Waiting for MTK device...");
    let mtk_port = loop {
        if let Ok(Some(mut port)) = PortType::find_and_open(args.vid, args.pid, args.backend) {
            if state.flash_mode != 0 && !args.mi_auth {
                port.set_connection_type(ConnectionType::Da)?;
            }

            if args.mi_auth && port.connection_type() != ConnectionType::Brom {
                bail!(
                    "--mi-auth requires a fresh BROM connection (normally USB 0E8D:0003); reconnect the device in BROM mode"
                );
            }

            info!("Found MTK port: {}", port.get_port_name());
            break port;
        } else if last_seen.elapsed() > timeout {
            state.reset()?;
            last_seen = Instant::now();
        }

        thread::sleep(Duration::from_millis(100));
    };

    let mut builder = DeviceBuilder::new(mtk_port)
        .with_log_level(args.da_log_level)
        .with_usb_log_channel(usb_log_channel)
        .require_brom_sla(args.mi_auth);

    if usb_log_channel && let Some(device_log) = setup_file_logger(DA_LOG_FILE) {
        builder = builder.with_device_log(device_log);
    }

    builder = if let Some(da) = da_data { builder.with_da_data(da) } else { builder };
    builder = if let Some(pl) = pl_data { builder.with_preloader(pl) } else { builder };
    builder = if let Some(auth) = auth_data { builder.with_auth(auth) } else { builder };

    let mut dev = builder.build()?;

    if state.hw_code != 0 && !args.mi_auth {
        let chip = SoC::try_from_hwcode(state.hw_code);
        let dev_info = DevInfoData {
            soc_id: state.soc_id,
            meid: state.meid,
            chip,
            hw_code: state.hw_code,
            hw_subcode: state.hw_subcode,
            partitions: vec![],
            target_config: state.target_config,
            bootctrl: None,
        };

        dev.reinit(dev_info)?;
    } else {
        if args.mi_auth && state.hw_code != 0 {
            info!(
                "--mi-auth was requested; ignoring the cached DA session and requesting a fresh one-time challenge"
            );
        }
        info!("Initializing device...");
        dev.init()?;

        state.soc_id = dev.devinfo().soc_id();
        state.meid = dev.devinfo().meid();
        state.hw_code = dev.devinfo().hw_code();
        state.hw_subcode = dev.devinfo().hw_subcode();
        state.target_config = dev.devinfo().target_config();
    }

    info!("=====================================");
    info!(
        "Chip: {}",
        dev.devinfo()
            .chip()
            .map(|c| c.marketing_seg_name())
            .unwrap_or_else(|| "Unknown".to_string())
    );
    info!("HW Code: 0x{:04X}", state.hw_code);
    info!("HW Subcode: 0x{:04X}", state.hw_subcode);
    info!("SBC: {}", (state.target_config & 0x1) != 0);
    info!("SLA: {}", (state.target_config & 0x2) != 0);
    info!("DAA: {}", (state.target_config & 0x4) != 0);
    info!("=====================================");

    Ok(dev)
}
