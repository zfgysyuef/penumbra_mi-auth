/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025-2026 Shomy
*/
use std::time::Duration;

use log::{debug, error, info};

use crate::Result;
use crate::auth::{AuthManager, SignData, SignPurpose, SignRequest};
use crate::error::{AuthError, PenumbraError, ProtocolError};
use crate::port::{ConnectionType, MAX_TIMEOUT, MIN_TIMEOUT, MtkPort};
use crate::preloader::cmd::Command;

pub struct PlProtocol<'a, P: MtkPort> {
    port: &'a mut P,
}

impl<'a, P: MtkPort> PlProtocol<'a, P> {
    const MAX_SLA_CHALLENGE_LEN: usize = 0x1000;
    const SEQ: [u8; 4] = [0xA0, 0x0A, 0x50, 0x05];

    pub const fn new(port: &'a mut P) -> Self {
        Self { port }
    }

    // Writes the provided data to the device
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.port.write_all(data)
    }

    // Reads the exact number of bytes required to fill the provided buffer
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.port.read_exact(buf)
    }

    pub fn echo(&mut self, data: &[u8], size: usize) -> Result<()> {
        self.write(data)?;
        let mut buf = vec![0u8; size];
        self.read(&mut buf)?;
        if buf == data { Ok(()) } else { Err(ProtocolError::DataMismatch.into()) }
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.port.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.port.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn write_u32_be(&mut self, value: u32) -> Result<()> {
        let buf = value.to_be_bytes();
        self.port.write_all(&buf)
    }

    /// Performs the handshake sequence with the preloader/bootrom.
    /// If the handshake is successful, the device is ready to receive commands.
    /// If the device is already handshaken, this will return Ok.
    pub fn handshake(&mut self) -> Result<()> {
        self.handshake_with_retries(5)
    }

    pub fn handshake_with_retries(&mut self, retries: usize) -> Result<()> {
        info!("Starting handshake...");
        let mut last_err = None;

        // When the device is connecting through preloader, the USB port
        // gets spammed with b"READY" messages.
        // As a fix, we send the first byte of the SEQ so it detects us!
        if self.port.connection_type() != ConnectionType::Brom {
            self.port.write_u8(Self::SEQ[0])?;
        }

        self.port.set_timeout(MAX_TIMEOUT)?;

        for attempt in 1..=retries {
            match self.handshake_seq() {
                Ok(()) => {
                    self.port.set_timeout(MIN_TIMEOUT)?;
                    info!("Handshake completed!");
                    return Ok(());
                }
                Err(err) => {
                    debug!("Handshake attempt {attempt}/{retries} failed: {err}");
                    std::thread::sleep(Duration::from_millis(10));

                    // We drain the USB port from any stale data in the buffer.
                    // Just to be sure, we also read u8s until we get a timeout,
                    // as sometimes flush might not be enough.
                    self.port.set_timeout(Duration::from_millis(50))?;
                    while self.port.read_u8().is_ok() {}
                    self.port.set_timeout(MAX_TIMEOUT)?;

                    self.port.flush()?;

                    last_err = Some(err);
                }
            }
        }

        error!("Handshake failed after {retries} attempts.");

        self.port.set_timeout(MIN_TIMEOUT)?;
        Err(last_err.unwrap_or_else(|| ProtocolError::HandshakeFailed.into()))
    }

    fn handshake_seq(&mut self) -> Result<()> {
        for &byte in &Self::SEQ {
            self.port.write_u8(byte)?;

            match self.port.read_u8() {
                Ok(resp) => {
                    let expected = byte ^ 0xFF;

                    if resp == expected {
                        continue;
                    } else if resp == Self::SEQ[0] {
                        // Already handshaken, so preloader just echoes
                        return Ok(());
                    } else {
                        return Err(ProtocolError::HandshakeMismatch(expected, resp).into());
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Jumps to the specified address
    pub fn jump_da(&mut self, address: u32) -> Result<()> {
        debug!("Jump to DA at 0x{:08X}", address);

        self.echo(&[Command::JumpDa as u8], 1)?;
        self.echo(&address.to_be_bytes(), 4)?;

        status_ok!(self);

        Ok(())
    }

    pub fn send_da(
        &mut self,
        da_data: &[u8],
        da_len: u32,
        address: u32,
        sig_len: u32,
    ) -> Result<()> {
        debug!("Sending DA, size: {}", da_data.len());
        self.echo(&[Command::SendDa as u8], 1)?;
        self.echo(&address.to_be_bytes(), 4)?;
        self.echo(&(da_len).to_be_bytes(), 4)?;
        self.echo(&sig_len.to_be_bytes(), 4)?;

        status_ok!(self);

        self.write(da_data)?;

        debug!("DA sent!");

        let checksum = self.read_u16_be()?;
        debug!("Received checksum: 0x{:04X}", checksum);

        status_ok!(self);

        Ok(())
    }

    pub fn send_auth(&mut self, data: &[u8]) -> Result<()> {
        self.echo(&[Command::SendAuth as u8], 1)?;

        let len = data.len() as u32;
        self.echo(&len.to_be_bytes(), 4)?;

        status_ok!(self);

        self.write(data)?;

        // Checksum
        self.read_u16_be()?;

        status_ok!(self);

        info!("Auth sent successfully!");
        Ok(())
    }

    pub fn get_hw_code(&mut self) -> Result<u16> {
        self.echo(&[Command::GetHwCode as u8], 1)?;

        let hw_code = self.read_u16_be()?;
        status_ok!(self);

        debug!("HW Code: 0x{:04X}", hw_code);

        Ok(hw_code)
    }

    pub fn get_hw_sw_ver(&mut self) -> Result<(u16, u16, u16)> {
        self.echo(&[Command::GetHwSwVer as u8], 1)?;

        let hw_sub_code = self.read_u16_be()?;
        let hw_ver = self.read_u16_be()?;
        let sw_ver = self.read_u16_be()?;
        status_ok!(self);

        debug!(
            "HW Sub Code: 0x{:04X}, HW Ver: 0x{:04X}, SW Ver: 0x{:04X}",
            hw_sub_code, hw_ver, sw_ver
        );

        Ok((hw_sub_code, hw_ver, sw_ver))
    }

    pub fn get_soc_id(&mut self) -> Result<[u8; 32]> {
        let mut soc_id = [0u8; 32];

        self.echo(&[Command::GetSocId as u8], 1)?;

        let length = self.read_u32_be()? as usize;

        if length > soc_id.len() {
            return Err(ProtocolError::InvalidResponseLength.into());
        }

        self.read(&mut soc_id)?;

        status_ok!(self);

        debug!("SoC ID: {:02X?}", soc_id);

        Ok(soc_id)
    }

    pub fn get_meid(&mut self) -> Result<[u8; 16]> {
        self.echo(&[Command::GetMeId as u8], 1)?;

        let mut meid = [0u8; 16];

        let length = self.read_u32_be()? as usize;

        if length != meid.len() {
            return Err(ProtocolError::InvalidResponseLength.into());
        }

        self.read(&mut meid)?;

        status_ok!(self);

        debug!("MEID: {:02X?}", meid);

        Ok(meid)
    }

    /// Returns the target configuration of the device.
    /// This configuration can be interpreted as follows:
    ///
    /// SBC = target_config & 0x1
    /// SLA = target_config & 0x2
    /// DAA = target_config & 0x4
    /// EppParam = target_config & 0x8
    /// RootCert = target_config & 0x10
    /// MemReadAuth = target_config & 0x20
    /// MemWriteAuth = target_config & 0x40
    /// CacheOpAuth = target_config & 0x80
    /// SctrlCert = target_config & 0x100
    pub fn get_target_config(&mut self) -> Result<u32> {
        self.echo(&[Command::GetTargetConfig as u8], 1)?;

        let config = self.read_u32_be()?;
        status_ok!(self);

        debug!("Target config: 0x{:08X}", config);

        Ok(config)
    }

    pub fn get_pl_capabilities(&mut self) -> Result<u32> {
        self.echo(&[Command::GetPlCap as u8], 1)?;

        let cap0 = self.read_u32_be()?;
        let _cap1 = self.read_u32_be()?; // Reserved

        Ok(cap0)
    }

    /// Reads memory from the device with size, split into 4-byte chunks.
    pub fn read32(&mut self, address: u32, size: usize, buf: &mut [u8]) -> Result<()> {
        let aligned = size.div_ceil(4) * 4;

        if buf.len() < aligned {
            return Err(PenumbraError::BufferTooSmall.into());
        }

        debug!("Read32: address=0x{:08X}, size={}, aligned={}", address, size, aligned);

        self.echo(&[Command::Read32 as u8], 1)?;
        self.echo(&address.to_be_bytes(), 4)?;
        self.echo(&((aligned / 4) as u32).to_be_bytes(), 4)?;

        status_ok!(self);

        for chunk in buf[..aligned].chunks_mut(4) {
            self.read(chunk)?;
        }

        status_ok!(self);

        Ok(())
    }

    pub fn sys_region_access(
        &mut self,
        region: u8,
        length: usize,
        offset: usize,
        data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        debug!(
            "Brom SysRegionAccess: region={}, length={}, offset={}, direction: {}",
            region,
            length,
            offset,
            if data.is_some() { "write" } else { "read" }
        );

        /*
         * Bit 0 = Read/Write (0 = Write, 1 = Read)
         * Bit 1-29 = Reserved
         * Bit 30-31 = Region 0 or 1
         */
        let attr: u32 = data.is_some() as u32 | ((region as u32) << 0x1E);

        self.echo(&[Command::SysRegionAccess as u8], 1)?;
        self.echo(&(attr).to_be_bytes(), 4)?;
        self.echo(&(offset as u32).to_be_bytes(), 4)?;
        self.echo(&(length as u32).to_be_bytes(), 4)?;

        status_ok!(self);

        if let Some(data) = data {
            self.write(data)?;
            status_ok!(self);
            Ok(None)
        } else {
            let mut buffer = vec![0u8; length];
            self.read(&mut buffer)?;
            status_ok!(self);
            Ok(Some(buffer))
        }
    }

    pub fn sla_challenge(&mut self, pubk_mod: &[u8]) -> Result<()> {
        self.sla_challenge_inner(pubk_mod, true)
    }

    /// Performs SLA without an additional SoC ID request for one-time BROM challenges.
    pub fn sla_challenge_raw(&mut self, pubk_mod: &[u8]) -> Result<()> {
        self.sla_challenge_inner(pubk_mod, false)
    }

    fn sla_challenge_inner(&mut self, pubk_mod: &[u8], include_soc_id: bool) -> Result<()> {
        let auth = AuthManager::get();
        if !auth.can_sign(pubk_mod) {
            return Err(AuthError::NoSignerAvailable.into());
        }

        let soc_id = if include_soc_id {
            self.get_soc_id().unwrap_or_default().to_vec()
        } else {
            Vec::new()
        };

        self.echo(&[Command::SlaChallenge as u8], 1)?;

        status_ok!(self);

        let length = self.read_u32_be()? as usize;
        if length == 0 || length > Self::MAX_SLA_CHALLENGE_LEN {
            return Err(ProtocolError::InvalidResponseLength.into());
        }
        let mut buffer = vec![0u8; length];
        self.read(&mut buffer)?;

        debug!("Brom Sla challenge, length: {}", length);

        let sign_data = SignData { raw: buffer, soc_id, ..Default::default() };

        let req = SignRequest {
            pubk_mod: pubk_mod.to_vec(),
            data: sign_data,
            purpose: SignPurpose::BromSla,
        };

        let signed = auth.sign(&req)?;
        let sig_len = signed.len() as u32;

        self.write_u32_be(sig_len)?;
        let resp_sig_len = self.read_u32_be()?;

        if sig_len != resp_sig_len {
            return Err(AuthError::InvalidSigLen(sig_len, resp_sig_len).into());
        }

        status_ok!(self);

        self.write(&signed)?;

        status_ok!(self);

        info!("Brom SLA challenge completed!");

        Ok(())
    }

    #[cfg(feature = "exploits")]
    pub fn exploit(&mut self) -> Result<bool> {
        use crate::exploit::{ExploitExt, Linecode};

        let cfg = self.get_target_config()?;

        if cfg == 0 {
            return Ok(true);
        }

        let success = Linecode.trigger(self.port)?;

        Ok(success)
    }
}
