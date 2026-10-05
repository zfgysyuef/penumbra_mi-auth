/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use penumbra::error::{AuthError, PenumbraError};
use penumbra::hacc::TryRead;
use penumbra::hacc::gfh::{GfhFile, GfhKind, GfhType};
use penumbra::{SignPurpose, SignRequest, Signer};

const MI_BLOB_PREFIX: &[u8] = &[
    0x02, 0x00, 0x00, 0x00, 0x01, 0x34, 0x02, 0x20, 0x30, 0x32, 0x31, 0x31, 0x34, 0x34, 0x42, 0x30,
    0x33, 0x42, 0x31, 0x36, 0x42, 0x41, 0x42, 0x36, 0x42, 0x38, 0x35, 0x36, 0x35, 0x30, 0x35, 0x36,
    0x31, 0x37, 0x33, 0x44, 0x36, 0x46, 0x41, 0x39, 0x03, 0x10,
];
const MI_CHALLENGE_LEN: usize = 16;
const MI_SIGNATURE_LEN: usize = 256;

/// Manual one-shot signer for Xiaomi's Preloader/BROM SLA challenge.
pub struct MiAuthSigner {
    active: AtomicBool,
    expected_pubk: Vec<u8>,
}

impl MiAuthSigner {
    pub fn from_auth(auth: &[u8]) -> penumbra::Result<Self> {
        let file = GfhFile::try_read(auth)?;
        let Some(GfhKind::ToolAuth(tool_auth)) = file.get_gfh(GfhType::ToolAuth) else {
            return Err(PenumbraError::InvalidAuthFile.into());
        };

        Ok(Self {
            active: AtomicBool::new(true),
            expected_pubk: tool_auth.sla_public_key.n_key().to_vec(),
        })
    }

    fn make_blob(challenge: &[u8]) -> penumbra::Result<Vec<u8>> {
        if challenge.len() != MI_CHALLENGE_LEN {
            return Err(AuthError::Other(format!(
                "MI authentication challenge must be {MI_CHALLENGE_LEN} bytes, got {}",
                challenge.len()
            ))
            .into());
        }

        let mut blob = Vec::with_capacity(MI_BLOB_PREFIX.len() + challenge.len());
        blob.extend_from_slice(MI_BLOB_PREFIX);
        blob.extend_from_slice(challenge);
        Ok(blob)
    }

    fn decode_signature(input: &str) -> Result<Vec<u8>, String> {
        let value = input.trim();
        if value.is_empty() {
            return Err("SIGN cannot be empty".into());
        }

        let (value, force_hex, force_base64) = if let Some(value) = value.strip_prefix("hex:") {
            (value.trim(), true, false)
        } else if let Some(value) = value.strip_prefix("base64:") {
            (value.trim(), false, true)
        } else {
            (value, false, false)
        };

        let hex_value = value.strip_prefix("0x").unwrap_or(value);
        let looks_hex = hex_value.len() == MI_SIGNATURE_LEN * 2
            && hex_value.as_bytes().iter().all(u8::is_ascii_hexdigit);
        let decoded = if force_hex || (!force_base64 && looks_hex) {
            hex::decode(hex_value).map_err(|e| format!("Invalid hexadecimal SIGN: {e}"))?
        } else {
            BASE64.decode(value).map_err(|e| format!("Invalid Base64/hex SIGN: {e}"))?
        };

        if decoded.len() != MI_SIGNATURE_LEN {
            return Err(format!(
                "SIGN must be exactly {MI_SIGNATURE_LEN} bytes, got {}",
                decoded.len()
            ));
        }

        Ok(decoded)
    }

    fn prompt_signature(blob: &[u8]) -> penumbra::Result<Vec<u8>> {
        println!("MI authentication BLOB (Base64): {}", BASE64.encode(blob));
        println!("MI authentication BLOB (hex): {}", hex::encode(blob));
        println!("Sign this one-time BLOB with the Xiaomi private-key service.");

        loop {
            print!("Paste the 256-byte SIGN as Base64 or hex: ");
            io::stdout()
                .flush()
                .map_err(|e| AuthError::Other(format!("Failed to flush SIGN prompt: {e}")))?;

            let mut input = String::new();
            let read = io::stdin()
                .read_line(&mut input)
                .map_err(|e| AuthError::Other(format!("Failed to read SIGN: {e}")))?;
            if read == 0 {
                return Err(
                    AuthError::Other("Reached end of input before receiving SIGN".into()).into()
                );
            }

            match Self::decode_signature(&input) {
                Ok(signature) => return Ok(signature),
                Err(error) => eprintln!("{error}; please try again."),
            }
        }
    }
}

impl Signer for MiAuthSigner {
    fn can_handle(&self, pubk_mod: &[u8]) -> bool {
        self.active.load(Ordering::Acquire) && pubk_mod == self.expected_pubk
    }

    fn is_authorized(&self, req: &SignRequest) -> bool {
        self.active.load(Ordering::Acquire)
            && req.purpose == SignPurpose::BromSla
            && req.pubk_mod == self.expected_pubk
    }

    fn sign(&self, req: &SignRequest) -> penumbra::Result<Vec<u8>> {
        if req.purpose != SignPurpose::BromSla
            || req.pubk_mod != self.expected_pubk
            || self
                .active
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(AuthError::NoSignerAvailable.into());
        }

        let blob = Self::make_blob(&req.data.raw)?;
        Self::prompt_signature(&blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_spflash_compatible_agaa_blob() {
        let challenge = hex::decode("22bb6ca8a9e35d32e3f71029623d7b23").unwrap();
        let blob = MiAuthSigner::make_blob(&challenge).unwrap();

        assert_eq!(blob.len(), 58);
        assert_eq!(
            BASE64.encode(blob),
            "AgAAAAE0AiAwMjExNDRCMDNCMTZCQUI2Qjg1NjUwNTYxNzNENkZBOQMQIrtsqKnjXTLj9xApYj17Iw=="
        );
    }

    #[test]
    fn accepts_hex_and_base64_signatures_without_swapping() {
        let signature: Vec<u8> = (0..MI_SIGNATURE_LEN).map(|n| n as u8).collect();
        assert_eq!(MiAuthSigner::decode_signature(&hex::encode(&signature)).unwrap(), signature);
        assert_eq!(MiAuthSigner::decode_signature(&BASE64.encode(&signature)).unwrap(), signature);
        assert_eq!(
            MiAuthSigner::decode_signature(&format!("hex:{}", hex::encode(&signature))).unwrap(),
            signature
        );
        assert_eq!(
            MiAuthSigner::decode_signature(&format!("base64:{}", BASE64.encode(&signature)))
                .unwrap(),
            signature
        );
    }

    #[test]
    fn rejects_wrong_challenge_and_signature_lengths() {
        assert!(MiAuthSigner::make_blob(&[0u8; 15]).is_err());
        assert!(MiAuthSigner::decode_signature("AA==").is_err());
    }
}
