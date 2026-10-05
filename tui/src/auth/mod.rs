/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy
*/
pub mod mi;
pub mod remote;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
pub use mi::MiAuthSigner;
use penumbra::AuthManager;
pub use remote::RemoteSigner;

use crate::config::AntumbraConfig;

pub fn init_auth(
    config: Arc<AntumbraConfig>,
    mi_auth: bool,
    auth_file: Option<&Path>,
) -> Result<()> {
    let auth = AuthManager::get();

    // The requested one-shot signer must take precedence over remote and default signers.
    if mi_auth {
        let auth_path = auth_file.ok_or_else(|| anyhow::anyhow!("--mi-auth requires --auth"))?;
        let auth_data = fs::read(auth_path)?;
        auth.register_signer_first(Arc::new(MiAuthSigner::from_auth(&auth_data)?))?;
    }

    let signer = Arc::new(RemoteSigner::new(config));

    auth.register_signer(signer)?;

    Ok(())
}
