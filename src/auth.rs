// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for App.
//!
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! thin wrappers matching the original App call sites (taking `&AppConfig` + `&HeaderMap`).

use axum::http::{HeaderMap, StatusCode};

use crate::config::AppConfig;

pub use sentin8::auth::client::AuthContext;

/// Verify the Bearer token and return the auth context.
pub async fn verify_token(
    config: &AppConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.auth_client, headers).await
}

/// Require any of the given scopes (platform admins bypass).
pub async fn require_any_scope(
    config: &AppConfig,
    headers: &HeaderMap,
    scopes: &[&str],
) -> Result<AuthContext, (StatusCode, String)> {
    let a = verify_token(config, headers).await?;
    a.require_any_scope(scopes)?;
    Ok(a)
}
