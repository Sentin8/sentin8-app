// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! App configuration.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// App runtime configuration from environment variables.
pub struct AppConfig {
    /// HTTPS listen port.
    pub port: u16,
    /// Database URL for the platform database.
    pub database_url: String,
    /// Auth issuer URL for token verification.
    pub sentin8_auth_issuer: String,
    /// Auth JWKS URL for signature verification.
    pub sentin8_auth_jwks_url: String,
    /// Sentin8:TLS service URL.
    pub sentin8_tls_url: String,
    /// Sentin8:TLS bearer token.
    pub sentin8_tls_token: String,
    /// Sentin8:Sys service URL.
    pub sentin8_sys_url: String,
    /// Auth base URL for admin API calls.
    pub sentin8_auth_base_url: String,
    /// Stat config for App telemetry.
    pub sentin8_stat_url: String,
    /// Stat property id App reports against.
    pub sentin8_stat_property_id: uuid::Uuid,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    pub auth_client: AuthClient,
    /// Bus base URL for event publication.
    pub sentin8_bus_url: String,
    /// Bus stream family for App events (default `"app"`).
    pub stream_family: String,
}

impl AppConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("SENTIN8_APP_PORT")
                .expect("SENTIN8_APP_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_APP_PORT must be a valid u16"),
            database_url: env::var("SENTIN8_APP_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_tls_url: env::var("TLS_URL").unwrap_or_else(|_| cfg.sentin8_tls_url()),
            sentin8_tls_token: env::var("TLS_TOKEN").unwrap_or_else(|_| "app-dev".into()),
            sentin8_sys_url: env::var("Sys_URL").unwrap_or_else(|_| cfg.sentin8_sys_url()),
            sentin8_auth_base_url: env::var("SENTIN8_AUTH_BASE_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_url()),
            sentin8_stat_url: env::var("SENTIN8_STAT_URL")
                .unwrap_or_else(|_| cfg.sentin8_stat_url()),
            sentin8_stat_property_id: env::var("SENTIN8_APP_STAT_PROPERTY_ID")
                .ok()
                .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| {
                    uuid::Uuid::parse_str("a0000000-0000-0000-0000-000000000004").unwrap()
                }),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("SENTIN8_APP_STREAM_FAMILY").unwrap_or_else(|_| "app".into()),
        }
    }
}
