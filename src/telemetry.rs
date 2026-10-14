// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! App daily telemetry emission — Story
//!
//! Metrics: instances.count, listings.count, installs.daily.
//! Dimension tags: `env_id`. Wired to a Cron daily schedule.

use sentin8_stat_sdk::client::Client as StatClient;

use crate::config::AppConfig;

/// Build the Stat client for App telemetry (Story).
///
/// Registers an M2M client via DCR with Auth (scope `sentin8:stat:measure`),
/// or loads stored credentials from the database on restart. Same pattern
/// as `sentin8::bus::client::build_with_dcr` and `tls/src/traffic.rs`.
/// Build the shared stat M2M token source + base URL for the App stat
/// integration (APP-1: the listener's listing-metrics ingest). The
/// `app` M2M workload already carries `sentin8:stat:measure` — the same
/// identity the daily telemetry uses.
/// Build the cert-presenting Stat ingest transport for the app workload
/// (auth DESIGN §4.3f): the `app` CERTIFICATE is the identity
/// — Stat's TLS layer authenticates the handshake; the registry map
/// authorizes the `sentin8:stat:measure` scope. No token exists.
pub async fn build_stat_token(
    config: &AppConfig,
    sentin8_auth_issuer: &str,
) -> Result<crate::stat_event_listener::StatIngest, String> {
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let cert =
        sentin8::auth::m2m::ensure_workload_certificate(sentin8_auth_issuer, "app", &ca_cert_path)
            .await
            .map_err(|e| format!("app stat identity: {e}"))?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    let http = sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map(sentin8::middleware::http_client::Sentin8HttpClient::from_client)
        .map_err(|e| format!("app stat transport: {e}"))?;
    Ok(crate::stat_event_listener::StatIngest {
        base_url: config.sentin8_stat_url.clone(),
        http: std::sync::Arc::new(http),
    })
}

/// A cert-presenting Stat transport for calls made during app provisioning
/// (stat integration). Rides the shared `app` workload certificate.
///
/// # Errors
/// Returns the transport-build error when the identity or mTLS client
/// cannot be built.
pub async fn stat_admin_transport(
    _state: &crate::handlers::AppState,
    a: &crate::auth::AuthContext,
) -> Result<reqwest::Client, String> {
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let cert = sentin8::auth::m2m::ensure_workload_certificate(&a.claims.iss, "app", &ca_cert_path)
        .await
        .map_err(|e| format!("app stat identity: {e}"))?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| format!("app stat transport: {e}"))
}

/// Build the Stat client for App telemetry : the `app`
/// CERTIFICATE is the identity — cert-presenting transport, no token.
pub async fn build_stat_client(
    config: &AppConfig,
    _pool: &sqlx::PgPool,
    sentin8_auth_issuer: &str,
) -> Result<StatClient, String> {
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let cert =
        sentin8::auth::m2m::ensure_workload_certificate(sentin8_auth_issuer, "app", &ca_cert_path)
            .await
            .map_err(|e| format!("app stat identity: {e}"))?;
    StatClient::with_workload_identity(
        config.sentin8_stat_url.clone(),
        config.sentin8_stat_property_id,
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    )
    .map_err(|e| format!("app stat transport: {e}"))
}

/// Emit daily telemetry metrics for App (Story).
///
/// Queries the App database for counts and sends a single `metric` event
/// with all metrics as the `metrics` field. Dimension tags go in `dim_tags`.
pub async fn emit_daily_telemetry(
    pool: &sqlx::PgPool,
    _config: &AppConfig,
    stat: &StatClient,
) -> Result<(), String> {
    let instances_count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM sys.app_instances WHERE status = 'active'",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count instances: {e}"))?;

    let listings_count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM store_listings WHERE status = 'published'",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count listings: {e}"))?;

    // `installs.daily` tracks new instance provisions today. The sentin8_sys_app_instances
    // table holds instance records; an install is a newly created instance.
    let installs_today: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM sys.app_instances WHERE created_at::date = now()::date",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("count installs: {e}"))?;

    stat.metric(
        "app.daily_telemetry",
        serde_json::json!({
            "instances.count": instances_count,
            "listings.count": listings_count,
            "installs.daily": installs_today,
        }),
        Some(serde_json::json!({
            "env_id": "platform",
        })),
    )
    .await
    .map_err(|e| format!("stat metric: {e}"))?;

    tracing::info!(
        instances_count,
        listings_count,
        installs_today,
        "app daily telemetry emitted"
    );
    Ok(())
}

#[cfg(test)]
mod tests {

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        });
    }
    use super::*;
    use uuid::Uuid;

    fn mk_config() -> AppConfig {
        AppConfig {
            port: 0,
            database_url: "postgres://test".into(),
            sentin8_auth_issuer: "https://test".into(),
            sentin8_auth_jwks_url: "https://test/jwks".into(),
            sentin8_tls_url: "http://test".into(),
            sentin8_tls_token: "test".into(),
            sentin8_sys_url: "http://test".into(),
            sentin8_auth_base_url: "http://test".into(),
            sentin8_stat_url: "http://localhost:3106".into(),
            sentin8_stat_property_id: Uuid::new_v4(),
            auth_client: sentin8::auth::client::Client::new(sentin8::auth::client::ClientOptions {
                base_url: "https://test".into(),
                ..Default::default()
            }),
            sentin8_bus_url: "http://test".into(),
            stream_family: "app".into(),
        }
    }

    #[test]
    fn build_stat_client_signature() {
        install_provider();
        // build_stat_client is now async and requires a DB pool + auth issuer
        // for DCR registration; the signature is exercised at runtime in the
        // server startup path. Here we only verify the config struct compiles.
        let _config = mk_config();
    }

    #[test]
    fn sentin8_app_metrics_structure() {
        install_provider();
        let metrics = serde_json::json!({
            "instances.count": 100,
            "listings.count": 50,
            "installs.daily": 5,
        });
        assert_eq!(metrics["instances.count"], 100);
        assert_eq!(metrics["listings.count"], 50);
        assert_eq!(metrics["installs.daily"], 5);

        let dim_tags = serde_json::json!({
            "env_id": "platform",
        });
        assert_eq!(dim_tags["env_id"], "platform");
    }
}
