// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for App.

use crate::handlers;
use axum::routing::{get, post, put};
use std::sync::Arc;

/// Build the service state (config, pool, clients, workers). Runs inside
/// the shell's `with_state` closure - the pool arrives already created and
/// PG18-checked; service-specific setup (Valkey data plane, DCR bus client,
/// engines, relays) happens here exactly as the pre-shell serve did.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::AppConfig::from_env();
    // auth DESIGN §4.3f: the `app` workload CERTIFICATE is
    // the identity - mint retries while Acme comes up (boot window); the
    // consumers' reconnect loops cover a late identity.
    let bus_client = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &config.sentin8_bus_url,
            &config.sentin8_auth_issuer,
            "app",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "app bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // ── Sentin8:Policy (- shell-owned boot): the shell's
    // boot step 8 already booted the engine (load + shared deps + hot-reload
    // + stat emitter). Services only CONSUME it - no second engine.
    let policy_engine = core.admin.policy.clone();

    let state = crate::handlers::AppState {
        config: Arc::new(config.clone()),
        pool: core.pool.clone(),
        _bus_client: bus_client.clone(),
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:app".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
    };

    // Story - background consumer of Bus `stat-pipeline` events that
    // surfaces app-usage metrics on store listings. Resilient: connection
    // failures are retried inside `run` with a 2s backoff. The stat ingest
    // (APP-1) reuses the daily-telemetry M2M identity (scope
    // `sentin8:stat:measure`); a failed DCR keeps the listener ACK-only.
    let stat_ingest = match crate::telemetry::build_stat_token(
        &config,
        &core.config.sentin8_auth_issuer,
    )
    .await
    {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::warn!(error = %e, "app: stat token source unavailable - listing metrics ingest disabled");
            None
        }
    };
    let listener = crate::stat_event_listener::StatEventListener::new(bus_client, stat_ingest);
    tokio::spawn(async move {
        listener.run().await;
    });

    // Story - daily telemetry via Stat. Fired at startup, then on a
    // 24h loop. Failures are logged and never abort the service.
    let pool = core.pool.clone();
    let stat_cfg = config.clone();
    let issuer = core.config.sentin8_auth_issuer.clone();
    tokio::spawn(async move {
        loop {
            match crate::telemetry::build_stat_client(&stat_cfg, &pool, &issuer).await {
                Ok(stat) => {
                    if let Err(e) =
                        crate::telemetry::emit_daily_telemetry(&pool, &stat_cfg, &stat).await
                    {
                        tracing::warn!(error = %e, "app: daily telemetry emit failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "app: stat client build failed");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;
        }
    });

    // Story - register App's step-handler profile with Sentin8:Flow
    // (domain = "app") so Flow can proxy-back for KYC/Approval/Document
    // steps during onboarding workflows. Best-effort: Flow may not be
    // reachable at boot; retried on the next restart.
    {
        let flow_url = sentin8::config::Sentin8Config::from_env().sentin8_flow_url();
        let cfg = sentin8::config::Sentin8Config::from_env();
        let base_url = format!("https://{}", cfg.platform_domain("sentin8:app"));
        let register = crate::steps::handler_profile_payload(&base_url, "internal");
        let http = reqwest::Client::new();
        tokio::spawn(async move {
            if let Err(e) = http
                .post(format!("{flow_url}/v1/handlers/register"))
                .json(&register)
                .send()
                .await
            {
                tracing::warn!(error = %e, "app: flow handler profile registration failed (non-fatal)");
            }
        });
    }

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` - custom payload).
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route(
            "/v1/admin/instances/uninstall",
            post(crate::admin_ui::uninstall_instance),
        )
        // Store API (Stories -7)
        .route(
            "/v1/app/store/listings",
            post(handlers::create_listing).get(handlers::list_listings),
        )
        .route(
            "/v1/app/store/listings/{id}",
            get(handlers::get_listing)
                .put(handlers::update_listing)
                .delete(handlers::archive_listing),
        )
        // Setup API (Stories -9, )
        .route("/v1/app/setup", post(handlers::setup_instance))
        .route("/v1/app/setup/{id}/status", get(handlers::setup_status))
        // Customer-mode instance discovery (auth DESIGN invariant 12): auth's
        // sign-up closure provisioning enumerates the env's customer-mode
        // instances via this OWNER API - it never touches `sys.app_instances`
        // (auth's sys.* grants are retired; DBX §6.6a).
        .route(
            "/v1/app/instances/customer-mode",
            get(handlers::customer_mode_instances),
        )
        // Runtime context (Stories , , , -34 - header-based, no auth)
        .route("/v1/app/runtime/context", get(handlers::runtime_context))
        // Admin API (Stories -16)
        .route(
            "/v1/app/admin/instances/{id}",
            get(handlers::get_instance_detail),
        )
        .route(
            "/v1/app/admin/instances/{id}/domain",
            put(handlers::update_instance_domain),
        )
        .route(
            "/v1/app/admin/instances/{id}/env-vars",
            put(handlers::update_instance_env_vars),
        )
        .route(
            "/v1/app/admin/instances/{id}/env-vars/resolve",
            get(handlers::resolve_instance_env_vars),
        )
        .route(
            "/v1/app/admin/instances/{id}/feature-flags",
            put(handlers::update_instance_feature_flags),
        )
        .route(
            "/v1/app/admin/instances/{id}/status",
            put(handlers::update_instance_status),
        )
        .route(
            "/v1/app/admin/instances/{id}/oauth-client",
            get(handlers::get_instance_oauth_client),
        )
        // Flow internal endpoint (Story)
        .route(
            "/v1/internal/steps/execute",
            post(handlers::execute_internal_step),
        )
        // ── Sentin8:Policy admin API ( - shared implementation,
        // one surface per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor - the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for crate::handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
