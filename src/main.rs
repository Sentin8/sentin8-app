// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 App — third-party app store, instance management.
//!
//! Boot runs on the platform `sentin8-shell` crate: registration flag,
//! PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

mod admin_ui;
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod auth_provision_client;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod dcr;
#[allow(dead_code)]
mod domains;
mod handlers;
mod openapi;
#[allow(dead_code)]
mod policy;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod stat_event_listener;
#[allow(dead_code)]
mod stat_integration;
#[allow(dead_code)]
mod steps;
#[allow(dead_code)]
mod telemetry;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:app", "SENTIN8_APP")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::AppOpenApi::openapi()),
    )
    .await
}
