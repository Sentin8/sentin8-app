// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Library surface for Sentin8:App - tests import service internals through
//! this crate name, mirroring the post/cron pattern.

#![deny(missing_docs)]

/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// Bearer token verification.
pub mod auth;
/// Auth membership provisioning client (proxy-back verbs, no table access).
pub mod auth_provision_client;
/// Environment configuration.
pub mod config;
/// OAuth dynamic client registration for app instances.
pub mod dcr;
/// Domain binding + DNS TXT verification for custom domains.
pub mod domains;
/// HTTP handlers - store listings, setup, runtime context, admin.
pub mod handlers;
/// OpenAPI spec assembly.
pub mod openapi;

// The utoipa dump for registration::print - mirrored from main.rs; the
// lib crate compiles registration::print too (test harnesses embedding
// via #[path] never invoke it, so the pointer is referenced, not run).
#[cfg_attr(test, allow(dead_code))]
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::AppOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
/// Service self-registration declarations.
pub mod registration;
/// Axum router and state builder.
pub mod server;
/// Bus consumer for Stat pipeline aggregates.
pub mod stat_event_listener;
/// Stat property creation + Web SDK snippet for app instances.
pub mod stat_integration;
/// Flow step handlers (proxy-back) for onboarding workflows.
pub mod steps;
/// Daily telemetry emission via Stat.
pub mod telemetry;
