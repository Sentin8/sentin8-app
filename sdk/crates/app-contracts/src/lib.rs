// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! # app-contracts
//!
//! Rust types for the App App-Store and runtime API - store listings,
//! visibility controls, and the runtime context handed to app instances.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Visibility controls which orgs/envs can see an App store listing.
///
/// - `Env`: only the owning environment can see the listing.
/// - `Org`: all environments under the owning organization can see the listing.
/// - `Public`: all organizations and environments can see the listing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppVisibility {
    /// Only the owning environment sees the listing.
    Env,
    /// All environments under the owning organization see the listing.
    Org,
    /// All organizations and environments see the listing (default).
    #[default]
    Public,
}

impl AppVisibility {
    /// The wire string for this visibility.
    pub fn as_str(&self) -> &'static str {
        match self {
            AppVisibility::Env => "env",
            AppVisibility::Org => "org",
            AppVisibility::Public => "public",
        }
    }

    /// Parse a wire string back into a visibility (`None` when unknown).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "env" => Some(AppVisibility::Env),
            "org" => Some(AppVisibility::Org),
            "public" => Some(AppVisibility::Public),
            _ => None,
        }
    }
}

/// One App Store listing - a published app in the store.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppStoreListing {
    /// Listing identity.
    pub id: Uuid,
    /// Human-facing app name.
    pub app_name: String,
    /// URL-safe slug (also the app hostname label).
    pub app_slug: String,
    /// Store description.
    pub description: String,
    /// Publication status.
    pub status: String,
    /// Creation timestamp (UTC).
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// The runtime context of an app instance - the tenant identity and
/// derived domains the app runtime needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppRuntimeContext {
    /// Owning organization.
    pub org_id: Uuid,
    /// Owning environment (the tenant key).
    pub env_id: Uuid,
    /// The app instance's identity.
    pub application_id: Uuid,
    /// The app slug (from the store listing).
    pub app_slug: String,
    /// The app instance's frontend hostname.
    pub hostname: String,
    /// The org's Auth (staff) domain.
    pub sentin8_auth_domain: String,
    /// The app BFF hostname - always `bff.{app_domain}`.
    pub sentin8_bff_domain: String,
    /// Instance lifecycle status.
    pub status: String,
    /// Instance display name (optional enrichment).
    #[serde(default)]
    pub instance_name: String,
    /// Instance description (optional enrichment).
    #[serde(default)]
    pub instance_description: String,
    /// Organization display name (optional enrichment).
    #[serde(default)]
    pub organization_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn app_visibility_serializes_lowercase() {
        for (v, wire) in [
            (AppVisibility::Env, "env"),
            (AppVisibility::Org, "org"),
            (AppVisibility::Public, "public"),
        ] {
            assert_eq!(serde_json::to_value(v).unwrap(), json!(wire));
            assert_eq!(AppVisibility::parse(wire), Some(v));
        }
        assert_eq!(AppVisibility::parse("bogus"), None);
        // Default is Public.
        assert_eq!(AppVisibility::default(), AppVisibility::Public);
        assert_eq!(AppVisibility::default().as_str(), "public");
    }

    #[test]
    fn app_store_listing_roundtrip() {
        let l = AppStoreListing {
            id: uuid::Uuid::new_v4(),
            app_name: "eBank".into(),
            app_slug: "ebank".into(),
            description: "Internet banking app".into(),
            status: "published".into(),
            created_at: utc("2026-01-01T00:00:00Z"),
        };
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["app_slug"], "ebank");
        let back: AppStoreListing = serde_json::from_value(v).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn app_runtime_context_defaults_when_absent() {
        // instance_name/instance_description/organization_name are
        // #[serde(default)] - older producers that omit them still parse.
        let ctx: AppRuntimeContext = serde_json::from_value(json!({
            "org_id": uuid::Uuid::new_v4(),
            "env_id": uuid::Uuid::new_v4(),
            "application_id": uuid::Uuid::new_v4(),
            "app_slug": "ebank",
            "hostname": "ebank.prod.ibank.local",
            "sentin8_auth_domain": "auth.ops.sys.example.com",
            "sentin8_bff_domain": "bff.ebank.prod.ibank.local",
            "status": "active"
        }))
        .unwrap();
        assert_eq!(ctx.instance_name, "");
        assert_eq!(ctx.instance_description, "");
        assert_eq!(ctx.organization_name, "");
        // BFF hostname convention: bff.{app_domain}.
        assert!(ctx.sentin8_bff_domain.starts_with("bff."));
    }

    #[test]
    fn app_runtime_context_full_roundtrip() {
        let ctx = AppRuntimeContext {
            org_id: uuid::Uuid::new_v4(),
            env_id: uuid::Uuid::new_v4(),
            application_id: uuid::Uuid::new_v4(),
            app_slug: "ebank".into(),
            hostname: "ebank.prod.ibank.local".into(),
            sentin8_auth_domain: "auth.ops.sys.example.com".into(),
            sentin8_bff_domain: "bff.ebank.prod.ibank.local".into(),
            status: "active".into(),
            instance_name: "Prod".into(),
            instance_description: "Production".into(),
            organization_name: "iBank".into(),
        };
        let v = serde_json::to_value(&ctx).unwrap();
        let back: AppRuntimeContext = serde_json::from_value(v).unwrap();
        assert_eq!(back, ctx);
    }
}
