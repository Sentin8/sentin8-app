// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Stories -27 - Stat integration for App app instances.
//!
//! When provisioning an app instance, App:
//! 1. Creates a Stat property via `POST /v1/admin/properties`
//! 2. Registers an Auth M2M client scoped to `sentin8:stat:measure`
//! 3. Generates the Web SDK snippet HTML for the app to embed
//!
//! The `propertyId` and M2M client ID are stored on the app instance record.
//!
//! See (Integration Points).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A Stat property created for an app instance.
/// A Stat property created for an app instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatProperty {
    /// Property id.
    pub property_id: Uuid,
    /// Property name.
    pub name: String,
    /// Property slug.
    pub slug: String,
}

/// An Auth M2M client scoped to `sentin8:stat:measure` for an app instance.
/// An Auth M2M client scoped to `sentin8:stat:measure` for an app instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatM2mClient {
    /// The registered client id.
    pub client_id: String,
    /// The registered client secret.
    pub client_secret: String,
}

/// Errors returned by Stat integration operations.
#[derive(Debug, thiserror::Error)]
pub enum StatIntegrationError {
    /// The HTTP request failed or returned a non-success status.
    #[error("Stat HTTP error: {0}")]
    Http(String),
    /// The response body could not be decoded.
    #[error("Stat response decode error: {0}")]
    Decode(String),
}

/// Create a Stat property for an app instance via `POST /v1/admin/properties`.
///
/// - `sentin8_stat_base_url`: Stat server URL.
/// - `admin_token`: a bearer token with `sentin8:stat:admin` scope.
/// - `instance_id`: the App app instance ID (used for slug uniqueness).
/// - `app_name`: the app display name (used for the property name).
///
/// The property slug is derived from the instance ID to guarantee uniqueness
/// across app instances within the same org/env.
/// Create the instance's Stat property. auth DESIGN §4.3f:
/// `http` is the cert-presenting transport (the `app` workload
/// certificate IS the identity - presented on the TLS handshake; Stat's
/// TLS layer authenticates it). No bearer token exists on this path.
///
/// # Errors
/// Returns [`StatIntegrationError`] on transport failure or a
/// non-success status.
pub async fn create_sentin8_stat_property(
    http: &reqwest::Client,
    sentin8_stat_base_url: &str,
    instance_id: Uuid,
    app_name: &str,
) -> Result<StatProperty, StatIntegrationError> {
    let slug = format!("app-{}", instance_id.simple());
    let body = serde_json::json!({
        "name": format!("{app_name} (App)"),
        "slug": slug,
    });
    let resp = http
        .post(format!(
            "{}/v1/admin/properties",
            sentin8_stat_base_url.trim_end_matches('/')
        ))
        .json(&body)
        .send()
        .await
        .map_err(|e| StatIntegrationError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(StatIntegrationError::Http(format!(
            "create property failed: status {status}: {text}"
        )));
    }
    let raw: PropertyResponse = resp
        .json()
        .await
        .map_err(|e| StatIntegrationError::Decode(e.to_string()))?;
    Ok(StatProperty {
        property_id: raw.id,
        name: raw.name,
        slug: raw.slug,
    })
}

/// Register an Auth M2M client scoped to `sentin8:stat:measure` for a Stat property.
///
/// Uses Auth DCR (`POST /oauth/register`) with
/// `grant_types = ["client_credentials"]` and `scope = "sentin8:stat:measure"`.
/// The returned client credentials are stored on the app instance record and
/// used by the app's BFF to tag server-side events to Stat.
pub async fn register_sentin8_stat_m2m_client(
    sentin8_auth_base_url: &str,
    property_id: Uuid,
) -> Result<StatM2mClient, StatIntegrationError> {
    let http = reqwest::Client::new();
    let body = serde_json::json!({
        "client_name": format!("app-stat-{property_id}"),
        "grant_types": ["client_credentials"],
        "response_types": [],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "sentin8:stat:measure",
        "application_type": "web",
    });
    let resp = http
        .post(format!(
            "{}/oauth/register",
            sentin8_auth_base_url.trim_end_matches('/')
        ))
        .json(&body)
        .send()
        .await
        .map_err(|e| StatIntegrationError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(StatIntegrationError::Http(format!(
            "register M2M client failed: status {status}: {text}"
        )));
    }
    let raw: DcrResponse = resp
        .json()
        .await
        .map_err(|e| StatIntegrationError::Decode(e.to_string()))?;
    Ok(StatM2mClient {
        client_id: raw.client_id,
        client_secret: raw.client_secret.unwrap_or_default(),
    })
}

/// Generate the Stat Web SDK snippet HTML for an app to embed.
///
/// The snippet loads the Stat Web SDK and initializes it with the property
/// ID. App injects this into the app's served HTML (Story).
pub fn generate_web_sdk_snippet(property_id: Uuid) -> String {
    format!(
        r#"<script src="https://stat.sentin8.dev/sdk.js" async></script>
<script>
  window.sentin8Stat = window.sentin8Stat || [];
  window.sentin8Stat.push(["init", {{ propertyId: "{property_id}" }}]);
</script>"#
    )
}

// ── Internal response types ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PropertyResponse {
    id: Uuid,
    name: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct DcrResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    /// Install the Graviola PQ crypto provider once - reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        });
    }
    use super::*;

    #[test]
    fn web_sdk_snippet_contains_property_id() {
        install_provider();
        let id = Uuid::new_v4();
        let snippet = generate_web_sdk_snippet(id);
        assert!(
            snippet.contains(&id.to_string()),
            "snippet must include property_id"
        );
        assert!(snippet.contains("stat.sentin8.dev/sdk.js"));
        assert!(snippet.contains("sentin8Stat"));
    }

    #[test]
    fn web_sdk_snippet_is_valid_html() {
        install_provider();
        let id = Uuid::new_v4();
        let snippet = generate_web_sdk_snippet(id);
        assert!(snippet.starts_with("<script"));
        assert!(snippet.contains("</script>"));
    }

    #[test]
    fn sentin8_stat_property_serializes() {
        install_provider();
        let p = StatProperty {
            property_id: Uuid::new_v4(),
            name: "eBank (App)".into(),
            slug: "app-deadbeef".into(),
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["name"], "eBank (App)");
        assert_eq!(json["slug"], "app-deadbeef");
    }

    #[test]
    fn m2m_client_serializes() {
        install_provider();
        let c = StatM2mClient {
            client_id: "m2m-123".into(),
            client_secret: "s3cr3t".into(),
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["client_id"], "m2m-123");
        assert_eq!(json["client_secret"], "s3cr3t");
    }

    #[tokio::test]
    async fn create_sentin8_stat_property_fails_on_connection_error() {
        let http = reqwest::Client::new();
        let res =
            create_sentin8_stat_property(&http, "http://127.0.0.1:1", Uuid::new_v4(), "eBank")
                .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn register_sentin8_stat_m2m_client_fails_on_connection_error() {
        let res = register_sentin8_stat_m2m_client("http://127.0.0.1:1", Uuid::new_v4()).await;
        assert!(res.is_err());
    }
}
