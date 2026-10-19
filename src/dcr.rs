// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Story - OAuth DCR (Dynamic Client Registration) integration with
//! Auth for App app instances.
//!
//! App registers an OAuth client with Auth via RFC 7591 `POST /oauth/register`
//! during instance setup. The returned `client_id` is stored on the app
//! instance record (`sentin8_sys_app_instances.oauth_client_id`).
//!
//! See

use serde::{Deserialize, Serialize};

/// An OAuth client registered with Auth via DCR.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthClient {
    /// The issued client_id (opaque, URL-safe).
    pub client_id: String,
    /// The issued client_secret (only present for confidential clients).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Unix epoch seconds when the client_id was issued.
    pub client_id_issued_at: i64,
}

/// Errors returned by DCR operations.
#[derive(Debug, thiserror::Error)]
pub enum DcrError {
    /// The HTTP request failed or returned a non-success status.
    #[error("DCR HTTP error: {0}")]
    Http(String),
    /// The response body could not be decoded.
    #[error("DCR decode error: {0}")]
    Decode(String),
}

/// Register an OAuth client with Auth via DCR (RFC 7591).
///
/// - `sentin8_auth_base_url`: the Auth issuer base URL (e.g. `https://sentin8-auth.ops.sys.sentin8.local`).
/// - `instance_id`: the App app instance ID (used to derive a stable client_name).
/// - `redirect_uris`: the redirect URIs the client may use.
/// - `scopes`: the scopes the app requires (from the listing's
///   `oauth_defaults.scopes`). The OIDC baseline (`openid profile email
///   offline_access`) is always included so the client can run an OIDC
///   flow.
///
/// Registers a **public** PKCE client (`token_endpoint_auth_method = "none"`,
/// `grant_types = ["authorization_code", "refresh_token"]`) by default - this
/// matches the BFF pattern used during app setup. The returned `OAuthClient`
/// captures the `client_id`, optional `client_secret`, and
/// `client_id_issued_at`.
pub async fn register_oauth_client(
    sentin8_auth_base_url: &str,
    instance_id: uuid::Uuid,
    redirect_uris: &[String],
    scopes: &[String],
) -> Result<OAuthClient, DcrError> {
    register_oauth_client_with_grants(
        sentin8_auth_base_url,
        instance_id,
        redirect_uris,
        scopes,
        &["authorization_code", "refresh_token"],
        true,
    )
    .await
}

/// Story - Register an OAuth client with custom grant types.
///
/// Used for the env-scoped CIBA client (adds `urn:openid:params:grant-type:ciba`)
/// and the staff client (standard grants). Same public PKCE client otherwise.
pub async fn register_oauth_client_with_grants(
    sentin8_auth_base_url: &str,
    instance_id: uuid::Uuid,
    redirect_uris: &[String],
    scopes: &[String],
    grant_types: &[&str],
    consent_required: bool,
) -> Result<OAuthClient, DcrError> {
    // Build the scope string: always include the OIDC baseline, then the
    // app-specific scopes (deduped, order-preserving).
    let baseline = ["openid", "profile", "email", "offline_access"];
    let mut all: Vec<&str> = baseline.to_vec();
    for s in scopes {
        if !all.contains(&s.as_str()) {
            all.push(s);
        }
    }
    let scope_str = all.join(" ");
    // Bounded per-request timeout: a hung TCP connect at a not-yet-routable
    // env auth (brand-new env mid-provisioning) must fail fast so the
    // caller's retry loop can proceed (design: retry-with-backoff at
    // setup_instance, not a request that never returns).
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| DcrError::Http(format!("http client: {e}")))?;
    let body = serde_json::json!({
        "client_name": format!("app-instance-{instance_id}"),
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": scope_str,
        "application_type": "web",
        "consent_required": consent_required,
    });
    let resp = http
        .post(format!(
            "{}/oauth/register",
            sentin8_auth_base_url.trim_end_matches('/')
        ))
        .json(&body)
        .send()
        .await
        .map_err(|e| DcrError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(DcrError::Http(format!(
            "DCR failed: status {status}: {text}"
        )));
    }
    let raw: DcrResponse = resp
        .json()
        .await
        .map_err(|e| DcrError::Decode(e.to_string()))?;
    Ok(OAuthClient {
        client_id: raw.client_id,
        client_secret: raw.client_secret,
        client_id_issued_at: raw.client_id_issued_at,
    })
}

/// Internal response shape (subset of RFC 7591 `RegisterResponse`).
#[derive(Debug, Deserialize)]
struct DcrResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    client_id_issued_at: i64,
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
    fn oauth_client_serializes_without_null_secret() {
        install_provider();
        let c = OAuthClient {
            client_id: "cli-123".into(),
            client_secret: None,
            client_id_issued_at: 1_700_000_000,
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["client_id"], "cli-123");
        assert_eq!(json["client_id_issued_at"], 1_700_000_000);
        // client_secret is skipped when None.
        assert!(json.get("client_secret").is_none());
    }

    #[test]
    fn oauth_client_serializes_with_secret() {
        install_provider();
        let c = OAuthClient {
            client_id: "cli-456".into(),
            client_secret: Some("s3cr3t".into()),
            client_id_issued_at: 1_700_000_001,
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["client_secret"], "s3cr3t");
    }

    #[tokio::test]
    async fn register_oauth_client_returns_error_on_connection_failure() {
        // Use an invalid port to guarantee a connection failure.
        let res = register_oauth_client(
            "http://127.0.0.1:1",
            uuid::Uuid::new_v4(),
            &["https://app.example.com/callback".to_string()],
            &["test:scope:read".to_string()],
        )
        .await;
        assert!(res.is_err(), "expected connection error");
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("DCR")
                || err.contains("error")
                || err.contains("refused")
                || err.contains("Connect")
                || err.contains("connect")
        );
    }
}
