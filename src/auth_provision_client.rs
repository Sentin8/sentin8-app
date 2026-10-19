// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Auth provisioning client.
//!
//! App's instance-setup step calls **auth's membership provisioning API**
//! (`POST /v1/admin/provision/*`) instead of INSERTing `auth.*` tables
//! directly - cross-service table access is prohibited: the owner
//! exposes the verbs, app holds a token (`sentin8:auth:admin:write` on the
//! `sentin8:app` workload). Copy of sys's `auth_provision.rs` (peers
//! cannot share a crate - dependency direction is one-way).

/// Auth provisioning API client - **certificate-presenting** (,
/// auth DESIGN §4.3f): the `sentin8:app` CERTIFICATE is the identity,
/// presented on the TLS handshake of every call; Auth's TLS layer
/// authenticates it. No bearer token exists on this path.
pub struct AuthProvisioner {
    auth_url: String,
    http: reqwest::Client,
}

impl AuthProvisioner {
    /// Build (or reuse) the process provisioner. Ensures the `sentin8:app`
    /// workload certificate (load-or-mint from Acme) and builds the
    /// cert-presenting transport.
    pub async fn connect() -> anyhow::Result<Self> {
        let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
        let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
        let cert =
            sentin8::auth::m2m::ensure_workload_certificate(&issuer, "sentin8:app", &ca_cert_path)
                .await?;
        let mtls = sentin8::middleware::mtls::MtlsConfig::new(
            &cert.ca_cert_path,
            &cert.cert_path,
            &cert.key_path,
        );
        Ok(Self {
            auth_url: issuer.trim_end_matches('/').to_string(),
            http: sentin8::middleware::mtls::build_mtls_client(&mtls)
                .map_err(|e| anyhow::anyhow!("mTLS transport: {e}"))?,
        })
    }

    async fn post(
        &self,
        path: &str,
        env_id: uuid::Uuid,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.auth_url, path);
        let resp = self
            .http
            .post(&url)
            // Auth's provisioning API resolves the target env from the
            // `x-sentin8-target-env-id` header (auth DESIGN - auth is
            // env-scoped); the body's env_id only feeds the SQL bind.
            // Mirror sys's provisioner: send the header on every call.
            .header("x-sentin8-target-env-id", env_id.to_string())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("auth provision {path}: {status} {text}");
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
    }

    /// Create a role in the env (returns its id).
    pub async fn role(
        &self,
        env_id: uuid::Uuid,
        name: &str,
        permissions: &[String],
    ) -> anyhow::Result<Uuid2> {
        let v = self
            .post(
                "/v1/admin/provision/role",
                env_id,
                serde_json::json!({ "env_id": env_id, "name": name, "permissions": permissions }),
            )
            .await?;
        Ok(parse_uuid(&v, "role_id"))
    }

    /// Nest a child role under a parent role.
    pub async fn role_nesting(
        &self,
        env_id: uuid::Uuid,
        parent_name: &str,
        child_name: &str,
    ) -> anyhow::Result<()> {
        self.post(
            "/v1/admin/provision/role_nesting",
            env_id,
            serde_json::json!({ "env_id": env_id, "parent_name": parent_name, "child_name": child_name }),
        )
        .await?;
        Ok(())
    }

    /// Create a group in the env (returns its id).
    pub async fn group(&self, env_id: uuid::Uuid, name: &str) -> anyhow::Result<Uuid2> {
        let v = self
            .post(
                "/v1/admin/provision/group",
                env_id,
                serde_json::json!({ "env_id": env_id, "name": name }),
            )
            .await?;
        Ok(parse_uuid(&v, "group_id"))
    }

    /// Attach a role to a group.
    pub async fn group_role(
        &self,
        env_id: uuid::Uuid,
        group_name: &str,
        role_name: &str,
    ) -> anyhow::Result<()> {
        self.post(
            "/v1/admin/provision/group_role",
            env_id,
            serde_json::json!({ "env_id": env_id, "group_name": group_name, "role_name": role_name }),
        )
        .await?;
        Ok(())
    }

    /// Add a user to a group (returns affected count).
    pub async fn group_member(
        &self,
        env_id: uuid::Uuid,
        group_name: &str,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<u64> {
        let v = self
            .post(
                "/v1/admin/provision/group_member",
                env_id,
                serde_json::json!({ "env_id": env_id, "group_name": group_name, "user_id": user_id }),
            )
            .await?;
        Ok(v["count"].as_u64().unwrap_or(0))
    }

    /// Attach a role directly to a user.
    pub async fn user_role(
        &self,
        env_id: uuid::Uuid,
        user_id: uuid::Uuid,
        role_name: &str,
    ) -> anyhow::Result<()> {
        self.post(
            "/v1/admin/provision/user_role",
            env_id,
            serde_json::json!({ "env_id": env_id, "user_id": user_id, "role_name": role_name }),
        )
        .await?;
        Ok(())
    }
}

/// UUID wrapper (avoids the sqlx::Error import in the signature).
pub type Uuid2 = uuid::Uuid;

/// Extract a UUID field from a JSON response (nil UUID when absent).
fn parse_uuid(v: &serde_json::Value, key: &str) -> Uuid2 {
    v[key]
        .as_str()
        .and_then(|s| Uuid2::parse_str(s).ok())
        .unwrap_or_else(Uuid2::nil)
}
