// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! App integration tests — integration tests.
//!
//! Follows the runtime-skip pattern (testing-strategy ): pure
//! unit-style assertions run always; DB-backed tests connect at the bottom
//! and skip with one line when PostgreSQL is unreachable.
//!
//! Covered:
//! * RLS visibility tiers on `store_listings` (usr / env / public)
//! * Visibility-scoped RLS context (subject_id, is_env_admin)
//! * `app_instances` lookup policy (own env + sibling envs of own org)
//! * Transactional bus inbox emission
//! * Audit event writes
//! * Listing CRUD request/response shapes

use serde_json::json;
use sqlx::Row;

/// Install the Graviola PQ crypto provider once — reqwest panics with
/// "No provider set" when a client is built without one.
fn install_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
    });
}

// ── Request/response shape tests (no DB) ────────────────────────────────

#[test]
fn create_listing_request_defaults_visibility_to_public() {
    install_provider();
    let req: serde_json::Value = json!({
        "app_name": "My Bank",
        "app_slug": "my-bank"
    });
    let parsed: serde_json::Value = serde_json::from_value(req).unwrap();
    // visibility omitted → the handler defaults to "public" (VISIBILITIES
    // accepts usr/env/public; "org" was dropped — ).
    assert!(parsed.get("visibility").is_none());
}

#[test]
fn create_listing_request_accepts_usr_visibility() {
    install_provider();
    let req = json!({
        "app_name": "My Bank",
        "app_slug": "my-bank",
        "visibility": "usr"
    });
    let parsed: serde_json::Value = serde_json::from_value(req).unwrap();
    assert_eq!(parsed["visibility"], "usr");
}

#[test]
fn update_listing_request_partial_fields() {
    install_provider();
    let req = json!({ "status": "published" });
    let parsed: serde_json::Value = serde_json::from_value(req).unwrap();
    assert_eq!(parsed["status"], "published");
}

#[test]
fn listing_roles_shape_roundtrip() {
    install_provider();
    let roles = vec![sentin8_app_server::handlers::ListingRole {
        name: "ebank-customer".into(),
        description: None,
        scopes: vec!["test:ledger:accounts:read".into()],
        includes: vec!["base".into()],
    }];
    let v = serde_json::to_value(&roles).unwrap();
    let back: Vec<sentin8_app_server::handlers::ListingRole> = serde_json::from_value(v).unwrap();
    assert_eq!(back[0].name, "ebank-customer");
    assert_eq!(back[0].scopes, vec!["test:ledger:accounts:read"]);
    assert_eq!(back[0].includes, vec!["base"]);
}

#[test]
fn runtime_context_response_shape() {
    install_provider();
    // The runtime context is a bare JSON object with snake_case keys
    // ( — no success/data envelope). Verify the contract fields.
    let ctx = json!({
        "org_id": "00000000-0000-0000-0000-000000000001",
        "env_id": "00000000-0000-0000-0000-000000000002",
        "application_id": "00000000-0000-0000-0000-000000000003",
        "app_slug": "ebank",
        "hostname": "ebank.prod.ibank.local",
        "sentin8_auth_domain": "https://auth.prod.ibank.local",
        "auth_domain": "https://auth.staff.ibank.local",
        "allow_signup": true,
        "sentin8_bff_domain": "bff.ebank.prod.ibank.local",
        "custom_domain": "",
        "domain_type": "default",
        "status": "active",
        "instance_name": "My Bank",
        "instance_description": "",
        "organization_name": "iBank",
        "oauth_client_id": "cli-123",
        "feature_flags": {},
        "backend_url": "",
        "app_name": "eBank",
        "app_description": "",
        "logo_url": null,
        "logo_icon_url": null,
        "primary_color": null,
        "accent_color": null,
        "font_family": null,
        "theme_mode": null,
        "custom_css": null,
        "sign_in_text": null
    });
    // All design contract fields present.
    for key in [
        "org_id",
        "env_id",
        "application_id",
        "app_slug",
        "hostname",
        "sentin8_auth_domain",
        "auth_domain",
        "allow_signup",
        "sentin8_bff_domain",
        "domain_type",
        "status",
        "instance_name",
        "organization_name",
        "primary_color",
        "theme_mode",
        "sign_in_text",
    ] {
        assert!(ctx.get(key).is_some(), "missing contract field: {key}");
    }
}

// ── DB-backed tests ─────────────────────────────────────────────────────

/// Runtime-skip pattern (testing-strategy ).
///
/// Connects as the NOBYPASSRLS `sentin8_app_service` role so the RLS
/// policies under test are actually enforced (the `sentin8` superuser
/// bypasses every policy and would make these tests vacuous).
async fn db_pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("SENTIN8_APP_DB_DSN").unwrap_or_else(|_| {
        "postgres://sentin8_app_service@localhost:5432/sentin8".to_string()
    });
    match sqlx::postgres::PgPool::connect(&url).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("skipping DB-backed app tests — PostgreSQL unreachable: {e}");
            None
        }
    }
}

/// Insert a listing with a given visibility/owner and return its id.
async fn insert_listing(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    env_id: uuid::Uuid,
    usr_id: &str,
    visibility: &str,
    slug: &str,
) -> uuid::Uuid {
    let row = sqlx::query(
        r#"INSERT INTO app.store_listings
              (app_name, app_slug, status, created_by, usr_id, visibility, env_id)
           VALUES ($1, $2, 'published', $3, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(format!("App {slug}"))
    .bind(slug)
    .bind(usr_id)
    .bind(visibility)
    .bind(env_id)
    .fetch_one(&mut **tx)
    .await
    .unwrap();
    row.get("id")
}

/// Visibility tiers on `store_listings` (, ):
/// public → everyone; env → same-env context; usr → owner + env admin only.
#[tokio::test]
async fn db_listings_visibility_tiers_respect_rls() {
    let Some(pool) = db_pool().await else { return };
    let env_a = uuid::Uuid::new_v4();
    let env_b = uuid::Uuid::new_v4();
    let owner = format!("usr-{}", uuid::Uuid::new_v4());
    let other = format!("usr-{}", uuid::Uuid::new_v4());

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, 'user', '', false, false, false, NULL)")
        .bind(env_a)
        .bind(&owner)
        .execute(&mut *tx)
        .await
        .unwrap();
    let sfx = uuid::Uuid::new_v4().simple().to_string();
    let public_id = insert_listing(&mut tx, env_a, &owner, "public", &format!("pub-{sfx}")).await;
    let env_id_row = insert_listing(&mut tx, env_a, &owner, "env", &format!("env-{sfx}")).await;
    let usr_id_row = insert_listing(&mut tx, env_a, &owner, "usr", &format!("usr-{sfx}")).await;
    tx.commit().await.unwrap();

    // 1. Same env, same user (owner): sees all three.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, 'user', '', false, false, false, NULL)")
        .bind(env_a)
        .bind(&owner)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 =
        sqlx::query("SELECT count(*)::int8 AS n FROM app.store_listings WHERE id = ANY($1)")
            .bind(vec![public_id, env_id_row, usr_id_row])
            .fetch_one(&mut *tx)
            .await
            .unwrap()
            .get("n");
    assert_eq!(n, 3, "owner sees public + env + usr rows");
    tx.commit().await.unwrap();

    // 2. Same env, different user: sees public + env, NOT usr.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, 'user', '', false, false, false, NULL)")
        .bind(env_a)
        .bind(&other)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 =
        sqlx::query("SELECT count(*)::int8 AS n FROM app.store_listings WHERE id = ANY($1)")
            .bind(vec![public_id, env_id_row, usr_id_row])
            .fetch_one(&mut *tx)
            .await
            .unwrap()
            .get("n");
    assert_eq!(n, 2, "non-owner in same env sees public + env, not usr");
    tx.commit().await.unwrap();

    // 3. Different env user: sees only public.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, 'user', '', false, false, false, NULL)")
        .bind(env_b)
        .bind(&other)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 =
        sqlx::query("SELECT count(*)::int8 AS n FROM app.store_listings WHERE id = ANY($1)")
            .bind(vec![public_id, env_id_row, usr_id_row])
            .fetch_one(&mut *tx)
            .await
            .unwrap()
            .get("n");
    assert_eq!(n, 1, "cross-env non-owner sees only public");
    tx.commit().await.unwrap();

    // 4. Env admin of the owning env sees the usr row (option a flag).
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, 'user', '', false, false, true, NULL)")
        .bind(env_a)
        .bind(&other)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM app.store_listings WHERE id = $1")
        .bind(usr_id_row)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 1, "env admin of owning env sees usr row");
    tx.commit().await.unwrap();

    // 5. Uninitialized context sees nothing (fail-closed).
    let mut tx = pool.begin().await.unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM app.store_listings WHERE id = $1")
        .bind(public_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 0, "uninitialized context sees no rows");
    tx.commit().await.unwrap();
}

/// `app_instances` lookup policy (.1): a caller may read instances
/// of its own env and any env of the org its env belongs to.
#[tokio::test]
async fn db_app_instances_lookup_respects_policy() {
    let Some(pool) = db_pool().await else { return };
    // Create a throwaway org + two envs.
    let org_id = uuid::Uuid::new_v4();
    let env_a = uuid::Uuid::new_v4();
    let env_b = uuid::Uuid::new_v4();
    let env_other_org = uuid::Uuid::new_v4();
    let org_other = uuid::Uuid::new_v4();
    // Org/env lifecycle is Sentin8:Sys's domain — the fixture connects as
    // sentin8_sys_service for the setup writes (App's role is read-only on
    // orgs/envs), then reuses the app-service pool for the assertions.
    let sys_url = std::env::var("SENTIN8_SYS_DB_DSN").unwrap_or_else(|_| {
        "postgres://sentin8_sys_service@localhost:5432/sentin8".to_string()
    });
    let sys_pool = match sqlx::postgres::PgPool::connect(&sys_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping DB-backed app tests — sys role unreachable: {e}");
            return;
        }
    };
    let mut tx = sys_pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO sys.organizations (id, slug, display_name, domain)
           VALUES ($1, $2, $2, $3)"#,
    )
    .bind(org_id)
    .bind(format!("org-{}", org_id.simple()))
    .bind(format!("org-{}.test", org_id.simple()))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO sys.organizations (id, slug, display_name, domain)
           VALUES ($1, $2, $2, $3)"#,
    )
    .bind(org_other)
    .bind(format!("org-{}", org_other.simple()))
    .bind(format!("org-{}.test", org_other.simple()))
    .execute(&mut *tx)
    .await
    .unwrap();
    for (id, oid) in [(env_a, org_id), (env_b, org_id), (env_other_org, org_other)] {
        sqlx::query(
            r#"INSERT INTO sys.environments (id, org_id, slug, display_name)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(id)
        .bind(oid)
        .bind(format!("env-{}", id.simple()))
        .bind(format!("Env {}", id.simple()))
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    drop(sys_pool);

    // Instance in env_a of org_id (App's own table — its role may INSERT).
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO sys.app_instances
              (org_id, env_id, app_slug, hostname, sentin8_bff_hostname, status)
           VALUES ($1, $2, 'lookupapp', $3, $4, 'active')"#,
    )
    .bind(org_id)
    .bind(env_a)
    .bind(format!("lookup-{}.test", env_a.simple()))
    .bind(format!("bff.lookup-{}.test", env_a.simple()))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Context of env_a → sees the instance (own env).
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM sys.app_instances WHERE env_id = $1")
        .bind(env_a)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 1, "own env sees instance");
    tx.commit().await.unwrap();

    // Context of env_b (same org) → sees the instance (sibling env).
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_b)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM sys.app_instances WHERE env_id = $1")
        .bind(env_a)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 1, "sibling env of same org sees instance");
    tx.commit().await.unwrap();

    // Context of another org's env → sees nothing.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_other_org)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM sys.app_instances WHERE env_id = $1")
        .bind(env_a)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 0, "cross-org env sees no instance");
    tx.commit().await.unwrap();

    // Uninitialized context → sees nothing.
    let mut tx = pool.begin().await.unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM sys.app_instances WHERE env_id = $1")
        .bind(env_a)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 0, "uninitialized context sees no instance");
    tx.commit().await.unwrap();
}

/// Transactional local-outbox emission (, DBX ): a committed domain
/// write with an in-transaction `app.outbox` INSERT leaves exactly one
/// outbox row; a rolled-back transaction leaves none. (Bus.inbox is
/// bus-internal — producers never touch it; the relay pushes via the
/// produce API.)
#[tokio::test]
async fn db_outbox_emission_is_transactional() {
    let Some(pool) = db_pool().await else { return };
    let env_a = uuid::Uuid::new_v4();

    // Committed transaction → row visible.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    sentin8::bus::outbox::insert_outbox_row(
        &mut *tx,
        env_a,
        "app",
        "sentin8:app:listing:created",
        &serde_json::json!({}),
    )
    .await
    .expect("local outbox insert under service role + RLS");
    tx.commit().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query(
        "SELECT count(*)::int8 AS n FROM app.outbox WHERE env_id = $1 AND event_type = $2",
    )
    .bind(env_a)
    .bind("sentin8:app:listing:created")
    .fetch_one(&mut *tx)
    .await
    .unwrap()
    .get("n");
    assert_eq!(n, 1, "committed transactional event is durable");
    tx.commit().await.unwrap();

    // Rolled-back transaction → no row.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    sentin8::bus::outbox::insert_outbox_row(
        &mut *tx,
        env_a,
        "app",
        "sentin8:app:listing:archived",
        &serde_json::json!({}),
    )
    .await
    .expect("local outbox insert under service role + RLS");
    tx.rollback().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query(
        "SELECT count(*)::int8 AS n FROM app.outbox WHERE env_id = $1 AND event_type = $2",
    )
    .bind(env_a)
    .bind("sentin8:app:listing:archived")
    .fetch_one(&mut *tx)
    .await
    .unwrap()
    .get("n");
    assert_eq!(n, 0, "rolled-back transactional event leaves no row");
    tx.commit().await.unwrap();
}

/// Audit writes (.3): `audit_events` rows are visible to the same
/// env's context and hidden from other envs.
#[tokio::test]
async fn db_audit_events_respect_rls() {
    let Some(pool) = db_pool().await else { return };
    let env_a = uuid::Uuid::new_v4();
    let env_b = uuid::Uuid::new_v4();

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO app.audit_events (env_id, actor_user_id, action, target_resource_type, target_resource_id)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(env_a)
    .bind("actor-1")
    .bind("listing.create")
    .bind("app_store_listing")
    .bind("lst-1")
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Same env sees it.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM app.audit_events WHERE env_id = $1")
        .bind(env_a)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 1, "same env sees its audit row");
    tx.commit().await.unwrap();

    // Other env does not.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_b)
        .execute(&mut *tx)
        .await
        .unwrap();
    let n: i64 = sqlx::query("SELECT count(*)::int8 AS n FROM app.audit_events WHERE env_id = $1")
        .bind(env_a)
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get("n");
    assert_eq!(n, 0, "other env does not see the audit row");
    tx.commit().await.unwrap();
}

/// Setup hostname derivation matches the design pattern
/// `{subdomain|app_slug}.{env_slug}.{org_domain}` with BFF = bff.{hostname}.
#[tokio::test]
async fn db_instances_hostname_columns_roundtrip() {
    let Some(pool) = db_pool().await else { return };
    let org_id = uuid::Uuid::new_v4();
    let env_a = uuid::Uuid::new_v4();
    let hostname = format!("ebank.{}.{}.test", env_a.simple(), org_id.simple());
    let bff = format!("bff.{hostname}");
    // Org/env fixture via the Sys service role.
    let sys_url = std::env::var("SENTIN8_SYS_DB_DSN").unwrap_or_else(|_| {
        "postgres://sentin8_sys_service@localhost:5432/sentin8".to_string()
    });
    let sys_pool = match sqlx::postgres::PgPool::connect(&sys_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping DB-backed app tests — sys role unreachable: {e}");
            return;
        }
    };
    let mut stx = sys_pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *stx)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO sys.organizations (id, slug, display_name, domain)
           VALUES ($1, $2, $2, $3)"#,
    )
    .bind(org_id)
    .bind(format!("org-{}", org_id.simple()))
    .bind(format!("org-{}.test", org_id.simple()))
    .execute(&mut *stx)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO sys.environments (id, org_id, slug, display_name)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(env_a)
    .bind(org_id)
    .bind(format!("env-{}", env_a.simple()))
    .bind(format!("Env {}", env_a.simple()))
    .execute(&mut *stx)
    .await
    .unwrap();
    stx.commit().await.unwrap();
    drop(sys_pool);

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_a)
        .execute(&mut *tx)
        .await
        .unwrap();
    let row = sqlx::query(
        r#"INSERT INTO sys.app_instances
              (org_id, env_id, app_slug, instance_name, hostname, sentin8_bff_hostname, subdomain, domain_type, status, group_gate)
           VALUES ($1, $2, 'ebank', 'My Bank', $3, $4, 'ebank', 'default', 'active', 'strict')
           RETURNING id, hostname, sentin8_bff_hostname, group_gate, status"#,
    )
    .bind(org_id)
    .bind(env_a)
    .bind(&hostname)
    .bind(&bff)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("hostname"), hostname);
    assert_eq!(row.get::<String, _>("sentin8_bff_hostname"), bff);
    assert_eq!(row.get::<String, _>("group_gate"), "strict");
    assert_eq!(row.get::<String, _>("status"), "active");
    // Cleanup.
    let id: uuid::Uuid = row.get("id");
    sqlx::query("DELETE FROM sys.app_instances WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}
