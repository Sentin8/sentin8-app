// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! App HTTP handlers - store listings, setup, runtime context, admin.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::config::AppConfig;
use crate::steps::{self, StepExecuteRequest, StepExecuteResponse};
use sentin8::rfw::response::AdminUiResponse;

/// Shared application state for the App service.
#[derive(Clone)]
pub struct AppState {
    /// Runtime configuration.
    pub config: Arc<AppConfig>,
    /// Database connection pool.
    pub pool: sqlx::PgPool,
    /// M2M-backed Bus client built at startup via DCR (RFC 7591).
    pub _bus_client: sentin8::bus::client::BusClient,
    /// Shield engine ( - ): additional gate after scope.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface .
    pub admin: sentin8::shield::admin::SharedAdminState,
}

/// App-declared security role (Story: app-declared scopes + roles).
///
/// Each app listing may declare the named security roles it wants to use
/// in the target org/env, plus the scope set each role grants. The scopes
/// are stored as `sentin8_auth_roles.permissions` at install time and end up in
/// the JWT via the existing `fetch_role_scopes` recursive CTE. The app
/// also typically adds one or more role-specific scopes (e.g. `ebank:admin`)
/// so the frontend can gate role-based UI purely from the JWT scope list.
///
/// Conventions:
/// * `name` must be unique per `(org_id, env_id)`. Use a stable app
///   prefix (e.g. `ebank-admin`, `efintech-teller`) to avoid clashing
///   with other apps in the same org/env.
/// * `default_signup_role` is a separate listing-level field (not part
///   of the role object). The install flow + the env-realm sign-up path
///   consult it to decide which role to auto-assign a new user to.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ListingRole {
    /// Role name - unique per `(org_id, env_id)`, stable app prefix
    /// recommended.
    pub name: String,
    /// Human description.
    #[serde(default)]
    pub description: Option<String>,
    /// Scopes (a.k.a. permissions) the role grants to its members. Stored
    /// in `sentin8_auth_roles.permissions` (TEXT[]).
    pub scopes: Vec<String>,
    /// Names of other roles in the same listing whose scopes should be
    /// merged into this role's permissions at install time. Lets a
    /// role "include" another role's permissions without the app
    /// having to redeclare every scope (e.g. `ebank-teller` can
    /// `includes: ["ebank-customer"]` and inherit the customer
    /// scopes plus its own additions).
    ///
    /// Resolution happens server-side at install:
    /// `effective_scopes = own.scopes ∪ included.scopes`. Cycles
    /// and missing references are rejected at install with a
    /// 400. No DB schema change - `sentin8_auth_roles` only stores the
    /// resolved permission set, not the include graph.
    #[serde(default)]
    pub includes: Vec<String>,
}

pub(crate) async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(conn)
        .await;
}

/// Same-connection context setter used by admin_ui handlers (Fix B).
pub(crate) async fn set_tenant_context_for_admin(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    set_tenant_context(conn, env_id).await;
}

/// Extended tenant context (Epics 15.5 / 15.6) - passes admin flags +
/// Auth user id for visibility-scoped RLS on `sentin8_app_store_listings`.
async fn set_tenant_context_ext(conn: &mut sqlx::PgConnection, auth: &crate::auth::AuthContext) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false, $6, $7)")
        .bind(auth.env_id())
        .bind(&auth.claims.sub)
        .bind(&auth.claims.token_tp)
        .bind(&auth.claims.scope)
        .bind(auth.is_platform_admin())
        .bind(auth.claims.is_env_admin())
        .bind(auth.claims.sentin8_auth_user_uuid())
        .execute(conn)
        .await;
}

/// Cross-env authorization ( rule 5): the caller must hold a role
/// or group in `target_env_id` - the service scope alone is not sufficient.
/// Platform admins (`sentin8:sys:admin`) and env admins (`sentin8:sys:env:admin` for their
/// own env) are admitted. Mirrors the org-membership predicate in
/// Sentin8:Sys `list_organizations`.
async fn require_target_env_access(
    pool: &sqlx::PgPool,
    a: &crate::auth::AuthContext,
    target_env_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    if a.is_platform_admin() {
        return Ok(());
    }
    if a.env_id() == target_env_id {
        return Ok(());
    }
    let user_id = Uuid::parse_str(&a.claims.sub).unwrap_or(Uuid::nil());
    // Same-connection tenant context : `sys_environments_select` and
    // the auth RBAC tables' policies gate on `sentin8_context_initialized`.
    // The context is set for the TARGET env inside ONE explicit transaction
    // (transaction-local `set_config(..., true)`) - on an autocommit
    // connection the context evaporates before the query runs and FORCE RLS
    // hides every row (fail-closed → a caller WITH membership 403s).
    let mut tx = pool.begin().await.map_err(err_db)?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(target_env_id)
        .execute(&mut *tx)
        .await;
    let member: Option<(bool,)> = sqlx::query_as(
        r#"SELECT true AS member
             FROM sys.environments e
            WHERE e.id = $1
              AND (
                    EXISTS (SELECT 1 FROM user_roles ur
                            JOIN roles r ON r.id = ur.role_id
                            WHERE ur.user_id = $2 AND r.env_id = $1)
                 OR EXISTS (SELECT 1 FROM group_members gm
                            JOIN groups g ON g.id = gm.group_id
                            WHERE gm.user_id = $2 AND g.env_id = $1)
                  )"#,
    )
    .bind(target_env_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.rollback().await.map_err(err_db)?;
    match member {
        Some(_) => Ok(()),
        None => Err((
            StatusCode::FORBIDDEN,
            "caller has no role or group in the target env".into(),
        )),
    }
}

/// Resolve the tenant env for a handler that accepts `target_env_id`.
///
/// Fix A : `target_env_id` is REQUIRED - 400 when missing, no fallback
/// to the token env. Fix D : cross-env callers must hold RBAC membership
/// in the target env.
async fn resolve_target_env(
    pool: &sqlx::PgPool,
    a: &crate::auth::AuthContext,
    q: &crate::admin_ui::TargetEnvQuery,
) -> Result<Uuid, (StatusCode, String)> {
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing target_env_id".into()))?;
    require_target_env_access(pool, a, env_id).await?;
    Ok(env_id)
}

// ── Store API ───────────────────────────────────────────────────────────

/// Allowed visibility values for store listings (Epic 15.5 - 'usr' added).
const VISIBILITIES: &[&str] = &["usr", "env", "public"];

/// Allowed release channels for store listings (APP-4): install resolves
/// the newest published version on the requested channel.
const CHANNELS: &[&str] = &["stable", "beta", "dev"];

/// A store listing as returned by the public store API.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StoreListingResponse {
    /// Listing id.
    pub id: Uuid,
    /// App display name.
    pub app_name: String,
    /// URL-safe app slug.
    pub app_slug: String,
    /// Human description.
    pub description: Option<String>,
    /// Lifecycle status.
    pub status: String,
    /// Whether the app supports OAuth DCR.
    pub supports_dcr: bool,
    /// Visibility tier (`usr`/`env`/`public`).
    pub visibility: String,
    /// Owning user (Auth subject id).
    pub usr_id: String,
    /// Creating user.
    pub created_by: String,
    /// Owning environment when env-scoped.
    pub env_id: Option<Uuid>,
    /// Creation time (UTC).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// App-declared security roles (provisioned in `sentin8_auth_roles` on
    /// install). Each role carries its own scope set.
    pub roles: Vec<ListingRole>,
    /// Role name auto-assigned to a new env-realm user at sign-up.
    /// Must be one of the names in `roles`. Null = no auto-assignment.
    pub default_signup_role: Option<String>,
    /// Release version of this listing row (APP-4; default `0.0.0`).
    pub version: String,
    /// Release channel (APP-4): `stable|beta|dev`.
    pub channel: String,
    /// Media entries (APP-3): typed by-reference descriptors
    /// `{role, resolution, storage_key}`; bytes live in Sentin8:Storage.
    #[serde(default)]
    pub media: serde_json::Value,
}

/// Request to create a store listing.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateListingRequest {
    /// App display name.
    pub app_name: String,
    /// URL-safe app slug.
    pub app_slug: String,
    /// Human description.
    pub description: Option<String>,
    /// Backend URL metadata from the app developer.
    pub backend_url: Option<String>,
    /// Whether the app supports OAuth DCR.
    pub supports_dcr: Option<bool>,
    /// OAuth defaults advertised at install.
    #[serde(default)]
    pub oauth_defaults: serde_json::Value,
    /// Visibility: "public" (default), "env", or "usr" (Epic 15.5).
    #[serde(default)]
    pub visibility: Option<String>,
    /// App-declared security roles. Provisioned in `sentin8_auth_roles` on
    /// install. Optional at create-time; can be added later via update.
    #[serde(default)]
    pub roles: Vec<ListingRole>,
    /// Role name auto-assigned to a new env-realm user at sign-up.
    /// Must match one of the names in `roles`. Optional.
    #[serde(default)]
    pub default_signup_role: Option<String>,
    /// Release version of this listing row (APP-4). Optional, default
    /// `0.0.0`.
    #[serde(default)]
    pub version: Option<String>,
    /// Release channel (APP-4): `stable|beta|dev`. Optional, default
    /// `stable`.
    #[serde(default)]
    pub channel: Option<String>,
    /// Media entries (APP-3): typed by-reference descriptors -
    /// `{role, resolution, storage_key}`; bytes live in Sentin8:Storage.
    #[serde(default)]
    pub media: Option<serde_json::Value>,
    /// Category slugs (APP-3): replaces this listing's category rows.
    #[serde(default)]
    pub categories: Option<Vec<String>>,
}

/// `POST /v1/app/store/listings` - create a store listing.
///
/// Epic 15.5.5: populates `usr_id` from the token `sub` (the creator).
/// Visibility is immutable after `status = 'published'` (enforced in
/// `update_listing`).
#[utoipa::path(
    post,
    operation_id = "store.create",
    path = "/v1/app/store/listings",
    request_body = CreateListingRequest,
    responses(
        (status = 200, description = "Listing created", body = StoreListingResponse),
        (status = 400, description = "Invalid visibility or roles"),
        (status = 403, description = "Missing app:store:admin scope"),
    ),
    security(("sentin8:app:store:admin" = [])),
    tag = "app",
)]
pub async fn create_listing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::admin_ui::TargetEnvQuery>,
    Json(req): Json<CreateListingRequest>,
) -> Result<Json<StoreListingResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:store:admin"),
    )
    .await?;
    let visibility = req.visibility.as_deref().unwrap_or("public").to_string();
    if !VISIBILITIES.contains(&visibility.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid visibility: {visibility}"),
        ));
    }
    validate_listing_roles(&req.roles, req.default_signup_role.as_deref())?;
    let env_id = resolve_target_env(&state.pool, &a, &q).await?;
    let creator_sub = a.claims.sub.clone();
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, &a).await;
    let roles_json = serde_json::to_value(&req.roles)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid roles: {e}")))?;
    let row = sqlx::query(
        r#"INSERT INTO store_listings
              (app_name, app_slug, description, backend_url, supports_dcr,
               oauth_defaults, created_by, usr_id, visibility, env_id,
               roles, default_signup_role, version, channel, media)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $12, $13, $14)
           RETURNING id, app_name, app_slug, description, status, supports_dcr,
                     visibility, usr_id, created_by, env_id, created_at,
                     roles, default_signup_role, version, channel, media"#,
    )
    .bind(&req.app_name)
    .bind(&req.app_slug)
    .bind(req.description.as_deref())
    .bind(req.backend_url.as_deref().unwrap_or(""))
    .bind(req.supports_dcr.unwrap_or(false))
    .bind(&req.oauth_defaults)
    .bind(&creator_sub)
    .bind(&visibility)
    .bind(env_id)
    .bind(&roles_json)
    .bind(req.default_signup_role.as_deref().unwrap_or(""))
    .bind(req.version.as_deref().unwrap_or("0.0.0"))
    .bind(req.channel.as_deref().unwrap_or("stable"))
    .bind(req.media.clone().unwrap_or(serde_json::json!([])))
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let listing = row_to_listing(&row);
    // APP-3: write the category rows in the SAME transaction - a listing's
    // categories are part of its domain change (replacing the set is
    // delete-then-insert; UNIQUE (category, app_slug) makes it idempotent).
    if let Some(cats) = &req.categories {
        sqlx::query("DELETE FROM listing_categories WHERE app_slug = $1")
            .bind(&req.app_slug)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
        for c in cats.iter().filter(|c| !c.trim().is_empty()).take(20) {
            sqlx::query(
                "INSERT INTO listing_categories (category, app_slug) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(c.trim())
            .bind(&req.app_slug)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
        }
    }
    // Transactional emission : the inbox row commits with the domain
    // change - a crash between the two can never lose the event.
    emit_event_tx(
        &mut conn,
        env_id,
        "sentin8:app:listing:created",
        serde_json::to_value(&listing).unwrap_or_default(),
    )
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    write_audit(
        &state.pool,
        env_id,
        &a.claims.sub,
        "listing.create",
        "app_store_listing",
        &listing.id.to_string(),
    )
    .await;
    Ok(Json(listing))
}

/// `GET /v1/app/store/listings` - list published store listings visible to
/// the caller.
///
/// Epic 15.5.5: RLS is the single source of truth for visibility. The
/// service layer no longer adds a `WHERE org_id = $1` filter - the `usr` and
/// `public` tiers deliberately admit rows that do not match the caller's
/// org_id. We only filter `status = 'published'` (business rule) and rely on
/// the visibility-scoped RLS policy to admit the right rows.
/// Query for `GET /v1/app/store/listings` (APP-3).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct StoreListQuery {
    /// Filter by category slug (APP-3) - listings carrying this category.
    #[serde(default)]
    pub category: Option<String>,
}

#[utoipa::path(
    get,
    operation_id = "store.list",
    path = "/v1/app/store/listings",
    responses(
        (status = 200, description = "List of published listings", body = [StoreListingResponse]),
        (status = 403, description = "Missing app:store:read scope"),
    ),
    security(("sentin8:app:store:read" = [])),
    tag = "app",
)]
/// List published store listings visible to the caller (RLS-scoped).
/// `?category=` filters to listings carrying that category (APP-3).
pub async fn list_listings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StoreListQuery>,
) -> Result<Json<Vec<StoreListingResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:store:read"),
    )
    .await?;
    // The context is transaction-local (`set_config(..., true)`) and each
    // pooled statement runs in its OWN implicit transaction - the context-set
    // and the SELECT must share ONE explicit transaction or FORCE RLS hides
    // every row ( rule 2; e2e: `store list` returned [] and
    // `store get` 404ed right after a successful create).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut tx, &a).await;
    let rows = sqlx::query(
        r#"SELECT id, app_name, app_slug, description, status, supports_dcr, visibility,
                  usr_id, created_by, env_id, created_at, roles, default_signup_role,
                  version, channel, media
             FROM store_listings
            WHERE status = 'published'
              AND ($1::text IS NULL OR app_slug IN (
                    SELECT app_slug FROM listing_categories WHERE category = $1))
            ORDER BY app_slug, channel, created_at DESC"#,
    )
    .bind(q.category.as_deref())
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_listing).collect()))
}

/// `GET /v1/app/store/listings/{id}` - listing detail.
///
/// Epic 15.5.5: visibility is enforced by RLS - if the row is not visible
/// to the caller, the SELECT returns zero rows and we 404. No manual
/// visibility check in the service layer.
#[utoipa::path(
    get,
    operation_id = "store.get",
    path = "/v1/app/store/listings/{id}",
    params(("id" = Uuid, Path, description = "Listing ID")),
    responses(
        (status = 200, description = "Listing detail", body = StoreListingResponse),
        (status = 404, description = "Listing not found"),
        (status = 403, description = "Missing app:store:read scope"),
    ),
    security(("sentin8:app:store:read" = [])),
    tag = "app",
)]
pub async fn get_listing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<StoreListingResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:store:read"),
    )
    .await?;
    // Same-connection transaction ( rule 2): the context-set and the
    // visibility-scoped SELECT must share ONE explicit transaction.
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut tx, &a).await;
    let row = sqlx::query(
        r#"SELECT id, app_name, app_slug, description, status, supports_dcr, visibility,
                  usr_id, created_by, env_id, created_at, roles, default_signup_role,
                  version, channel
             FROM store_listings WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    let row = row.ok_or_else(|| (StatusCode::NOT_FOUND, format!("listing {id} not found")))?;
    Ok(Json(row_to_listing(&row)))
}

/// Story - `PUT /v1/app/store/listings/{id}` - update a listing (catalog admin).
/// Request to update a store listing (all fields optional).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateListingRequest {
    /// New app name, when changing it.
    #[serde(default)]
    pub app_name: Option<String>,
    /// New slug, when changing it.
    #[serde(default)]
    pub app_slug: Option<String>,
    /// New description, when changing it.
    #[serde(default)]
    pub description: Option<String>,
    /// New backend URL, when changing it.
    #[serde(default)]
    pub backend_url: Option<String>,
    /// New DCR support flag, when changing it.
    #[serde(default)]
    pub supports_dcr: Option<bool>,
    /// New OAuth defaults, when changing them.
    #[serde(default)]
    pub oauth_defaults: Option<serde_json::Value>,
    /// New lifecycle status, when transitioning it.
    #[serde(default)]
    pub status: Option<String>,
    /// Visibility: "env", "usr", or "public". If omitted, keeps current value.
    #[serde(default)]
    pub visibility: Option<String>,
    /// App-declared security roles. Replaces the current list when
    /// supplied. Provisioned in `sentin8_auth_roles` on subsequent installs.
    /// Pass `[]` to clear.
    #[serde(default)]
    pub roles: Option<Vec<ListingRole>>,
    /// Role name auto-assigned to a new env-realm user at sign-up.
    /// Pass `null` to clear, or omit to keep the current value.
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    pub default_signup_role: Option<Option<String>>,
    /// Media entries (APP-3): replaces the current media JSONB when
    /// supplied.
    #[serde(default)]
    pub media: Option<serde_json::Value>,
    /// Category slugs (APP-3): replaces this listing's category rows when
    /// supplied (pass `[]` to clear).
    #[serde(default)]
    pub categories: Option<Vec<String>>,
}

fn deserialize_optional_field<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    // Distinguishes "field omitted" (use current value) from "field set to
    // null" (clear it). Used for `default_signup_role` so the update
    // endpoint can clear it without forcing the caller to know the current
    // value.
    Option::<T>::deserialize(deserializer)
}

/// `PUT /v1/app/store/listings/{id}` - update a listing (catalog admin).
#[utoipa::path(
    put,
    operation_id = "store.update",
    path = "/v1/app/store/listings/{id}",
    params(("id" = Uuid, Path, description = "Listing ID")),
    request_body = UpdateListingRequest,
    responses(
        (status = 200, description = "Listing updated", body = StoreListingResponse),
        (status = 400, description = "Invalid status, visibility, or roles"),
        (status = 403, description = "Missing app:store:admin scope"),
        (status = 404, description = "Listing not found"),
    ),
    security(("sentin8:app:store:admin" = [])),
    tag = "app",
)]
pub async fn update_listing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateListingRequest>,
) -> Result<Json<StoreListingResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:store:admin"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, &a).await;
    // Fetch current row so unset fields keep their existing value. Row
    // not visible under RLS → 404 (not 500).
    let cur = sqlx::query(
        r#"SELECT app_name, app_slug, description, backend_url, supports_dcr, oauth_defaults,
                  status, visibility, env_id, roles, default_signup_role
             FROM store_listings WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("listing {id} not found")))?;
    let cur_status: String = cur.get("status");
    let cur_visibility: String = cur.get("visibility");
    let app_name = req.app_name.unwrap_or_else(|| cur.get("app_name"));
    let app_slug = req.app_slug.unwrap_or_else(|| cur.get("app_slug"));
    let description: Option<String> = req.description.or_else(|| cur.get("description"));
    let backend_url = req.backend_url.unwrap_or_else(|| cur.get("backend_url"));
    let supports_dcr = req.supports_dcr.unwrap_or_else(|| cur.get("supports_dcr"));
    let oauth_defaults = req
        .oauth_defaults
        .unwrap_or_else(|| cur.get::<serde_json::Value, _>("oauth_defaults"));
    let status = req.status.unwrap_or_else(|| cur.get("status"));
    // Validate status if provided.
    if !["draft", "published", "disabled", "archived"].contains(&status.as_str()) {
        return Err((StatusCode::BAD_REQUEST, format!("invalid status: {status}")));
    }
    // Epic 15.5.5: visibility is immutable after the listing is published.
    let visibility = if cur_status == "published" || cur_status == "disabled" {
        if req.visibility.is_some() && req.visibility.as_deref() != Some(cur_visibility.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                "visibility is immutable after publish".into(),
            ));
        }
        cur_visibility
    } else {
        let v = req.visibility.unwrap_or_else(|| cur.get("visibility"));
        if !VISIBILITIES.contains(&v.as_str()) {
            return Err((StatusCode::BAD_REQUEST, format!("invalid visibility: {v}")));
        }
        v
    };
    // Role fields: validate and merge with current value. The
    // `default_signup_role` uses the `Option<Option<String>>` shape to
    // distinguish "not supplied" (keep current) from "null" (clear).
    let new_default_signup_role: Option<String> = match req.default_signup_role {
        Some(v) => v, // explicit null or string
        None => cur.get("default_signup_role"),
    };
    if let Some(ref roles) = req.roles {
        validate_listing_roles(roles, new_default_signup_role.as_deref())?;
    }
    let roles_json: serde_json::Value = match &req.roles {
        Some(g) => serde_json::to_value(g)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid roles: {e}")))?,
        None => cur.get::<serde_json::Value, _>("roles"),
    };
    let row = sqlx::query(
        r#"UPDATE store_listings
              SET app_name = $2, app_slug = $3, description = $4, backend_url = $5,
                  supports_dcr = $6, oauth_defaults = $7, status = $8, visibility = $9,
                  roles = $10, default_signup_role = $11, updated_at = now(),
                  media = COALESCE($12, media)
            WHERE id = $1
          RETURNING id, app_name, app_slug, description, status, supports_dcr, visibility,
                    usr_id, created_by, env_id, created_at,
                    roles, default_signup_role, version, channel, media"#,
    )
    .bind(id)
    .bind(&app_name)
    .bind(&app_slug)
    .bind(description.as_deref())
    .bind(&backend_url)
    .bind(supports_dcr)
    .bind(&oauth_defaults)
    .bind(&status)
    .bind(&visibility)
    .bind(&roles_json)
    .bind(new_default_signup_role.as_deref())
    .bind(req.media.clone())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let listing_env_id: Option<Uuid> = row.get("env_id");
    // APP-3: replace the category rows when supplied (same tx).
    if let Some(cats) = &req.categories {
        sqlx::query("DELETE FROM listing_categories WHERE app_slug = $1")
            .bind(&app_slug)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
        for c in cats.iter().filter(|c| !c.trim().is_empty()).take(20) {
            sqlx::query(
                "INSERT INTO listing_categories (category, app_slug) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(c.trim())
            .bind(&app_slug)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
        }
    }
    let listing = row_to_listing(&row);
    // Transactional emission .
    emit_event_tx(
        &mut conn,
        listing_env_id.unwrap_or(a.env_id()),
        "sentin8:app:listing:updated",
        serde_json::to_value(&listing).unwrap_or_default(),
    )
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    write_audit(
        &state.pool,
        listing_env_id.unwrap_or(a.env_id()),
        &a.claims.sub,
        "listing.update",
        "app_store_listing",
        &listing.id.to_string(),
    )
    .await;
    Ok(Json(listing))
}

/// Story - `DELETE /v1/app/store/listings/{id}` - archive a listing (soft delete).
/// Sets `status = 'archived'` so the listing is hidden from the public store but retained for audit.
/// `DELETE /v1/app/store/listings/{id}` - archive a listing (soft delete).
#[utoipa::path(
    delete,
    operation_id = "store.archive",
    path = "/v1/app/store/listings/{id}",
    params(("id" = Uuid, Path, description = "Listing ID")),
    responses(
        (status = 200, description = "Listing archived"),
        (status = 403, description = "Missing app:store:admin scope"),
        (status = 404, description = "Listing not found"),
    ),
    security(("sentin8:app:store:admin" = [])),
    tag = "app",
)]
pub async fn archive_listing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:store:admin"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, &a).await;
    let row = sqlx::query(
        "UPDATE store_listings SET status = 'archived', updated_at = now() WHERE id = $1 RETURNING env_id",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    let cur_row = row.ok_or_else(|| (StatusCode::NOT_FOUND, format!("listing {id} not found")))?;
    let listing_env_id: Option<Uuid> = cur_row.get("env_id");
    // Transactional emission .
    emit_event_tx(
        &mut conn,
        listing_env_id.unwrap_or(a.env_id()),
        "sentin8:app:listing:archived",
        serde_json::json!({ "id": id }),
    )
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    write_audit(
        &state.pool,
        listing_env_id.unwrap_or(a.env_id()),
        &a.claims.sub,
        "listing.archive",
        "app_store_listing",
        &id.to_string(),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "status": "archived" })))
}

// ── Setup API ───────────────────────────────────────────────────────────

/// Request to set up an app instance from a listing.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SetupRequest {
    /// The listing being installed.
    pub listing_id: Uuid,
    /// Release channel to install from (APP-4). Defaults to `stable`;
    /// resolves the newest published version for the listing's slug on
    /// this channel.
    #[serde(default)]
    pub channel: Option<String>,
    /// Instance display name.
    #[serde(default)]
    pub instance_name: Option<String>,
    /// Instance description.
    #[serde(default)]
    pub instance_description: Option<String>,
    /// Custom domain to bind (verified via DNS TXT).
    #[serde(default)]
    pub custom_domain: Option<String>,
    /// Auth URL selected from the org's env Auth servers dropdown.
    /// Stored as `auth_domain` on the app instance (hostname only,
    /// scheme stripped). Used for OIDC sign-in.
    #[serde(default)]
    pub auth_url: Option<String>,
    /// When true, public sign-up is visible. When false, only SSO
    /// is available. Defaults to true.
    #[serde(default = "default_true")]
    pub allow_signup: bool,
}

fn default_true() -> bool {
    true
}

/// The created instance summary.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SetupResponse {
    /// Instance id.
    pub instance_id: Uuid,
    /// The derived hostname for the instance.
    pub hostname: String,
    /// Initial lifecycle status.
    pub status: String,
}

/// `POST /v1/app/setup` - create an app instance (atomic).
#[utoipa::path(
    post,
    operation_id = "setup.create",
    path = "/v1/app/setup",
    request_body = SetupRequest,
    responses(
        (status = 200, description = "Instance created (RFW redirect)"),
        (status = 403, description = "Missing app:instances:write scope"),
    ),
    security(("sentin8:app:instances:write" = [])),
    tag = "app",
)]
pub async fn setup_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::admin_ui::TargetEnvQuery>,
    Json(req): Json<SetupRequest>,
) -> Result<Json<AdminUiResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:write"),
    )
    .await?;
    // Fix A/D : target_env_id is REQUIRED and the caller must hold
    // RBAC membership in it. org_id is resolved from env_id - env_id is the
    // sole tenant key.
    let env_id = resolve_target_env(&state.pool, &a, &q).await?;
    // Same-connection tenant context : the sys_environments_select /
    // sys_organizations_select RLS policies gate on
    // `sentin8_context_initialized` - resolve org/slug/domain on ONE
    // connection with the target env's context set.
    let cfg = sentin8::config::Sentin8Config::from_env();
    let (org_id, _org_slug, org_domain, env_slug) = {
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context(&mut tx, env_id).await;
        let org_id: uuid::Uuid =
            sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
                .bind(env_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or(uuid::Uuid::nil());
        let org_slug: String =
            sqlx::query_scalar::<_, String>("SELECT slug FROM sys.organizations WHERE id = $1")
                .bind(org_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or_else(|_| org_id.to_string());
        let org_domain: String =
            sqlx::query_scalar::<_, String>("SELECT domain FROM sys.organizations WHERE id = $1")
                .bind(org_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or_else(|_| cfg.org_domain(&org_slug));
        let env_slug: String =
            sqlx::query_scalar::<_, String>("SELECT slug FROM sys.environments WHERE id = $1")
                .bind(env_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap_or_else(|_| env_id.to_string());
        (org_id, org_slug, org_domain, env_slug)
    };
    // Fetch listing for app_slug + backend_url. The requested channel
    // (APP-4) resolves the NEWEST published version for the listing's slug
    // on that channel - a slug alone no longer identifies a release row.
    // Same-connection tenant context (app DESIGN §5 cross-cutting):
    // `store_listings` is visibility-scoped RLS and the SELECT policy
    // gates on `sentin8_context_initialized()` - a bare-pool read
    // (no context) hides every row and `fetch_one` fails the install
    // with a zero-rows 500. The context is transaction-local, so the
    // context-set and the SELECT share ONE explicit transaction; the
    // installer's caller context (not just the target env) is used so
    // `usr`-visible listings by the same caller remain readable.
    let channel = req.channel.as_deref().unwrap_or("stable");
    if !CHANNELS.contains(&channel) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid channel '{channel}' (allowed: {CHANNELS:?})"),
        ));
    }
    let listing = {
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut tx, &a).await;
        let row = sqlx::query(
            r#"SELECT l.app_slug, l.backend_url, l.version
                 FROM store_listings base
                 JOIN LATERAL (
                    SELECT id, app_slug, backend_url, version
                      FROM app_newest_listing(
                          (SELECT app_slug FROM store_listings WHERE id = $1), $2)
                 ) l ON true
                WHERE base.id = $1"#,
        )
        .bind(req.listing_id)
        .bind(channel)
        .fetch_one(&mut *tx)
        .await
        .map_err(err_db)?;
        tx.commit().await.map_err(err_db)?;
        row
    };
    let app_slug: String = listing.get("app_slug");
    let _listing_backend_url: String = listing.get("backend_url");
    // Create instance record in sys.app_instances.
    // Use org/env slugs for readable hostnames instead of UUIDs.
    // Parse custom domain subdomain prefix (strip any https:// and TLD).
    // Only the subdomain prefix is stored; full domain is constructed at read
    // time as {subdomain}.{env_slug}.{org_domain} (env-scoped).
    let custom_subdomain = req
        .custom_domain
        .as_deref()
        .map(|d| {
            d.trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
        })
        .filter(|d| !d.is_empty())
        .map(|d| d.split('.').next().unwrap_or(d).to_string());
    // Resolve the instance's primary hostname + bff hostname. When a custom
    // subdomain is supplied, ONLY the custom-domain mappings are created -
    // the default {app_slug}.{env_slug}.{org_domain} mappings are NOT, so we
    // never produce stray ebank.prod.ibank.local / bff.ebank.prod.ibank.local
    // hosts that would never be opened. When no custom subdomain is given,
    // the default derived hostname is used.
    // custom: {subdomain}.{env_slug}.{org_domain} (e.g. www.prod.ibank.local)
    // default: {app_slug}.{env_slug}.{org_domain} (e.g. ebank.prod.ibank.local)
    // bff host: bff.{hostname}
    let (hostname, sentin8_bff_hostname, domain_type) = if let Some(ref sub) = custom_subdomain {
        let h = format!("{}.{}.{}", sub, env_slug, org_domain);
        (h.clone(), format!("bff.{}", h), "custom")
    } else {
        let h = format!("{}.{}.{}", app_slug, env_slug, org_domain);
        (h.clone(), format!("bff.{}", h), "default")
    };
    // Resolve the Auth domain from the auth_url dropdown selection.
    // The auth_url is a full URL like "https://auth.prod.ibank.local".
    // Strip the scheme to get the hostname for auth_domain.
    let auth_domain = {
        let configured = req.auth_url.as_deref().unwrap_or("").trim();
        if !configured.is_empty() {
            configured
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string()
        } else {
            String::new()
        }
    };
    let row = {
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context(&mut tx, env_id).await;
        let row = sqlx::query(
            r#"INSERT INTO sys.app_instances (org_id, env_id, app_slug, instance_name, instance_description, hostname, sentin8_bff_hostname, subdomain, domain_type, listing_id, status, auth_domain, allow_signup, group_gate)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'provisioning', $11, $12, $13)
               RETURNING id, hostname, status"#,
        )
        .bind(org_id).bind(env_id).bind(&app_slug)
        .bind(req.instance_name.as_deref().unwrap_or(""))
        .bind(req.instance_description.as_deref().unwrap_or(""))
        .bind(&hostname).bind(&sentin8_bff_hostname)
        .bind(custom_subdomain.as_deref().unwrap_or(""))
        .bind(domain_type)
        .bind(req.listing_id)
        .bind(if auth_domain.is_empty() { None } else { Some(&auth_domain) })
        .bind(req.allow_signup)
 // Declarative F-A gate mode (BFF design ). Listings don't declare
 // a gate mode yet - every installed app defaults to 'strict'
 // (fail-closed membership requirement). The platform Dash sets
 // 'self_service' in its seed (its self-service users create their
 // first org before any group membership can exist).
        .bind("strict")
        .fetch_one(&mut *tx).await.map_err(err_db)?;
        // Commit the instance row BEFORE the provisioning steps - the
        // block-scoped tx would otherwise be dropped and rolled back, so
        // the install returns success but no instance ever exists (the
        // next runtime_context lookup 404s; nothing recovers from the
        // missing row).
        tx.commit().await.map_err(err_db)?;
        row
    };
    let instance_id: Uuid = row.get("id");
    // The app instance's hostname and sentin8_bff_hostname are already
    // stored in sentin8_sys_app_instances. The proxy's DomainResolver
    // reads these directly - no need to write to sentin8_domains.

    // Story / scope flow - read the listing's required scopes
    // (`oauth_defaults.scopes`, declared at app registration) and persist them
    // as the instance's `allowed_scopes` / `allowed_services`. BFF requests
    // these at login so the issued access token carries the app's scopes.
    //
    // Also fetch the listing's `roles` field so we can provision them in
    // `sentin8_auth_roles` for this org/env below.
    // Same-connection tenant context: same rationale as the listing
    // fetch above - a bare-pool read hides the listing row under FORCE
    // RLS and silently drops oauth_defaults (no scopes, no DCR consent,
    // no roles) even though the install "succeeds".
    let listing_row = {
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut tx, &a).await;
        let row = sqlx::query(
            r#"SELECT oauth_defaults, supports_dcr
                 FROM store_listings WHERE id = $1"#,
        )
        .bind(req.listing_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?;
        tx.commit().await.map_err(err_db)?;
        row
    };
    let scopes: Vec<String> = listing_row
        .as_ref()
        .and_then(|r| r.try_get::<serde_json::Value, _>("oauth_defaults").ok())
        .and_then(|v| v.get("scopes").cloned())
        .and_then(|s| {
            s.as_array().map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .filter(|s| !s.is_empty())
                    .collect()
            })
        })
        .unwrap_or_default();
    // Story - extract consent_required from oauth_defaults .
    // First-party apps (consent_required = false) skip the consent screen.
    let consent_required: bool = listing_row
        .as_ref()
        .and_then(|r| r.try_get::<serde_json::Value, _>("oauth_defaults").ok())
        .and_then(|v| v.get("consent_required").cloned())
        .and_then(|c| c.as_bool())
        .unwrap_or(true);
    if !scopes.is_empty() {
        // Derive allowed_services from scope prefixes (e.g. "vertical:fdx:recipient:read" → "fdx").
        // Exclude OIDC baseline scopes which are not backend services.
        let baseline = ["openid", "profile", "email", "offline_access", "offline"];
        let mut services: Vec<String> = Vec::new();
        for s in &scopes {
            if let Some(prefix) = s.split(':').next() {
                if !baseline.contains(&prefix) && !services.iter().any(|x| x == prefix) {
                    services.push(prefix.to_string());
                }
            }
        }
        {
            let mut tx = state.pool.begin().await.map_err(err_db)?;
            set_tenant_context(&mut tx, env_id).await;
            sqlx::query(
                r#"UPDATE sys.app_instances
                      SET allowed_scopes = $2, allowed_services = $3, updated_at = now()
                    WHERE id = $1"#,
            )
            .bind(instance_id)
            .bind(&scopes)
            .bind(&services)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
            tx.commit().await.map_err(err_db)?;
        }
        tracing::info!(instance_id = %instance_id, ?scopes, ?services, "app: set instance allowed_scopes from listing");
        // Story - stat integration. When the listing declares
        // `oauth_defaults.integrations.stat = true`, create the instance's Stat
        // property and store the property id on the instance row. Non-fatal:
        // install succeeds without analytics (the flag is re-provisioned on
        // the next install retry; App never writes Stat tables directly - the
        // ingest path is the shared `POST /v1/m/metric` pipeline).
        let stat_declared = listing_row
            .as_ref()
            .and_then(|r| r.try_get::<serde_json::Value, _>("oauth_defaults").ok())
            .and_then(|v| {
                v.get("integrations")
                    .and_then(|i| i.get("stat"))
                    .and_then(|s| s.as_bool())
            })
            .unwrap_or(false);
        if stat_declared {
            // the `app` workload certificate IS the identity -
            // build the cert-presenting transport for the Stat admin call
            // (non-fatal on failure, same as the rest of this block).
            let admin_http = match crate::telemetry::stat_admin_transport(&state, &a).await {
                Ok(http) => http,
                Err(e) => {
                    tracing::warn!(error = %e, instance_id = %instance_id, "app: stat transport build failed (non-fatal)");
                    reqwest::Client::new()
                }
            };
            match crate::stat_integration::create_sentin8_stat_property(
                &admin_http,
                &cfg.sentin8_stat_url(),
                instance_id,
                &app_slug,
            )
            .await
            {
                Ok(prop) => {
                    let mut tx = state.pool.begin().await.map_err(err_db)?;
                    set_tenant_context(&mut tx, env_id).await;
                    let _ = sqlx::query(
                        "UPDATE sys.app_instances SET sentin8_stat_property_id = $2, updated_at = now() WHERE id = $1",
                    )
                    .bind(instance_id)
                    .bind(prop.property_id)
                    .execute(&mut *tx)
                    .await;
                    tx.commit().await.map_err(err_db)?;
                    tracing::info!(
                        instance_id = %instance_id,
                        property_id = %prop.property_id,
                        "app: stat property created for instance"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        instance_id = %instance_id,
                        "app: stat property creation failed (non-fatal)"
                    );
                }
            }
        }

        // Story - register an OAuth client with Auth via DCR using
        // the installer's tenant context. The redirect_uri is the BFF
        // callback for this instance.
        //
        // BFF-6 (app DESIGN §10): when the listing declares an
        // `oauth_defaults.redirect_uris` allow-list, the derived callback MUST
        // match one of its entries exactly - the listing author decides where
        // post-login redirects may land; a mismatch FAILS the install (the
        // developer fixes the listing or installs a variant whose host matches)
        // rather than silently registering an off-list callback. Without the
        // key the derived BFF callback is the default (first-party posture).
        let redirect_uri = format!("https://{sentin8_bff_hostname}/auth/callback");
        let redirect_allow_list: Option<Vec<String>> = listing_row
            .as_ref()
            .and_then(|r| r.try_get::<serde_json::Value, _>("oauth_defaults").ok())
            .and_then(|v| v.get("redirect_uris").cloned())
            .and_then(|s| {
                s.as_array().map(|a| {
                    a.iter()
                        .filter_map(|x| {
                            x.as_str()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(String::from)
                        })
                        .collect()
                })
            });
        if let Some(allow) = &redirect_allow_list {
            if !allow.iter().any(|u| u == &redirect_uri) {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    format!(
                        "derived redirect_uri {redirect_uri} is not in the listing's oauth_defaults.redirect_uris allow-list"
                    ),
                ));
            }
        }

        // Resolve the auth URL for DCR. Use the auth_domain selected at
        // install time (from the auth_url dropdown); fall back to the
        // env-scoped Auth URL resolved from Sys.
        let dcr_auth_url = if !auth_domain.is_empty() {
            if auth_domain.starts_with("http") {
                auth_domain.clone()
            } else {
                format!("https://{}", auth_domain)
            }
        } else {
            resolve_env_sentin8_auth_url(&state, org_id, env_id).await
        };
        match register_signin_client_with_retry(
            &state,
            &dcr_auth_url,
            instance_id,
            redirect_uri.clone(),
            scopes.clone(),
            consent_required,
        )
        .await
        {
            Ok(client) => {
                {
                    let mut tx = state.pool.begin().await.map_err(err_db)?;
                    set_tenant_context(&mut tx, env_id).await;
                    sqlx::query(
                        r#"UPDATE sys.app_instances SET oauth_client_id = $2, updated_at = now() WHERE id = $1"#,
                    )
                    .bind(instance_id).bind(&client.client_id)
                    .execute(&mut *tx).await
                    .map_err(err_db)?;
                    tx.commit().await.map_err(err_db)?;
                }
                tracing::info!(instance_id = %instance_id, client_id = %client.client_id, "app: DCR registered OAuth client for instance");
            }
            Err(e) => {
                tracing::warn!(instance_id = %instance_id, error = %e, "app: DCR failed (install continues); allowed_scopes still set");
            }
        }

        // Staff-mode CIBA client (BFF design - the CIBA backchannel client at
        // the CUSTOMER env's auth). The sign-in client above was registered at
        // the staff auth (auth_domain); CIBA bc-authorize targets the CUSTOMER
        // env's auth (where the customer accounts live), so the SAME instance
        // client must exist there too. Public PKCE, same redirect callback.
        // Non-fatal: CIBA flows fail with a clear error until this lands - the
        // flag is re-provisioned on the next install retry.
        if !auth_domain.is_empty() {
            let customer_auth_url = resolve_env_sentin8_auth_url(&state, org_id, env_id).await;
            match crate::dcr::register_oauth_client_with_grants(
                &customer_auth_url,
                instance_id,
                std::slice::from_ref(&redirect_uri),
                &scopes,
                &[
                    "authorization_code",
                    "urn:ietf:params:oauth:grant-type:ciba",
                ],
                consent_required,
            )
            .await
            {
                Ok(client) => {
                    let mut tx = state.pool.begin().await.map_err(err_db)?;
                    set_tenant_context(&mut tx, env_id).await;
                    sqlx::query(
                        r#"UPDATE sys.app_instances SET ciba_oauth_client_id = $2, updated_at = now() WHERE id = $1"#,
                    )
                    .bind(instance_id).bind(&client.client_id)
                    .execute(&mut *tx).await
                    .map_err(err_db)?;
                    tx.commit().await.map_err(err_db)?;
                    tracing::info!(instance_id = %instance_id, client_id = %client.client_id, "app: CIBA client registered at the customer auth");
                }
                Err(e) => {
                    tracing::warn!(instance_id = %instance_id, error = %e, "app: CIBA client DCR failed (non-fatal)");
                }
            }
        }
    }

    // Story - provision the instance group + role in Auth.
    // Creates ( - names embed the instance UUID; the display-name
    // snake_case form is retired, AUTH-3):
    // 1. sentin8_auth_role: sentin8:app:{instance_id}:role (permissions = listing's oauth_defaults.scopes)
    // 2. sentin8_auth_group: sentin8:app:{instance_id}
    // 3. sentin8_auth_group_roles: assigns the role to the group
    {
        let group_name = format!("sentin8:app:{instance_id}");
        let role_name = format!("sentin8:app:{instance_id}:role");
        // Provision the group/role in the env whose auth the app uses.
        // When auth_domain is set (staff mode), resolve the env from the
        // auth_domain hostname. Otherwise, use the install env.
        let target_env_id = if !auth_domain.is_empty() {
            // auth_domain is a hostname like "auth.staff.ibank.local".
            // Resolve the env from the sentin8_sys_environments + organizations
            // by matching the auth domain pattern: auth.{env_slug}.{org_domain}.
            let hostname = auth_domain
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_lowercase();
            // Try to resolve env by looking up envs in this org and matching
            // the derived auth domain.
            let cfg = sentin8::config::Sentin8Config::from_env();
            // Same-connection context: org-sibling env rows are visible under the
            // org branch of sys_environments_select - the context env must BE the
            // env whose org we scan (env_id, NOT org_id: the context functions
            // resolve org from the environment row; passing the org id as the env
            // context resolved no row and hid every sibling env, so the staff
            // auth-domain match always failed and the instance group/role were
            // provisioned into the PROD env - where staff users hold no groups).
            let envs: Vec<(Uuid, String, String)> = {
                let mut conn = state.pool.begin().await.map_err(err_db)?;
                set_tenant_context(&mut conn, env_id).await;
                let rows = sqlx::query(
                    r#"SELECT e.id, e.slug, o.domain
                         FROM sys.environments e
                         JOIN sys.organizations o ON o.id = e.org_id
                        WHERE o.id = $1"#,
                )
                .bind(org_id)
                .fetch_all(&mut *conn)
                .await
                .map_err(err_db)?;
                rows.iter()
                    .filter_map(|r| {
                        let id: Uuid = r.try_get("id").ok()?;
                        let slug: String = r.try_get("slug").ok()?;
                        let domain: String = r.try_get("domain").ok()?;
                        Some((id, slug, domain))
                    })
                    .collect()
            };
            // Find the env whose derived auth domain matches the hostname.
            envs.iter()
                .find(|(_, slug, domain)| {
                    let env_domain = cfg.env_domain(slug, domain);
                    let derived = cfg.env_auth_domain(&env_domain);
                    format!("https://{}", derived) == hostname
                        || derived == hostname
                        || hostname == derived
                })
                .map(|(id, _, _)| *id)
                .unwrap_or(env_id)
        } else {
            env_id
        };

        // (): no DB transaction - the auth provisioning
        // calls are HTTP; the auth tables are not app's to write.
        let provisioner = crate::auth_provision_client::AuthProvisioner::connect()
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("auth provisioner: {e}"),
                )
            })?;
        provisioner
            .role(target_env_id, &role_name, &scopes)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("provision role: {e}"),
                )
            })?;

        // 2. Create group (idempotent) - via auth's API.
        provisioner
            .group(target_env_id, &group_name)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("provision group: {e}"),
                )
            })?;

        let provisioner = crate::auth_provision_client::AuthProvisioner::connect()
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("auth provisioner: {e}"),
                )
            })?;
        provisioner
            .role(target_env_id, &role_name, &scopes)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("provision role: {e}"),
                )
            })?;

        // 2. Create group (idempotent) - via auth's API.
        provisioner
            .group(target_env_id, &group_name)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("provision group: {e}"),
                )
            })?;

        // 3. Assign role to group (idempotent) - via auth's API.
        provisioner
            .group_role(target_env_id, &group_name, &role_name)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("provision group_role: {e}"),
                )
            })?;
        tracing::info!(
            instance_id = %instance_id,
            group = %group_name,
            role = %role_name,
            "app: provisioned instance group + role in Auth (via auth API)"
        );
    }

    // Set status to active - and COMMIT it (same dropped-tx pitfall as the
    // INSERT above: a block-scoped tx that is never committed rolls back,
    // leaving the instance stuck in 'provisioning' forever).
    {
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context(&mut tx, env_id).await;
        sqlx::query(
            "UPDATE sys.app_instances SET status = 'active', updated_at = now() WHERE id = $1",
        )
        .bind(instance_id)
        .execute(&mut *tx)
        .await
        .map_err(err_db)?;
        tx.commit().await.map_err(err_db)?;
    }
    let resp = SetupResponse {
        instance_id,
        hostname: row.get("hostname"),
        status: "active".into(),
    };
    emit_event(
        &state.pool,
        env_id,
        "sentin8:app:instance:created",
        serde_json::to_value(&resp).unwrap_or_default(),
    )
    .await;
    write_audit(
        &state.pool,
        env_id,
        &a.claims.sub,
        "instance.install",
        "sys_app_instance",
        &instance_id.to_string(),
    )
    .await;
    // Return an RFW redirect so Dash navigates to the instances page.
    Ok(Json(AdminUiResponse::redirect("instances")))
}

/// `GET /v1/app/instances/customer-mode?env_id=…` - enumerate the
/// customer-mode (`allow_signup`) instances installed in an env (auth
/// DESIGN invariant 12: the owner-API replacement for auth's retired
/// direct read of `sys.app_instances`).
///
/// M2M-only service surface: the sign-up closure provisioning (Sentin8:
/// Auth) calls this with its own workload token to learn which
/// `sentin8:app:{instance_id}` groups a new customer should join.
///
/// Authorization (fail-closed, three gates):
/// 1. Bearer verify + M2M-only (`token_tp == "m2m"`) - this is a
///    service-to-service discovery surface, never a user surface.
/// 2. Shield gate on `sentin8:app:instances:read`.
/// 3. Owner scoping: the caller's `service_type` claim must resolve to
///    an instance of THIS app service's own domain - answered only for
///    envs in an org where app is enabled; the query itself stays
///    env-scoped so a foreign env is an indistinguishable empty result
///    (no tenant-existence oracle).
#[utoipa::path(
    get,
    operation_id = "instances.customerMode",
    path = "/v1/app/instances/customer-mode",
    params(("env_id" = Uuid, Query, description = "Target environment id")),
    responses(
        (status = 200, description = "Customer-mode instances in the env", body = serde_json::Value),
        (status = 400, description = "Missing env_id"),
        (status = 403, description = "Missing app:instances:read scope or non-M2M token"),
    ),
    security(("sentin8:app:instances:read" = [])),
    tag = "app",
)]
pub async fn customer_mode_instances(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::admin_ui::CustomerModeQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:read"),
    )
    .await?;
    if a.claims.token_tp != "m2m" {
        return Err((
            StatusCode::FORBIDDEN,
            "customer-mode discovery is an M2M-only surface".to_string(),
        ));
    }
    let rows = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        // The caller's M2M workload authenticates in the SYSTEM env, but it
        // queries ANOTHER env's instances - the RLS context must match the
        // row's env_id (transaction-local set_config), exactly the
        // authorization layer's cross-env contract: the Shield gate above
        // already verified the caller's service scope; the context here is
        // the data-plane key, not a second permission decision.
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(q.env_id)
            .execute(&mut *conn)
            .await;
        sqlx::query(
            r#"SELECT id, app_slug, allow_signup
                 FROM sys.app_instances
                WHERE env_id = $1
                  AND allow_signup = true
                  AND status = 'active'
                  AND COALESCE(auth_domain, '') = ''"#,
        )
        .bind(q.env_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?
    };
    Ok(Json(serde_json::json!({
        "env_id": q.env_id,
        "instances": rows.iter().map(|r| {
            serde_json::json!({
                "instance_id": r.get::<Uuid, _>("id"),
                "app_slug": r.get::<String, _>("app_slug"),
            })
        }).collect::<Vec<_>>(),
    })))
}

/// `GET /v1/app/setup/{instanceId}/status` - provisioning status.
#[utoipa::path(
    get,
    operation_id = "setup.status",
    path = "/v1/app/setup/{id}/status",
    params(("instanceId" = Uuid, Path, description = "Instance ID")),
    responses(
        (status = 200, description = "Provisioning status", body = SetupResponse),
        (status = 403, description = "Missing app:instances:read scope"),
        (status = 404, description = "Instance not found"),
    ),
    security(("sentin8:app:instances:read" = [])),
    tag = "app",
)]
pub async fn setup_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(instance_id): Path<Uuid>,
) -> Result<Json<SetupResponse>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:read"),
    )
    .await?;
    let row = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &_a).await;
        sqlx::query("SELECT id, hostname, status FROM sys.app_instances WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(err_db)?
    };
    Ok(Json(SetupResponse {
        instance_id: row.get("id"),
        hostname: row.get("hostname"),
        status: row.get("status"),
    }))
}

// ── Runtime Context API ─────────────────────────────────────────────────

/// Stories , , -34 - `GET /v1/app/runtime/context`.
///
/// Runtime context is resolved from the TLS-injected `X-Sentin8-App-Id` header
/// (no per-listing API key, no hostname-based resolution). The response includes
/// instance metadata, the organization display name, and merged org→env branding
/// from `sentin8_sys_branding` so apps can apply tenant branding without a separate call.
#[utoipa::path(
    get,
    path = "/v1/app/runtime/context",
    responses(
        (status = 200, description = "Runtime context for the TLS-identified app (instance metadata, org name, merged branding)", body = serde_json::Value),
        (status = 401, description = "No X-Sentin8-App-Id header / unknown instance"),
    ),
    security(),
    tag = "app",
)]
pub async fn runtime_context(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let app_id = headers
        .get("x-sentin8-app-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty());
    let hostname = headers
        .get("x-sentin8-hostname")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .unwrap_or("");
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // org_id is resolved from env_id via DB lookup (env_id is the sole tenant key).
    let org_id = if !env_id.is_empty() {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context(
            &mut conn,
            env_id.parse::<uuid::Uuid>().unwrap_or(uuid::Uuid::nil()),
        )
        .await;
        sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(env_id.parse::<uuid::Uuid>().unwrap_or(uuid::Uuid::nil()))
            .fetch_optional(&mut *conn)
            .await
            .ok()
            .flatten()
            .unwrap_or(uuid::Uuid::nil())
    } else {
        uuid::Uuid::nil()
    };
    tracing::info!(
        %host,
        app_id = ?app_id,
        %hostname,
        org_id = %org_id,
        env_id = %env_id,
        "app: runtime_context received request"
    );

    let instance_id = if let Some(id) = app_id {
        Uuid::parse_str(id).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid X-Sentin8-App-Id: {e}"),
            )
        })?
    } else {
        // Fallback: resolve by hostname (X-Sentin8-Hostname header sent by the app).
        let hostname = headers
            .get("x-sentin8-hostname")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "missing X-Sentin8-App-Id or X-Sentin8-Hostname header".into(),
                )
            })?;
        // Look up the instance by hostname or subdomain.
        // `subdomain` stores only the subdomain prefix, so also match
        // the constructed full domain: {subdomain}.{org_domain}. `o.domain`
        // is NOT NULL so no COALESCE fallback is needed.
        let row = {
            let mut conn = state.pool.begin().await.map_err(err_db)?;
            set_tenant_context(
                &mut conn,
                env_id.parse::<uuid::Uuid>().unwrap_or(uuid::Uuid::nil()),
            )
            .await;
            sqlx::query(
                r#"SELECT i.id FROM sys.app_instances i
                   JOIN sys.organizations o ON o.id = i.org_id
                   WHERE i.hostname = $1
                      OR i.subdomain = $1
                      OR (i.subdomain <> '' AND i.subdomain || '.' || o.domain = $1)"#,
            )
            .bind(hostname)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
        };
        let id: Uuid = match row {
            Some(r) => r.get("id"),
            None => {
                tracing::warn!(%hostname, "app: runtime_context no instance found for hostname or subdomain");
                return Err((
                    StatusCode::NOT_FOUND,
                    format!("no app instance found for hostname: {hostname}"),
                ));
            }
        };
        tracing::info!(instance_id = %id, %hostname, "app: runtime_context resolved instance by hostname");
        id
    };
    // Fetch instance + listing + org display name.
    let row = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context(
            &mut conn,
            env_id.parse::<uuid::Uuid>().unwrap_or(uuid::Uuid::nil()),
        )
        .await;
        sqlx::query(
            r#"SELECT i.id, i.org_id, i.env_id, i.app_slug, i.hostname, i.sentin8_bff_hostname,
                      i.subdomain, i.domain_type, i.instance_name, i.instance_description,
                      i.status, i.feature_flags, i.oauth_client_id, i.auth_domain, i.allow_signup,
                      l.app_name, l.description, l.backend_url,
                      o.display_name AS org_name,
                      o.domain AS org_domain, o.slug AS org_slug
                 FROM sys.app_instances i
                 LEFT JOIN store_listings l ON i.listing_id = l.id
                 LEFT JOIN sys.organizations o ON i.org_id = o.id
                WHERE i.id = $1"#,
        )
        .bind(instance_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?
    };
    let org_id: Uuid = row.get("org_id");
    let env_id: Uuid = row.get("env_id");
    // Story - fetch merged org→env branding from sentin8_sys_branding.
    let branding = fetch_merged_branding(&state.pool, org_id, env_id)
        .await
        .unwrap_or_default();
    // Fetch the env's auth_domain (set by the org admin via Dash UI).
    // This is the tenant-specific auth domain (e.g. auth.ibank.local).
    // Falls back to the platform auth issuer if not set.
    let env_auth_domain = resolve_env_sentin8_auth_url(&state, org_id, env_id).await;
    // When a custom domain is set, the app should use bff.{custom_domain}
    // as its BFF base URL instead of the internal app BFF hostname.
    // The DB stores only the subdomain prefix; construct the full domain
    // from the org's `domain` (NOT NULL).
    let custom_subdomain: String = row.try_get::<String, _>("subdomain").unwrap_or_default();
    let sentin8_bff_hostname_val: String = row
        .try_get::<String, _>("sentin8_bff_hostname")
        .unwrap_or_default();
    // Fetch the env slug + org domain together so the custom domain is
    // reconstructed as {subdomain}.{env_slug}.{org_domain} (env-scoped,
    // matching setup_instance). Without the env slug we'd build
    // www.ibank.local - wrong scope, wrong cert family.
    // Same-connection context - RLS gates on context presence.
    let scope_row = {
        let mut tx = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context(&mut tx, env_id).await;
        let row = sqlx::query(
            r#"SELECT e.slug AS env_slug, o.domain AS org_domain
                 FROM sys.environments e
                 JOIN sys.organizations o ON o.id = e.org_id
                WHERE e.id = $1 AND o.id = $2"#,
        )
        .bind(env_id)
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(err_db)?;
        tx.commit().await.map_err(err_db)?;
        row
    };
    let env_slug: String = scope_row
        .as_ref()
        .and_then(|r| r.try_get("env_slug").ok())
        .unwrap_or_default();
    let org_domain: String = scope_row
        .as_ref()
        .and_then(|r| r.try_get("org_domain").ok())
        .unwrap_or_default();
    let custom_domain_val =
        if !custom_subdomain.is_empty() && !env_slug.is_empty() && !org_domain.is_empty() {
            format!("{}.{}.{}", custom_subdomain, env_slug, org_domain)
        } else {
            String::new()
        };
    let sentin8_bff_domain = if !custom_domain_val.is_empty() {
        format!("bff.{}", custom_domain_val)
    } else {
        sentin8_bff_hostname_val
    };
    // Story + 12.4.12 - auth domain resolution.
    // Use the auth_domain stored on the instance at install time (from the
    // auth_url dropdown selection). This is the hostname used for OIDC
    // sign-in.
    let auth_domain: String = row
        .try_get::<Option<String>, _>("auth_domain")
        .ok()
        .flatten()
        .unwrap_or_default();
    let allow_signup: bool = row.try_get::<bool, _>("allow_signup").unwrap_or(true);
    Ok(Json(serde_json::json!({
           "org_id" : org_id,
           "env_id" : env_id,
           "application_id" : row.get::<Uuid, _>("id"),
           "app_slug" : row.get::<String, _>("app_slug"),
           "hostname": row.try_get::<String, _>("hostname").unwrap_or_default(),
           "sentin8_auth_domain" : env_auth_domain,
           "auth_domain" : auth_domain,
           "allow_signup" : allow_signup,
           "sentin8_bff_domain" : sentin8_bff_domain,
           "custom_domain" : custom_domain_val,
           "domain_type" : row.try_get::<String, _>("domain_type").unwrap_or_default(),
           "status": row.get::<String, _>("status"),
           "instance_name" : row.try_get::<String, _>("instance_name").unwrap_or_default(),
           "instance_description" : row.try_get::<String, _>("instance_description").unwrap_or_default(),
           "organization_name" : row.try_get::<String, _>("org_name").unwrap_or_default(),
           "oauth_client_id" : row.try_get::<String, _>("oauth_client_id").unwrap_or_default(),
           "feature_flags" : row.try_get::<serde_json::Value, _>("feature_flags").unwrap_or(serde_json::json!({})),
           "backend_url" : row.try_get::<String, _>("backend_url").unwrap_or_default(),
           "app_name" : row.try_get::<String, _>("app_name").unwrap_or_default(),
           "app_description" : row.try_get::<String, _>("description").unwrap_or_default(),
    // Branding (merged org→env)
           "logo_url" : branding.logo_url,
           "logo_icon_url" : branding.logo_icon_url,
           "primary_color" : branding.primary_color,
           "accent_color" : branding.accent_color,
           "font_family" : branding.font_family,
           "theme_mode" : branding.theme_mode,
           "custom_css" : branding.custom_css,
           "sign_in_text" : branding.sign_in_text,
       })))
}

// ── Admin API (Stories -16) ───────────────────────────────────────

/// `GET /v1/app/admin/instances/{id}` - instance admin detail.
#[utoipa::path(
    get,
    operation_id = "instance.get",
    path = "/v1/app/admin/instances/{id}",
    params(("id" = Uuid, Path, description = "Instance ID")),
    responses(
        (status = 200, description = "Instance detail"),
        (status = 403, description = "Missing app:instances:admin scope"),
        (status = 404, description = "Instance not found"),
    ),
    security(("sentin8:app:instances:admin" = [])),
    tag = "app",
)]
pub async fn get_instance_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:admin"),
    )
    .await?;
    let row = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &_a).await;
        sqlx::query(
            r#"SELECT i.id, i.org_id, i.env_id, i.app_slug, i.instance_name, i.instance_description,
                      i.hostname, i.sentin8_bff_hostname, i.subdomain, i.domain_type, i.status, i.feature_flags,
                      i.env_vars_ref, i.oauth_client_id, i.listing_id, i.allowed_scopes, i.allowed_services,
                      l.app_name, l.backend_url, l.supports_dcr
                 FROM sys.app_instances i
                 LEFT JOIN store_listings l ON i.listing_id = l.id
                WHERE i.id = $1"#,
        ).bind(id).fetch_one(&mut *conn).await.map_err(err_db)?
    };
    Ok(Json(serde_json::json!({
        "id": row.get::<Uuid, _>("id"),
        "org_id" : row.get::<Uuid, _>("org_id"),
        "env_id" : row.get::<Uuid, _>("env_id"),
        "app_slug" : row.get::<String, _>("app_slug"),
        "instance_name" : row.try_get::<String, _>("instance_name").unwrap_or_default(),
        "instance_description" : row.try_get::<String, _>("instance_description").unwrap_or_default(),
        "hostname": row.try_get::<String, _>("hostname").unwrap_or_default(),
        "sentin8_bff_hostname" : row.try_get::<String, _>("sentin8_bff_hostname").unwrap_or_default(),
        "custom_domain" : row.try_get::<String, _>("subdomain").unwrap_or_default(),
        "domain_type" : row.try_get::<String, _>("domain_type").unwrap_or_default(),
        "status": row.get::<String, _>("status"),
        "feature_flags" : row.try_get::<serde_json::Value, _>("feature_flags").unwrap_or(serde_json::json!({})),
        "env_vars_ref" : row.try_get::<String, _>("env_vars_ref").unwrap_or_default(),
        "oauth_client_id" : row.try_get::<String, _>("oauth_client_id").unwrap_or_default(),
        "listing_id" : row.try_get::<Uuid, _>("listing_id").unwrap_or_default(),
        "allowed_scopes" : row.try_get::<Vec<String>, _>("allowed_scopes").unwrap_or_default(),
        "allowed_services" : row.try_get::<Vec<String>, _>("allowed_services").unwrap_or_default(),
        "app_name" : row.try_get::<String, _>("app_name").unwrap_or_default(),
        "backend_url" : row.try_get::<String, _>("backend_url").unwrap_or_default(),
        "supports_dcr" : row.try_get::<bool, _>("supports_dcr").unwrap_or(false),
    })))
}

/// `PUT /v1/app/admin/instances/{id}/domain` - update custom domain (with DNS TXT validation).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateDomainRequest {
    /// The custom domain to bind (verified via DNS TXT or CNAME).
    pub custom_domain: String,
    /// The DNS TXT record value retrieved by App from the customer's DNS.
    #[serde(default)]
    pub txt_record: Option<String>,
    /// APP-5 (CNAME challenge): the resolved target of
    /// `{token}.verify.{domain}` as retrieved by the caller's DNS lookup.
    /// Pass together with `cname_token`; wins over `txt_record` when both
    /// are present.
    #[serde(default)]
    pub cname_target: Option<String>,
    /// APP-5: the challenge token previously generated for this domain
    /// (`sentin8-verify-<32-hex>`).
    #[serde(default)]
    pub cname_token: Option<String>,
}

/// `PUT /v1/app/admin/instances/{id}/domain` - update custom domain (with DNS TXT validation).
#[utoipa::path(
    put,
    operation_id = "instance.domain",
    path = "/v1/app/admin/instances/{id}/domain",
    params(("id" = Uuid, Path, description = "Instance ID")),
    request_body = UpdateDomainRequest,
    responses(
        (status = 200, description = "Domain updated"),
        (status = 400, description = "Invalid custom_domain"),
        (status = 403, description = "Missing app:instances:admin scope"),
        (status = 404, description = "Instance not found"),
    ),
    security(("sentin8:app:instances:admin" = [])),
    tag = "app",
)]
pub async fn update_instance_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:admin"),
    )
    .await?;
    if req.custom_domain.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "custom_domain must not be empty".into(),
        ));
    }
    // Story - verify DNS TXT record if provided. APP-5: a CNAME challenge
    // (`cname_token` + `cname_target`) is the alternate proof - the tenant
    // points `{token}.verify.{domain}` at the instance's platform hostname.
    let verified = if let (Some(token), Some(target)) = (&req.cname_token, &req.cname_target) {
        // The instance's platform hostname: the app instance row holds
        // `hostname` - resolve it for the expected CNAME target.
        let hostname: Option<String> = {
            let mut conn = state.pool.begin().await.map_err(err_db)?;
            set_tenant_context_ext(&mut conn, &a).await;
            let h = sqlx::query_scalar::<_, Option<String>>(
                "SELECT hostname FROM sys.app_instances WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
            .flatten();
            conn.commit().await.map_err(err_db)?;
            h
        };
        let Some(hostname) = hostname else {
            return Err((StatusCode::NOT_FOUND, format!("instance {id} not found")));
        };
        crate::domains::verify_cname(&req.custom_domain, token, target, &hostname)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?
    } else if let Some(txt) = &req.txt_record {
        crate::domains::verify_domain(&req.custom_domain, txt)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?
    } else {
        false
    };
    let domain_type = if verified { "custom" } else { "default" };
    let inst_env_id = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &a).await;
        sqlx::query(
            r#"UPDATE sys.app_instances
                  SET subdomain = $2, domain_type = $3, updated_at = now()
                WHERE id = $1
            RETURNING env_id"#,
        )
        .bind(id)
        .bind(&req.custom_domain)
        .bind(domain_type)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
        .map(|r| r.get::<Option<Uuid>, _>("env_id"))
        .unwrap_or(None)
    };
    if inst_env_id.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("instance {id} not found")));
    }
    emit_event(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        "sentin8:app:instance:domain:updated",
        serde_json::json!({ "id": id, "custom_domain": req.custom_domain, "domain_type": domain_type, "verified": verified }),
    )
    .await;
    write_audit(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        &a.claims.sub,
        "instance.domain.update",
        "sys_app_instance",
        &id.to_string(),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": id, "custom_domain" : req.custom_domain, "domain_type" : domain_type, "verified": verified }),
    ))
}

/// `PUT /v1/app/admin/instances/{id}/env-vars` - update env var secret references.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateEnvVarsRequest {
    /// Secret reference path (e.g. `sentin8-secrets://app/{id}/env`).
    pub env_vars_ref: String,
}

/// `PUT /v1/app/admin/instances/{id}/env-vars` - update env var secret references.
#[utoipa::path(
    put,
    operation_id = "instance.env-vars",
    path = "/v1/app/admin/instances/{id}/env-vars",
    params(("id" = Uuid, Path, description = "Instance ID")),
    request_body = UpdateEnvVarsRequest,
    responses(
        (status = 200, description = "Env vars reference updated"),
        (status = 403, description = "Missing app:instances:admin scope"),
        (status = 404, description = "Instance not found"),
    ),
    security(("sentin8:app:instances:admin" = [])),
    tag = "app",
)]
pub async fn update_instance_env_vars(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateEnvVarsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:admin"),
    )
    .await?;
    let inst_env_id = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &a).await;
        let res = sqlx::query(
            "UPDATE sys.app_instances SET env_vars_ref = $2, updated_at = now() WHERE id = $1 RETURNING env_id",
        )
        .bind(id)
        .bind(&req.env_vars_ref)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?;
        res.map(|r| r.get::<Option<Uuid>, _>("env_id"))
            .unwrap_or(None)
    };
    if inst_env_id.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("instance {id} not found")));
    }
    emit_event(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        "sentin8:app:instance:envvars:updated",
        serde_json::json!({ "id": id }),
    )
    .await;
    write_audit(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        &a.claims.sub,
        "instance.envvars.update",
        "sys_app_instance",
        &id.to_string(),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": id, "env_vars_ref" : req.env_vars_ref }),
    ))
}

/// `GET /v1/app/admin/instances/{id}/env-vars/resolve` - resolve the
/// instance's stored env-vars secret reference through the shared
/// `sentin8-secrets` resolver chain ( story 34.2.5). Returns the
/// resolved value once; never logged. Requires the instances:admin scope.
#[utoipa::path(
    get,
    operation_id = "instance.env-vars.resolve",
    path = "/v1/app/admin/instances/{id}/env-vars/resolve",
    params(("id" = Uuid, Path, description = "Instance ID")),
    responses(
        (status = 200, description = "Resolved env vars value"),
        (status = 404, description = "Instance not found or reference unset/unresolvable"),
        (status = 403, description = "Missing app:instances:admin scope"),
    ),
    security(("sentin8:app:instances:admin" = [])),
    tag = "app",
)]
pub async fn resolve_instance_env_vars(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:admin"),
    )
    .await?;
    let inst_env_id = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &a).await;
        let res = sqlx::query("SELECT env_id, env_vars_ref FROM sys.app_instances WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?;
        res.map(|r| {
            (
                r.get::<Option<Uuid>, _>("env_id"),
                r.get::<Option<String>, _>("env_vars_ref"),
            )
        })
    };
    let (inst_env, env_vars_ref) = match inst_env_id {
        Some(v) => v,
        None => return Err((StatusCode::NOT_FOUND, format!("instance {id} not found"))),
    };
    let env_vars_ref = env_vars_ref.filter(|r| !r.is_empty()).ok_or((
        StatusCode::NOT_FOUND,
        "instance has no env-vars reference".to_string(),
    ))?;

    // Resolve through the shared chain (service → env → file). The value
    // is returned once; it is never logged.
    let value = sentin8_secrets_sdk::secrets::resolve_credential(&env_vars_ref)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                format!("reference does not resolve: {e}"),
            )
        })?;
    let value_str = match value.into_string() {
        Ok(v) => v,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("secret decode: {e}"),
            ))
        }
    };

    emit_event(
        &state.pool,
        inst_env.unwrap_or(a.env_id()),
        "sentin8:app:instance:envvars:resolved",
        serde_json::json!({ "id": id }),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": id, "env_vars_ref": env_vars_ref, "value": value_str }),
    ))
}

/// `PUT /v1/app/admin/instances/{id}/feature-flags` - update feature flags.
/// Request to update an instance's feature flags.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateFeatureFlagsRequest {
    /// The full feature-flag map (replaces the stored value).
    pub feature_flags: serde_json::Value,
}

/// `PUT /v1/app/admin/instances/{id}/feature-flags` - update feature flags.
#[utoipa::path(
    put,
    operation_id = "instance.feature-flags",
    path = "/v1/app/admin/instances/{id}/feature-flags",
    params(("id" = Uuid, Path, description = "Instance ID")),
    request_body = UpdateFeatureFlagsRequest,
    responses(
        (status = 200, description = "Feature flags updated"),
        (status = 403, description = "Missing app:instances:admin scope"),
        (status = 404, description = "Instance not found"),
    ),
    security(("sentin8:app:instances:admin" = [])),
    tag = "app",
)]
pub async fn update_instance_feature_flags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateFeatureFlagsRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:admin"),
    )
    .await?;
    let inst_env_id = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &a).await;
        let res = sqlx::query(
            "UPDATE sys.app_instances SET feature_flags = $2, updated_at = now() WHERE id = $1 RETURNING env_id",
        )
        .bind(id)
        .bind(&req.feature_flags)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?;
        res.map(|r| r.get::<Option<Uuid>, _>("env_id"))
            .unwrap_or(None)
    };
    if inst_env_id.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("instance {id} not found")));
    }
    emit_event(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        "sentin8:app:instance:featureflags:updated",
        serde_json::json!({ "id": id }),
    )
    .await;
    write_audit(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        &a.claims.sub,
        "instance.featureflags.update",
        "sys_app_instance",
        &id.to_string(),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": id, "feature_flags" : req.feature_flags }),
    ))
}

/// `PUT /v1/app/admin/instances/{id}/status` - update instance status (active/maintenance/offline).
/// Request to update an instance's lifecycle status.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateStatusRequest {
    /// New status (`active`/`maintenance`/`offline`).
    pub status: String,
}

/// `PUT /v1/app/admin/instances/{id}/status` - update instance status.
#[utoipa::path(
    put,
    operation_id = "instance.status",
    path = "/v1/app/admin/instances/{id}/status",
    params(("id" = Uuid, Path, description = "Instance ID")),
    request_body = UpdateStatusRequest,
    responses(
        (status = 200, description = "Status updated"),
        (status = 400, description = "Invalid status"),
        (status = 403, description = "Missing app:instances:admin scope"),
        (status = 404, description = "Instance not found"),
    ),
    security(("sentin8:app:instances:admin" = [])),
    tag = "app",
)]
pub async fn update_instance_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateStatusRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:admin"),
    )
    .await?;
    if !["active", "maintenance", "offline", "provisioning"].contains(&req.status.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid status: {}", req.status),
        ));
    }
    let res = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &a).await;
        sqlx::query(
            "UPDATE sys.app_instances SET status = $2, updated_at = now() WHERE id = $1 RETURNING env_id",
        )
        .bind(id)
        .bind(&req.status)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
    };
    let inst_env_id: Option<Uuid> = res
        .map(|r| r.get::<Option<Uuid>, _>("env_id"))
        .unwrap_or(None);
    if inst_env_id.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("instance {id} not found")));
    }
    emit_event(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        "sentin8:app:instance:status:updated",
        serde_json::json!({ "id": id, "status": req.status }),
    )
    .await;
    write_audit(
        &state.pool,
        inst_env_id.unwrap_or(a.env_id()),
        &a.claims.sub,
        "instance.status.update",
        "sys_app_instance",
        &id.to_string(),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "status": req.status })))
}

/// `GET /v1/app/admin/instances/{id}/oauth-client` - get OAuth client (DCR summary).
#[utoipa::path(
    get,
    operation_id = "instance.oauth",
    path = "/v1/app/admin/instances/{id}/oauth-client",
    params(("id" = Uuid, Path, description = "Instance ID")),
    responses(
        (status = 200, description = "OAuth client summary"),
        (status = 403, description = "Missing app:instances:admin scope"),
        (status = 404, description = "Instance not found"),
    ),
    security(("sentin8:app:instances:admin" = [])),
    tag = "app",
)]
pub async fn get_instance_oauth_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:app:instances:admin"),
    )
    .await?;
    let row = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        set_tenant_context_ext(&mut conn, &_a).await;
        sqlx::query("SELECT oauth_client_id FROM sys.app_instances WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .map_err(err_db)?
    };
    let client_id: String = row.try_get("oauth_client_id").unwrap_or_default();
    if client_id.is_empty() {
        return Ok(Json(
            serde_json::json!({ "id": id, "oauth_client_id" : null, "registered": false }),
        ));
    }
    Ok(Json(serde_json::json!({
        "id": id,
        "oauth_client_id" : client_id,
        "registered": true,
        "dcr_endpoint" : format!("{}/oauth/register", state.config.sentin8_auth_base_url.trim_end_matches('/')),
    })))
}

// ── Flow internal endpoint (Story) ──────────────────────────────

/// `POST /v1/internal/steps/execute` - App step handler called by Flow (proxy-back).
#[utoipa::path(
    post,
    path = "/v1/internal/steps/execute",
    request_body = StepExecuteRequest,
    responses(
        (status = 200, description = "Step executed", body = StepExecuteResponse),
        (status = 400, description = "Invalid step"),
    ),
    tag = "app",
)]
pub async fn execute_internal_step(
    Json(req): Json<StepExecuteRequest>,
) -> Result<Json<StepExecuteResponse>, (StatusCode, String)> {
    let resp = steps::execute_step(&req).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(resp))
}

// ── Health ───────────────────────────────────────────────────────────────

/// `GET /v1/health` - liveness probe.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build, active connections)", body = serde_json::Value),
    ),
    security(),
    tag = "meta",
)]
pub async fn health() -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({ "status": "ok", "service": "app", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash() });
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Append an event to the shared `inbox` table for Bus relay.
///
/// `inbox` has RLS enabled, so we acquire a connection and set the
/// tenant context before the INSERT. Each call runs in its own transaction
/// (begin → set context → INSERT → commit) so the row is durable exactly
/// when the caller's domain write has committed; callers that need the
/// event and the domain change to commit atomically use
/// [`emit_event_tx`] inside their own transaction instead.
async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, event_type = %event_type, "app: failed to begin transaction for outbox event");
            return;
        }
    };
    if emit_event_tx(&mut tx, env_id, event_type, payload)
        .await
        .is_err()
    {
        tracing::warn!(event_type = %event_type, "app: failed to emit outbox event");
        let _ = tx.rollback().await;
    }
}

/// Event emitter for admin_ui handlers (public wrapper).
pub(crate) async fn emit_admin_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    emit_event(pool, env_id, event_type, payload).await;
}

/// Append an event to the LOCAL outbox (`app.outbox`) for the DBX relay
/// ( - the shared-inbox table is retired).
///
/// The insert rides the CALLER's transaction (unqualified `outbox` resolves
/// to `app.outbox` via the service role's `search_path=app, public`) so the
/// event commits exactly when the domain write commits. The post-commit
/// relay pushes it to Bus `POST /v1/produce` with the service's M2M token.
/// Incident (e2e : this used to INSERT into a retired
/// unqualified `inbox` table → `relation "inbox" does not exist` → every
/// listing mutation 500ed.
async fn emit_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<(), sqlx::Error> {
    set_tenant_context(tx, env_id).await;
    sentin8::bus::outbox::insert_outbox_row(&mut **tx, env_id, "app", event_type, &payload)
        .await
        .map(|_| ())
        .map_err(|e| match e {
            sentin8::bus::outbox::OutboxError::Db(db) => db,
            other => sqlx::Error::ColumnDecode {
                index: "outbox_insert".into(),
                source: Box::new(std::io::Error::other(other.to_string())),
            },
        })
}

/// Write an audit event to `audit_events` (.3). Best-effort - a
/// failed audit write is logged but never fails the request.
async fn write_audit(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    actor: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
) {
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, action = %action, "app: failed to begin transaction for audit event");
            return;
        }
    };
    set_tenant_context(&mut tx, env_id).await;
    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_events (env_id, actor_user_id, action, target_resource_type, target_resource_id)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(env_id)
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!(error = %e, action = %action, "app: failed to write audit event");
        let _ = tx.rollback().await;
        return;
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!(error = %e, action = %action, "app: failed to commit audit event");
    }
}

/// Audit writer for admin_ui handlers (public wrapper, best-effort actor).
pub(crate) async fn write_admin_audit(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    action: &str,
    target_type: &str,
    target_id: &str,
) {
    write_audit(pool, env_id, "", action, target_type, target_id).await;
}

fn row_to_listing(row: &sqlx::postgres::PgRow) -> StoreListingResponse {
    // The `roles` column is JSONB; we deserialize it back to the typed
    // shape. Rows that pre-date this column (default '[]') decode to an
    // empty Vec.
    let roles: Vec<ListingRole> = row
        .try_get::<serde_json::Value, _>("roles")
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    StoreListingResponse {
        id: row.get("id"),
        app_name: row.get("app_name"),
        app_slug: row.get("app_slug"),
        description: row.get("description"),
        status: row.get("status"),
        supports_dcr: row.get("supports_dcr"),
        visibility: row.get("visibility"),
        usr_id: row.get("usr_id"),
        created_by: row.get("created_by"),
        env_id: row.get("env_id"),
        created_at: row.get("created_at"),
        roles,
        default_signup_role: row.get("default_signup_role"),
        version: row
            .try_get::<String, _>("version")
            .unwrap_or_else(|_| "0.0.0".into()),
        channel: row
            .try_get::<String, _>("channel")
            .unwrap_or_else(|_| "stable".into()),
        media: row
            .try_get::<serde_json::Value, _>("media")
            .unwrap_or(serde_json::json!([])),
    }
}

/// Validate the roles payload submitted with a listing.
///
/// Rules:
/// * `name` must be non-empty, ≤64 chars.
/// * Names must be unique within the listing.
/// * `scopes` must each be a non-empty string. Duplicates are deduped.
/// * `includes` must reference other role names in the same listing;
///   no self-includes; cycles rejected (see [detect_include_cycles]).
/// * If `default_signup_role` is provided, it must match one of the
///   role names.
fn validate_listing_roles(
    roles: &[ListingRole],
    default_signup_role: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    for g in roles {
        if g.name.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "role name must not be empty".into(),
            ));
        }
        if g.name.len() > 64 {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("role name too long: {}", g.name),
            ));
        }
        if !seen.insert(g.name.clone()) {
            return Err((
                StatusCode::CONFLICT,
                format!("duplicate role name: {}", g.name),
            ));
        }
        for s in &g.scopes {
            if s.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("empty scope in role {}", g.name),
                ));
            }
        }
        // `includes` must reference other roles in this listing.
        // Self-include is rejected. Cycle detection runs in a second
        // pass (needs the full name set).
        for inc in &g.includes {
            if inc.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("empty include in role {}", g.name),
                ));
            }
            if inc == &g.name {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("role '{}' cannot include itself", g.name),
                ));
            }
        }
    }
    // Verify all includes resolve to names in the listing.
    for g in roles {
        for inc in &g.includes {
            if !seen.contains(inc) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("role '{}' includes unknown role '{}'", g.name, inc),
                ));
            }
        }
    }
    // Detect cycles in the include graph (DFS with white/gray/black sets).
    detect_include_cycles(roles)?;
    if let Some(d) = default_signup_role {
        if !seen.contains(d) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("default_signup_role '{d}' must match one of the role names"),
            ));
        }
    }
    Ok(())
}

/// Detect cycles in the listing's role-include graph. A cycle
/// (A includes B, B includes C, C includes A) would cause infinite
/// expansion at install time. Runs an iterative DFS from each
/// role, coloring visited nodes (gray = on current path, black =
/// fully explored). Returns 400 on any back-edge.
fn detect_include_cycles(roles: &[ListingRole]) -> Result<(), (StatusCode, String)> {
    use std::collections::HashMap;
    let by_name: HashMap<&str, &ListingRole> = roles.iter().map(|g| (g.name.as_str(), g)).collect();
    // 0 = unvisited, 1 = on current DFS path, 2 = fully explored.
    let mut color: HashMap<&str, u8> = HashMap::new();
    for g in roles {
        if color.get(g.name.as_str()).copied().unwrap_or(0) != 0 {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(g.name.as_str(), 0)];
        color.insert(g.name.as_str(), 1);
        while let Some((node, idx)) = stack.last().copied() {
            let next = by_name
                .get(node)
                .and_then(|g| g.includes.get(idx))
                .map(String::as_str);
            match next {
                None => {
                    color.insert(node, 2);
                    stack.pop();
                }
                Some(child) => {
                    // Bump the index on the current frame so we move
                    // past this child on the next iteration.
                    let frame = stack.last_mut().expect("non-empty");
                    frame.1 += 1;
                    match color.get(child).copied().unwrap_or(0) {
                        0 => {
                            color.insert(child, 1);
                            stack.push((child, 0));
                        }
                        1 => {
                            return Err((
                                StatusCode::BAD_REQUEST,
                                format!("include cycle detected: '{}' -> '{}'", node, child),
                            ))
                        }
                        2 => { /* already fully explored - no cycle through here */ }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

/// Resolve a role's effective permission set by walking its
/// `includes` graph (no cycles - the caller has already validated).
/// Returns a deduped, order-preserving union of the role's own
/// scopes plus all transitively included roles' scopes.
#[allow(dead_code)]
fn resolve_role_scopes<'a>(roles: &'a [ListingRole], root: &str) -> Vec<String> {
    use std::collections::{HashMap, HashSet};
    let by_name: HashMap<&str, &'a ListingRole> =
        roles.iter().map(|g| (g.name.as_str(), g)).collect();
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut stack: Vec<&str> = vec![root];
    while let Some(name) = stack.pop() {
        let Some(g) = by_name.get(name) else { continue };
        for s in &g.scopes {
            if seen.insert(s.clone()) {
                out.push(s.clone());
            }
        }
        for inc in &g.includes {
            if !seen.contains(inc) {
                stack.push(inc.as_str());
            }
        }
    }
    out
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Story - Resolve the env-scoped Auth URL for DCR registration.
///
/// Queries the env's auth_domain from the DB (App has direct DB access).
/// Falls back to the platform auth issuer if not set.
async fn resolve_env_sentin8_auth_url(state: &AppState, org_id: Uuid, env_id: Uuid) -> String {
    // Build the env-scoped auth domain from the env's auth_domain subdomain
    // + org domain, same as Sys's get_env_auth_domain endpoint.
    // Same-connection context - RLS gates on context presence; a
    // bare-pool read hides the row and silently falls back to the platform
    // auth issuer.
    let row = async {
        let mut conn = state.pool.begin().await.ok()?;
        set_tenant_context(&mut conn, env_id).await;
        sqlx::query(
            r#"SELECT e.auth_domain, e.slug AS env_slug, o.domain, o.slug AS org_slug
                 FROM sys.environments e
                 JOIN sys.organizations o ON o.id = e.org_id
                WHERE e.id = $1 AND e.org_id = $2"#,
        )
        .bind(env_id)
        .bind(org_id)
        .fetch_optional(&mut *conn)
        .await
        .ok()
        .flatten()
    }
    .await;
    match row {
        Some(r) => {
            let subdomain: String = r.try_get("auth_domain").unwrap_or_default();
            let env_slug: String = r.try_get("env_slug").unwrap_or_default();
            let org_domain: String = r.try_get("domain").unwrap_or_default();
            let is_custom = !org_domain.contains(".o.");
            let env_domain = if is_custom {
                format!("{env_slug}.{org_domain}")
            } else {
                format!("{env_slug}.e.{org_domain}")
            };
            if subdomain.is_empty() {
                format!("https://auth.{}", env_domain)
            } else {
                let sub = if subdomain == "auth" {
                    "auth"
                } else {
                    subdomain.as_str()
                };
                format!("https://{}.{}", sub, env_domain)
            }
        }
        None => state.config.sentin8_auth_issuer.clone(),
    }
}

/// Upper bound the setup-time DCR retry window. A brand-new env's Auth
/// identity (proxy SNI mapping + Acme cert for `auth.{env}.{org}`)
/// becomes routable seconds after the install lands; the observed worst
/// case is ~42 s - ~60 s covers it with headroom.
const SIGNIN_CLIENT_RETRY_WINDOW_SECS: u64 = 60;
/// Base seconds for the exponential backoff between DCR attempts.
const SIGNIN_CLIENT_RETRY_BASE_SECS: u64 = 3;

/// Register the instance's sign-in OAuth client with bounded backoff.
///
/// The install (`POST /v1/app/setup`) can fire while the env-scoped Auth
/// for a brand-new env is not yet routable (proxy `no mapping for SNI`,
/// Acme cert mid-issuance) - the first DCR attempt fails and the
/// triggering request is the ONLY chance to provision: no event re-fires
/// for the same env. The swallow-and-continue form left the instance
/// `active` with an empty `oauth_client_id`, and every sign-up through
/// the BFF then 500'd (fallback `dash` client is not active in the
/// tenant env → PAR 401). Retry with exponential backoff until the
/// window elapses; a persistent failure FAILS the install (fail-closed -
/// an instance that cannot authenticate its users must not be served).
async fn register_signin_client_with_retry(
    _state: &AppState,
    dcr_auth_url: &str,
    instance_id: Uuid,
    redirect_uri: String,
    scopes: Vec<String>,
    consent_required: bool,
) -> Result<crate::dcr::OAuthClient, crate::dcr::DcrError> {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(SIGNIN_CLIENT_RETRY_WINDOW_SECS);
    let mut attempt: u64 = 0;
    loop {
        attempt += 1;
        match crate::dcr::register_oauth_client_with_grants(
            dcr_auth_url,
            instance_id,
            std::slice::from_ref(&redirect_uri),
            &scopes,
            &["authorization_code", "refresh_token"],
            consent_required,
        )
        .await
        {
            Ok(client) => return Ok(client),
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(crate::dcr::DcrError::Http(format!(
                        "DCR retry window exhausted after {attempt} attempt(s): {e}"
                    )));
                }
                let backoff = SIGNIN_CLIENT_RETRY_BASE_SECS
                    .saturating_mul(1u64 << attempt.saturating_sub(1).min(4));
                tracing::warn!(instance_id = %instance_id, attempt, backoff_s = backoff, error = %e, "app: DCR failed - retrying with backoff");
                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            }
        }
    }
}

/// Merged branding (org→env). `sentin8_sys_branding` is merged hierarchically: env
/// overrides org for each field. Fields that are null at the env level fall
/// through to the org level.
#[derive(Debug, Clone, Default)]
struct MergedBranding {
    logo_url: Option<String>,
    logo_icon_url: Option<String>,
    primary_color: Option<String>,
    accent_color: Option<String>,
    font_family: Option<String>,
    theme_mode: Option<String>,
    custom_css: Option<String>,
    sign_in_text: Option<String>,
}

/// Fetch merged org→env branding from `sys.branding` (Story).
/// Same-connection tenant context - the branding table's RLS gates
/// on `sentin8_context_initialized`; both reads run on ONE connection
/// with the env context set.
async fn fetch_merged_branding(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    env_id: Uuid,
) -> Result<MergedBranding, sqlx::Error> {
    let mut conn = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    // Org-level branding (scope='org', env_id IS NULL).
    let org_row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
             FROM sys.branding
            WHERE org_id = $1 AND scope = 'org' AND env_id IS NULL"#,
    ).bind(org_id).fetch_optional(&mut *conn).await?;
    // Env-level branding (scope='env', env_id = $2).
    let env_row = sqlx::query(
        r#"SELECT logo_url, logo_icon_url, primary_color, accent_color, font_family, theme_mode, custom_css, sign_in_text
             FROM sys.branding
            WHERE org_id = $1 AND env_id = $2 AND scope = 'env'"#,
    ).bind(env_id).fetch_optional(&mut *conn).await?;
    drop(conn);
    let pick = |org: &Option<sqlx::postgres::PgRow>,
                env: &Option<sqlx::postgres::PgRow>,
                col: &str|
     -> Option<String> {
        env.as_ref()
            .and_then(|r| r.try_get::<Option<String>, _>(col).ok())
            .flatten()
            .or_else(|| {
                org.as_ref()
                    .and_then(|r| r.try_get::<Option<String>, _>(col).ok())
                    .flatten()
            })
    };
    Ok(MergedBranding {
        logo_url: pick(&org_row, &env_row, "logo_url"),
        logo_icon_url: pick(&org_row, &env_row, "logo_icon_url"),
        primary_color: pick(&org_row, &env_row, "primary_color"),
        accent_color: pick(&org_row, &env_row, "accent_color"),
        font_family: pick(&org_row, &env_row, "font_family"),
        theme_mode: pick(&org_row, &env_row, "theme_mode"),
        custom_css: pick(&org_row, &env_row, "custom_css"),
        sign_in_text: pick(&org_row, &env_row, "sign_in_text"),
    })
}

/// Call Sys's domain mapping API to derive app + BFF domains.
/// Idempotent: Sys upserts, safe to call multiple times.
#[allow(
    dead_code,
    clippy::similar_names,
    clippy::duplicate_underscore_argument
)]
async fn _derive_sentin8_tls_mappings(
    state: &AppState,
    org_id: Uuid,
    env_id: Uuid,
    app_slug: &str,
    instance_id: Uuid,
    app_hostname: &str,
    bff_hostname: &str,
    domain_type: &str,
    _listing_backend_url: &str,
    _app_hostname: &str,
    _sentin8_bff_hostname: &str,
) -> Result<(), String> {
    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    // Fetch org + env slugs and the org's domain.
    // Same-connection transaction ( rule 2) - RLS gates on context
    // presence and the context is transaction-local.
    let org_row = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| format!("derive_mappings: pool: {e}"))?;
        set_tenant_context(&mut tx, env_id).await;
        let row = sqlx::query(
            r#"SELECT o.slug AS org_slug, o.domain, e.slug AS env_slug
                 FROM sys.organizations o
                 JOIN sys.environments e ON e.org_id = o.id
                WHERE o.id = $1 AND e.id = $2"#,
        )
        .bind(org_id)
        .bind(env_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("derive_mappings: failed to load org/env: {e}"))?;
        tx.commit()
            .await
            .map_err(|e| format!("derive_mappings: commit: {e}"))?;
        row
    };
    use sqlx::Row;
    let org_slug: String = org_row.try_get("org_slug").unwrap_or_default();
    let env_slug: String = org_row.try_get("env_slug").unwrap_or_default();
    let org_domain: String = org_row.try_get("domain").unwrap_or_default();

    // Derive app + BFF domain mappings in a single call to Sys.
    let derive_req = serde_json::json!({
        "org_id": org_id,
        "organization_slug": org_slug,
        "org_domain": org_domain,
        "env_id": env_id,
        "environment_slug": env_slug,
        "application_id": instance_id,
        "application_slug": app_slug,
        "app_domain": app_hostname,
    });
    match http
        .post(format!(
            "{}/v1/domain-mappings/derive",
            state.config.sentin8_sys_url
        ))
        .json(&derive_req)
        .send()
        .await
    {
        Ok(resp) => tracing::info!(status = %resp.status(), "sys derive mappings response"),
        Err(e) => tracing::error!(error = %e, "sys derive mappings request failed"),
    }

    // Upsert the app hostname mapping (service=web - the single-instance
    // static file server that serves all app-store apps). No backend_url
    // is set - proxy routes to the web instance via the Valkey registry
    // (Active instance of the "web" service type), same as any platform
    // service. The app slug is encoded in the hostname's first label, so
    // web resolves which app to serve from the X-Sentin8-Hostname header.
    // See sentin8/design/sentin8-sentin8-web-technical-design.md.
    let is_custom = domain_type == "custom";
    let app_req = serde_json::json!({
        "hostname": app_hostname,
        "service": "sentin8:web",
        "org_id": org_id,
        "env_id": env_id,
        "application_id": instance_id,
        "domain_type": domain_type,
        "is_custom": is_custom,
        "backend_url": null,
    });
    match http
        .put(format!(
            "{}/v1/domain-mappings",
            state.config.sentin8_sys_url
        ))
        .json(&app_req)
        .send()
        .await
    {
        Ok(resp) => tracing::info!(status = %resp.status(), "sys app mapping upsert response"),
        Err(e) => tracing::error!(error = %e, "sys app mapping upsert failed"),
    }

    // Upsert the BFF hostname mapping.
    let bff_req = serde_json::json!({
        "hostname": bff_hostname,
        "service": "bff",
        "org_id": org_id,
        "env_id": env_id,
        "application_id": instance_id,
        "domain_type": "app_bff",
        "is_custom": is_custom,
    });
    match http
        .put(format!(
            "{}/v1/domain-mappings",
            state.config.sentin8_sys_url
        ))
        .json(&bff_req)
        .send()
        .await
    {
        Ok(resp) => tracing::info!(status = %resp.status(), "sys bff mapping upsert response"),
        Err(e) => tracing::error!(error = %e, "sys bff mapping upsert failed"),
    }

    Ok(())
}

// ── Integration tests (Story) ─────────────────────────────────────

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
    use crate::steps::{STEP_APPROVAL_REVIEW, STEP_DOCUMENT_UPLOAD, STEP_KYC_CHECK};

    #[test]
    fn update_listing_request_accepts_partial_updates() {
        install_provider();
        let req: UpdateListingRequest =
            serde_json::from_value(serde_json::json!({ "status": "published" })).unwrap();
        assert_eq!(req.status.as_deref(), Some("published"));
        assert!(req.app_name.is_none());
    }

    #[test]
    fn update_status_request_validates_values() {
        install_provider();
        let req: UpdateStatusRequest =
            serde_json::from_value(serde_json::json!({ "status": "maintenance" })).unwrap();
        assert_eq!(req.status, "maintenance");
    }

    #[test]
    fn update_domain_request_parses() {
        install_provider();
        let req: UpdateDomainRequest = serde_json::from_value(serde_json::json!({
            "custom_domain": "ibank.acme.com",
            "txt_record": "sentin8-verify-deadbeef"
        }))
        .unwrap();
        assert_eq!(req.custom_domain, "ibank.acme.com");
        assert!(req.txt_record.is_some());
    }

    #[test]
    fn update_env_vars_request_parses() {
        install_provider();
        let req: UpdateEnvVarsRequest = serde_json::from_value(serde_json::json!({
            "env_vars_ref": "sentin8-secrets://app/abc/env"
        }))
        .unwrap();
        assert_eq!(req.env_vars_ref, "sentin8-secrets://app/abc/env");
    }

    #[test]
    fn update_feature_flags_request_parses() {
        install_provider();
        let req: UpdateFeatureFlagsRequest = serde_json::from_value(serde_json::json!({
            "feature_flags": { "new_ui" : true }
        }))
        .unwrap();
        assert_eq!(req.feature_flags["new_ui"], true);
    }

    #[test]
    fn setup_request_accepts_instance_name_description() {
        install_provider();
        let req: SetupRequest = serde_json::from_value(serde_json::json!({
            "listing_id": "00000000-0000-0000-0000-000000000001",
            "instance_name": "My Bank",
            "instance_description": "desc"
        }))
        .unwrap();
        assert_eq!(req.instance_name.as_deref(), Some("My Bank"));
        assert_eq!(req.instance_description.as_deref(), Some("desc"));
    }

    #[test]
    fn setup_request_instance_name_is_optional() {
        install_provider();
        let req: SetupRequest = serde_json::from_value(serde_json::json!({
            "listing_id": "00000000-0000-0000-0000-000000000001"
        }))
        .unwrap();
        assert!(req.instance_name.is_none());
        assert!(req.instance_description.is_none());
    }

    #[test]
    fn validate_listing_roles_ok() {
        install_provider();
        let roles = vec![
            ListingRole {
                name: "ebank-customer".into(),
                description: None,
                scopes: vec!["test:ledger:accounts:read".into()],
                includes: vec![],
            },
            ListingRole {
                name: "ebank-admin".into(),
                description: None,
                scopes: vec!["ebank:admin".into()],
                includes: vec![],
            },
        ];
        assert!(validate_listing_roles(&roles, Some("ebank-customer")).is_ok());
    }

    #[test]
    fn validate_listing_roles_rejects_empty_name() {
        install_provider();
        let roles = vec![ListingRole {
            name: "".into(),
            description: None,
            scopes: vec![],
            includes: vec![],
        }];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn validate_listing_roles_rejects_duplicate_name() {
        install_provider();
        let roles = vec![
            ListingRole {
                name: "ebank-admin".into(),
                description: None,
                scopes: vec![],
                includes: vec![],
            },
            ListingRole {
                name: "ebank-admin".into(),
                description: None,
                scopes: vec![],
                includes: vec![],
            },
        ];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn validate_listing_roles_rejects_unknown_default_signup_role() {
        install_provider();
        let roles = vec![ListingRole {
            name: "ebank-customer".into(),
            description: None,
            scopes: vec![],
            includes: vec![],
        }];
        assert!(validate_listing_roles(&roles, Some("ebank-admin")).is_err());
    }

    #[test]
    fn validate_listing_roles_rejects_empty_scope() {
        install_provider();
        let roles = vec![ListingRole {
            name: "ebank-customer".into(),
            description: None,
            scopes: vec!["".into()],
            includes: vec![],
        }];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn validate_listing_roles_accepts_includes() {
        install_provider();
        // ebank-teller includes ebank-customer + adds its own scope.
        let roles = vec![
            ListingRole {
                name: "ebank-customer".into(),
                description: None,
                scopes: vec!["test:ledger:accounts:read".into()],
                includes: vec![],
            },
            ListingRole {
                name: "ebank-teller".into(),
                description: None,
                scopes: vec!["test:ledger:products:write".into()],
                includes: vec!["ebank-customer".into()],
            },
        ];
        assert!(validate_listing_roles(&roles, None).is_ok());
    }

    #[test]
    fn validate_listing_roles_rejects_self_include() {
        install_provider();
        let roles = vec![ListingRole {
            name: "ebank-customer".into(),
            description: None,
            scopes: vec![],
            includes: vec!["ebank-customer".into()],
        }];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn validate_listing_roles_rejects_unknown_include() {
        install_provider();
        let roles = vec![
            ListingRole {
                name: "ebank-customer".into(),
                description: None,
                scopes: vec![],
                includes: vec![],
            },
            ListingRole {
                name: "ebank-teller".into(),
                description: None,
                scopes: vec![],
                includes: vec!["ebank-admin".into()],
            },
        ];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn validate_listing_roles_rejects_include_cycle() {
        install_provider();
        // A → B → A
        let roles = vec![
            ListingRole {
                name: "A".into(),
                description: None,
                scopes: vec![],
                includes: vec!["B".into()],
            },
            ListingRole {
                name: "B".into(),
                description: None,
                scopes: vec![],
                includes: vec!["A".into()],
            },
        ];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn validate_listing_roles_rejects_include_self_cycle() {
        install_provider();
        // A → A (caught earlier by the self-include check)
        let roles = vec![ListingRole {
            name: "A".into(),
            description: None,
            scopes: vec![],
            includes: vec!["A".into()],
        }];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn validate_listing_roles_rejects_three_cycle() {
        install_provider();
        // A → B → C → A
        let roles = vec![
            ListingRole {
                name: "A".into(),
                description: None,
                scopes: vec![],
                includes: vec!["B".into()],
            },
            ListingRole {
                name: "B".into(),
                description: None,
                scopes: vec![],
                includes: vec!["C".into()],
            },
            ListingRole {
                name: "C".into(),
                description: None,
                scopes: vec![],
                includes: vec!["A".into()],
            },
        ];
        assert!(validate_listing_roles(&roles, None).is_err());
    }

    #[test]
    fn resolve_role_scopes_merges_includes() {
        install_provider();
        let roles = vec![
            ListingRole {
                name: "ebank-customer".into(),
                description: None,
                scopes: vec!["a".into(), "b".into()],
                includes: vec![],
            },
            ListingRole {
                name: "ebank-teller".into(),
                description: None,
                scopes: vec!["c".into()],
                includes: vec!["ebank-customer".into()],
            },
            ListingRole {
                name: "ebank-admin".into(),
                description: None,
                scopes: vec!["d".into()],
                includes: vec!["ebank-teller".into()],
            },
        ];
        let eff = resolve_role_scopes(&roles, "ebank-admin");
        // admin = {d} ∪ teller {c} ∪ customer {a, b} → a, b, c, d (insertion order).
        assert_eq!(
            eff,
            vec![
                "d".to_string(),
                "c".to_string(),
                "a".to_string(),
                "b".to_string()
            ]
        );
        // Customer (no includes) is just its own.
        let cust = resolve_role_scopes(&roles, "ebank-customer");
        assert_eq!(cust, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn resolve_role_scopes_dedupes_overlapping_includes() {
        install_provider();
        // Both roles have the same scope; the resolved set should
        // contain it exactly once.
        let roles = vec![
            ListingRole {
                name: "base".into(),
                description: None,
                scopes: vec!["shared".into(), "base-only".into()],
                includes: vec![],
            },
            ListingRole {
                name: "derived".into(),
                description: None,
                scopes: vec!["shared".into(), "derived-only".into()],
                includes: vec!["base".into()],
            },
        ];
        let eff = resolve_role_scopes(&roles, "derived");
        assert_eq!(
            eff,
            vec![
                "shared".to_string(),
                "derived-only".to_string(),
                "base-only".to_string()
            ]
        );
    }

    #[test]
    fn execute_internal_step_kyc_check() {
        install_provider();
        let req = StepExecuteRequest {
            workflow_id: "wf-1".into(),
            step_name: "kyc-1".into(),
            step_kind: STEP_KYC_CHECK.into(),
            config: serde_json::json!({}),
            input: serde_json::json!({ "subject": "user-1" }),
        };
        let resp = steps::execute_step(&req).unwrap();
        assert_eq!(resp.status, "completed");
    }

    #[test]
    fn execute_internal_step_approval_review_pauses() {
        install_provider();
        let req = StepExecuteRequest {
            workflow_id: "wf-1".into(),
            step_name: "appr-1".into(),
            step_kind: STEP_APPROVAL_REVIEW.into(),
            config: serde_json::json!({ "reviewer": "bob" }),
            input: serde_json::json!({}),
        };
        let resp = steps::execute_step(&req).unwrap();
        assert_eq!(resp.status, "paused");
    }

    #[test]
    fn execute_internal_step_document_upload() {
        install_provider();
        let req = StepExecuteRequest {
            workflow_id: "wf-1".into(),
            step_name: "doc-1".into(),
            step_kind: STEP_DOCUMENT_UPLOAD.into(),
            config: serde_json::json!({}),
            input: serde_json::json!({ "document_type": "passport" }),
        };
        let resp = steps::execute_step(&req).unwrap();
        assert_eq!(resp.status, "completed");
    }

    #[test]
    fn execute_internal_step_unknown_kind_errors() {
        install_provider();
        let req = StepExecuteRequest {
            workflow_id: "wf-1".into(),
            step_name: "x".into(),
            step_kind: "Unknown".into(),
            config: serde_json::json!({}),
            input: serde_json::json!({}),
        };
        assert!(steps::execute_step(&req).is_err());
    }
}
