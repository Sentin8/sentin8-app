// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:App Admin UI handlers — RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;
use sqlx::Row;

/// Query parameters accepting an explicit target environment.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct TargetEnvQuery {
    /// Target env id — REQUIRED for cross-env admin calls, never defaulted.
    #[serde(default)]
    pub target_env_id: Option<String>,
}

/// Query parameters for the customer-mode instance discovery surface
/// (auth DESIGN invariant 12): the env to enumerate is explicit — never
/// derived from the caller's token env, since the calling M2M workload
/// authenticates in the SYSTEM env.
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct CustomerModeQuery {
    /// Environment to enumerate customer-mode instances in.
    pub env_id: uuid::Uuid,
}

/// `GET /v1/admin/ui/{page}` — RFW page definition for the requested page.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = serde_json::Value),
        (status = 403, description = "Caller lacks an app read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:app:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::require_any_scope(
        &state.config,
        &headers,
        &[
            "sentin8:app:store:read",
            "sentin8:app:store:admin",
            "sentin8:sys:admin",
            "sentin8:sys:org:admin",
            "sentin8:sys:env:admin",
        ],
    )
    .await?;
    // Page definitions are static — target_env_id is only needed for the
    // install page (to resolve auth domain dropdown options).
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok());

    // For the install page, build the Auth URL dropdown options.
    // Only show auth domains for environments in the caller's org.
    // org_id is resolved from env_id (the sole tenant key) via DB lookup.
    let (auth_domain_options, default_auth_domain): (
        Vec<FormFieldOption>,
        Option<serde_json::Value>,
    ) = if page == "install" {
        let env_id = env_id.ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing target_env_id for install page".into(),
            )
        })?;
        let cfg = sentin8::config::Sentin8Config::from_env();
        // Resolve org_id + env/org slugs + sibling envs in ONE explicit
        // transaction with the target env's context ( rule 2): the
        // context is transaction-local (`set_config(..., true)`) and each
        // pooled statement runs in its OWN implicit transaction — a
        // bare-acquire context-set evaporates before the next statement
        // and FORCE RLS hides every row.
        let (_org_id, current_env_slug, current_org_domain, options_rows) = {
            let mut tx = state
                .pool
                .begin()
                .await
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            crate::handlers::set_tenant_context_for_admin(&mut tx, env_id).await;
            let org_id: uuid::Uuid =
                sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
                    .bind(env_id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap_or(sentin8::config::SYSTEM_ORG_ID);
            let current_env_slug: String =
                sqlx::query_scalar("SELECT slug FROM sys.environments WHERE id = $1")
                    .bind(env_id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap_or_default();
            let current_org_domain: String =
                sqlx::query_scalar("SELECT domain FROM sys.organizations WHERE id = $1")
                    .bind(org_id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap_or_default();
            let rows = sqlx::query(
                r#"SELECT e.slug AS env_slug, o.domain AS org_domain
                   FROM sys.environments e
                   JOIN sys.organizations o ON o.id = e.org_id
                   WHERE o.id = $1 AND o.status <> 'archived' AND e.status <> 'archived'
                   ORDER BY e.slug"#,
            )
            .bind(org_id)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default();
            (org_id, current_env_slug, current_org_domain, rows)
        };

        let options: Vec<FormFieldOption> = options_rows
            .iter()
            .filter_map(|r| {
                let env_slug: String = r.try_get("env_slug").ok()?;
                let org_domain: String = r.try_get("org_domain").ok()?;
                if org_domain.is_empty() {
                    return None;
                }
                let env_domain = cfg.env_domain(&env_slug, &org_domain);
                let auth_host = cfg.env_auth_domain(&env_domain);
                let hostname = format!("https://{auth_host}");
                Some(FormFieldOption {
                    value: hostname.clone(),
                    label: hostname,
                })
            })
            .collect();

        // Default to the current env's auth domain.
        let default = if !current_env_slug.is_empty() && !current_org_domain.is_empty() {
            let env_domain = cfg.env_domain(&current_env_slug, &current_org_domain);
            let auth_host = cfg.env_auth_domain(&env_domain);
            Some(serde_json::json!(format!("https://{auth_host}")))
        } else {
            None
        };

        (options, default)
    } else {
        (vec![], None)
    };

    let def = match page.as_str() {
        "overview" => AdminPage::new("App Overview").widget(card("Summary","Instance list and store listing cards.")).build(),
        "store" => AdminPage::new("App Store")
            .action(link("Create Listing", "store/new"))
            .widget(table_with_actions(vec![
                cols("app_name", "App"),
                cols("description", "Description"),
                cols("status", "Status"),
            ], "/store", vec![
                row_action("View", "store/{id}"),
                row_action("Install", "install?listing_id={id}"),
            ]))
            .build(),
        "store/new" => AdminPage::new("Create Listing")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "app_name".into(),
                        label: "App Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. My Bank App".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "app_slug".into(),
                        label: "App Slug".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. my-bank-app".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("Unique identifier for this app. Used in URLs and domain names.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "description".into(),
                        label: "Description".into(),
                        field_type: FormFieldType::Textarea,
                        required: false,
                        placeholder: Some("What does this app do?".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "backend_url".into(),
                        label: "Backend URL".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("e.g. https://my-app-backend.ops.sys.sentin8.local".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("The backend service URL for this app. Leave empty if not applicable.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "visibility".into(),
                        label: "Visibility".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!("public")),
                        options: Some(vec![
                            FormFieldOption { value: "public".into(), label: "Public — visible to all orgs".into() },
                            FormFieldOption { value: "env".into(), label: "Env — visible only within this env".into() },
                            FormFieldOption { value: "usr".into(), label: "Private — visible only to me".into() },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/app/store/listings".into(),
                submit_label: "Create Listing".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "install" => AdminPage::new("Install App")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "listing_id".into(),
                        label: "Listing ID".into(),
                        field_type: FormFieldType::Hidden,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "custom_domain".into(),
                        label: "Subdomain".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. ebank (defaults to app slug)".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("The subdomain prefix for this app instance.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "instance_name".into(),
                        label: "Instance Name (optional)".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: Some("Display name for this instance".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "instance_description".into(),
                        label: "Description (optional)".into(),
                        field_type: FormFieldType::Textarea,
                        required: false,
                        placeholder: Some("What this instance is for".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "auth_url".into(),
                        label: "Auth URL".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: default_auth_domain,
                        options: Some(auth_domain_options),
                        validation: None,
                        width: None,
                        help_text: Some("Select the Auth server for this app. Defaults to the current env's Auth.".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "allow_signup".into(),
                        label: "Allow Sign-up".into(),
                        field_type: FormFieldType::Checkbox,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(true)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("When checked, public sign-up is visible. When unchecked, only SSO is available (staff mode).".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/app/setup".into(),
                submit_label: "Install".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "instances" => AdminPage::new("Instances")
            .action(link("Install App", "store"))
            .widget(table_with_actions(vec![
                cols("app_name", "App"),
                cols("status", "Status"),
                cols("domain", "Domain"),
            ], "/instances", vec![
                row_action("View", "instances/{id}"),
                row_action("Uninstall", "uninstall?instance_id={id}"),
            ]))
            .build(),
        "uninstall" => AdminPage::new("Uninstall App")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "instance_id".into(),
                        label: "Instance ID".into(),
                        field_type: FormFieldType::Hidden,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/instances/uninstall".into(),
                submit_label: "Confirm Uninstall".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .widget(card("Warning", "Uninstalling will permanently remove this app instance, its domain, and OAuth client. This action cannot be undone."))
            .build(),
 // ── Policy Studio (design , story 28.14) — shared page
 // constructors; the guard guarantees `Some` ( dispatch).
        p if sentin8::rfw::policy_page("sentin8:app", p).is_some() => sentin8::rfw
            ::policy_page("sentin8:app", p)
            .expect("policy_page checked in guard")
            .build(),
        _ => return Err((axum::http::StatusCode::NOT_FOUND, format!("Unknown admin UI page: {page}"))),
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// `GET /v1/admin/{resource}` — returns a JSON array of admin data rows.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = serde_json::Value),
        (status = 403, description = "Caller lacks an app read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:app:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::require_any_scope(
        &state.config,
        &headers,
        &[
            "sentin8:app:store:read",
            "sentin8:app:store:admin",
            "sentin8:sys:admin",
            "sentin8:sys:org:admin",
            "sentin8:sys:env:admin",
        ],
    )
    .await?;
    // Fix A : target_env_id is REQUIRED — no fallback to the token env.
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing target_env_id".into(),
            )
        })?;
    // ( rule 2): set RLS context
    // and run the data queries on the SAME pooled connection. The previous
    // shape set context on one connection (org lookup) then queried
    // `state.pool` — a different connection with no context — so FORCE RLS
    // hid every row and the store page rendered "No data" right after a
    // successful create.
    // Explicit transaction ( rule 2): the context is transaction-local
    // and each pooled statement runs in its OWN implicit transaction — the
    // context-set and the queries must share ONE transaction.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::handlers::set_tenant_context_for_admin(&mut tx, env_id).await;
    let org_id: uuid::Uuid =
        sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
            .bind(env_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
            .unwrap_or(sentin8::config::SYSTEM_ORG_ID);
    let rows: Vec<serde_json::Value> = match resource.as_str() {
 // Visibility is enforced by the visibility-scoped RLS policy 
 // — no manual visibility filter here.
        "store" => sqlx::query("SELECT id::text, app_name, app_slug, description, status, backend_url FROM store_listings ORDER BY created_at DESC LIMIT 100")
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "app_name": row.get::<Option<String>, &str>("app_name").unwrap_or_default(),
                "app_slug": row.get::<Option<String>, &str>("app_slug").unwrap_or_default(),
                "description": row.get::<Option<String>, &str>("description").unwrap_or_default(),
                "status": row.get::<Option<String>, &str>("status").unwrap_or_default(),
                "backend_url": row.get::<Option<String>, &str>("backend_url").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        "instances" => sqlx::query("SELECT id::text, instance_name, status, hostname FROM sys.app_instances WHERE org_id = $1 AND env_id = $2 ORDER BY created_at DESC LIMIT 100")
            .bind(org_id).bind(env_id)
            .fetch_all(&mut *tx).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "app_name": row.get::<Option<String>, &str>("instance_name").unwrap_or_default(),
                "status": row.get::<Option<String>, &str>("status").unwrap_or_default(),
                "domain": row.get::<Option<String>, &str>("hostname").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        _ => vec![],
    };
    Ok(Json(serde_json::Value::Array(rows)))
}

/// `POST /v1/admin/instances/uninstall` — uninstall an app instance.
/// Body: `{ "instance_id": "uuid" }`. Deletes the instance if it belongs
/// to the caller's org/env (RLS-enforced).
#[utoipa::path(
    post,
    path = "/v1/admin/instances/uninstall",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Instance uninstalled (RLS-own check enforced)", body = serde_json::Value),
        (status = 403, description = "Caller lacks an app admin scope"),
        (status = 404, description = "Unknown instance"),
    ),
    security(("sentin8:app:admin" = [])),
    tag = "app",
)]
pub async fn uninstall_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::require_any_scope(
        &state.config,
        &headers,
        &[
            "sentin8:app:store:admin",
            "sentin8:sys:admin",
            "sentin8:sys:org:admin",
            "sentin8:sys:env:admin",
        ],
    )
    .await?;
    // Fix A : target_env_id is REQUIRED.
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing target_env_id".into(),
            )
        })?;
    let org_id: uuid::Uuid = {
        // Same-connection tenant context : the sys_environments_select
        // RLS policy gates on sentin8_context_initialized — a bare-pool
        // SELECT returns 0 rows under FORCE RLS and the fallback would
        // silently substitute SYSTEM_ORG_ID (breaking the RLS-scoped delete).
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        crate::handlers::set_tenant_context_for_admin(&mut tx, env_id).await;
        let org: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT org_id FROM sys.environments WHERE id = $1")
                .bind(env_id)
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten();
        tx.commit()
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        org.unwrap_or(sentin8::config::SYSTEM_ORG_ID)
    };
    let instance_id = body.get("instance_id").and_then(|v| v.as_str()).ok_or((
        axum::http::StatusCode::BAD_REQUEST,
        "missing instance_id".into(),
    ))?;

    let deleted = {
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        crate::handlers::set_tenant_context_for_admin(&mut tx, env_id).await;
        let res = sqlx::query(
            "DELETE FROM sys.app_instances WHERE id = $1 AND org_id = $2 AND env_id = $3 RETURNING app_slug",
        )
        .bind(instance_id)
        .bind(org_id)
        .bind(env_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("db error: {e}"),
            )
        })?;
        let deleted = res.map(|r| r.get::<String, _>("app_slug"));
        tx.commit()
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        deleted
    };
    if deleted.is_none() {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            format!("instance {instance_id} not found in env"),
        ));
    }
    crate::handlers::emit_admin_event(
        &state.pool,
        env_id,
        "sentin8:app:instance:uninstalled",
        serde_json::json!({ "id": instance_id }),
    )
    .await;
    crate::handlers::write_admin_audit(
        &state.pool,
        env_id,
        "instance.uninstall",
        "sys_app_instance",
        instance_id,
    )
    .await;

    Ok(Json(serde_json::json!({
        "response_type": "redirect",
        "route": "instances"
    })))
}

fn _col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
fn _table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn _row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("0xe145".into()),
    }
}
