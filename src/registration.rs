// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:App.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.
//! See .

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, CrossSchemaGrant, PgRole, PolicySetDecl, Registration,
    RelationDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:app:read,sentin8:app:write",
    role: "sentin8_app_service",
    bypass_rls: false,
    database: "sentin8",
    // Declared platform-registry reads/writes (DBX ):
    // app provisions app instances into `sys.app_instances` (platform-owned
    // registry, DML granted by sys init.sql) and resolves tenant slugs/
    // domains/branding from `sys.environments` / `sys.organizations` /
    // `sys.branding` for hostname + theming derivation. SELECT-only except
    // `sys.app_instances` (the instance CRUD is app's domain operation).
    cross_schema_grants: &[
        CrossSchemaGrant {
            schema: "sys",
            table: "app_instances",
            privilege: "SELECT",
        },
        CrossSchemaGrant {
            schema: "sys",
            table: "environments",
            privilege: "SELECT",
        },
        CrossSchemaGrant {
            schema: "sys",
            table: "organizations",
            privilege: "SELECT",
        },
        CrossSchemaGrant {
            schema: "sys",
            table: "branding",
            privilege: "SELECT",
        },
    ],
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "store",
        label: "Store",
        ui_endpoint: "/v1/admin/ui/store",
        data_endpoint: "/v1/admin/store",
        icon: "0xe60a",
    },
    AdminUiPage {
        route: "instances",
        label: "Instances",
        ui_endpoint: "/v1/admin/ui/instances",
        data_endpoint: "/v1/admin/instances",
        icon: "0xe1cb",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");
const SQL_2_LISTING_VERSIONING: &str = include_str!("../sql/v2_listing_versioning.sql");
const SQL_3_LISTING_MEDIA_CATEGORIES: &str = include_str!("../sql/v3_listing_media_categories.sql");

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi` sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::AppOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Default declarative policy sets (Sentin8:Policy design /):
/// action-granular scope permits over the LIVE effective scope set. Seeded
/// `origin='platform'`, `mode='enforced'` (decision - step 5 is
/// the only gate; shadow is the emergency one-UPDATE rollback lever only).
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:app over the LIVE effective scope set. Enforced - step 5 is the only gate.",
        policies: "permit(principal, action == Action::\"sentin8:app:instances:read\", resource) when { principal.scopes.contains(\"sentin8:app:instances:read\") };\npermit(principal, action == Action::\"sentin8:app:instances:read\", resource) when { principal.scopes.contains(\"sentin8:app:instances:admin\") };\npermit(principal, action == Action::\"sentin8:app:instances:write\", resource) when { principal.scopes.contains(\"sentin8:app:instances:write\") };\npermit(principal, action == Action::\"sentin8:app:instances:write\", resource) when { principal.scopes.contains(\"sentin8:app:instances:admin\") };\npermit(principal, action == Action::\"sentin8:app:instances:admin\", resource) when { principal.scopes.contains(\"sentin8:app:instances:admin\") };\npermit(principal, action == Action::\"sentin8:app:store:read\", resource) when { principal.scopes.contains(\"sentin8:app:store:read\") };\npermit(principal, action == Action::\"sentin8:app:store:read\", resource) when { principal.scopes.contains(\"sentin8:app:store:admin\") };\npermit(principal, action == Action::\"sentin8:app:store:admin\", resource) when { principal.scopes.contains(\"sentin8:app:store:admin\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples (design ) - none declared by this
/// service today; env admins author their own graph via the admin API.
const RELATIONS: &[RelationDecl] = &[];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants (-AUTH-2, self-registration ): this
/// service's own `certless:<workload>` rows, upserted by `vertical enroll`.
/// The static auth seed is retired - this declaration is the ONLY
/// provisioning path ( "DCR is dynamic").
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "app-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    // : the provisioning workload calls auth's membership API for
    // instance group/role setup (`/v1/admin/provision/*`).
    sentin8::registration::M2mGrant {
        workload: "sentin8:app",
        scopes: &[
            "sentin8:bus:consume",
            "sentin8:bus:produce",
            "sentin8:stat:measure",
            "sentin8:auth:admin:write",
        ],
    },
    sentin8::registration::M2mGrant {
        workload: "app",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:app-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "app-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-app-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:app",
        subdomain: "app",
        health_path: "/v1/health",
        admin_scopes: &[
            // Granular vocabulary: handlers gate
            // store management on `sentin8:app:store:*` and instances on
            // `sentin8:app:instances:*` - the bare `sentin8:app:admin` scope is accepted by
            // no handler.
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:admin"),
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:store:admin"),
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:store:read"),
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:instances:write"),
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:instances:read"),
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:instances:admin"),
            // Policy-admin surface (policy design ; per-service scope).
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:policy:read"),
            AdminScope::Tuple("sentin8:app:admin", "sentin8:app:policy:write"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "App",
            icon: "0xe08f",
            service_flag: "app",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![
            SqlMigration {
                version: 1,
                name: "init",
                sql: SQL_1_INIT,
            },
            SqlMigration {
                version: 2,
                name: "listing_versioning",
                sql: SQL_2_LISTING_VERSIONING,
            },
            SqlMigration {
                version: 3,
                name: "listing_media_categories",
                sql: SQL_3_LISTING_MEDIA_CATEGORIES,
            },
        ],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
