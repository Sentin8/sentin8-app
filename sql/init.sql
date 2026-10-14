-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:App — app store listings, instances mapping, and audit events.
--
-- Note: Sentin8:App instances are stored in sentin8_sys_app_instances (owned by
-- Sentin8:Sys). The Stat integration columns (sentin8_stat_property_id,
-- sentin8_stat_m2m_client_id) and domain verification columns
-- (domain_verification_token, domain_verified) live on that Sys-owned table.

-- Sentin8:App store listings
CREATE SCHEMA IF NOT EXISTS app;
CREATE TABLE IF NOT EXISTS app.store_listings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name        TEXT NOT NULL,
    app_slug        TEXT NOT NULL UNIQUE,
    description     TEXT,
    backend_url     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'disabled', 'archived')),
    supports_dcr    BOOLEAN NOT NULL DEFAULT false,
    oauth_defaults  JSONB NOT NULL DEFAULT '{}',
    created_by      TEXT NOT NULL DEFAULT '',
    -- Owning user (Sentin8:Auth subject id). Populated from the token `sub` at
    -- create time. Used by visibility-scoped RLS (§4.3a) when visibility =
    -- 'usr' — only this user (+ sys/org/env admins) can see the row.
    usr_id          TEXT NOT NULL DEFAULT '',
    -- Visibility controls which orgs/envs/users can see this listing in
    -- their App Store. 'public' (default) = all orgs and envs; 'env' = only
    -- the owning env; 'usr' = only the owning user (+ sys/org/env admins).
    -- See §4.3a.
    visibility      TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('usr', 'env', 'public')),
    -- Owning env. NULL for 'public'/'usr' listings. Used to scope 'env'
    -- visibility to the creator's env. org_id is NOT stored — it is resolved
    -- from env_id via sentin8_sys_environments at query time (env_id is
    -- globally unique).
    env_id          UUID,
    -- Roles and default signup role for DCR (OAuth client registration).
    roles           JSONB NOT NULL DEFAULT '[]',
    default_signup_role TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_app_store_listings_visibility ON app.store_listings (visibility);
CREATE INDEX IF NOT EXISTS idx_app_store_listings_usr ON app.store_listings (usr_id) WHERE usr_id <> '';

-- RLS: visibility-scoped SELECT policy (§4.3a). Admits sys admin via
-- bypass, org/env admins via context-stamped flags (option a), and the
-- owning user for 'usr'-visibility rows. INSERT/UPDATE/DELETE require the
-- caller to be the owner or a platform admin.
ALTER TABLE app.store_listings ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.store_listings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_store_listings_select ON app.store_listings;
CREATE POLICY app_store_listings_select ON app.store_listings
    FOR SELECT USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR (visibility = 'public')
            OR (visibility = 'env'
                               AND env_id = sentin8_current_env_id())
            OR (visibility = 'usr' AND (
                  usr_id = sentin8_current_subject_id()
                  OR sentin8_is_env_admin()
                ))
        )
    );
DROP POLICY IF EXISTS app_store_listings_insert ON app.store_listings;
CREATE POLICY app_store_listings_insert ON app.store_listings
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR usr_id = sentin8_current_subject_id()
        )
    );
DROP POLICY IF EXISTS app_store_listings_update ON app.store_listings;
CREATE POLICY app_store_listings_update ON app.store_listings
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND (
            sentin8_bypass_rls()
            OR usr_id = sentin8_current_subject_id()
        )
    );
-- No DELETE policy on app.store_listings: listings are archived
-- (status = 'archived' via update_listing paths), never deleted —
-- the former bypass-only policy admitted nothing for any NOBYPASSRLS
-- role and was removed.

-- Sentin8:App instances are stored in sentin8_sys_app_instances (owned by
-- Sentin8:Sys).

-- Sentin8:App audit events
CREATE TABLE IF NOT EXISTS app.audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID,
    actor_user_id       TEXT,
    action              TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id  TEXT,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version      TEXT NOT NULL DEFAULT '1.0'
);

-- ── App-declared security roles (Story: app-declared scopes + roles) ──
-- Each Sentin8:App listing may declare the named security roles it wants to use
-- in the target org/env, plus the scope set each role grants. At install
-- time Sentin8:App provisions these rows directly into `sentin8_auth_roles` so the roles
-- are available before the first user signs up.
--
-- Shape (JSONB):
-- [
--   {
--     "name": "ebank-customer",
--     "description": "Standard banking customer",
--     "scopes": ["bank8:ledger:accounts:read", "bank8:ledger:accounts:write", ...]
--   },
--   {
--     "name": "ebank-teller",
--     "description": "Branch staff",
--     "scopes": ["bank8:ledger:accounts:read", "bank8:ledger:accounts:write", ...]
--   },
--   {
--     "name": "ebank-admin",
--     "description": "Bank administrator",
--     "scopes": ["bank8:ledger:products:read", "bank8:ledger:products:write", ...]
--   }
-- ]
--
-- The frontend can derive a user's role purely from scopes present in the
-- JWT (roles contribute their permissions to the token at issuance), so
-- each role must include a unique role-scope (e.g. "ebank:admin") that the
-- client uses to gate the admin UI. See the EBank listing for the
-- canonical naming convention.

-- ── RLS: app.audit_events (Story 12.4.36) ───────────────────────────
ALTER TABLE app.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS app_audit_select ON app.audit_events;
CREATE POLICY app_audit_select ON app.audit_events FOR SELECT
    USING (sentin8_context_initialized() AND (env_id IS NULL OR env_id = sentin8_current_env_id()));
DROP POLICY IF EXISTS app_audit_insert ON app.audit_events;
CREATE POLICY app_audit_insert ON app.audit_events FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND (env_id IS NULL OR env_id = sentin8_current_env_id()));

-- ── Grants ──

-- sentin8_app_service: DML on all app tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    app.store_listings, app.audit_events
    TO sentin8_app_service;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: app.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("app").
CREATE TABLE IF NOT EXISTS app.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_app_outbox_unrelayed
    ON app.outbox (created_at) WHERE relayed = false;
ALTER TABLE app.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON app.outbox;
CREATE POLICY outbox_select ON app.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON app.outbox;
CREATE POLICY outbox_insert ON app.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON app.outbox;
CREATE POLICY outbox_update ON app.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION app.app_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('app_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON app.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON app.outbox
    FOR EACH ROW
    EXECUTE FUNCTION app.app_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("app").
CREATE TABLE IF NOT EXISTS app.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_app_audit_journal_unpushed
    ON app.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE app.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON app.audit_journal;
CREATE POLICY audit_journal_dml ON app.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned — the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA app TO sentin8_app_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.outbox TO sentin8_app_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO sentin8_app_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.audit_journal TO sentin8_app_service;
