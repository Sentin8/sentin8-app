-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
-- SPDX-License-Identifier: Apache-2.0

-- ── APP-4: per-listing versioning (version + channel) ───────────────────
-- A listing row is now a (slug, channel) release: `version` orders
-- releases within a channel, `channel` selects the release train
-- (stable|beta|dev). Install resolves the newest published version for
-- the requested channel - a slug alone no longer identifies a row.
-- Greenfield: the v1 slug-only UNIQUE constraint is replaced by
-- UNIQUE (app_slug, channel).

-- Drop the v1 slug-only unique (its name is the auto-generated one from
-- `app_slug TEXT NOT NULL UNIQUE`).
ALTER TABLE app.store_listings DROP CONSTRAINT IF EXISTS store_listings_app_slug_key;

ALTER TABLE app.store_listings
    ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT '0.0.0',
    ADD COLUMN IF NOT EXISTS channel TEXT NOT NULL DEFAULT 'stable'
        CHECK (channel IN ('stable', 'beta', 'dev'));

-- One release per (slug, channel).
ALTER TABLE app.store_listings
    DROP CONSTRAINT IF EXISTS app_store_listings_slug_channel_key;
ALTER TABLE app.store_listings
    ADD CONSTRAINT app_store_listings_slug_channel_key UNIQUE (app_slug, channel);

CREATE INDEX IF NOT EXISTS idx_app_store_listings_channel
    ON app.store_listings (app_slug, channel, version DESC);

-- Install resolution helper: newest published version for a slug on a
-- channel (semver-ordered by string compare of zero-padded segments is
-- NOT used - versions are advisory ordering keys; newest = highest
-- version text among published rows, tie-broken by created_at DESC).
CREATE OR REPLACE FUNCTION app.app_newest_listing(
    p_app_slug TEXT,
    p_channel TEXT
) RETURNS TABLE (
    id UUID,
    app_slug TEXT,
    backend_url TEXT,
    version TEXT
) LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
    RETURN QUERY
        SELECT l.id, l.app_slug, l.backend_url, l.version
          FROM app.store_listings l
         WHERE l.app_slug = p_app_slug
           AND l.channel = p_channel
           AND l.status = 'published'
         ORDER BY l.version DESC, l.created_at DESC
         LIMIT 1;
END;
$fn$;