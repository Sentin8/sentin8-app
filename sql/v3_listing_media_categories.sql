-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
-- SPDX-License-Identifier: Apache-2.0

-- ── APP-3: listing media + categories ──────────────────────────────────
-- Media: typed entries stored BY REFERENCE - bytes live in Sentin8:Storage
-- under `app/{listing_id}/{role}.{ext}`; the JSONB row holds only the
-- reference (post DESIGN §5 secrets rule analog: no blobs in tables).
-- Categories: a join table keyed by slug so the store can filter; the
-- category vocabulary is free-form (the store UI groups by distinct
-- category).

ALTER TABLE app.store_listings
    ADD COLUMN IF NOT EXISTS media JSONB NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS app.listing_categories (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category    TEXT NOT NULL,
    app_slug    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (category, app_slug)
);

CREATE INDEX IF NOT EXISTS idx_app_listing_categories_cat
    ON app.listing_categories (category);
CREATE INDEX IF NOT EXISTS idx_app_listing_categories_slug
    ON app.listing_categories (app_slug);

ALTER TABLE app.listing_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.listing_categories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS listing_categories_dml ON app.listing_categories;
CREATE POLICY listing_categories_dml ON app.listing_categories
    USING (sentin8_context_initialized())
    WITH CHECK (sentin8_context_initialized());
GRANT SELECT, INSERT, UPDATE, DELETE ON app.listing_categories TO sentin8_app_service;