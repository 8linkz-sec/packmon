CREATE TABLE lifecycle_products (
    product_slug TEXT PRIMARY KEY,
    -- Display label from endoflife.date result[].label; the API slug lives in product_slug.
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'endoflife.date',
    identifiers JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE lifecycle_releases (
    product_slug TEXT NOT NULL REFERENCES lifecycle_products(product_slug) ON DELETE CASCADE,
    cycle TEXT NOT NULL,
    latest TEXT NOT NULL DEFAULT '',
    release_date DATE,
    is_lts BOOLEAN NOT NULL DEFAULT false,
    lts_from DATE,
    is_eoas BOOLEAN NOT NULL DEFAULT false,
    eoas_from DATE,
    is_eol BOOLEAN NOT NULL DEFAULT false,
    eol_from DATE,
    is_discontinued BOOLEAN NOT NULL DEFAULT false,
    discontinued_from DATE,
    is_eoes BOOLEAN,
    eoes_from DATE,
    is_maintained BOOLEAN NOT NULL DEFAULT false,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (product_slug, cycle)
);

CREATE TABLE lifecycle_package_map (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    product_slug TEXT NOT NULL REFERENCES lifecycle_products(product_slug) ON DELETE CASCADE,
    purl_type TEXT NOT NULL DEFAULT '',
    purl_namespace TEXT NOT NULL DEFAULT '',
    purl_name TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'endoflife.date',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ecosystem, name, product_slug)
);

CREATE INDEX lifecycle_package_map_lookup_idx
    ON lifecycle_package_map(ecosystem, name);
