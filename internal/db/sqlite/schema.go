// Package sqlite implements a local SQLite store for offline scanning.
// It uses modernc.org/sqlite (pure Go, no CGO) so the packmon binary
// can be cross-compiled for all target platforms without a C toolchain.
package sqlite

// schemaSQL is the DDL executed on first open (IF NOT EXISTS is safe for
// repeated calls). The schema is a compact subset of the server-side
// PostgreSQL schema -- see Phase 1, DE-17 for the parity matrix.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS vulnerabilities_local (
	row_key        TEXT PRIMARY KEY,
	id             TEXT NOT NULL,
	ecosystem      TEXT NOT NULL,
	name           TEXT NOT NULL,
	version_ranges TEXT,                  -- JSON string
	versions_affected TEXT,              -- JSON string
	references_json TEXT,                 -- JSON string
	severity       TEXT NOT NULL,
	cvss_score     REAL,
	epss_score     REAL,
	cisa_kev       INTEGER DEFAULT 0,
	summary        TEXT
);

CREATE INDEX IF NOT EXISTS idx_vuln_eco_name
	ON vulnerabilities_local(ecosystem, name);

CREATE INDEX IF NOT EXISTS idx_vuln_id
	ON vulnerabilities_local(id);

CREATE TABLE IF NOT EXISTS malicious_local (
	id        TEXT PRIMARY KEY,
	ecosystem TEXT NOT NULL,
	name      TEXT NOT NULL,
	versions  TEXT,                        -- JSON string, NULL = all versions
	reference_urls TEXT,                   -- JSON string
	risk_type TEXT NOT NULL,
	severity  TEXT NOT NULL DEFAULT 'CRITICAL',
	summary   TEXT
);

CREATE INDEX IF NOT EXISTS idx_mal_eco_name
	ON malicious_local(ecosystem, name);

CREATE TABLE IF NOT EXISTS reputation_findings_local (
	id        TEXT PRIMARY KEY,
	ecosystem TEXT NOT NULL,
	name      TEXT NOT NULL,
	version   TEXT NOT NULL,
	type      TEXT NOT NULL,
	risk_type TEXT NOT NULL,
	severity  TEXT NOT NULL DEFAULT 'CRITICAL',
	summary   TEXT
);

CREATE INDEX IF NOT EXISTS idx_rep_eco_name
	ON reputation_findings_local(ecosystem, name);

CREATE TABLE IF NOT EXISTS lifecycle_releases_local (
	id                TEXT PRIMARY KEY,
	ecosystem         TEXT NOT NULL,
	name              TEXT NOT NULL,
	product_slug      TEXT NOT NULL,
	product_label     TEXT NOT NULL DEFAULT '',
	cycle             TEXT NOT NULL,
	latest            TEXT NOT NULL DEFAULT '',
	release_date      TEXT,
	is_lts            INTEGER NOT NULL DEFAULT 0,
	lts_from          TEXT,
	is_eoas           INTEGER NOT NULL DEFAULT 0,
	eoas_from         TEXT,
	is_eol            INTEGER NOT NULL DEFAULT 0,
	eol_from          TEXT,
	is_discontinued   INTEGER NOT NULL DEFAULT 0,
	discontinued_from TEXT,
	is_eoes           INTEGER,
	eoes_from         TEXT,
	is_maintained     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS lifecycle_releases_local_lookup_idx
	ON lifecycle_releases_local(ecosystem, name);

CREATE TABLE IF NOT EXISTS sync_meta (
	key   TEXT PRIMARY KEY,
	value TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	repo_name          TEXT,
	branch             TEXT,
	scanned_at         TEXT NOT NULL,      -- ISO 8601
	packages_count     INTEGER,
	findings_count     INTEGER,
	finding_ids        TEXT,               -- JSON array of finding IDs
	finding_severities TEXT                -- JSON array of severity strings
);
`
