package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
	versionpkg "github.com/8linkz/packmon/internal/version"

	_ "modernc.org/sqlite"
)

// Store is a local SQLite implementation that covers the subset of
// db.Store needed for offline scanning: FindVulnerabilities,
// FindMalicious, and Close. It does NOT implement the full Store
// interface -- server-only methods (feed writes, queue, admin, etc.)
// are not present.
type Store struct {
	db     *sql.DB
	dbPath string
}

// New opens (or creates) the SQLite database at dbPath and ensures the
// schema tables exist. The parent directory is created if it does not
// exist. The returned Store is safe for concurrent use.
func New(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("sqlite: create directory %s: %w", dir, err)
	}

	// modernc.org/sqlite uses the driver name "sqlite".
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %s: %w", dbPath, err)
	}

	// Limit to one writer at a time (SQLite concurrency model).
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		closeSilently(db)
		return nil, fmt.Errorf("sqlite: ping %s: %w", dbPath, err)
	}

	// Create schema tables (idempotent).
	if _, err := db.Exec(schemaSQL); err != nil {
		closeSilently(db)
		return nil, fmt.Errorf("sqlite: create schema: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		closeSilently(db)
		return nil, err
	}

	return &Store{db: db, dbPath: dbPath}, nil
}

// DB returns the underlying *sql.DB for use by sync and history code
// within this package.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Path returns the filesystem path of the database file.
func (s *Store) Path() string {
	return s.dbPath
}

// Close releases the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// FindVulnerabilities returns all vulnerability findings that match the
// given ecosystem and package name. Version matching is done in
// application code against the stored version_ranges JSON.
func (s *Store) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	const query = `
		SELECT id, ecosystem, name, version_ranges, severity,
		       cvss_score, epss_score, cisa_kev, summary
		FROM vulnerabilities_local
		WHERE ecosystem = ? AND name = ?`

	rows, err := s.db.QueryContext(ctx, query, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query vulnerabilities: %w", err)
	}
	defer closeSilently(rows)

	var findings []domain.Finding
	for rows.Next() {
		var (
			id         string
			eco        string
			pkg        string
			rangesJSON sql.NullString
			severity   string
			cvssScore  sql.NullFloat64
			epssScore  sql.NullFloat64
			cisaKEV    int
			summary    sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &rangesJSON, &severity,
			&cvssScore, &epssScore, &cisaKEV, &summary); err != nil {
			return nil, fmt.Errorf("sqlite: scan vulnerability row: %w", err)
		}

		// Check whether the requested version falls within any affected range.
		// Uses the shared version package which handles both full OSV and
		// flat range formats, and dispatches to ecosystem-specific comparators.
		if version != "" && rangesJSON.Valid && rangesJSON.String != "" {
			affected, matchErr := versionpkg.VersionAffected(version, rangesJSON.String, "", eco)
			if matchErr != nil {
				// If we cannot parse ranges, treat the package as affected
				// (fail-safe: do not silently hide vulnerabilities).
				_ = matchErr
			} else if !affected {
				continue
			}
		}

		title := summary.String
		if title == "" {
			title = id
		}

		findings = append(findings, domain.Finding{
			Name:       pkg,
			Version:    version,
			Ecosystem:  domain.Ecosystem(eco),
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.Severity(severity),
			AdvisoryID: id,
			Title:      title,
			Source:     "local",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate vulnerability rows: %w", err)
	}

	return findings, nil
}

// FindMalicious returns all malicious-package findings that match the
// given ecosystem and package name.
func (s *Store) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	const query = `
		SELECT id, ecosystem, name, versions, risk_type, severity, summary
		FROM malicious_local
		WHERE ecosystem = ? AND name = ?`

	rows, err := s.db.QueryContext(ctx, query, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query malicious: %w", err)
	}
	defer closeSilently(rows)

	var findings []domain.Finding
	for rows.Next() {
		var (
			id          string
			eco         string
			pkg         string
			versionsRaw sql.NullString
			riskType    string
			severity    string
			summary     sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &versionsRaw, &riskType,
			&severity, &summary); err != nil {
			return nil, fmt.Errorf("sqlite: scan malicious row: %w", err)
		}

		// If version is specified and the finding has a versions list, check membership.
		if version != "" && versionsRaw.Valid && versionsRaw.String != "" {
			var versions []string
			if err := json.Unmarshal([]byte(versionsRaw.String), &versions); err == nil && len(versions) > 0 {
				found := false
				for _, v := range versions {
					if v == version {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
		}

		title := summary.String
		if title == "" {
			title = fmt.Sprintf("malicious package: %s (%s)", pkg, riskType)
		}

		findings = append(findings, domain.Finding{
			Name:      pkg,
			Ecosystem: domain.Ecosystem(eco),
			Type:      domain.FindingTypeMalicious,
			Severity:  domain.Severity(severity),
			Title:     title,
			RiskType:  riskType,
			Source:    "local",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate malicious rows: %w", err)
	}

	return findings, nil
}

// GetSyncMeta reads a value from the sync_meta table.
func (s *Store) GetSyncMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM sync_meta WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("sqlite: get sync meta %q: %w", key, err)
	}
	return value, nil
}

// SetSyncMeta writes a key-value pair into the sync_meta table.
func (s *Store) SetSyncMeta(ctx context.Context, key, value string) error {
	const upsert = `INSERT INTO sync_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	_, err := s.db.ExecContext(ctx, upsert, key, value)
	if err != nil {
		return fmt.Errorf("sqlite: set sync meta %q: %w", key, err)
	}
	return nil
}

// Version matching is now handled by the shared versionpkg
// (github.com/8linkz/packmon/internal/version) package. The local
// duplicated helpers have been removed.

func migrateSchema(db *sql.DB) error {
	hasRowKey, err := tableHasColumn(db, "vulnerabilities_local", "row_key")
	if err != nil {
		return err
	}
	if hasRowKey {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("sqlite: begin schema migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	statements := []string{
		`ALTER TABLE vulnerabilities_local RENAME TO vulnerabilities_local_old`,
		`CREATE TABLE vulnerabilities_local (
			row_key        TEXT PRIMARY KEY,
			id             TEXT NOT NULL,
			ecosystem      TEXT NOT NULL,
			name           TEXT NOT NULL,
			version_ranges TEXT,
			severity       TEXT NOT NULL,
			cvss_score     REAL,
			epss_score     REAL,
			cisa_kev       INTEGER DEFAULT 0,
			summary        TEXT
		)`,
		`INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, cisa_kev, summary)
		 SELECT id || '|' || ecosystem || '|' || name, id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, cisa_kev, summary
		 FROM vulnerabilities_local_old`,
		`DROP TABLE vulnerabilities_local_old`,
		`CREATE INDEX idx_vuln_eco_name ON vulnerabilities_local(ecosystem, name)`,
		`CREATE INDEX idx_vuln_id ON vulnerabilities_local(id)`,
	}

	for _, stmt := range statements {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite: migrate schema: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit schema migration: %w", err)
	}
	return nil
}

func tableHasColumn(db *sql.DB, tableName, columnName string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + tableName + `)`)
	if err != nil {
		return false, fmt.Errorf("sqlite: inspect table %s: %w", tableName, err)
	}
	defer closeSilently(rows)

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return false, fmt.Errorf("sqlite: scan table info for %s: %w", tableName, err)
		}
		if strings.EqualFold(name, columnName) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("sqlite: iterate table info for %s: %w", tableName, err)
	}
	return false, nil
}
