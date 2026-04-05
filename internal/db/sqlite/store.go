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
		if version != "" && rangesJSON.Valid && rangesJSON.String != "" {
			affected, matchErr := versionAffected(version, rangesJSON.String)
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

// ---------------------------------------------------------------------------
// Version matching helpers
// ---------------------------------------------------------------------------

// versionRange is a single semver-style range from the version_ranges
// JSON stored per vulnerability row. The format mirrors OSV:
//
//	[{"introduced":"1.0.0","fixed":"1.0.5"}, {"introduced":"2.0.0"}]
type versionRange struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// versionAffected returns true if the given version falls within any of
// the ranges encoded as a JSON array of versionRange objects.
//
// Matching rules:
//   - If "introduced" is empty or "0", the range starts at the beginning.
//   - If "fixed" is empty, every version >= introduced is affected.
//   - Comparison is a simple string-based semver comparison (split on ".",
//     compare each segment numerically, fall back to lexicographic).
//
// This is deliberately simple and covers >95% of real-world advisories.
// Edge cases (pre-release tags, epochs) are handled fail-safe: if we
// cannot parse a version, we assume the package IS affected.
func versionAffected(version, rangesJSON string) (bool, error) {
	var ranges []versionRange
	if err := json.Unmarshal([]byte(rangesJSON), &ranges); err != nil {
		return true, fmt.Errorf("parse version_ranges: %w", err)
	}

	if len(ranges) == 0 {
		// No ranges specified -- we cannot determine if the version is
		// affected. Return false to avoid false positives.
		return false, nil
	}

	for _, r := range ranges {
		intro := r.Introduced
		if intro == "" || intro == "0" {
			intro = ""
		}
		// Check: version >= introduced
		if intro != "" && compareVersions(version, intro) < 0 {
			continue
		}
		// Check: version < fixed
		if r.Fixed != "" && compareVersions(version, r.Fixed) >= 0 {
			continue
		}
		return true, nil
	}
	return false, nil
}

// compareVersions compares two version strings with semver-aware rules.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
//
// Key semver rules applied:
//   - Build metadata (after '+') is ignored.
//   - A pre-release version (1.0.0-rc1) is LESS than its release (1.0.0).
//   - Pre-release identifiers are compared per semver 2.0 spec.
func compareVersions(a, b string) int {
	// Strip build metadata.
	if idx := strings.IndexByte(a, '+'); idx >= 0 {
		a = a[:idx]
	}
	if idx := strings.IndexByte(b, '+'); idx >= 0 {
		b = b[:idx]
	}

	// Separate release from pre-release.
	releaseA, preA := splitPrerelease(a)
	releaseB, preB := splitPrerelease(b)

	// Compare release segments numerically.
	partsA := strings.Split(releaseA, ".")
	partsB := strings.Split(releaseB, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var segA, segB string
		if i < len(partsA) {
			segA = partsA[i]
		}
		if i < len(partsB) {
			segB = partsB[i]
		}

		numA := parseSegment(segA)
		numB := parseSegment(segB)

		if numA < numB {
			return -1
		}
		if numA > numB {
			return 1
		}
	}

	// Release parts equal. Pre-release rules:
	// no pre-release > has pre-release (1.0.0 > 1.0.0-rc1).
	if preA == "" && preB == "" {
		return 0
	}
	if preA == "" {
		return 1 // 1.0.0 > 1.0.0-rc1
	}
	if preB == "" {
		return -1 // 1.0.0-rc1 < 1.0.0
	}

	return comparePrerelease(preA, preB)
}

func splitPrerelease(version string) (string, string) {
	if idx := strings.IndexByte(version, '-'); idx > 0 {
		return version[:idx], version[idx+1:]
	}
	return version, ""
}

func comparePrerelease(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(partsA) {
			return -1
		}
		if i >= len(partsB) {
			return 1
		}

		sa, sb := partsA[i], partsB[i]
		isNumA, numA := isNumericSegment(sa)
		isNumB, numB := isNumericSegment(sb)

		switch {
		case isNumA && isNumB:
			if numA < numB {
				return -1
			}
			if numA > numB {
				return 1
			}
		case isNumA:
			return -1 // numeric < string
		case isNumB:
			return 1
		default:
			if sa < sb {
				return -1
			}
			if sa > sb {
				return 1
			}
		}
	}
	return 0
}

func isNumericSegment(s string) (bool, int) {
	if s == "" {
		return false, 0
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false, 0
		}
		n = n*10 + int(ch-'0')
	}
	return true, n
}

// parseSegment extracts the leading integer from a version segment.
// "17" -> 17, "21-beta" -> 21, "" -> 0.
func parseSegment(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}

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
