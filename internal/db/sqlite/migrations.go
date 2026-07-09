package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

func migrateSchema(db *sql.DB) error {
	if err := migrateVulnerabilityRowKeys(db); err != nil {
		return err
	}
	if err := ensureVulnerabilityLocalColumns(db); err != nil {
		return err
	}
	if err := ensureMaliciousLocalColumns(db); err != nil {
		return err
	}
	if err := ensureScanHistorySchema(db); err != nil {
		return err
	}
	if err := normalizeExistingCaseInsensitivePackageNames(db); err != nil {
		return err
	}

	return nil
}

func migrateVulnerabilityRowKeys(db *sql.DB) error {
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
			versions_affected TEXT,
			references_json TEXT,
			severity       TEXT NOT NULL,
			cvss_score     REAL,
			epss_score     REAL,
			epss_percentile REAL,
			cisa_kev       INTEGER DEFAULT 0,
			summary        TEXT,
			source         TEXT NOT NULL DEFAULT 'local'
		)`,
		`INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, references_json, severity, cvss_score, epss_score, epss_percentile, cisa_kev, summary, source)
		 SELECT id || '|' || ecosystem || '|' || name, id, ecosystem, name, version_ranges, '[]', '[]', severity, cvss_score, epss_score, NULL, cisa_kev, summary, 'local'
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

func ensureVulnerabilityLocalColumns(db *sql.DB) error {
	hasVersionsAffected, err := tableHasColumn(db, "vulnerabilities_local", "versions_affected")
	if err != nil {
		return err
	}
	if !hasVersionsAffected {
		if _, err := db.Exec(`ALTER TABLE vulnerabilities_local ADD COLUMN versions_affected TEXT`); err != nil {
			return fmt.Errorf("sqlite: add versions_affected column: %w", err)
		}
	}

	hasVulnReferences, err := tableHasColumn(db, "vulnerabilities_local", "references_json")
	if err != nil {
		return err
	}
	if !hasVulnReferences {
		if _, err := db.Exec(`ALTER TABLE vulnerabilities_local ADD COLUMN references_json TEXT`); err != nil {
			return fmt.Errorf("sqlite: add vulnerability references_json column: %w", err)
		}
	}

	hasEPSSPercentile, err := tableHasColumn(db, "vulnerabilities_local", "epss_percentile")
	if err != nil {
		return err
	}
	if !hasEPSSPercentile {
		if _, err := db.Exec(`ALTER TABLE vulnerabilities_local ADD COLUMN epss_percentile REAL`); err != nil {
			return fmt.Errorf("sqlite: add vulnerability epss_percentile column: %w", err)
		}
	}

	hasVulnSource, err := tableHasColumn(db, "vulnerabilities_local", "source")
	if err != nil {
		return err
	}
	if !hasVulnSource {
		if _, err := db.Exec(`ALTER TABLE vulnerabilities_local ADD COLUMN source TEXT NOT NULL DEFAULT 'local'`); err != nil {
			return fmt.Errorf("sqlite: add vulnerability source column: %w", err)
		}
	}

	return nil
}

func ensureMaliciousLocalColumns(db *sql.DB) error {
	hasMaliciousTable, err := tableExists(db, "malicious_local")
	if err != nil {
		return err
	}
	if !hasMaliciousTable {
		return nil
	}

	hasMaliciousReferences, err := tableHasColumn(db, "malicious_local", "reference_urls")
	if err != nil {
		return err
	}
	if !hasMaliciousReferences {
		if _, err := db.Exec(`ALTER TABLE malicious_local ADD COLUMN reference_urls TEXT`); err != nil {
			return fmt.Errorf("sqlite: add malicious reference_urls column: %w", err)
		}
	}
	hasMaliciousVersionRanges, err := tableHasColumn(db, "malicious_local", "version_ranges")
	if err != nil {
		return err
	}
	if !hasMaliciousVersionRanges {
		if _, err := db.Exec(`ALTER TABLE malicious_local ADD COLUMN version_ranges TEXT`); err != nil {
			return fmt.Errorf("sqlite: add malicious version_ranges column: %w", err)
		}
	}
	hasMaliciousSource, err := tableHasColumn(db, "malicious_local", "source")
	if err != nil {
		return err
	}
	if !hasMaliciousSource {
		if _, err := db.Exec(`ALTER TABLE malicious_local ADD COLUMN source TEXT NOT NULL DEFAULT 'local'`); err != nil {
			return fmt.Errorf("sqlite: add malicious source column: %w", err)
		}
	}

	return nil
}

func ensureScanHistorySchema(db *sql.DB) error {
	hasHistoryTable, err := tableExists(db, "scan_history")
	if err != nil {
		return err
	}
	if !hasHistoryTable {
		return nil
	}

	hasHistoryCommit, err := tableHasColumn(db, "scan_history", "commit")
	if err != nil {
		return err
	}
	if !hasHistoryCommit {
		if _, err := db.Exec(`ALTER TABLE scan_history ADD COLUMN "commit" TEXT`); err != nil {
			return fmt.Errorf("sqlite: add scan history commit column: %w", err)
		}
	}
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_history_repo_scanned_at ON scan_history(repo_name, scanned_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_history_repo_retention ON scan_history(COALESCE(repo_name, ''), scanned_at DESC, id DESC)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite: create scan history index: %w", err)
		}
	}

	return nil
}

type localPackageNameRow struct {
	key       string
	id        string
	ecosystem string
	name      string
}

func normalizeExistingCaseInsensitivePackageNames(db *sql.DB) error {
	if err := normalizeExistingVulnerabilityPackageNames(db); err != nil {
		return err
	}
	for _, table := range []string{"malicious_local", "reputation_findings_local", "lifecycle_releases_local"} {
		if err := normalizeExistingNamedRows(db, table); err != nil {
			return err
		}
	}
	return nil
}

func normalizeExistingVulnerabilityPackageNames(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT row_key, id, ecosystem, name
		FROM vulnerabilities_local
		WHERE lower(ecosystem) IN ('pypi', 'nuget')`)
	if err != nil {
		return fmt.Errorf("sqlite: inspect vulnerability package names: %w", err)
	}

	items := make([]localPackageNameRow, 0)
	for rows.Next() {
		var item localPackageNameRow
		if err := rows.Scan(&item.key, &item.id, &item.ecosystem, &item.name); err != nil {
			ioutils.CloseSilently(rows)
			return fmt.Errorf("sqlite: scan vulnerability package name: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		ioutils.CloseSilently(rows)
		return fmt.Errorf("sqlite: iterate vulnerability package names: %w", err)
	}
	ioutils.CloseSilently(rows)

	for _, item := range items {
		normalized := normalizePackageName(item.ecosystem, item.name)
		if normalized == item.name {
			continue
		}
		rowKey := syncVulnerabilityRowKey(item.id, item.ecosystem, normalized)
		if _, err := db.Exec(`DELETE FROM vulnerabilities_local WHERE row_key = ? AND row_key <> ?`, rowKey, item.key); err != nil {
			return fmt.Errorf("sqlite: remove duplicate normalized vulnerability row: %w", err)
		}
		if _, err := db.Exec(`UPDATE vulnerabilities_local SET row_key = ?, name = ? WHERE row_key = ?`, rowKey, normalized, item.key); err != nil {
			return fmt.Errorf("sqlite: normalize vulnerability package name: %w", err)
		}
	}
	return nil
}

func normalizeExistingNamedRows(db *sql.DB, table string) error {
	exists, err := tableExists(db, table)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	rows, err := db.Query(`
		SELECT id, ecosystem, name
		FROM ` + table + `
		WHERE lower(ecosystem) IN ('pypi', 'nuget')`) // #nosec G202 -- table is chosen from a fixed internal allowlist.
	if err != nil {
		return fmt.Errorf("sqlite: inspect %s package names: %w", table, err)
	}

	items := make([]localPackageNameRow, 0)
	for rows.Next() {
		var item localPackageNameRow
		if err := rows.Scan(&item.id, &item.ecosystem, &item.name); err != nil {
			ioutils.CloseSilently(rows)
			return fmt.Errorf("sqlite: scan %s package name: %w", table, err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		ioutils.CloseSilently(rows)
		return fmt.Errorf("sqlite: iterate %s package names: %w", table, err)
	}
	ioutils.CloseSilently(rows)

	for _, item := range items {
		normalized := normalizePackageName(item.ecosystem, item.name)
		if normalized == item.name {
			continue
		}
		if _, err := db.Exec(`UPDATE `+table+` SET name = ? WHERE id = ?`, normalized, item.id); err != nil { // #nosec G202 -- table is chosen from a fixed internal allowlist.
			return fmt.Errorf("sqlite: normalize %s package name: %w", table, err)
		}
	}
	return nil
}

func tableExists(db *sql.DB, tableName string) (bool, error) {
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, tableName).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: inspect table %s: %w", tableName, err)
	}
	return true, nil
}

func tableHasColumn(db *sql.DB, tableName, columnName string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + tableName + `)`)
	if err != nil {
		return false, fmt.Errorf("sqlite: inspect table %s: %w", tableName, err)
	}
	defer ioutils.CloseSilently(rows)

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
