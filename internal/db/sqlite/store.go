package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz/packmon/internal/db"
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
	ecosystem = strings.TrimSpace(ecosystem)
	name = normalizePackageName(ecosystem, strings.TrimSpace(name))
	version = strings.TrimSpace(version)

	const query = `
		SELECT id, ecosystem, name, version_ranges, versions_affected, references_json, severity,
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
			id           string
			eco          string
			pkg          string
			rangesJSON   sql.NullString
			versionsJSON sql.NullString
			refsJSON     sql.NullString
			severity     string
			cvssScore    sql.NullFloat64
			epssScore    sql.NullFloat64
			cisaKEV      int
			summary      sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &rangesJSON, &versionsJSON, &refsJSON, &severity,
			&cvssScore, &epssScore, &cisaKEV, &summary); err != nil {
			return nil, fmt.Errorf("sqlite: scan vulnerability row: %w", err)
		}

		// Check whether the requested version falls within any affected range.
		// Uses the shared version package which handles both full OSV and
		// flat range formats, and dispatches to ecosystem-specific comparators.
		if version != "" && rangesJSON.Valid && rangesJSON.String != "" {
			affected, matchErr := versionpkg.VersionAffected(version, rangesJSON.String, versionsJSON.String, eco)
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
		resources := resourceLinksFromVulnerabilityReferences(id, refsJSON.String)
		primaryURL := ""
		if len(resources) > 0 {
			primaryURL = resources[0].URL
		}

		findings = append(findings, domain.Finding{
			Name:         pkg,
			Version:      version,
			Ecosystem:    domain.Ecosystem(eco),
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.Severity(severity),
			AdvisoryID:   id,
			Title:        title,
			URL:          primaryURL,
			Resources:    resources,
			FixedVersion: versionpkg.ExtractFixedVersionConstraint(rangesJSON.String),
			Source:       "local",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate vulnerability rows: %w", err)
	}

	return findings, nil
}

func (s *Store) FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	where, args, versionsByPackage := localPackagePredicate(packages)
	if where == "" {
		return nil, nil
	}

	query := `
		SELECT id, ecosystem, name, version_ranges, versions_affected, references_json, severity,
		       cvss_score, epss_score, cisa_kev, summary
		FROM vulnerabilities_local
		WHERE ` + where // #nosec G202 -- localPackagePredicate uses fixed SQL fragments and bound args.

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query vulnerability batch: %w", err)
	}
	defer closeSilently(rows)

	var findings []domain.Finding
	for rows.Next() {
		var (
			id           string
			eco          string
			pkg          string
			rangesJSON   sql.NullString
			versionsJSON sql.NullString
			refsJSON     sql.NullString
			severity     string
			cvssScore    sql.NullFloat64
			epssScore    sql.NullFloat64
			cisaKEV      int
			summary      sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &rangesJSON, &versionsJSON, &refsJSON, &severity,
			&cvssScore, &epssScore, &cisaKEV, &summary); err != nil {
			return nil, fmt.Errorf("sqlite: scan vulnerability batch row: %w", err)
		}

		versions := versionsByPackage[localPackageKey{ecosystem: eco, name: pkg}]
		if len(versions) == 0 {
			findings = append(findings, localVulnerabilityFinding(id, eco, pkg, "", rangesJSON.String, refsJSON.String, severity, summary.String))
			continue
		}

		for _, version := range versions {
			if rangesJSON.Valid && rangesJSON.String != "" {
				affected, matchErr := versionpkg.VersionAffected(version, rangesJSON.String, versionsJSON.String, eco)
				if matchErr == nil && !affected {
					continue
				}
			}
			findings = append(findings, localVulnerabilityFinding(id, eco, pkg, version, rangesJSON.String, refsJSON.String, severity, summary.String))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate vulnerability batch rows: %w", err)
	}

	return findings, nil
}

func localVulnerabilityFinding(id, ecosystem, name, version, rangesJSON, refsJSON, severity, summary string) domain.Finding {
	title := summary
	if title == "" {
		title = id
	}
	resources := resourceLinksFromVulnerabilityReferences(id, refsJSON)
	primaryURL := ""
	if len(resources) > 0 {
		primaryURL = resources[0].URL
	}
	return domain.Finding{
		Name:         name,
		Version:      version,
		Ecosystem:    domain.Ecosystem(ecosystem),
		Type:         domain.FindingTypeVulnerability,
		Severity:     domain.Severity(severity),
		AdvisoryID:   id,
		Title:        title,
		URL:          primaryURL,
		Resources:    resources,
		FixedVersion: versionpkg.ExtractFixedVersionConstraint(rangesJSON),
		Source:       "local",
	}
}

// FindMalicious returns all malicious-package findings that match the
// given ecosystem and package name.
func (s *Store) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	ecosystem = strings.TrimSpace(ecosystem)
	name = normalizePackageName(ecosystem, strings.TrimSpace(name))
	version = strings.TrimSpace(version)

	const query = `
		SELECT id, ecosystem, name, versions, reference_urls, risk_type, severity, summary
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
			id            string
			eco           string
			pkg           string
			versionsRaw   sql.NullString
			referencesRaw sql.NullString
			riskType      string
			severity      string
			summary       sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &versionsRaw, &referencesRaw, &riskType,
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
			Name:       pkg,
			Ecosystem:  domain.Ecosystem(eco),
			Type:       domain.FindingTypeMalicious,
			Severity:   domain.Severity(severity),
			AdvisoryID: id,
			Title:      title,
			URL:        firstURLFromJSON(referencesRaw.String),
			RiskType:   riskType,
			Source:     "local",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate malicious rows: %w", err)
	}

	reputationFindings, err := s.findReputationFindings(ctx, ecosystem, name, version)
	if err != nil {
		return nil, err
	}
	findings = append(findings, reputationFindings...)

	return findings, nil
}

func (s *Store) FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	where, args, versionsByPackage := localPackagePredicate(packages)
	if where == "" {
		return nil, nil
	}

	query := `
		SELECT id, ecosystem, name, versions, reference_urls, risk_type, severity, summary
		FROM malicious_local
		WHERE ` + where // #nosec G202 -- localPackagePredicate uses fixed SQL fragments and bound args.

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query malicious batch: %w", err)
	}
	defer closeSilently(rows)

	var findings []domain.Finding
	for rows.Next() {
		var (
			id            string
			eco           string
			pkg           string
			versionsRaw   sql.NullString
			referencesRaw sql.NullString
			riskType      string
			severity      string
			summary       sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &versionsRaw, &referencesRaw, &riskType,
			&severity, &summary); err != nil {
			return nil, fmt.Errorf("sqlite: scan malicious batch row: %w", err)
		}

		requestedVersions := versionsByPackage[localPackageKey{ecosystem: eco, name: pkg}]
		if len(requestedVersions) == 0 {
			findings = append(findings, localMaliciousFinding(id, eco, pkg, "", referencesRaw.String, riskType, severity, summary.String))
			continue
		}

		var findingVersions []string
		hasVersionList := false
		if versionsRaw.Valid && strings.TrimSpace(versionsRaw.String) != "" {
			if err := json.Unmarshal([]byte(versionsRaw.String), &findingVersions); err == nil && len(findingVersions) > 0 {
				hasVersionList = true
			}
		}

		for _, version := range requestedVersions {
			if hasVersionList && !containsString(findingVersions, version) {
				continue
			}
			findings = append(findings, localMaliciousFinding(id, eco, pkg, version, referencesRaw.String, riskType, severity, summary.String))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate malicious batch rows: %w", err)
	}

	reputationFindings, err := s.findReputationFindingsBatch(ctx, where, args, versionsByPackage)
	if err != nil {
		return nil, err
	}
	findings = append(findings, reputationFindings...)

	return findings, nil
}

func localMaliciousFinding(id, ecosystem, name, version, referencesRaw, riskType, severity, summary string) domain.Finding {
	title := summary
	if title == "" {
		title = fmt.Sprintf("malicious package: %s (%s)", name, riskType)
	}
	return domain.Finding{
		Name:       name,
		Version:    version,
		Ecosystem:  domain.Ecosystem(ecosystem),
		Type:       domain.FindingTypeMalicious,
		Severity:   domain.Severity(severity),
		AdvisoryID: id,
		Title:      title,
		URL:        firstURLFromJSON(referencesRaw),
		RiskType:   riskType,
		Source:     "local",
	}
}

func (s *Store) FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error) {
	if source != "" && source != "reversinglabs" {
		return nil, nil
	}
	return s.queryReputationFindings(ctx, ecosystem, name, "")
}

func (s *Store) findReputationFindings(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	if version == "" {
		return nil, nil
	}
	return s.queryReputationFindings(ctx, ecosystem, name, version)
}

func (s *Store) queryReputationFindings(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	ecosystem = strings.TrimSpace(ecosystem)
	name = normalizePackageName(ecosystem, strings.TrimSpace(name))
	version = strings.TrimSpace(version)

	query := `
		SELECT id, ecosystem, name, version, type, risk_type, severity, summary
		FROM reputation_findings_local
		WHERE ecosystem = ? AND name = ?`
	args := []any{ecosystem, name}
	if version != "" {
		query += ` AND version = ?`
		args = append(args, version)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query reputation findings: %w", err)
	}
	defer closeSilently(rows)

	var findings []domain.Finding
	for rows.Next() {
		var (
			id       string
			eco      string
			pkg      string
			ver      string
			typ      string
			riskType string
			severity string
			summary  sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &ver, &typ, &riskType, &severity, &summary); err != nil {
			return nil, fmt.Errorf("sqlite: scan reputation finding row: %w", err)
		}

		title := summary.String
		if title == "" {
			title = id
		}

		findings = append(findings, domain.Finding{
			Name:       pkg,
			Version:    ver,
			Ecosystem:  domain.Ecosystem(eco),
			Type:       domain.FindingType(typ),
			Severity:   domain.Severity(severity),
			AdvisoryID: id,
			Title:      title,
			RiskType:   riskType,
			Source:     "reversinglabs",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate reputation finding rows: %w", err)
	}
	return findings, nil
}

func (s *Store) findReputationFindingsBatch(ctx context.Context, packageWhere string, packageArgs []any, versionsByPackage map[localPackageKey][]string) ([]domain.Finding, error) {
	query := `
		SELECT id, ecosystem, name, version, type, risk_type, severity, summary
		FROM reputation_findings_local
		WHERE ` + packageWhere // #nosec G202 -- packageWhere is produced by localPackagePredicate with bound args.

	rows, err := s.db.QueryContext(ctx, query, packageArgs...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query reputation batch: %w", err)
	}
	defer closeSilently(rows)

	var findings []domain.Finding
	for rows.Next() {
		var (
			id       string
			eco      string
			pkg      string
			ver      string
			typ      string
			riskType string
			severity string
			summary  sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &ver, &typ, &riskType, &severity, &summary); err != nil {
			return nil, fmt.Errorf("sqlite: scan reputation batch row: %w", err)
		}
		if !containsString(versionsByPackage[localPackageKey{ecosystem: eco, name: pkg}], ver) {
			continue
		}

		title := summary.String
		if title == "" {
			title = id
		}
		findings = append(findings, domain.Finding{
			Name:       pkg,
			Version:    ver,
			Ecosystem:  domain.Ecosystem(eco),
			Type:       domain.FindingType(typ),
			Severity:   domain.Severity(severity),
			AdvisoryID: id,
			Title:      title,
			RiskType:   riskType,
			Source:     "reversinglabs",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate reputation batch rows: %w", err)
	}
	return findings, nil
}

type localPackageKey struct {
	ecosystem string
	name      string
}

func localPackagePredicate(packages []db.PackageQuery) (string, []any, map[localPackageKey][]string) {
	if len(packages) == 0 {
		return "", nil, nil
	}
	seen := make(map[localPackageKey]struct{}, len(packages))
	versionsByPackage := make(map[localPackageKey][]string, len(packages))
	clauses := make([]string, 0, len(packages))
	args := make([]any, 0, len(packages)*2)
	for _, pkg := range packages {
		ecosystem := strings.TrimSpace(pkg.Ecosystem)
		name := normalizePackageName(ecosystem, strings.TrimSpace(pkg.Name))
		if ecosystem == "" || name == "" {
			continue
		}
		key := localPackageKey{ecosystem: ecosystem, name: name}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			clauses = append(clauses, `(ecosystem = ? AND name = ?)`)
			args = append(args, ecosystem, name)
		}
		if version := strings.TrimSpace(pkg.Version); version != "" {
			versionsByPackage[key] = append(versionsByPackage[key], version)
		}
	}
	if len(clauses) == 0 {
		return "", nil, nil
	}
	return strings.Join(clauses, " OR "), args, versionsByPackage
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

type localFindingReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func resourceLinksFromVulnerabilityReferences(advisoryID, raw string) []domain.ResourceLink {
	links := make([]domain.ResourceLink, 0)
	if canonical := canonicalResourceLink(advisoryID); canonical.URL != "" {
		links = append(links, canonical)
	}

	if strings.TrimSpace(raw) == "" {
		return links
	}

	var refs []localFindingReference
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return links
	}

	seen := make(map[string]struct{}, len(links)+len(refs))
	for _, link := range links {
		seen[link.URL] = struct{}{}
	}
	for _, ref := range refs {
		if strings.EqualFold(strings.TrimSpace(ref.Type), "PACKAGE") {
			continue
		}
		link := resourceLinkFromURL(ref.URL)
		if link.URL == "" {
			continue
		}
		if _, ok := seen[link.URL]; ok {
			continue
		}
		seen[link.URL] = struct{}{}
		links = append(links, link)
	}
	return links
}

func canonicalResourceLink(advisoryID string) domain.ResourceLink {
	switch {
	case strings.HasPrefix(advisoryID, "GHSA-"):
		return domain.ResourceLink{Label: "GHSA", URL: "https://github.com/advisories/" + advisoryID}
	case strings.HasPrefix(advisoryID, "RUSTSEC-"):
		return domain.ResourceLink{Label: "RustSec", URL: "https://rustsec.org/advisories/" + advisoryID + ".html"}
	case strings.HasPrefix(advisoryID, "CVE-"):
		return domain.ResourceLink{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + advisoryID}
	default:
		return domain.ResourceLink{}
	}
}

func resourceLinkFromURL(raw string) domain.ResourceLink {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return domain.ResourceLink{}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return domain.ResourceLink{}
	}
	host := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "www.")
	switch {
	case host == "github.com" && strings.Contains(strings.ToLower(parsed.EscapedPath()), "/security/advisories/"):
		return domain.ResourceLink{Label: "GHSA", URL: raw}
	case host == "github.com":
		return domain.ResourceLink{Label: "GitHub", URL: raw}
	case host == "nvd.nist.gov":
		return domain.ResourceLink{Label: "NVD", URL: raw}
	case host == "rustsec.org":
		return domain.ResourceLink{Label: "RustSec", URL: raw}
	case host == "osv.dev":
		return domain.ResourceLink{Label: "OSV", URL: raw}
	case host == "cve.org" || host == "cve.mitre.org":
		return domain.ResourceLink{Label: "CVE", URL: raw}
	default:
		return domain.ResourceLink{Label: host, URL: raw}
	}
}

func firstURLFromJSON(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var urls []string
	if err := json.Unmarshal([]byte(raw), &urls); err != nil {
		return ""
	}
	for _, candidate := range urls {
		if link := resourceLinkFromURL(candidate); link.URL != "" {
			return link.URL
		}
	}
	return ""
}

func migrateSchema(db *sql.DB) error {
	hasRowKey, err := tableHasColumn(db, "vulnerabilities_local", "row_key")
	if err != nil {
		return err
	}
	if !hasRowKey {
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
			cisa_kev       INTEGER DEFAULT 0,
			summary        TEXT
		)`,
			`INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, references_json, severity, cvss_score, epss_score, cisa_kev, summary)
		 SELECT id || '|' || ecosystem || '|' || name, id, ecosystem, name, version_ranges, '[]', '[]', severity, cvss_score, epss_score, cisa_kev, summary
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
	}

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

	hasMaliciousTable, err := tableExists(db, "malicious_local")
	if err != nil {
		return err
	}
	if hasMaliciousTable {
		hasMaliciousReferences, err := tableHasColumn(db, "malicious_local", "reference_urls")
		if err != nil {
			return err
		}
		if !hasMaliciousReferences {
			if _, err := db.Exec(`ALTER TABLE malicious_local ADD COLUMN reference_urls TEXT`); err != nil {
				return fmt.Errorf("sqlite: add malicious reference_urls column: %w", err)
			}
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
