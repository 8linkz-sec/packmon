package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/findinglinks"
	versionpkg "github.com/8linkz-sec/packmon/internal/version"

	_ "modernc.org/sqlite"
)

// Store is a local SQLite implementation that covers the subset of db.Store
// needed for offline scanning and local package views. It does NOT implement
// the full Store interface -- server-only methods (feed writes, queue, admin,
// etc.) are not present.
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
	if err := ensurePrivateSQLiteDatabaseFile(dbPath); err != nil {
		return nil, err
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

	unlockMigration, err := acquireSQLiteMigrationLock(dbPath)
	if err != nil {
		closeSilently(db)
		return nil, err
	}
	defer unlockMigration()

	// Create schema tables (idempotent).
	if _, err := db.Exec(schemaSQL); err != nil {
		closeSilently(db)
		return nil, fmt.Errorf("sqlite: create schema: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		closeSilently(db)
		return nil, err
	}
	if err := restrictSQLiteFilePermissions(dbPath); err != nil {
		closeSilently(db)
		return nil, err
	}

	return &Store{db: db, dbPath: dbPath}, nil
}

var (
	sqliteMigrationLockTimeout      = 5 * time.Second
	sqliteMigrationLockPollInterval = 25 * time.Millisecond
)

func acquireSQLiteMigrationLock(dbPath string) (func(), error) {
	if skipSQLiteMigrationLock(dbPath) {
		return func() {}, nil
	}

	lockPath := dbPath + ".migrate.lock"
	deadline := time.Now().Add(sqliteMigrationLockTimeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- lock path is derived from the local DB path.
		if err == nil {
			unlocked := false
			return func() {
				if unlocked {
					return
				}
				unlocked = true
				closeSilently(file)
				_ = os.Remove(lockPath)
			}, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("sqlite: create migration lock %s: %w", lockPath, err)
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("sqlite: acquire migration lock %s: %w", lockPath, err)
		}
		time.Sleep(sqliteMigrationLockPollInterval)
	}
}

func skipSQLiteMigrationLock(dbPath string) bool {
	return skipSQLiteFilePermissionHardening(dbPath)
}

func ensurePrivateSQLiteDatabaseFile(dbPath string) error {
	if skipSQLiteFilePermissionHardening(dbPath) {
		return nil
	}
	file, err := os.OpenFile(dbPath, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- local DB path is user/config supplied.
	if err != nil {
		return fmt.Errorf("sqlite: create database file %s: %w", dbPath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("sqlite: close database file %s: %w", dbPath, err)
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return fmt.Errorf("sqlite: restrict database file %s: %w", dbPath, err)
	}
	return nil
}

func restrictSQLiteFilePermissions(dbPath string) error {
	if skipSQLiteFilePermissionHardening(dbPath) {
		return nil
	}
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := chmodExistingSQLiteFile(path, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func chmodExistingSQLiteFile(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("sqlite: restrict database file %s: %w", path, err)
	}
	return nil
}

func skipSQLiteFilePermissionHardening(dbPath string) bool {
	dbPath = strings.TrimSpace(dbPath)
	return dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:")
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
		       cvss_score, epss_score, cisa_kev, summary, source
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
			source       sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &rangesJSON, &versionsJSON, &refsJSON, &severity,
			&cvssScore, &epssScore, &cisaKEV, &summary, &source); err != nil {
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
			Source:       localFindingSource(source.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate vulnerability rows: %w", err)
	}

	return findings, nil
}

func (s *Store) FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	chunks := localPackagePredicateChunks(packages, localPackagePredicateChunkSize)
	if len(chunks) == 0 {
		return nil, nil
	}

	findings := make([]domain.Finding, 0)
	for _, chunk := range chunks {
		chunkFindings, err := s.findVulnerabilitiesBatchChunk(ctx, chunk)
		if err != nil {
			return nil, err
		}
		findings = append(findings, chunkFindings...)
	}
	return findings, nil
}

func (s *Store) findVulnerabilitiesBatchChunk(ctx context.Context, chunk localPackagePredicateChunk) ([]domain.Finding, error) {
	query := `
		WITH requested(ecosystem, name) AS (VALUES ` + chunk.values + `)
		SELECT v.id, v.ecosystem, v.name, v.version_ranges, v.versions_affected, v.references_json, v.severity,
		       v.cvss_score, v.epss_score, v.cisa_kev, v.summary, v.source
		FROM vulnerabilities_local AS v
		JOIN requested AS r ON r.ecosystem = v.ecosystem AND r.name = v.name` // #nosec G202 -- localPackagePredicateChunks uses fixed SQL fragments and bound args.

	rows, err := s.db.QueryContext(ctx, query, chunk.args...)
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
			source       sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &rangesJSON, &versionsJSON, &refsJSON, &severity,
			&cvssScore, &epssScore, &cisaKEV, &summary, &source); err != nil {
			return nil, fmt.Errorf("sqlite: scan vulnerability batch row: %w", err)
		}

		versions := chunk.versionsByPackage[localPackageKey{ecosystem: eco, name: pkg}]
		if len(versions) == 0 {
			findings = append(findings, localVulnerabilityFinding(id, eco, pkg, "", rangesJSON.String, refsJSON.String, severity, summary.String, source.String))
			continue
		}

		for _, version := range versions {
			if rangesJSON.Valid && rangesJSON.String != "" {
				affected, matchErr := versionpkg.VersionAffected(version, rangesJSON.String, versionsJSON.String, eco)
				if matchErr == nil && !affected {
					continue
				}
			}
			findings = append(findings, localVulnerabilityFinding(id, eco, pkg, version, rangesJSON.String, refsJSON.String, severity, summary.String, source.String))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate vulnerability batch rows: %w", err)
	}

	return findings, nil
}

func localVulnerabilityFinding(id, ecosystem, name, version, rangesJSON, refsJSON, severity, summary, source string) domain.Finding {
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
		Source:       localFindingSource(source),
	}
}

// FindMalicious returns all malicious-package findings that match the
// given ecosystem and package name.
func (s *Store) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	ecosystem = strings.TrimSpace(ecosystem)
	name = normalizePackageName(ecosystem, strings.TrimSpace(name))
	version = strings.TrimSpace(version)

	const query = `
		SELECT id, ecosystem, name, version_ranges, versions, reference_urls, risk_type, severity, summary, source
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
			rangesRaw     sql.NullString
			versionsRaw   sql.NullString
			referencesRaw sql.NullString
			riskType      string
			severity      string
			summary       sql.NullString
			source        sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &rangesRaw, &versionsRaw, &referencesRaw, &riskType,
			&severity, &summary, &source); err != nil {
			return nil, fmt.Errorf("sqlite: scan malicious row: %w", err)
		}

		affected, err := localMaliciousAffectsVersion(id, eco, version, nullableStringValue(rangesRaw), nullableStringValue(versionsRaw))
		if err != nil {
			return nil, err
		}
		if !affected {
			continue
		}

		title := summary.String
		if title == "" {
			title = fmt.Sprintf("malicious package: %s (%s)", pkg, riskType)
		}

		findings = append(findings, domain.Finding{
			Name:       pkg,
			Ecosystem:  domain.Ecosystem(eco),
			Type:       db.FindingTypeForMaliciousRiskType(riskType),
			Severity:   domain.Severity(severity),
			AdvisoryID: id,
			Title:      title,
			URL:        firstURLFromJSON(referencesRaw.String),
			RiskType:   riskType,
			Source:     localFindingSource(source.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate malicious rows: %w", err)
	}

	return findings, nil
}

func (s *Store) FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	chunks := localPackagePredicateChunks(packages, localPackagePredicateChunkSize)
	if len(chunks) == 0 {
		return nil, nil
	}

	findings := make([]domain.Finding, 0)
	for _, chunk := range chunks {
		chunkFindings, err := s.findMaliciousBatchChunk(ctx, chunk)
		if err != nil {
			return nil, err
		}
		findings = append(findings, chunkFindings...)
	}
	return findings, nil
}

func (s *Store) findMaliciousBatchChunk(ctx context.Context, chunk localPackagePredicateChunk) ([]domain.Finding, error) {
	query := `
		WITH requested(ecosystem, name) AS (VALUES ` + chunk.values + `)
		SELECT m.id, m.ecosystem, m.name, m.version_ranges, m.versions, m.reference_urls, m.risk_type, m.severity, m.summary, m.source
		FROM malicious_local AS m
		JOIN requested AS r ON r.ecosystem = m.ecosystem AND r.name = m.name` // #nosec G202 -- localPackagePredicateChunks uses fixed SQL fragments and bound args.

	rows, err := s.db.QueryContext(ctx, query, chunk.args...)
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
			rangesRaw     sql.NullString
			versionsRaw   sql.NullString
			referencesRaw sql.NullString
			riskType      string
			severity      string
			summary       sql.NullString
			source        sql.NullString
		)

		if err := rows.Scan(&id, &eco, &pkg, &rangesRaw, &versionsRaw, &referencesRaw, &riskType,
			&severity, &summary, &source); err != nil {
			return nil, fmt.Errorf("sqlite: scan malicious batch row: %w", err)
		}

		requestedVersions := chunk.versionsByPackage[localPackageKey{ecosystem: eco, name: pkg}]
		if len(requestedVersions) == 0 {
			findings = append(findings, localMaliciousFinding(id, eco, pkg, "", referencesRaw.String, riskType, severity, summary.String, source.String))
			continue
		}

		for _, version := range requestedVersions {
			affected, err := localMaliciousAffectsVersion(id, eco, version, nullableStringValue(rangesRaw), nullableStringValue(versionsRaw))
			if err != nil {
				return nil, err
			}
			if !affected {
				continue
			}
			findings = append(findings, localMaliciousFinding(id, eco, pkg, version, referencesRaw.String, riskType, severity, summary.String, source.String))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate malicious batch rows: %w", err)
	}

	return findings, nil
}

func localMaliciousFinding(id, ecosystem, name, version, referencesRaw, riskType, severity, summary, source string) domain.Finding {
	title := summary
	if title == "" {
		title = fmt.Sprintf("malicious package: %s (%s)", name, riskType)
	}
	return domain.Finding{
		Name:       name,
		Version:    version,
		Ecosystem:  domain.Ecosystem(ecosystem),
		Type:       db.FindingTypeForMaliciousRiskType(riskType),
		Severity:   domain.Severity(severity),
		AdvisoryID: id,
		Title:      title,
		URL:        firstURLFromJSON(referencesRaw),
		RiskType:   riskType,
		Source:     localFindingSource(source),
	}
}

func localFindingSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "local"
	}
	return source
}

func (s *Store) FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error) {
	if source != "" && source != "reversinglabs" {
		return nil, nil
	}
	return s.queryReputationFindings(ctx, ecosystem, name, "")
}

func (s *Store) FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	if source != "" && source != "reversinglabs" {
		return nil, nil
	}
	chunks := localPackagePredicateChunks(packages, localPackagePredicateChunkSize)
	if len(chunks) == 0 {
		return nil, nil
	}

	findings := make([]domain.Finding, 0)
	for _, chunk := range chunks {
		chunkFindings, err := s.findReputationFindingsBatch(ctx, chunk)
		if err != nil {
			return nil, err
		}
		findings = append(findings, chunkFindings...)
	}
	return findings, nil
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

		finding := domain.Finding{
			Name:       pkg,
			Version:    ver,
			Ecosystem:  domain.Ecosystem(eco),
			Type:       domain.FindingType(typ),
			Severity:   domain.Severity(severity),
			AdvisoryID: id,
			Title:      title,
			RiskType:   riskType,
			Source:     "reversinglabs",
		}
		finding.Severity = domain.NormalizeFindingSeverity(finding)
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate reputation finding rows: %w", err)
	}
	return findings, nil
}

func (s *Store) findReputationFindingsBatch(ctx context.Context, chunk localPackagePredicateChunk) ([]domain.Finding, error) {
	query := `
		WITH requested(ecosystem, name) AS (VALUES ` + chunk.values + `)
		SELECT rep.id, rep.ecosystem, rep.name, rep.version, rep.type, rep.risk_type, rep.severity, rep.summary
		FROM reputation_findings_local AS rep
		JOIN requested AS r ON r.ecosystem = rep.ecosystem AND r.name = rep.name` // #nosec G202 -- localPackagePredicateChunks uses fixed SQL fragments and bound args.

	rows, err := s.db.QueryContext(ctx, query, chunk.args...)
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
		if !containsString(chunk.versionsByPackage[localPackageKey{ecosystem: eco, name: pkg}], ver) {
			continue
		}
		title := summary.String
		if title == "" {
			title = id
		}
		finding := domain.Finding{
			Name:       pkg,
			Version:    ver,
			Ecosystem:  domain.Ecosystem(eco),
			Type:       domain.FindingType(typ),
			Severity:   domain.Severity(severity),
			AdvisoryID: id,
			Title:      title,
			RiskType:   riskType,
			Source:     "reversinglabs",
		}
		finding.Severity = domain.NormalizeFindingSeverity(finding)
		findings = append(findings, finding)
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

const localPackagePredicateChunkSize = 400

type localPackagePredicateChunk struct {
	where             string
	values            string
	args              []any
	versionsByPackage map[localPackageKey][]string
}

type localPackagePredicateChunkBuilder struct {
	clauses           []string
	values            []string
	args              []any
	versionsByPackage map[localPackageKey][]string
}

func localPackagePredicate(packages []db.PackageQuery) (string, []any, map[localPackageKey][]string) {
	chunks := localPackagePredicateChunks(packages, len(packages))
	if len(chunks) == 0 {
		return "", nil, nil
	}
	chunk := chunks[0]
	return chunk.where, chunk.args, chunk.versionsByPackage
}

func localPackagePredicateChunks(packages []db.PackageQuery, maxKeys int) []localPackagePredicateChunk {
	if len(packages) == 0 {
		return nil
	}
	if maxKeys <= 0 {
		maxKeys = localPackagePredicateChunkSize
	}

	builders := make([]localPackagePredicateChunkBuilder, 0, (len(packages)/maxKeys)+1)
	chunkByKey := make(map[localPackageKey]int, len(packages))

	for _, pkg := range packages {
		ecosystem := strings.TrimSpace(pkg.Ecosystem)
		name := normalizePackageName(ecosystem, strings.TrimSpace(pkg.Name))
		if ecosystem == "" || name == "" {
			continue
		}
		key := localPackageKey{ecosystem: ecosystem, name: name}
		chunkIndex, ok := chunkByKey[key]
		if !ok {
			if len(builders) == 0 || len(builders[len(builders)-1].clauses) >= maxKeys {
				builders = append(builders, localPackagePredicateChunkBuilder{
					clauses:           make([]string, 0, maxKeys),
					values:            make([]string, 0, maxKeys),
					args:              make([]any, 0, maxKeys*2),
					versionsByPackage: make(map[localPackageKey][]string, maxKeys),
				})
			}
			chunkIndex = len(builders) - 1
			chunkByKey[key] = chunkIndex
			builders[chunkIndex].clauses = append(builders[chunkIndex].clauses, `(ecosystem = ? AND name = ?)`)
			builders[chunkIndex].values = append(builders[chunkIndex].values, `(?, ?)`)
			builders[chunkIndex].args = append(builders[chunkIndex].args, ecosystem, name)
		}
		if version := strings.TrimSpace(pkg.Version); version != "" {
			builders[chunkIndex].versionsByPackage[key] = append(builders[chunkIndex].versionsByPackage[key], version)
		}
	}

	chunks := make([]localPackagePredicateChunk, 0, len(builders))
	for _, builder := range builders {
		if len(builder.clauses) == 0 {
			continue
		}
		chunks = append(chunks, localPackagePredicateChunk{
			where:             strings.Join(builder.clauses, " OR "),
			values:            strings.Join(builder.values, ", "),
			args:              builder.args,
			versionsByPackage: builder.versionsByPackage,
		})
	}
	return chunks
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func nullableStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func validateLocalMaliciousVersions(id, versionsJSON string) error {
	trimmed := strings.TrimSpace(versionsJSON)
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var values []string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return fmt.Errorf("sqlite: malicious finding %s versions must be null or an array of strings: %w", id, err)
	}
	return nil
}

func localMaliciousAffectsVersion(id, ecosystem, version, rangesJSON, versionsJSON string) (bool, error) {
	if strings.TrimSpace(version) == "" {
		return true, nil
	}
	if err := validateLocalMaliciousVersions(id, versionsJSON); err != nil {
		return false, err
	}
	rangesJSON = strings.TrimSpace(rangesJSON)
	if rangesJSON == "" || rangesJSON == "null" {
		rangesJSON = "[]"
	}
	versionsJSON = strings.TrimSpace(versionsJSON)
	if versionsJSON == "" || versionsJSON == "null" {
		versionsJSON = "[]"
	}
	affected, err := versionpkg.VersionAffected(version, rangesJSON, versionsJSON, ecosystem)
	if err != nil {
		return false, fmt.Errorf("sqlite: malicious finding %s version constraints invalid: %w", id, err)
	}
	return affected, nil
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
// (github.com/8linkz-sec/packmon/internal/version) package. The local
// duplicated helpers have been removed.

func resourceLinksFromVulnerabilityReferences(advisoryID, raw string) []domain.ResourceLink {
	return findinglinks.ResourceLinksFromVulnerabilityReferences(advisoryID, raw)
}

func canonicalResourceLink(advisoryID string) domain.ResourceLink {
	link, _, _ := findinglinks.CanonicalVulnerabilityResource(advisoryID)
	return link
}

func resourceLinkFromURL(raw string) domain.ResourceLink {
	return findinglinks.ResourceLinkFromURL(raw)
}

func firstURLFromJSON(raw string) string {
	return findinglinks.FirstSafeHTTPURLFromJSON(raw)
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
	}

	hasHistoryTable, err := tableExists(db, "scan_history")
	if err != nil {
		return err
	}
	if hasHistoryTable {
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
		} {
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("sqlite: create scan history index: %w", err)
			}
		}
	}

	if err := normalizeExistingCaseInsensitivePackageNames(db); err != nil {
		return err
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
			closeSilently(rows)
			return fmt.Errorf("sqlite: scan vulnerability package name: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		closeSilently(rows)
		return fmt.Errorf("sqlite: iterate vulnerability package names: %w", err)
	}
	closeSilently(rows)

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
			closeSilently(rows)
			return fmt.Errorf("sqlite: scan %s package name: %w", table, err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		closeSilently(rows)
		return fmt.Errorf("sqlite: iterate %s package names: %w", table, err)
	}
	closeSilently(rows)

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
