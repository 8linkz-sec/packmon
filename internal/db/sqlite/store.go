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

	"github.com/8linkz-sec/packmon/internal/ioutils"

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
func New(dbPath string) (store *Store, err error) {
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
		ioutils.CloseSilently(db)
		return nil, fmt.Errorf("sqlite: ping %s: %w", dbPath, err)
	}

	unlockMigration, err := acquireSQLiteMigrationLock(dbPath)
	if err != nil {
		ioutils.CloseSilently(db)
		return nil, err
	}
	defer func() {
		if unlockErr := unlockMigration(); unlockErr != nil {
			ioutils.CloseSilently(db)
			store = nil
			if err != nil {
				err = errors.Join(err, unlockErr)
			} else {
				err = unlockErr
			}
		}
	}()

	// Create schema tables (idempotent).
	if _, err := db.Exec(schemaSQL); err != nil {
		ioutils.CloseSilently(db)
		return nil, fmt.Errorf("sqlite: create schema: %w", err)
	}
	if err := migrateSchema(db); err != nil {
		ioutils.CloseSilently(db)
		return nil, err
	}
	if err := restrictSQLiteFilePermissions(dbPath); err != nil {
		ioutils.CloseSilently(db)
		return nil, err
	}

	return &Store{db: db, dbPath: dbPath}, nil
}

var (
	sqliteMigrationLockTimeout      = 5 * time.Second
	sqliteMigrationLockPollInterval = 25 * time.Millisecond
	sqliteSyncLockTimeout           = 5 * time.Second
	removeSQLiteMigrationLockFile   = os.Remove
)

func acquireSQLiteMigrationLock(dbPath string) (func() error, error) {
	if skipSQLiteMigrationLock(dbPath) {
		return func() error { return nil }, nil
	}

	lockPath := dbPath + ".migrate.lock"
	deadline := time.Now().Add(sqliteMigrationLockTimeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- lock path is derived from the local DB path.
		if err == nil {
			unlocked := false
			return func() error {
				if unlocked {
					return nil
				}
				unlocked = true
				return releaseSQLiteMigrationLock(file, lockPath)
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

func releaseSQLiteMigrationLock(file *os.File, lockPath string) error {
	var errs []error
	if err := file.Close(); err != nil {
		errs = append(errs, fmt.Errorf("sqlite: close migration lock %s: %w", lockPath, err))
	}
	if err := removeSQLiteMigrationLockFile(lockPath); err != nil {
		errs = append(errs, fmt.Errorf("sqlite: remove migration lock %s: %w", lockPath, err))
	}
	return errors.Join(errs...)
}

func skipSQLiteMigrationLock(dbPath string) bool {
	return skipSQLiteFilePermissionHardening(dbPath)
}

func acquireSQLiteSyncLock(ctx context.Context, dbPath string) (func(), error) {
	if skipSQLiteSyncLock(dbPath) {
		return func() {}, nil
	}
	return acquireSQLiteLockFile(ctx, dbPath+".sync.lock", sqliteSyncLockTimeout, "sync")
}

func skipSQLiteSyncLock(dbPath string) bool {
	return skipSQLiteFilePermissionHardening(dbPath)
}

func acquireSQLiteLockFile(ctx context.Context, lockPath string, timeout time.Duration, purpose string) (func(), error) {
	deadline := time.Now().Add(timeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- lock path is derived from the local DB path.
		if err == nil {
			unlocked := false
			return func() {
				if unlocked {
					return
				}
				unlocked = true
				ioutils.CloseSilently(file)
				_ = os.Remove(lockPath)
			}, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("sqlite: create %s lock %s: %w", purpose, lockPath, err)
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("sqlite: acquire %s lock %s: %w", purpose, lockPath, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("sqlite: acquire %s lock %s: %w", purpose, lockPath, ctx.Err())
		case <-time.After(sqliteMigrationLockPollInterval):
		}
	}
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
	defer ioutils.CloseSilently(rows)

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

		// Check whether the requested version falls within any affected range
		// or explicit affected-version list.
		if version != "" {
			constraintRanges, constraintVersions := db.NormalizeVersionConstraintJSON(nullableStringValue(rangesJSON), nullableStringValue(versionsJSON))
			affected, matchErr := versionpkg.VersionAffected(version, constraintRanges, constraintVersions, eco)
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
			FixedVersion: versionpkg.ExtractFixedVersionConstraintFor(version, rangesJSON.String, ecosystem),
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
	defer ioutils.CloseSilently(rows)

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
			constraintRanges, constraintVersions := db.NormalizeVersionConstraintJSON(nullableStringValue(rangesJSON), nullableStringValue(versionsJSON))
			affected, matchErr := versionpkg.VersionAffected(version, constraintRanges, constraintVersions, eco)
			if matchErr == nil && !affected {
				continue
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
		FixedVersion: versionpkg.ExtractFixedVersionConstraintFor(version, rangesJSON, ecosystem),
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
	defer ioutils.CloseSilently(rows)

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

		findings = append(findings, localMaliciousFinding(id, eco, pkg, version, referencesRaw.String, riskType, severity, summary.String, source.String))
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
	defer ioutils.CloseSilently(rows)

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
	chunks := localReputationPackagePredicateChunks(packages, localReputationPredicateChunkSize)
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
	defer ioutils.CloseSilently(rows)

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

func (s *Store) findReputationFindingsBatch(ctx context.Context, chunk localReputationPackagePredicateChunk) ([]domain.Finding, error) {
	query := reputationBatchQuery(chunk)
	rows, err := s.db.QueryContext(ctx, query, chunk.args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query reputation batch: %w", err)
	}
	defer ioutils.CloseSilently(rows)

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

func reputationBatchQuery(chunk localReputationPackagePredicateChunk) string {
	query := `
		WITH requested(ecosystem, name, version) AS (VALUES ` + chunk.values + `)
		SELECT rep.id, rep.ecosystem, rep.name, rep.version, rep.type, rep.risk_type, rep.severity, rep.summary
		FROM reputation_findings_local AS rep
		JOIN requested AS r ON r.ecosystem = rep.ecosystem AND r.name = rep.name AND r.version = rep.version` // #nosec G202 -- localReputationPackagePredicateChunks uses fixed SQL fragments and bound args.
	return query
}

type localPackageKey struct {
	ecosystem string
	name      string
}

const (
	localPackagePredicateChunkSize    = 400
	localReputationPredicateChunkSize = 300
)

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

type localReputationPackageKey struct {
	ecosystem string
	name      string
	version   string
}

type localReputationPackagePredicateChunk struct {
	values string
	args   []any
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

func localReputationPackagePredicateChunks(packages []db.PackageQuery, maxKeys int) []localReputationPackagePredicateChunk {
	if len(packages) == 0 {
		return nil
	}
	if maxKeys <= 0 {
		maxKeys = localReputationPredicateChunkSize
	}

	type builder struct {
		values []string
		args   []any
	}

	builders := make([]builder, 0, (len(packages)/maxKeys)+1)
	seen := make(map[localReputationPackageKey]struct{}, len(packages))
	for _, pkg := range packages {
		ecosystem := strings.TrimSpace(pkg.Ecosystem)
		name := normalizePackageName(ecosystem, strings.TrimSpace(pkg.Name))
		version := strings.TrimSpace(pkg.Version)
		if ecosystem == "" || name == "" || version == "" {
			continue
		}

		key := localReputationPackageKey{ecosystem: ecosystem, name: name, version: version}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if len(builders) == 0 || len(builders[len(builders)-1].values) >= maxKeys {
			builders = append(builders, builder{
				values: make([]string, 0, maxKeys),
				args:   make([]any, 0, maxKeys*3),
			})
		}
		current := &builders[len(builders)-1]
		current.values = append(current.values, `(?, ?, ?)`)
		current.args = append(current.args, ecosystem, name, version)
	}

	chunks := make([]localReputationPackagePredicateChunk, 0, len(builders))
	for _, builder := range builders {
		if len(builder.values) == 0 {
			continue
		}
		chunks = append(chunks, localReputationPackagePredicateChunk{
			values: strings.Join(builder.values, ", "),
			args:   builder.args,
		})
	}
	return chunks
}

func nullableStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

type localVersionRange struct {
	Events []localVersionEvent `json:"events"`
}

type localVersionEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

func validateLocalVersionRanges(id, field, rangesJSON string, allowNull bool) error {
	trimmed := strings.TrimSpace(rangesJSON)
	if trimmed == "" {
		return nil
	}
	if trimmed == "null" {
		if allowNull {
			return nil
		}
		return fmt.Errorf("sqlite: finding %s %s must be an array of range objects", id, field)
	}
	var ranges []localVersionRange
	if err := json.Unmarshal([]byte(trimmed), &ranges); err != nil {
		return fmt.Errorf("sqlite: finding %s %s must be an array of range objects: %w", id, field, err)
	}
	for i, versionRange := range ranges {
		if len(versionRange.Events) == 0 {
			return fmt.Errorf("sqlite: finding %s %s[%d].events must not be empty", id, field, i)
		}
		for j, event := range versionRange.Events {
			if strings.TrimSpace(event.Introduced) == "" &&
				strings.TrimSpace(event.Fixed) == "" &&
				strings.TrimSpace(event.LastAffected) == "" &&
				strings.TrimSpace(event.Limit) == "" {
				return fmt.Errorf("sqlite: finding %s %s[%d].events[%d] must set introduced, fixed, last_affected, or limit", id, field, i, j)
			}
		}
	}
	return nil
}

func validateLocalStringArray(id, field, versionsJSON string, allowNull bool) error {
	trimmed := strings.TrimSpace(versionsJSON)
	if trimmed == "" {
		return nil
	}
	if trimmed == "null" {
		if allowNull {
			return nil
		}
		return fmt.Errorf("sqlite: finding %s %s must be an array of strings", id, field)
	}
	var values []string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return fmt.Errorf("sqlite: finding %s %s must be an array of strings: %w", id, field, err)
	}
	return nil
}

func validateLocalMaliciousVersions(id, versionsJSON string) error {
	return validateLocalStringArray(id, "versions", versionsJSON, true)
}

func localMaliciousAffectsVersion(id, ecosystem, version, rangesJSON, versionsJSON string) (bool, error) {
	if strings.TrimSpace(version) == "" {
		return true, nil
	}
	if err := validateLocalVersionRanges(id, "version_ranges", rangesJSON, true); err != nil {
		return false, err
	}
	if err := validateLocalMaliciousVersions(id, versionsJSON); err != nil {
		return false, err
	}
	rangesJSON, versionsJSON = db.NormalizeVersionConstraintJSON(rangesJSON, versionsJSON)
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

func firstURLFromJSON(raw string) string {
	return findinglinks.FirstSafeHTTPURLFromJSON(raw)
}
