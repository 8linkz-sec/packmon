//go:build integration

package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresMigrationTestImage = "cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"

func startMigrationPostgres(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; Docker-backed migration tests require the explicit integration gate to run against Docker: %v", err)
	}

	containerName := fmt.Sprintf("packmon-migrations-unit-%d", time.Now().UnixNano())
	run := exec.Command("docker", "run", "-d", "--rm", // #nosec G204 -- test launches a fixed docker image with generated container name/port.
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", "127.0.0.1::5432",
		postgresMigrationTestImage,
	)
	out, err := run.Output()
	if err != nil {
		t.Fatalf("docker postgres unavailable: %v", err)
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run() // #nosec G204 -- cleanup uses generated test container name.
		_ = exec.Command("docker", "rm", "-f", containerID).Run()   // #nosec G204 -- cleanup uses docker-returned test container ID.
	})

	port := dockerMigrationPublishedPort(t, containerName, "5432/tcp")
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("docker", "exec", containerName, "pg_isready", "-U", "packmon", "-d", "packmon") // #nosec G204 -- test probes a generated docker container.
		if err := cmd.Run(); err == nil {
			dsn := fmt.Sprintf("postgres://packmon:packmon@127.0.0.1:%d/packmon?sslmode=disable", port)
			waitForMigrationPostgresDSN(t, dsn)
			return dsn
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container %s did not become ready", containerName)
	return ""
}

func dockerMigrationPublishedPort(t *testing.T, containerName, containerPort string) int {
	t.Helper()

	out, err := exec.Command("docker", "port", containerName, containerPort).Output()
	if err != nil {
		t.Fatalf("docker port %s %s: %v", containerName, containerPort, err)
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) == 0 {
		t.Fatalf("docker port %s %s returned no mapping", containerName, containerPort)
	}
	_, port, err := net.SplitHostPort(lines[len(lines)-1])
	if err != nil {
		t.Fatalf("parse docker port mapping %q: %v", lines[len(lines)-1], err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse docker host port %q: %v", port, err)
	}
	return n
}

func waitForMigrationPostgresDSN(t *testing.T, dsn string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		db, err := sql.Open("pgx", dsn)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err = db.PingContext(ctx)
			cancel()
			ioutils.CloseSilently(db)
		}
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres DSN did not become reachable")
}

func TestRunAndVersionAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)

	if _, _, err := Version(dsn); err == nil {
		t.Fatal("Version() before Run error = nil, want unmigrated database error")
	}
	if err := Run(dsn); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := Run(dsn); err != nil {
		t.Fatalf("Run() second call error = %v", err)
	}
	version, dirty, err := Version(dsn)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if dirty || version != ExpectedVersion {
		t.Fatalf("Version() = %d dirty=%v, want %d clean", version, dirty, ExpectedVersion)
	}
}

func TestRunRecordsMigrationChecksumsAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)

	if err := Run(dsn); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	var cleanRows int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM schema_migrations
		WHERE dirty = false
			AND name IS NOT NULL
			AND checksum IS NOT NULL
			AND length(checksum) = 64`).Scan(&cleanRows); err != nil {
		t.Fatalf("query recorded migration checksums: %v", err)
	}
	if cleanRows != ExpectedVersion {
		t.Fatalf("recorded clean migration checksum rows = %d, want %d", cleanRows, ExpectedVersion)
	}

	latest := latestEmbeddedMigration(t)
	var name, checksum string
	var dirty bool
	if err := db.QueryRowContext(ctx, `
		SELECT name, checksum, dirty
		FROM schema_migrations
		WHERE version = $1`, latest.version).Scan(&name, &checksum, &dirty); err != nil {
		t.Fatalf("query latest migration metadata: %v", err)
	}
	if name != latest.name {
		t.Fatalf("latest migration name = %q, want %q", name, latest.name)
	}
	if checksum != expectedEmbeddedMigrationChecksum(t, latest.name) {
		t.Fatalf("latest migration checksum = %q, want checksum of %s", checksum, latest.name)
	}
	if dirty {
		t.Fatal("latest migration recorded as dirty, want clean")
	}

	var eventRows int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM schema_migration_events
		WHERE success = true
			AND dirty = false
			AND finished_at IS NOT NULL
			AND started_at <= finished_at
			AND checksum IS NOT NULL
			AND length(checksum) = 64`).Scan(&eventRows); err != nil {
		t.Fatalf("query migration event history: %v", err)
	}
	if eventRows != ExpectedVersion {
		t.Fatalf("successful migration event rows = %d, want %d", eventRows, ExpectedVersion)
	}

	var eventName, eventChecksum string
	var eventSuccess, eventDirty bool
	if err := db.QueryRowContext(ctx, `
		SELECT name, checksum, success, dirty
		FROM schema_migration_events
		WHERE version = $1
		ORDER BY id DESC
		LIMIT 1`, latest.version).Scan(&eventName, &eventChecksum, &eventSuccess, &eventDirty); err != nil {
		t.Fatalf("query latest migration event: %v", err)
	}
	if eventName != latest.name {
		t.Fatalf("latest migration event name = %q, want %q", eventName, latest.name)
	}
	if eventChecksum != expectedEmbeddedMigrationChecksum(t, latest.name) {
		t.Fatalf("latest migration event checksum = %q, want checksum of %s", eventChecksum, latest.name)
	}
	if !eventSuccess || eventDirty {
		t.Fatalf("latest migration event success=%v dirty=%v, want success clean", eventSuccess, eventDirty)
	}
}

func TestRunBackfillsChecksumsOnLegacySchemaMigrationsTable(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version bigint not null primary key,
			dirty boolean not null
		)`); err != nil {
		t.Fatalf("create legacy schema_migrations table: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, dirty) VALUES($1, false)`, ExpectedVersion); err != nil {
		t.Fatalf("insert legacy schema version: %v", err)
	}

	if err := Run(dsn); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	var cleanRows int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM schema_migrations
		WHERE dirty = false
			AND name IS NOT NULL
			AND checksum IS NOT NULL
			AND length(checksum) = 64`).Scan(&cleanRows); err != nil {
		t.Fatalf("query backfilled migration checksums: %v", err)
	}
	if cleanRows != ExpectedVersion {
		t.Fatalf("backfilled clean migration checksum rows = %d, want %d", cleanRows, ExpectedVersion)
	}

	var name, checksum string
	if err := db.QueryRowContext(ctx, `
		SELECT name, checksum
		FROM schema_migrations
		WHERE version = 1`).Scan(&name, &checksum); err != nil {
		t.Fatalf("query backfilled initial migration metadata: %v", err)
	}
	if name != "001_initial.up.sql" {
		t.Fatalf("backfilled initial migration name = %q, want 001_initial.up.sql", name)
	}
	if checksum != expectedEmbeddedMigrationChecksum(t, name) {
		t.Fatalf("backfilled initial migration checksum = %q, want checksum of %s", checksum, name)
	}
}

func TestRunRejectsStoredChecksumMismatchAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)

	if err := Run(dsn); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	latest := latestEmbeddedMigration(t)
	if _, err := db.ExecContext(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS name text`); err != nil {
		t.Fatalf("add name column for mismatch setup: %v", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text`); err != nil {
		t.Fatalf("add checksum column for mismatch setup: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE schema_migrations
		SET name = $1, checksum = $2
		WHERE version = $3`, latest.name, strings.Repeat("0", 64), latest.version); err != nil {
		t.Fatalf("corrupt stored migration checksum: %v", err)
	}

	if err := Run(dsn); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Run() after checksum drift error = %v, want checksum mismatch", err)
	}
}

func TestRunWaitsForPostgresAdvisoryLock(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("Conn() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		t.Fatalf("acquire external migration lock: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(dsn)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("Run() completed while another session held migration advisory lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	var unlocked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey).Scan(&unlocked); err != nil {
		t.Fatalf("release external migration lock: %v", err)
	}
	if !unlocked {
		t.Fatal("external migration lock was not released")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run() after advisory lock release error = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run() did not complete after advisory lock release")
	}
}

func TestVersionDoesNotCreateSchemaMigrationsTable(t *testing.T) {
	dsn := startMigrationPostgres(t)

	if _, _, err := Version(dsn); err == nil {
		t.Fatal("Version() before Run error = nil, want unmigrated database error")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var tableName sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.schema_migrations')::text`).Scan(&tableName); err != nil {
		t.Fatalf("query schema_migrations table presence: %v", err)
	}
	if tableName.Valid {
		t.Fatalf("schema_migrations table exists after read-only Version(): %q", tableName.String)
	}
}

func TestRunCreatesLifecycleTablesAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)

	if err := Run(dsn); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(sqlDB)

	ctx := context.Background()
	for _, table := range []string{"lifecycle_products", "lifecycle_releases", "lifecycle_package_map"} {
		var exists bool
		err := sqlDB.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, table).Scan(&exists)
		if err != nil {
			t.Fatalf("check lifecycle table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("lifecycle table %s does not exist after migration", table)
		}
	}
}

func TestRunRejectsDirtyDatabase(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	if err := markDirty(ctx, db, 1, "001_initial.up.sql"); err != nil {
		t.Fatalf("markDirty() error = %v", err)
	}
	if err := Run(dsn); err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("Run(dirty) error = %v, want dirty error", err)
	}
}

func TestRunRejectsDatabaseAheadOfBinary(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, dirty) VALUES($1, false)`, ExpectedVersion+1); err != nil {
		t.Fatalf("insert ahead schema version: %v", err)
	}

	if err := Run(dsn); err == nil || !strings.Contains(err.Error(), "newer than binary") {
		t.Fatalf("Run(ahead) error = %v, want newer-than-binary error", err)
	}
}

func TestVersionRejectsNegativeSchemaVersion(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, dirty) VALUES(-1, false)`); err != nil {
		t.Fatalf("insert negative schema version: %v", err)
	}

	if _, _, err := Version(dsn); err == nil || !strings.Contains(err.Error(), "invalid negative schema version") {
		t.Fatalf("Version(negative) error = %v, want invalid negative schema version", err)
	}
}

func TestApplyMigrationFailureLeavesDirtyVersion(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}

	err = applyMigration(ctx, db, migrationFile{
		version: 77,
		name:    "077_bad.up.sql",
		sql:     "not valid sql",
	})
	if err == nil || !strings.Contains(err.Error(), "apply 077_bad.up.sql") {
		t.Fatalf("applyMigration() error = %v, want apply error", err)
	}

	version, dirty, ok, err := currentVersion(ctx, db)
	if err != nil {
		t.Fatalf("currentVersion() error = %v", err)
	}
	if !ok || version != 77 || !dirty {
		t.Fatalf("currentVersion() = version=%d dirty=%v ok=%v, want 77 dirty", version, dirty, ok)
	}

	var success, eventDirty, finished bool
	if err := db.QueryRowContext(ctx, `
		SELECT success, dirty, finished_at IS NOT NULL
		FROM schema_migration_events
		WHERE version = 77 AND name = '077_bad.up.sql'
		ORDER BY id DESC
		LIMIT 1`).Scan(&success, &eventDirty, &finished); err != nil {
		t.Fatalf("query failed migration event: %v", err)
	}
	if success || !eventDirty || !finished {
		t.Fatalf("failed migration event success=%v dirty=%v finished=%v, want failed dirty finished event", success, eventDirty, finished)
	}
}

func TestNormalizeUnknownSeverityMigrationRollbackRestoresBackedUpRows(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	createPre005Schema(t, ctx, db)
	seedNormalizeUnknownSeverityFixtures(t, ctx, db)

	up, err := ReadEmbeddedMigration(5, MigrationDirectionUp)
	if err != nil {
		t.Fatalf("read migration 005 up: %v", err)
	}
	if err := applyMigration(ctx, db, migrationFile{
		version:   up.Version,
		name:      up.Name,
		direction: up.Direction,
		sql:       up.SQL,
	}); err != nil {
		t.Fatalf("apply migration 005 up: %v", err)
	}

	var vulnerabilityRows, maliciousRows int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id = 'OSV-MAL-1'`).Scan(&vulnerabilityRows); err != nil {
		t.Fatalf("count migrated malicious vulnerability: %v", err)
	}
	if vulnerabilityRows != 0 {
		t.Fatalf("malicious vulnerability rows after up = %d, want 0", vulnerabilityRows)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM malicious_findings WHERE id = 'OSV-MAL-1' AND source = 'osv'`).Scan(&maliciousRows); err != nil {
		t.Fatalf("count migrated malicious finding: %v", err)
	}
	if maliciousRows != 1 {
		t.Fatalf("malicious finding rows after up = %d, want 1", maliciousRows)
	}
	var normalizedSeverity string
	if err := db.QueryRowContext(ctx, `SELECT severity FROM vulnerabilities WHERE id = 'OSV-UNKNOWN-1'`).Scan(&normalizedSeverity); err != nil {
		t.Fatalf("query normalized severity: %v", err)
	}
	if normalizedSeverity != "LOW" {
		t.Fatalf("normalized severity after up = %q, want LOW", normalizedSeverity)
	}

	down, err := ReadEmbeddedMigration(5, MigrationDirectionDown)
	if err != nil {
		t.Fatalf("read migration 005 down: %v", err)
	}
	if err := applyMigration(ctx, db, migrationFile{
		version:   down.Version,
		name:      down.Name,
		direction: down.Direction,
		sql:       down.SQL,
	}); err != nil {
		t.Fatalf("apply migration 005 down: %v", err)
	}

	assertNormalizeUnknownSeverityRollbackRestored(t, ctx, db)
}

func TestReputationRiskStatusRollbackRestoresOnlyRowsConvertedByUp(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	createPre009ReputationSchema(t, ctx, db)
	seedReputationRiskStatusFixtures(t, ctx, db)

	up, err := ReadEmbeddedMigration(9, MigrationDirectionUp)
	if err != nil {
		t.Fatalf("read migration 009 up: %v", err)
	}
	if err := applyMigration(ctx, db, migrationFile{
		version:   up.Version,
		name:      up.Name,
		direction: up.Direction,
		sql:       up.SQL,
	}); err != nil {
		t.Fatalf("apply migration 009 up: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO package_reputation_cache (
			ecosystem, name, version, source, status, severity, summary, evidence
		)
		VALUES (
			'npm', 'post-migration-risk', '1.0.0', 'reversinglabs', 'risk', 'LOW',
			'ReversingLabs: malware incident history',
			'{"assessment":"risk","signals":["incidents.type.malware"]}'::jsonb
		)`); err != nil {
		t.Fatalf("insert post-migration risk row: %v", err)
	}

	down, err := ReadEmbeddedMigration(9, MigrationDirectionDown)
	if err != nil {
		t.Fatalf("read migration 009 down: %v", err)
	}
	if err := applyMigration(ctx, db, migrationFile{
		version:   down.Version,
		name:      down.Name,
		direction: down.Direction,
		sql:       down.SQL,
	}); err != nil {
		t.Fatalf("apply migration 009 down: %v", err)
	}

	got := map[string]string{}
	rows, err := db.QueryContext(ctx, `
		SELECT name, status
		FROM package_reputation_cache
		ORDER BY name`)
	if err != nil {
		t.Fatalf("query reputation rows: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	for rows.Next() {
		var name, status string
		if err := rows.Scan(&name, &status); err != nil {
			t.Fatalf("scan reputation row: %v", err)
		}
		got[name] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate reputation rows: %v", err)
	}

	want := map[string]string{
		"historical-incident": "malicious",
		"active-malware":      "malicious",
		"post-migration-risk": "risk",
	}
	for name, wantStatus := range want {
		if got[name] != wantStatus {
			t.Fatalf("status for %s after rollback = %q, want %q; all rows: %#v", name, got[name], wantStatus, got)
		}
	}
}

func createPre005Schema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	stmts := []string{
		`CREATE TABLE vulnerabilities (
			id TEXT PRIMARY KEY,
			summary TEXT NOT NULL,
			details TEXT,
			severity TEXT NOT NULL DEFAULT 'LOW',
			cvss_score REAL,
			epss_score REAL,
			epss_percentile REAL,
			cisa_kev BOOLEAN NOT NULL DEFAULT FALSE,
			exploit_exists BOOLEAN NOT NULL DEFAULT FALSE,
			published TIMESTAMPTZ NOT NULL,
			modified TIMESTAMPTZ NOT NULL,
			withdrawn TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE vulnerability_aliases (
			id SERIAL PRIMARY KEY,
			vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
			alias_id TEXT NOT NULL,
			UNIQUE(vulnerability_id, alias_id)
		)`,
		`CREATE TABLE vulnerability_sources (
			id SERIAL PRIMARY KEY,
			vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
			source TEXT NOT NULL,
			source_id TEXT NOT NULL,
			url TEXT,
			raw_json JSONB,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(vulnerability_id, source)
		)`,
		`CREATE TABLE vulnerability_references (
			id SERIAL PRIMARY KEY,
			vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
			type TEXT,
			url TEXT NOT NULL,
			source TEXT NOT NULL DEFAULT '',
			UNIQUE(vulnerability_id, source, url)
		)`,
		`CREATE TABLE affected_packages (
			id SERIAL PRIMARY KEY,
			vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			version_ranges JSONB NOT NULL DEFAULT '[]',
			versions_affected JSONB NOT NULL DEFAULT '[]',
			UNIQUE(vulnerability_id, ecosystem, name)
		)`,
		`CREATE TABLE malicious_findings (
			id TEXT PRIMARY KEY,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			versions JSONB,
			source TEXT NOT NULL,
			risk_type TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'CRITICAL',
			summary TEXT NOT NULL,
			description TEXT,
			reference_urls JSONB NOT NULL DEFAULT '[]',
			origin_ref TEXT,
			published TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_by TEXT
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("create pre-005 schema: %v\n%s", err, stmt)
		}
	}
}

func createPre009ReputationSchema(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	stmts := []string{
		`CREATE TABLE package_reputation_cache (
			id              SERIAL      PRIMARY KEY,
			ecosystem       TEXT        NOT NULL,
			name            TEXT        NOT NULL,
			version         TEXT        NOT NULL,
			source          TEXT        NOT NULL,
			status          TEXT        NOT NULL CHECK (status IN ('pending', 'malicious', 'removed', 'clean', 'not_found', 'unsupported', 'error')),
			severity        TEXT        NOT NULL DEFAULT 'CRITICAL',
			summary         TEXT        NOT NULL DEFAULT '',
			description     TEXT        NOT NULL DEFAULT '',
			reference_urls  JSONB       NOT NULL DEFAULT '[]',
			evidence        JSONB       NOT NULL DEFAULT '{}',
			last_checked_at TIMESTAMPTZ,
			next_check_at   TIMESTAMPTZ,
			last_error      TEXT        NOT NULL DEFAULT '',
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(ecosystem, name, version, source)
		)`,
		`CREATE INDEX idx_reputation_due
			ON package_reputation_cache(source, ecosystem, name, next_check_at)
			WHERE status IN ('pending', 'error', 'malicious', 'removed', 'clean', 'not_found')`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("create pre-009 reputation schema: %v\nSQL:\n%s", err, stmt)
		}
	}
}

func seedReputationRiskStatusFixtures(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	stmts := []string{
		`INSERT INTO package_reputation_cache (
			ecosystem, name, version, source, status, severity, summary, evidence
		)
		VALUES (
			'npm', 'historical-incident', '1.0.0', 'reversinglabs', 'malicious', 'CRITICAL',
			'ReversingLabs: malicious package',
			'{"assessment":"malicious","signals":["incidents.type.malware"]}'::jsonb
		)`,
		`INSERT INTO package_reputation_cache (
			ecosystem, name, version, source, status, severity, summary, evidence
		)
		VALUES (
			'npm', 'active-malware', '1.0.0', 'reversinglabs', 'malicious', 'CRITICAL',
			'ReversingLabs: malicious package',
			'{"assessment":"malicious","signals":["incidents.type.malware","package.all_malicious"]}'::jsonb
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed reputation risk fixture: %v\nSQL:\n%s", err, stmt)
		}
	}
}

func seedNormalizeUnknownSeverityFixtures(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	const rawMalicious = `{
		"affected": [
			{
				"package": {"ecosystem": "crates.io", "name": "bad-crate"},
				"versions": ["1.0.0"],
				"database_specific": {"categories": ["malicious"], "source": "RUSTSEC-2024-0001"}
			}
		],
		"references": [{"url": "https://example.test/osv-mal-1"}]
	}`
	const rawUnknown = `{"affected": [{"package": {"ecosystem": "npm", "name": "unknown-pkg"}}]}`

	if _, err := db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (
			id, summary, details, severity, cvss_score, epss_score, epss_percentile,
			cisa_kev, exploit_exists, published, modified, withdrawn, created_at, updated_at
		)
		VALUES
			('OSV-MAL-1', 'malicious typosquat', 'malicious package details', 'UNKNOWN', 1.2, 0.3, 0.4,
			 true, true, '2024-01-02T03:04:05Z', '2024-01-03T03:04:05Z', NULL,
			 '2024-01-04T03:04:05Z', '2024-01-05T03:04:05Z'),
			('OSV-UNKNOWN-1', 'unknown severity vuln', 'non-malicious details', 'UNKNOWN', NULL, NULL, NULL,
			 false, false, '2024-02-02T03:04:05Z', '2024-02-03T03:04:05Z', NULL,
			 '2024-02-04T03:04:05Z', '2024-02-05T03:04:05Z')`); err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO vulnerability_aliases (vulnerability_id, alias_id)
		VALUES ('OSV-MAL-1', 'RUSTSEC-2024-0001'), ('OSV-UNKNOWN-1', 'CVE-2024-0001')`); err != nil {
		t.Fatalf("seed aliases: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO vulnerability_sources (vulnerability_id, source, source_id, url, raw_json, updated_at)
		VALUES
			('OSV-MAL-1', 'osv', 'OSV-MAL-1', 'https://example.test/osv-mal-1', $1::jsonb, '2024-01-06T03:04:05Z'),
			('OSV-UNKNOWN-1', 'osv', 'OSV-UNKNOWN-1', 'https://example.test/osv-unknown-1', $2::jsonb, '2024-02-06T03:04:05Z')`,
		rawMalicious, rawUnknown); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO vulnerability_references (vulnerability_id, type, url, source)
		VALUES ('OSV-MAL-1', 'ADVISORY', 'https://example.test/osv-mal-1', 'osv')`); err != nil {
		t.Fatalf("seed references: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO affected_packages (vulnerability_id, ecosystem, name, version_ranges, versions_affected)
		VALUES
			('OSV-MAL-1', 'cargo', 'bad-crate', '[]'::jsonb, '["1.0.0"]'::jsonb),
			('OSV-UNKNOWN-1', 'npm', 'unknown-pkg', '[]'::jsonb, '[]'::jsonb)`); err != nil {
		t.Fatalf("seed affected packages: %v", err)
	}
}

func assertNormalizeUnknownSeverityRollbackRestored(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	var severity, updatedAt string
	if err := db.QueryRowContext(ctx, `
		SELECT severity, updated_at::text
		FROM vulnerabilities
		WHERE id = 'OSV-UNKNOWN-1'`).Scan(&severity, &updatedAt); err != nil {
		t.Fatalf("query restored unknown vulnerability: %v", err)
	}
	if severity != "UNKNOWN" || !strings.Contains(updatedAt, "2024-02-05 03:04:05") {
		t.Fatalf("restored non-malicious vulnerability severity/updated_at = %q/%q, want UNKNOWN/original timestamp", severity, updatedAt)
	}

	var maliciousVulnRows, aliasRows, sourceRows, referenceRows, affectedRows, maliciousFindingRows int
	queries := map[string]*int{
		`SELECT COUNT(*) FROM vulnerabilities WHERE id = 'OSV-MAL-1' AND severity = 'UNKNOWN'`:                  &maliciousVulnRows,
		`SELECT COUNT(*) FROM vulnerability_aliases WHERE vulnerability_id = 'OSV-MAL-1'`:                       &aliasRows,
		`SELECT COUNT(*) FROM vulnerability_sources WHERE vulnerability_id = 'OSV-MAL-1' AND source = 'osv'`:    &sourceRows,
		`SELECT COUNT(*) FROM vulnerability_references WHERE vulnerability_id = 'OSV-MAL-1' AND source = 'osv'`: &referenceRows,
		`SELECT COUNT(*) FROM affected_packages WHERE vulnerability_id = 'OSV-MAL-1' AND name = 'bad-crate'`:    &affectedRows,
		`SELECT COUNT(*) FROM malicious_findings WHERE id = 'OSV-MAL-1'`:                                        &maliciousFindingRows,
	}
	for query, dest := range queries {
		if err := db.QueryRowContext(ctx, query).Scan(dest); err != nil {
			t.Fatalf("query rollback state %q: %v", query, err)
		}
	}
	if maliciousVulnRows != 1 || aliasRows != 1 || sourceRows != 1 || referenceRows != 1 || affectedRows != 1 {
		t.Fatalf("restored malicious vulnerability rows = vuln:%d aliases:%d sources:%d refs:%d affected:%d, want all 1",
			maliciousVulnRows, aliasRows, sourceRows, referenceRows, affectedRows)
	}
	if maliciousFindingRows != 0 {
		t.Fatalf("malicious finding rows after rollback = %d, want 0", maliciousFindingRows)
	}

	for _, table := range []string{
		"packmon_m005_vulnerabilities_backup",
		"packmon_m005_vulnerability_aliases_backup",
		"packmon_m005_vulnerability_sources_backup",
		"packmon_m005_vulnerability_references_backup",
		"packmon_m005_affected_packages_backup",
		"packmon_m005_malicious_findings_backup",
		"packmon_m005_malicious_vulnerability_ids",
		"packmon_m005_malicious_finding_ids",
	} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check backup table %s: %v", table, err)
		}
		if exists {
			t.Fatalf("backup table %s still exists after rollback", table)
		}
	}
}

func latestEmbeddedMigration(t *testing.T) migrationFile {
	t.Helper()

	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations() error = %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("embeddedUpMigrations() returned no migrations")
	}
	return migrations[len(migrations)-1]
}

func expectedEmbeddedMigrationChecksum(t *testing.T, name string) string {
	t.Helper()

	data, err := fs.ReadFile(name)
	if err != nil {
		t.Fatalf("read embedded migration %s: %v", name, err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
