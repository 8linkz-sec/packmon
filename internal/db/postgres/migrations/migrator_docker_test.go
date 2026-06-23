//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresMigrationTestImage = "cgr.dev/chainguard/postgres:latest@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"

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
			closeSilently(db)
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

func TestRunWaitsForPostgresAdvisoryLock(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer closeSilently(db)

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
	defer closeSilently(db)

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
	defer closeSilently(sqlDB)

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
	defer closeSilently(db)

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
	defer closeSilently(db)

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
	defer closeSilently(db)

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
	defer closeSilently(db)

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
}
