package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func startMigrationPostgres(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	containerName := fmt.Sprintf("packmon-migrations-unit-%d", time.Now().UnixNano())
	port := freeMigrationTestPort(t)
	run := exec.Command("docker", "run", "-d", "--rm", // #nosec G204 -- test launches a fixed docker image with generated container name/port.
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", fmt.Sprintf("%d:5432", port),
		"postgres:16-alpine",
	)
	out, err := run.Output()
	if err != nil {
		t.Skipf("docker postgres unavailable: %v", err)
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run() // #nosec G204 -- cleanup uses generated test container name.
		_ = exec.Command("docker", "rm", "-f", containerID).Run()   // #nosec G204 -- cleanup uses docker-returned test container ID.
	})

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

func freeMigrationTestPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
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
