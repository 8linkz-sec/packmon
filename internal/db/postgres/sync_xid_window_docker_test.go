//go:build integration

package postgres

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// postgresEpochDockerTestImage uses the shell-bearing official Alpine image
// because the normal hardened test image intentionally has no shell. The shell
// is needed only before startup to run initdb and pg_resetwal against a stopped
// test cluster.
const postgresEpochDockerTestImage = "postgres@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5"

func startDockerPostgresStoreAtXIDEpoch(t *testing.T, epoch int) (*Store, string) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; past-epoch PostgreSQL tests require the explicit integration gate to run against Docker: %v", err)
	}

	containerName := fmt.Sprintf("packmon-pg-epoch-%d-%d", epoch, time.Now().UnixNano())
	const initAtEpoch = `
set -eu
mkdir -p "$PGDATA"
password_file=/tmp/packmon-postgres-password
printf '%s\n' "$POSTGRES_PASSWORD" > "$password_file"
initdb -D "$PGDATA" --username="$POSTGRES_USER" --pwfile="$password_file" --auth-local=trust --auth-host=scram-sha-256
rm -f "$password_file"
printf '\nhost all all all scram-sha-256\n' >> "$PGDATA/pg_hba.conf"
pg_resetwal -f -e "$PACKMON_TEST_XID_EPOCH" "$PGDATA"
exec postgres -D "$PGDATA" \
  -c listen_addresses='*' \
  -c shared_preload_libraries=pg_stat_statements \
  -c compute_query_id=on \
  -c track_io_timing=on \
  -c pg_stat_statements.track=top \
  -c pg_stat_statements.track_utility=off
`
	run := exec.Command("docker", "run", "-d", "--rm", // #nosec G204 -- test launches a fixed image with generated container name/port and numeric epoch.
		"--name", containerName,
		"--user", "postgres",
		"--entrypoint", "sh",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-e", "PGDATA=/tmp/packmon-pgdata",
		"-e", "PACKMON_TEST_XID_EPOCH="+strconv.Itoa(epoch),
		"-p", "127.0.0.1::5432",
		postgresEpochDockerTestImage,
		"-ec", initAtEpoch,
	)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("start past-epoch docker postgres: %v: %s", err, strings.TrimSpace(string(out)))
	}
	containerID := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run() // #nosec G204 -- cleanup uses generated test container name.
		_ = exec.Command("docker", "rm", "-f", containerID).Run()   // #nosec G204 -- cleanup uses docker-returned test container ID.
	})

	port := dockerPostgresPublishedPort(t, containerName, "5432/tcp")
	adminDSN := fmt.Sprintf("postgres://packmon:packmon@127.0.0.1:%d/postgres?sslmode=disable", port)
	waitForPostgresDSN(t, adminDSN)
	adminPool, err := pgxpool.New(context.Background(), adminDSN)
	if err != nil {
		t.Fatalf("open past-epoch postgres admin pool: %v", err)
	}
	if _, err := adminPool.Exec(context.Background(), `CREATE DATABASE packmon`); err != nil {
		adminPool.Close()
		t.Fatalf("create past-epoch packmon database: %v", err)
	}
	adminPool.Close()

	dsn := fmt.Sprintf("postgres://packmon:packmon@127.0.0.1:%d/packmon?sslmode=disable", port)
	waitForPostgresDSN(t, dsn)
	if err := migrations.Run(dsn); err != nil {
		t.Fatalf("migrate past-epoch postgres: %v", err)
	}
	store, err := New(context.Background(), dsn, nil, &PoolConfig{MaxConns: 2, MinConns: 1})
	if err != nil {
		t.Fatalf("open past-epoch postgres store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close past-epoch postgres store: %v", err)
		}
	})
	return store, dsn
}

// TestSyncXIDWindowsAgainstPastEpochPostgres proves the SQL window helpers and
// a real delta hand-off while PostgreSQL itself is running in transaction-ID
// epoch 5. Evaluating an epoch-5 watermark on an epoch-0 server exercises only
// the fail-open out-of-window branch and cannot prove the modulo arithmetic in
// the normal in-window path past the first 2^32 transactions.
func TestSyncXIDWindowsAgainstPastEpochPostgres(t *testing.T) {
	store, _ := startDockerPostgresStoreAtXIDEpoch(t, 5)
	ctx := context.Background()

	var current int64
	if err := store.pool.QueryRow(ctx, `SELECT txid_current()`).Scan(&current); err != nil {
		t.Fatalf("read current past-epoch transaction ID: %v", err)
	}
	if got := current / 4294967296; got != 5 {
		t.Fatalf("PostgreSQL transaction ID %d is in epoch %d, want epoch 5", current, got)
	}

	testSyncXIDConditionsMatchTheirModel(ctx, t, store)
	testDeltaDeliversRowCommittedAfterTheSnapshot(ctx, t, store)
}

// testSyncXIDConditionsMatchTheirModel evaluates syncXIDAtOrAfterSQL and
// syncXIDBeforeSQL on PostgreSQL for 32-bit xmin values around the
// database's next transaction ID and for watermarks inside, at the edge of,
// and outside the 2^31 window (including one from the future), and checks
// each result against the Go model the unit tests verify across the
// wraparound and past the first epoch. This pins PostgreSQL's integer
// semantics, the once-per-statement window subquery, and the binding of the
// 64-bit watermark as text.
func testSyncXIDConditionsMatchTheirModel(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	var next int64
	if err := store.pool.QueryRow(ctx, `SELECT txid_snapshot_xmax(txid_current_snapshot())`).Scan(&next); err != nil {
		t.Fatalf("read next transaction ID: %v", err)
	}
	low := func(xid int64) string { return strconv.FormatInt(((xid%4294967296)+4294967296)%4294967296, 10) }
	xmins := []string{"2", "3000000000", low(next - 200), low(next - 101), low(next - 100), low(next - 50), low(next - 1), low(next), low(next + 1000)}
	watermarks := []int64{next - 100, next - 1, next, next + 1, next - 2147483647, next - 2147483648, syncTestEpoch5 + 1000}

	for _, watermark := range watermarks {
		rows, err := store.pool.Query(ctx, `
			SELECT txid_snapshot_xmax(txid_current_snapshot()), x.row_xid::text::bigint,
				`+syncXIDAtOrAfterSQL("x.row_xid", "$1")+`,
				`+syncXIDBeforeSQL("x.row_xid", "$1")+`
			FROM unnest($2::text[]) AS raw(value)
			CROSS JOIN LATERAL (SELECT raw.value::xid AS row_xid) x`,
			strconv.FormatInt(watermark, 10), xmins)
		if err != nil {
			t.Fatalf("evaluate xid conditions for watermark %d: %v", watermark, err)
		}
		count := 0
		for rows.Next() {
			var (
				stmtNext          int64
				xmin              uint32
				atOrAfter, before bool
			)
			if err := rows.Scan(&stmtNext, &xmin, &atOrAfter, &before); err != nil {
				rows.Close()
				t.Fatalf("scan xid conditions: %v", err)
			}
			count++
			if want := syncTestXIDAtOrAfter(xmin, watermark, stmtNext); atOrAfter != want {
				t.Errorf("at or after(xmin %d, watermark %d, next %d) = %v on PostgreSQL, want %v", xmin, watermark, stmtNext, atOrAfter, want)
			}
			if want := syncTestXIDBefore(xmin, watermark, stmtNext); before != want {
				t.Errorf("before(xmin %d, watermark %d, next %d) = %v on PostgreSQL, want %v", xmin, watermark, stmtNext, before, want)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate xid conditions: %v", err)
		}
		if count != len(xmins) {
			t.Fatalf("evaluated %d xmin values for watermark %d, want %d", count, watermark, len(xmins))
		}
	}
}

// testDeltaDeliversRowCommittedAfterTheSnapshot reproduces the change the
// since_xid leg exists for: a transaction that started before a sync's
// snapshot (so its updated_at predates the snapshot) and commits after it.
// The sync cannot see the row, and the next delta must deliver it through
// since_xid; by timestamp alone it is missed.
func testDeltaDeliversRowCommittedAfterTheSnapshot(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "MAL-xid-late-commit"
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin late transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, severity, summary, updated_at)
		VALUES ($1, 'npm', 'xid-late-commit', 'openssf', 'malware', 'CRITICAL', 'late commit', clock_timestamp() - interval '1 hour')`, id); err != nil {
		t.Fatalf("insert late malicious finding: %v", err)
	}

	since := syncDeltaBoundary(ctx, t, store).Add(-2 * time.Hour)
	first, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
	if err != nil {
		t.Fatalf("ExportSync(while the late transaction runs) error = %v", err)
	}
	if syncMaliciousExportContains(first.Malicious, id) {
		t.Fatalf("ExportSync(while the late transaction runs) delivered uncommitted %s", id)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit late transaction: %v", err)
	}

	timestampOnly, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &first.SyncedAt})
	if err != nil {
		t.Fatalf("ExportSync(next delta by timestamp) error = %v", err)
	}
	if syncMaliciousExportContains(timestampOnly.Malicious, id) {
		t.Fatalf("ExportSync(next delta by timestamp) delivered %s, want the fixture to depend on since_xid", id)
	}
	next, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &first.SyncedAt, SinceXID: first.SyncedXID})
	if err != nil {
		t.Fatalf("ExportSync(next delta) error = %v", err)
	}
	if !syncMaliciousExportContains(next.Malicious, id) {
		t.Fatalf("ExportSync(next delta since xid %d) missed %s committed after the previous snapshot", first.SyncedXID, id)
	}
}

func syncMaliciousExportContains(rows []db.SyncMalicious, id string) bool {
	for _, row := range rows {
		if row.ID == id {
			return true
		}
	}
	return false
}
