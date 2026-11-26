//go:build integration

package postgres

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The Docker-backed tests start one throwaway PostgreSQL container per test. The GitLab runners have no Docker
// daemon, so the integration job runs the server as a job service and names it in these variables instead. Each
// holds the URL of the server's maintenance database (for example .../postgres?sslmode=disable) with the user
// packmon:packmon, because the tests derive their role DSNs from that user part. The server must be a
// throwaway one: serviceTestPostgresDSN drops its packmon database and the serviceTestRoles.
const (
	// testPostgresURLEnv names a server started with pg_stat_statements preloaded, like the default container.
	testPostgresURLEnv = "PACKMON_TEST_POSTGRES_URL"
)

// serviceTestPostgresDSN returns the DSN of an empty packmon database on the server envName names, or false
// when the variable is unset and the caller starts its own container. Like a new container, the server is
// reset first: the previous test's packmon database and the roles of serviceTestRoles are dropped. Tests sharing
// one server therefore run one at a time (go test -p 1, no t.Parallel).
func serviceTestPostgresDSN(t *testing.T, envName string) (string, bool) {
	t.Helper()

	raw := os.Getenv(envName)
	if raw == "" {
		return "", false
	}
	target, err := url.Parse(raw)
	if err != nil || target.Scheme != "postgres" || target.User.String() != "packmon:packmon" {
		t.Fatalf("%s must be a postgres:// URL with the user packmon:packmon", envName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn := connectServiceTestPostgres(ctx, t, raw, envName)
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			t.Fatalf("close the %s connection: %v", envName, err)
		}
	}()
	resetServiceTestPostgres(ctx, t, conn, envName)

	target.Path = "/packmon"
	return target.String(), true
}

// serviceTestRoles are the roles the integration tests create (f103_f105_contracts_docker_test.go,
// f149_f152_migration_contracts_docker_test.go, migrator_docker_test.go). The reset drops only these, so a
// server named by mistake loses no other role; a test that creates a new role adds it here.
var serviceTestRoles = []string{"f104_limited", "packmon_f149", "packmon_migrator"}

func connectServiceTestPostgres(ctx context.Context, t *testing.T, raw, envName string) *pgx.Conn {
	t.Helper()

	for {
		conn, err := pgx.Connect(ctx, raw)
		if err == nil {
			return conn
		}
		select {
		case <-ctx.Done():
			t.Fatalf("connect to the %s server: %v", envName, err)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func resetServiceTestPostgres(ctx context.Context, t *testing.T, conn *pgx.Conn, envName string) {
	t.Helper()

	if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS packmon WITH (FORCE)`); err != nil {
		t.Fatalf("drop the previous packmon database on the %s server: %v", envName, err)
	}
	for _, role := range serviceTestRoles {
		if _, err := conn.Exec(ctx, `DROP ROLE IF EXISTS `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatalf("drop test role %q on the %s server: %v", role, envName, err)
		}
	}
	if _, err := conn.Exec(ctx, `CREATE DATABASE packmon`); err != nil {
		t.Fatalf("create the packmon database on the %s server: %v", envName, err)
	}
}
