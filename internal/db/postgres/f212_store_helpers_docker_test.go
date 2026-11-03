//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestF212WithTxTransactionBoundaries(t *testing.T) {
	store, dsn := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, err := store.pool.Exec(ctx, `
		CREATE TABLE f212_tx_events (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE f212_tx_parents (
			id INTEGER PRIMARY KEY
		);
		CREATE TABLE f212_tx_children (
			id TEXT PRIMARY KEY,
			parent_id INTEGER NOT NULL REFERENCES f212_tx_parents(id) DEFERRABLE INITIALLY DEFERRED
		)`); err != nil {
		t.Fatalf("create F212 transaction fixtures: %v", err)
	}

	countRows := func(t *testing.T, label, query string) int {
		t.Helper()
		var count int
		if err := store.pool.QueryRow(ctx, query).Scan(&count); err != nil {
			t.Fatalf("count %s rows: %v", label, err)
		}
		return count
	}

	t.Run("callback error rolls back and is preserved", func(t *testing.T) {
		marker := errors.New("f212 callback failure")
		err := withTx(ctx, store.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO f212_tx_events(id) VALUES ('rolled-back')`); err != nil {
				return err
			}
			return marker
		})
		if !errors.Is(err, marker) {
			t.Fatalf("withTx(callback error) = %v, want marker", err)
		}
		if got := countRows(t, "events", `SELECT COUNT(*)::int FROM f212_tx_events`); got != 0 {
			t.Fatalf("rows after callback error = %d, want 0", got)
		}
	})

	t.Run("successful callback commits before return", func(t *testing.T) {
		err := withTx(ctx, store.pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO f212_tx_events(id) VALUES ('committed')`)
			return err
		})
		if err != nil {
			t.Fatalf("withTx(success) error = %v", err)
		}
		if got := countRows(t, "events", `SELECT COUNT(*)::int FROM f212_tx_events`); got != 1 {
			t.Fatalf("rows after successful callback = %d, want 1", got)
		}
	})

	t.Run("deferred constraint failure is reported as commit failure", func(t *testing.T) {
		err := withTx(ctx, store.pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO f212_tx_children(id,parent_id) VALUES ('deferred-failure', 212)`)
			return err
		})
		var pgErr *pgconn.PgError
		if err == nil || !strings.Contains(err.Error(), "commit tx:") || !errors.As(err, &pgErr) || pgErr.Code != "23503" {
			t.Fatalf("withTx(deferred constraint) = %v, want wrapped commit SQLSTATE 23503", err)
		}
		if got := countRows(t, "children", `SELECT COUNT(*)::int FROM f212_tx_children`); got != 0 {
			t.Fatalf("rows after failed commit = %d, want 0", got)
		}
	})

	t.Run("begin failure does not invoke callback", func(t *testing.T) {
		closedPool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("pgxpool.New() error = %v", err)
		}
		closedPool.Close()

		called := false
		err = withTx(ctx, closedPool, func(pgx.Tx) error {
			called = true
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "begin tx:") {
			t.Fatalf("withTx(closed pool) = %v, want begin context", err)
		}
		if called {
			t.Fatal("withTx(closed pool) invoked callback")
		}
	})
}
