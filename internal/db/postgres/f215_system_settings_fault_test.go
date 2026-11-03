package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
)

type f215SystemSettingsExecer struct {
	query string
	args  []any
	tag   pgconn.CommandTag
	err   error
	calls int
}

func (e *f215SystemSettingsExecer) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	e.calls++
	e.query = query
	e.args = append([]any(nil), args...)
	return e.tag, e.err
}

func TestF215SystemSettingsWriteRoutesArgumentsAndFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if _, ok := expectedSystemSettingsUpdatedAt(nil); ok {
		t.Fatal("expectedSystemSettingsUpdatedAt(nil) unexpectedly found a revision")
	}
	if _, ok := expectedSystemSettingsUpdatedAt(&db.SystemSettings{}); ok {
		t.Fatal("expectedSystemSettingsUpdatedAt(empty) unexpectedly found a revision")
	}
	settings := &db.SystemSettings{
		BlockThreshold:      "HIGH",
		RateLimitPerMinute:  121,
		RateLimitBurst:      31,
		ScanLogRetention:    90*time.Second + 999*time.Millisecond,
		AdminAuditRetention: 48*time.Hour + 500*time.Millisecond,
	}
	wantBaseArgs := []any{"HIGH", 121, 31, int64(90), int64(172800)}

	t.Run("unrevisioned upsert succeeds with whole-second retention", func(t *testing.T) {
		t.Parallel()
		execer := &f215SystemSettingsExecer{tag: pgconn.NewCommandTag("INSERT 0 1")}
		if err := upsertSystemSettingsTx(ctx, execer, settings); err != nil {
			t.Fatalf("upsertSystemSettingsTx() error = %v", err)
		}
		if execer.calls != 1 || !strings.Contains(execer.query, "ON CONFLICT (id) DO UPDATE") {
			t.Fatalf("Exec calls/query = %d/%q, want one unconditional upsert", execer.calls, execer.query)
		}
		if !reflect.DeepEqual(execer.args, wantBaseArgs) {
			t.Fatalf("Exec args = %#v, want %#v", execer.args, wantBaseArgs)
		}
	})

	t.Run("write without revision routes through unconditional upsert", func(t *testing.T) {
		t.Parallel()
		execer := &f215SystemSettingsExecer{tag: pgconn.NewCommandTag("INSERT 0 1")}
		if err := writeSystemSettingsAtRevisionTx(ctx, execer, settings); err != nil {
			t.Fatalf("writeSystemSettingsAtRevisionTx() error = %v", err)
		}
		if execer.calls != 1 || !strings.Contains(execer.query, "ON CONFLICT (id) DO UPDATE") || !reflect.DeepEqual(execer.args, wantBaseArgs) {
			t.Fatalf("unrevisioned Exec calls/query/args = %d/%q/%#v", execer.calls, execer.query, execer.args)
		}
	})

	t.Run("unrevisioned upsert wraps driver failure", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("settings write failed")
		execer := &f215SystemSettingsExecer{err: sentinel}
		err := upsertSystemSettingsTx(ctx, execer, settings)
		if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "postgres: upsert system settings") {
			t.Fatalf("upsertSystemSettingsTx() error = %v, want wrapped driver failure", err)
		}
		if !reflect.DeepEqual(execer.args, wantBaseArgs) {
			t.Fatalf("Exec args = %#v, want %#v", execer.args, wantBaseArgs)
		}
	})

	t.Run("explicit absent revision uses insert-only statement", func(t *testing.T) {
		t.Parallel()
		zero := time.Time{}
		input := *settings
		input.ExpectedUpdatedAt = &zero
		execer := &f215SystemSettingsExecer{tag: pgconn.NewCommandTag("INSERT 0 1")}
		if err := writeSystemSettingsAtRevisionTx(ctx, execer, &input); err != nil {
			t.Fatalf("writeSystemSettingsAtRevisionTx() error = %v", err)
		}
		if execer.calls != 1 || !strings.Contains(execer.query, "ON CONFLICT (id) DO NOTHING") {
			t.Fatalf("Exec calls/query = %d/%q, want one insert-only write", execer.calls, execer.query)
		}
		if !reflect.DeepEqual(execer.args, wantBaseArgs) {
			t.Fatalf("Exec args = %#v, want %#v", execer.args, wantBaseArgs)
		}
	})

	t.Run("explicit absent revision reports conflict when row exists", func(t *testing.T) {
		t.Parallel()
		zero := time.Time{}
		input := *settings
		input.ExpectedUpdatedAt = &zero
		execer := &f215SystemSettingsExecer{tag: pgconn.NewCommandTag("INSERT 0 0")}
		if err := writeSystemSettingsAtRevisionTx(ctx, execer, &input); !errors.Is(err, db.ErrConflict) {
			t.Fatalf("writeSystemSettingsAtRevisionTx() error = %v, want ErrConflict", err)
		}
	})

	t.Run("matching revision is normalized to UTC", func(t *testing.T) {
		t.Parallel()
		zone := time.FixedZone("fixture", 3*60*60)
		expected := time.Date(2026, 11, 3, 12, 30, 0, 123000000, zone)
		input := *settings
		input.ExpectedUpdatedAt = &expected
		execer := &f215SystemSettingsExecer{tag: pgconn.NewCommandTag("UPDATE 1")}
		if err := writeSystemSettingsAtRevisionTx(ctx, execer, &input); err != nil {
			t.Fatalf("writeSystemSettingsAtRevisionTx() error = %v", err)
		}
		wantArgs := append(append([]any(nil), wantBaseArgs...), expected.UTC())
		if execer.calls != 1 || !strings.Contains(execer.query, "updated_at = $6") || !reflect.DeepEqual(execer.args, wantArgs) {
			t.Fatalf("revision Exec calls/query/args = %d/%q/%#v, want UTC revision %#v", execer.calls, execer.query, execer.args, wantArgs)
		}
	})

	t.Run("updated-at fallback routes through revision update", func(t *testing.T) {
		t.Parallel()
		expected := time.Date(2026, 11, 3, 9, 15, 0, 456000000, time.UTC)
		input := *settings
		input.UpdatedAt = expected
		execer := &f215SystemSettingsExecer{tag: pgconn.NewCommandTag("UPDATE 1")}
		if err := writeSystemSettingsAtRevisionTx(ctx, execer, &input); err != nil {
			t.Fatalf("writeSystemSettingsAtRevisionTx() error = %v", err)
		}
		wantArgs := append(append([]any(nil), wantBaseArgs...), expected)
		if !reflect.DeepEqual(execer.args, wantArgs) {
			t.Fatalf("revision Exec args = %#v, want %#v", execer.args, wantArgs)
		}
	})
}
