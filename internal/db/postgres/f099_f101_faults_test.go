package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type f099ScriptedRow struct {
	scan func(...any) error
}

func (r f099ScriptedRow) Scan(dest ...any) error {
	if r.scan == nil {
		return nil
	}
	return r.scan(dest...)
}

type f099ScriptedTx struct {
	pgx.Tx
	exec     func(string, ...any) (pgconn.CommandTag, error)
	queryRow func(string, ...any) pgx.Row
}

func (tx *f099ScriptedTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if tx.exec == nil {
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	return tx.exec(sql, args...)
}

func (tx *f099ScriptedTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if tx.queryRow == nil {
		return f099ScriptedRow{}
	}
	return tx.queryRow(sql, args...)
}

type f099ScriptedExecer struct {
	exec func(string, ...any) (pgconn.CommandTag, error)
}

func (e f099ScriptedExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return e.exec(sql, args...)
}

type f099ScriptedQuerier struct {
	row pgx.Row
}

func (q f099ScriptedQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return q.row
}

func f099SuccessfulAuditTx(t *testing.T, action string) *f099ScriptedTx {
	t.Helper()
	createdAt := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	return &f099ScriptedTx{
		exec: func(_ string, _ ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
		queryRow: func(sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "nextval"):
				return f099ScriptedRow{scan: func(dest ...any) error {
					*(dest[0].(*int)) = 17
					return nil
				}}
			case strings.Contains(sql, "SELECT row_digest"):
				return f099ScriptedRow{scan: func(...any) error { return pgx.ErrNoRows }}
			case strings.Contains(sql, "INSERT INTO admin_audit_log"):
				return f099ScriptedRow{scan: func(dest ...any) error {
					*(dest[0].(*string)) = `{"phase":"test"}`
					*(dest[1].(*string)) = "2001:db8::1"
					*(dest[2].(*string)) = "corr-f099"
					*(dest[3].(*time.Time)) = createdAt
					return nil
				}}
			default:
				t.Fatalf("unexpected QueryRow for %s: %s", action, strings.Join(strings.Fields(sql), " "))
				return f099ScriptedRow{scan: func(...any) error { return errors.New("unexpected query") }}
			}
		},
	}
}

func TestF099AdminAuthAuditFailureBranches(t *testing.T) {
	ctx := context.Background()
	audit := func(action string) *db.AdminAuditEntry {
		return &db.AdminAuditEntry{Action: action, Details: []byte(`{"phase":"test"}`), IP: "2001:db8::1", CorrelationID: "corr-f099"}
	}

	t.Run("pipeline success", func(t *testing.T) {
		tx := f099SuccessfulAuditTx(t, "password_change")
		mutations := 0
		err := runAdminAuthAuditMutationTx(ctx, tx, func() error {
			mutations++
			return nil
		}, audit("password_change"))
		if err != nil || mutations != 1 {
			t.Fatalf("runAdminAuthAuditMutationTx() = %v, mutations = %d; want nil, 1", err, mutations)
		}
	})

	t.Run("auth lock", func(t *testing.T) {
		want := errors.New("lock failed")
		tx := &f099ScriptedTx{exec: func(string, ...any) (pgconn.CommandTag, error) { return pgconn.CommandTag{}, want }}
		mutated := false
		err := runAdminAuthAuditMutationTx(ctx, tx, func() error { mutated = true; return nil }, audit("password_change"))
		if !errors.Is(err, want) || mutated {
			t.Fatalf("runAdminAuthAuditMutationTx() = %v, mutated = %t", err, mutated)
		}
	})

	t.Run("mutation", func(t *testing.T) {
		want := errors.New("mutation failed")
		err := runAdminAuthAuditMutationTx(ctx, &f099ScriptedTx{}, func() error { return want }, audit("password_change"))
		if !errors.Is(err, want) {
			t.Fatalf("runAdminAuthAuditMutationTx() = %v, want wrapped %v", err, want)
		}
	})

	t.Run("audit", func(t *testing.T) {
		err := runAdminAuthAuditMutationTx(ctx, &f099ScriptedTx{}, func() error { return nil }, nil)
		if !errors.Is(err, db.ErrAdminAuditLog) || !strings.Contains(err.Error(), errNilAdminAuditEntry.Error()) {
			t.Fatalf("runAdminAuthAuditMutationTx() = %v, want admin audit error", err)
		}
	})

	t.Run("password exec", func(t *testing.T) {
		want := errors.New("password update failed")
		err := changeAdminPasswordTx(ctx, f099ScriptedExecer{exec: func(string, ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, want
		}}, "new", "old")
		if !errors.Is(err, want) {
			t.Fatalf("changeAdminPasswordTx() = %v, want wrapped %v", err, want)
		}
	})

	t.Run("password conflict", func(t *testing.T) {
		err := changeAdminPasswordTx(ctx, f099ScriptedExecer{exec: func(string, ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}}, "new", "old")
		if !errors.Is(err, db.ErrAdminAuthConflict) {
			t.Fatalf("changeAdminPasswordTx() = %v, want ErrAdminAuthConflict", err)
		}
	})

	t.Run("login lock", func(t *testing.T) {
		want := errors.New("login lock failed")
		tx := &f099ScriptedTx{exec: func(sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "SELECT id FROM admin_auth") {
				return pgconn.CommandTag{}, want
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}}
		err := insertAdminAuditLogTx(ctx, tx, audit("login_success"))
		if !errors.Is(err, want) {
			t.Fatalf("insertAdminAuditLogTx() = %v, want wrapped %v", err, want)
		}
	})

	t.Run("sequence reserve", func(t *testing.T) {
		want := errors.New("sequence failed")
		tx := &f099ScriptedTx{queryRow: func(string, ...any) pgx.Row {
			return f099ScriptedRow{scan: func(...any) error { return want }}
		}}
		err := insertAdminAuditLogTx(ctx, tx, audit("password_change"))
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "reserve admin audit id") {
			t.Fatalf("insertAdminAuditLogTx() = %v, want sequence error", err)
		}
	})

	t.Run("predecessor read", func(t *testing.T) {
		want := errors.New("predecessor failed")
		calls := 0
		tx := &f099ScriptedTx{queryRow: func(string, ...any) pgx.Row {
			calls++
			if calls == 1 {
				return f099ScriptedRow{scan: func(dest ...any) error { *(dest[0].(*int)) = 18; return nil }}
			}
			return f099ScriptedRow{scan: func(...any) error { return want }}
		}}
		err := insertAdminAuditLogTx(ctx, tx, audit("password_change"))
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "read previous admin audit digest") {
			t.Fatalf("insertAdminAuditLogTx() = %v, want predecessor error", err)
		}
	})

	t.Run("insert returning", func(t *testing.T) {
		want := errors.New("insert failed")
		calls := 0
		tx := &f099ScriptedTx{queryRow: func(string, ...any) pgx.Row {
			calls++
			switch calls {
			case 1:
				return f099ScriptedRow{scan: func(dest ...any) error { *(dest[0].(*int)) = 19; return nil }}
			case 2:
				return f099ScriptedRow{scan: func(...any) error { return pgx.ErrNoRows }}
			default:
				return f099ScriptedRow{scan: func(...any) error { return want }}
			}
		}}
		err := insertAdminAuditLogTx(ctx, tx, audit("password_change"))
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "insert admin audit log") {
			t.Fatalf("insertAdminAuditLogTx() = %v, want insert error", err)
		}
	})

	t.Run("digest update", func(t *testing.T) {
		want := errors.New("digest failed")
		tx := f099SuccessfulAuditTx(t, "password_change")
		tx.exec = func(sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "UPDATE admin_audit_log SET row_digest") {
				return pgconn.CommandTag{}, want
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		err := insertAdminAuditLogTx(ctx, tx, audit("password_change"))
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "update admin audit digest") {
			t.Fatalf("insertAdminAuditLogTx() = %v, want digest error", err)
		}
	})

	t.Run("login timestamp", func(t *testing.T) {
		want := errors.New("login timestamp failed")
		tx := f099SuccessfulAuditTx(t, "login_success")
		tx.exec = func(sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "UPDATE admin_auth SET last_login_at") {
				return pgconn.CommandTag{}, want
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		err := insertAdminAuditLogTx(ctx, tx, audit("login_success"))
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "update admin last_login_at") {
			t.Fatalf("insertAdminAuditLogTx() = %v, want login timestamp error", err)
		}
	})
}

func TestF101APIKeyHelperFailureBranches(t *testing.T) {
	ctx := context.Background()
	want := errors.New("driver failed")

	t.Run("create scan", func(t *testing.T) {
		id, err := createAPIKeyTx(ctx, f099ScriptedQuerier{row: f099ScriptedRow{scan: func(...any) error { return want }}}, "ci", "hash", nil)
		if id != 0 || !errors.Is(err, want) {
			t.Fatalf("createAPIKeyTx() = %d, %v; want 0, wrapped %v", id, err, want)
		}
	})

	tests := []struct {
		name string
		call func(postgresExecer) error
	}{
		{name: "revoke exec", call: func(e postgresExecer) error { return revokeAPIKeyTx(ctx, e, 7) }},
		{name: "revoke zero", call: func(e postgresExecer) error { return revokeAPIKeyTx(ctx, e, 7) }},
		{name: "delete exec", call: func(e postgresExecer) error { return deleteAPIKeyTx(ctx, e, 7) }},
		{name: "delete zero", call: func(e postgresExecer) error { return deleteAPIKeyTx(ctx, e, 7) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isExecFailure := strings.HasSuffix(tt.name, "exec")
			execer := f099ScriptedExecer{exec: func(string, ...any) (pgconn.CommandTag, error) {
				if isExecFailure {
					return pgconn.CommandTag{}, want
				}
				return pgconn.NewCommandTag("UPDATE 0"), nil
			}}
			err := tt.call(execer)
			if err == nil {
				t.Fatalf("%s returned nil error", tt.name)
			}
			if isExecFailure && !errors.Is(err, want) {
				t.Fatalf("%s error = %v, want wrapped %v", tt.name, err, want)
			}
			if !isExecFailure && !strings.Contains(err.Error(), fmt.Sprintf("API key %d", 7)) {
				t.Fatalf("%s error = %v, want key id", tt.name, err)
			}
		})
	}
}
