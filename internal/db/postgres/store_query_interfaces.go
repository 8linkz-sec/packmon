package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type postgresQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type postgresExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type postgresQueryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
