package postgres

import (
	"errors"
	"fmt"
	"strings"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
)

// postgresCheckViolation is SQLSTATE check_violation: a row value failed a
// CHECK constraint such as the version JSON shape checks.
const postgresCheckViolation = "23514"

// classifyFeedImportDataError marks err as db.ErrInvalidFeedImportData when
// PostgreSQL refused the imported values themselves: any data exception (SQLSTATE
// class 22, for example a real underflow, a NUL byte in text or an unsupported
// \u0000 escape in jsonb) or a CHECK violation. Every other error, including
// connection loss, cancellation and unique/foreign-key conflicts, is returned
// unchanged so it keeps surfacing as a server-side failure.
func classifyFeedImportDataError(err error) error {
	if err == nil || errors.Is(err, db.ErrInvalidFeedImportData) {
		return err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (strings.HasPrefix(pgErr.Code, "22") || pgErr.Code == postgresCheckViolation) {
		return fmt.Errorf("%w: %w", db.ErrInvalidFeedImportData, err)
	}
	return err
}

// invalidFeedImportDataf builds a store-side validation error for imported
// values that is recognizable as db.ErrInvalidFeedImportData.
func invalidFeedImportDataf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", db.ErrInvalidFeedImportData, fmt.Sprintf(format, args...))
}
