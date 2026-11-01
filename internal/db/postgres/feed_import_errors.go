package postgres

import (
	"errors"
	"fmt"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
)

// feedImportDataErrorCodes are the SQLSTATE codes that mean PostgreSQL refused
// an imported value itself. Other data exceptions (class 22, for example
// division by zero or an invalid parameter value) point at a query or server
// problem and stay server errors.
var feedImportDataErrorCodes = map[string]struct{}{
	"22001": {}, // string_data_right_truncation: value too long for the column
	"22003": {}, // numeric_value_out_of_range, including a real underflow
	"22007": {}, // invalid_datetime_format
	"22008": {}, // datetime_field_overflow
	"22021": {}, // character_not_in_repertoire: a NUL byte in text
	"22P02": {}, // invalid_text_representation
	"22P05": {}, // untranslatable_character: a \u0000 escape in jsonb
	"23514": {}, // check_violation, such as the version JSON shape checks
}

// classifyFeedImportDataError marks err as db.ErrInvalidFeedImportData when
// PostgreSQL refused the imported values themselves (feedImportDataErrorCodes).
// Every other error, including connection loss, cancellation, unique and
// foreign-key conflicts and other data exceptions, is returned unchanged so it
// keeps surfacing as a server-side failure.
func classifyFeedImportDataError(err error) error {
	if err == nil || errors.Is(err, db.ErrInvalidFeedImportData) {
		return err
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	if _, ok := feedImportDataErrorCodes[pgErr.Code]; ok {
		return fmt.Errorf("%w: %w", db.ErrInvalidFeedImportData, err)
	}
	return err
}

// invalidFeedImportDataf builds a store-side validation error for imported
// values that is recognizable as db.ErrInvalidFeedImportData.
func invalidFeedImportDataf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", db.ErrInvalidFeedImportData, fmt.Sprintf(format, args...))
}
