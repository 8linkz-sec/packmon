package migrations

import (
	"context"
	"strings"
	"testing"
)

func TestF203NoTransactionMigrationRejectsMalformedSQLBeforeExecution(t *testing.T) {
	t.Parallel()

	recorder := &recordingSQLExecutor{}
	err := applyMigrationWithoutTransaction(context.Background(), recorder, migrationFile{
		name: "901_malformed.up.sql",
		sql:  "SELECT 'unterminated",
	})
	if err == nil || !strings.Contains(err.Error(), "parse 901_malformed.up.sql") || !strings.Contains(err.Error(), "unterminated SQL statement") {
		t.Fatalf("applyMigrationWithoutTransaction() error = %v, want named parse failure", err)
	}
	if len(recorder.statements) != 0 {
		t.Fatalf("executed statements after parse failure = %#v, want none", recorder.statements)
	}
}
