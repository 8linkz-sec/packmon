package migrations

import (
	"strings"
	"testing"
)

// TestSplitSQLStatementsSplitsOnTopLevelSemicolons covers the base case. Each
// migration file is executed statement by statement, so a wrong split either
// runs a fragment (a syntax error) or merges two statements that must not share
// a transaction.
func TestSplitSQLStatementsSplitsOnTopLevelSemicolons(t *testing.T) {
	t.Parallel()

	statements, err := splitSQLStatements("CREATE TABLE a (id int); CREATE TABLE b (id int);")
	if err != nil {
		t.Fatalf("splitSQLStatements: %v", err)
	}
	if len(statements) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(statements), statements)
	}
	if statements[0] != "CREATE TABLE a (id int)" || statements[1] != "CREATE TABLE b (id int)" {
		t.Fatalf("statements = %q, want both trimmed and without the semicolon", statements)
	}
}

// TestSplitSQLStatementsDropsEmptyFragments keeps stray and trailing semicolons
// from producing empty statements, which the driver would reject.
func TestSplitSQLStatementsDropsEmptyFragments(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"",
		"   \n\t  ",
		";;;",
		"SELECT 1;;",
		"\n;\nSELECT 1;\n;\n",
	} {
		statements, err := splitSQLStatements(input)
		if err != nil {
			t.Errorf("splitSQLStatements(%q) = %v", input, err)
			continue
		}
		for _, statement := range statements {
			if strings.TrimSpace(statement) == "" {
				t.Errorf("splitSQLStatements(%q) produced an empty statement", input)
			}
		}
	}
}

// TestSplitSQLStatementsIgnoresSemicolonsInsideLiterals is the core correctness
// property: a semicolon inside a string or identifier is data, not a boundary.
// Splitting there would truncate the statement and execute a fragment.
func TestSplitSQLStatementsIgnoresSemicolonsInsideLiterals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "single quotes", input: `INSERT INTO t VALUES ('a;b');`},
		{name: "double-quoted identifier", input: `CREATE TABLE "weird;name" (id int);`},
		{name: "escaped single quote", input: `INSERT INTO t VALUES ('it''s; fine');`},
		{name: "escaped double quote", input: `CREATE TABLE "a""b;c" (id int);`},
	} {
		statements, err := splitSQLStatements(tc.input)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if len(statements) != 1 {
			t.Errorf("%s: got %d statements, want 1: %q", tc.name, len(statements), statements)
		}
	}
}

// TestSplitSQLStatementsIgnoresSemicolonsInsideComments covers both comment
// forms. Migration files carry explanatory comments, and a semicolon in prose
// must not split the statement it documents.
func TestSplitSQLStatementsIgnoresSemicolonsInsideComments(t *testing.T) {
	t.Parallel()

	lineComment := "-- first; second\nCREATE TABLE a (id int);"
	statements, err := splitSQLStatements(lineComment)
	if err != nil {
		t.Fatalf("line comment: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("line comment produced %d statements, want 1: %q", len(statements), statements)
	}

	blockComment := "/* first; second */ CREATE TABLE a (id int);"
	statements, err = splitSQLStatements(blockComment)
	if err != nil {
		t.Fatalf("block comment: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("block comment produced %d statements, want 1: %q", len(statements), statements)
	}

	// A comment between statements must not merge them either.
	between := "CREATE TABLE a (id int);\n-- note; here\nCREATE TABLE b (id int);"
	statements, err = splitSQLStatements(between)
	if err != nil {
		t.Fatalf("comment between statements: %v", err)
	}
	if len(statements) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(statements), statements)
	}
}

// TestSplitSQLStatementsKeepsDollarQuotedBodiesIntact is the case the dollar-tag
// scanner exists for. A PL/pgSQL function body is full of semicolons; splitting
// inside one would execute a fragment of the function.
func TestSplitSQLStatementsKeepsDollarQuotedBodiesIntact(t *testing.T) {
	t.Parallel()

	function := `CREATE FUNCTION f() RETURNS int AS $$
BEGIN
	PERFORM 1;
	PERFORM 2;
	RETURN 3;
END;
$$ LANGUAGE plpgsql;`

	statements, err := splitSQLStatements(function)
	if err != nil {
		t.Fatalf("splitSQLStatements: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("got %d statements, want the function body kept whole: %q", len(statements), statements)
	}
	if !strings.Contains(statements[0], "RETURN 3;") {
		t.Fatalf("statement lost its body:\n%s", statements[0])
	}
}

// TestSplitSQLStatementsHandlesNamedDollarTags covers the tagged form. The
// closing tag must match the opening one, so a `$$` inside a `$body$` block does
// not end it early.
func TestSplitSQLStatementsHandlesNamedDollarTags(t *testing.T) {
	t.Parallel()

	function := `CREATE FUNCTION f() RETURNS text AS $body$
	SELECT 'a $$ b';
$body$ LANGUAGE sql;
CREATE TABLE after (id int);`

	statements, err := splitSQLStatements(function)
	if err != nil {
		t.Fatalf("splitSQLStatements: %v", err)
	}
	if len(statements) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(statements), statements)
	}
	if !strings.Contains(statements[0], "$body$") {
		t.Errorf("first statement lost its dollar tag:\n%s", statements[0])
	}
	if !strings.HasPrefix(statements[1], "CREATE TABLE after") {
		t.Errorf("second statement = %q, want the statement after the function", statements[1])
	}
}

// TestSplitSQLStatementsTreatsABareDollarAsText covers the non-tag case: a `$`
// that does not open a valid tag is ordinary content, for example a positional
// parameter.
func TestSplitSQLStatementsTreatsABareDollarAsText(t *testing.T) {
	t.Parallel()

	statements, err := splitSQLStatements("UPDATE t SET a = $1 WHERE b = $2;")
	if err != nil {
		t.Fatalf("splitSQLStatements: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("got %d statements, want 1: %q", len(statements), statements)
	}
	if !strings.Contains(statements[0], "$1") || !strings.Contains(statements[0], "$2") {
		t.Fatalf("statement lost its placeholders: %q", statements[0])
	}
}

// TestSplitSQLStatementsRejectsUnterminatedConstructs is the fail-closed half. A
// truncated migration file must be refused rather than executed up to the point
// where it was cut off, which would leave the schema half-migrated.
func TestSplitSQLStatementsRejectsUnterminatedConstructs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "unterminated single quote", input: `INSERT INTO t VALUES ('oops;`},
		{name: "unterminated identifier", input: `CREATE TABLE "oops (id int);`},
		{name: "unterminated block comment", input: "/* note\nCREATE TABLE a (id int);"},
		{name: "unterminated dollar quote", input: "CREATE FUNCTION f() AS $$ BEGIN RETURN 1;"},
		{name: "unterminated named dollar quote", input: "CREATE FUNCTION f() AS $body$ SELECT 1;"},
	} {
		statements, err := splitSQLStatements(tc.input)
		if err == nil {
			t.Errorf("%s: splitSQLStatements = %q, nil; want an error", tc.name, statements)
		}
	}

	// An unterminated *line* comment is fine: end of file ends the comment.
	if _, err := splitSQLStatements("CREATE TABLE a (id int);\n-- trailing note"); err != nil {
		t.Errorf("a trailing line comment was rejected: %v", err)
	}
}

// TestReadDollarQuoteTagAcceptsOnlyValidTags covers the tag scanner directly.
// Misreading a tag either swallows the rest of the file as a quoted body or
// splits inside one.
func TestReadDollarQuoteTagAcceptsOnlyValidTags(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		"$$rest":          "$$",
		"$body$rest":      "$body$",
		"$BODY_1$rest":    "$BODY_1$",
		"$_$rest":         "$_$",
		"$tag9$SELECT 1;": "$tag9$",
	} {
		got, ok := readDollarQuoteTag(input)
		if !ok {
			t.Errorf("readDollarQuoteTag(%q) reported no tag", input)
			continue
		}
		if got != want {
			t.Errorf("readDollarQuoteTag(%q) = %q, want %q", input, got, want)
		}
	}

	for _, input := range []string{
		"",              // nothing to read
		"SELECT 1",      // does not start with $
		"$1",            // positional parameter, not a tag
		"$ta g$",        // space is not a tag character
		"$ta-g$",        // dash is not a tag character
		"$unterminated", // no closing dollar
	} {
		if got, ok := readDollarQuoteTag(input); ok {
			t.Errorf("readDollarQuoteTag(%q) = %q, true; want no tag", input, got)
		}
	}
}

// TestIsDollarQuoteTagCharMatchesPostgresIdentifierRules pins the character set
// a dollar tag may use. Accepting too much would turn `$1` into a tag opener.
func TestIsDollarQuoteTagCharMatchesPostgresIdentifierRules(t *testing.T) {
	t.Parallel()

	for _, ch := range []byte("abcxyzABCXYZ0189_") {
		if !isDollarQuoteTagChar(ch) {
			t.Errorf("isDollarQuoteTagChar(%q) = false, want it accepted", string(ch))
		}
	}
	for _, ch := range []byte(" \t\n-.$'\"/*;") {
		if isDollarQuoteTagChar(ch) {
			t.Errorf("isDollarQuoteTagChar(%q) = true, want it rejected", string(ch))
		}
	}
}

// TestSplitSQLStatementsHandlesARealisticMigration exercises the states together
// on a file shaped like the ones in this repository.
func TestSplitSQLStatementsHandlesARealisticMigration(t *testing.T) {
	t.Parallel()

	migration := `-- 0042_add_audit_digest.sql
-- Adds the digest chain; see docs/runbook.md.

ALTER TABLE admin_audit_log
	ADD COLUMN row_digest text NOT NULL DEFAULT '';

/* The trigger keeps the chain append-only;
   it must not be split. */
CREATE OR REPLACE FUNCTION audit_digest() RETURNS trigger AS $fn$
BEGIN
	NEW.row_digest := encode(digest(NEW.details::text, 'sha256'), 'hex');
	RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TRIGGER audit_digest_trg
	BEFORE INSERT ON admin_audit_log
	FOR EACH ROW EXECUTE FUNCTION audit_digest();`

	statements, err := splitSQLStatements(migration)
	if err != nil {
		t.Fatalf("splitSQLStatements: %v", err)
	}
	if len(statements) != 3 {
		t.Fatalf("got %d statements, want 3:\n%q", len(statements), statements)
	}
	if !strings.Contains(statements[1], "RETURN NEW;") {
		t.Errorf("the function body was split:\n%s", statements[1])
	}
	if !strings.HasPrefix(statements[2], "CREATE TRIGGER") {
		t.Errorf("third statement = %q, want the trigger", statements[2])
	}
}
