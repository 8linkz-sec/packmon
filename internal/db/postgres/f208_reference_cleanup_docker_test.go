//go:build integration

package postgres

import (
	"context"
	"slices"
	"strings"
	"testing"
)

type f208ReferenceRow struct {
	id              int64
	vulnerabilityID string
	referenceType   string
	url             string
	source          string
}

func TestF208RemovePacketStormReferencesIsAtomicAndRepeatable(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ('F208-REFS', 'F208 reference cleanup fixture', 'LOW', clock_timestamp(), clock_timestamp());
		INSERT INTO vulnerability_references(vulnerability_id, type, url, source) VALUES
			('F208-REFS', 'WEB', 'https://packetstormsecurity.com/files/100/first.html', 'f208'),
			('F208-REFS', 'WEB', 'HTTPS://PACKETSTORM.NEWS/files/200/second.html', 'f208'),
			('F208-REFS', 'WEB', 'https://example.com/packetstormsecurity.com-is-a-path', 'f208'),
			('F208-REFS', 'WEB', 'https://example.com/advisory', 'f208');
		CREATE FUNCTION f208_reject_reference_delete() RETURNS trigger LANGUAGE plpgsql AS $$
		DECLARE
			remaining_targets integer;
		BEGIN
			SELECT COUNT(*) INTO remaining_targets
			FROM vulnerability_references
			WHERE lower(url) LIKE '%packetstormsecurity.com%'
			   OR lower(url) LIKE '%packetstorm.news%';
			IF remaining_targets <> 0 THEN
				RAISE EXCEPTION 'F208 cleanup left % matching references before rollback', remaining_targets;
			END IF;
			RAISE EXCEPTION 'F208 forced delete failure after deleting all matching references';
			RETURN NULL;
		END
		$$;
		CREATE TRIGGER f208_reject_reference_delete
			AFTER DELETE ON vulnerability_references
			FOR EACH STATEMENT EXECUTE FUNCTION f208_reject_reference_delete()`); err != nil {
		t.Fatalf("create F208 fixtures: %v", err)
	}
	before := readF208References(t, ctx, store)
	assertF208SeedReferences(t, before)

	removed, err := store.RemovePacketStormReferences(ctx)
	if err == nil || !strings.Contains(err.Error(), "postgres: remove Packet Storm references") ||
		!strings.Contains(err.Error(), "F208 forced delete failure after deleting all matching references") {
		t.Fatalf("RemovePacketStormReferences(forced failure) = %d, %v; want wrapped trigger error", removed, err)
	}
	if removed != 0 {
		t.Fatalf("RemovePacketStormReferences(forced failure) removed = %d, want 0", removed)
	}
	if afterFailure := readF208References(t, ctx, store); !slices.Equal(afterFailure, before) {
		t.Fatalf("references after forced failure = %#v, want exact pre-delete rows %#v", afterFailure, before)
	}

	if _, err := store.pool.Exec(ctx, `
		DROP TRIGGER f208_reject_reference_delete ON vulnerability_references;
		DROP FUNCTION f208_reject_reference_delete()`); err != nil {
		t.Fatalf("remove F208 failure trigger: %v", err)
	}

	removed, err = store.RemovePacketStormReferences(ctx)
	if err != nil {
		t.Fatalf("RemovePacketStormReferences(success) error = %v", err)
	}
	if removed != 3 {
		t.Fatalf("RemovePacketStormReferences(success) = %d, want 3", removed)
	}
	wantSurvivors := []f208ReferenceRow{before[3]}
	if afterSuccess := readF208References(t, ctx, store); !slices.Equal(afterSuccess, wantSurvivors) {
		t.Fatalf("references after cleanup = %#v, want exact unrelated row %#v", afterSuccess, wantSurvivors)
	}

	removed, err = store.RemovePacketStormReferences(ctx)
	if err != nil {
		t.Fatalf("RemovePacketStormReferences(no-op) error = %v", err)
	}
	if removed != 0 {
		t.Fatalf("RemovePacketStormReferences(no-op) = %d, want 0", removed)
	}
	if afterNoop := readF208References(t, ctx, store); !slices.Equal(afterNoop, wantSurvivors) {
		t.Fatalf("references after repeated cleanup = %#v, want unchanged row %#v", afterNoop, wantSurvivors)
	}
}

func readF208References(t *testing.T, ctx context.Context, store *Store) []f208ReferenceRow {
	t.Helper()

	rows, err := store.pool.Query(ctx, `
		SELECT id, vulnerability_id, COALESCE(type, ''), url, source
		FROM vulnerability_references
		WHERE vulnerability_id = 'F208-REFS'
		ORDER BY id`)
	if err != nil {
		t.Fatalf("query F208 references: %v", err)
	}
	defer rows.Close()

	var got []f208ReferenceRow
	for rows.Next() {
		var row f208ReferenceRow
		if err := rows.Scan(&row.id, &row.vulnerabilityID, &row.referenceType, &row.url, &row.source); err != nil {
			t.Fatalf("scan F208 reference: %v", err)
		}
		got = append(got, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate F208 references: %v", err)
	}
	return got
}

func assertF208SeedReferences(t *testing.T, got []f208ReferenceRow) {
	t.Helper()

	wantURLs := []string{
		"https://packetstormsecurity.com/files/100/first.html",
		"HTTPS://PACKETSTORM.NEWS/files/200/second.html",
		"https://example.com/packetstormsecurity.com-is-a-path",
		"https://example.com/advisory",
	}
	if len(got) != len(wantURLs) {
		t.Fatalf("seed reference count = %d, want %d: %#v", len(got), len(wantURLs), got)
	}
	for i, row := range got {
		if row.id <= 0 || (i > 0 && row.id <= got[i-1].id) {
			t.Fatalf("seed reference IDs are not positive and increasing: %#v", got)
		}
		if row.vulnerabilityID != "F208-REFS" || row.referenceType != "WEB" || row.url != wantURLs[i] || row.source != "f208" {
			t.Fatalf("seed reference %d = %#v, want advisory F208-REFS, type WEB, URL %q, source f208", i, row, wantURLs[i])
		}
	}
}
