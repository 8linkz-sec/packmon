//go:build integration

package postgres

import (
	"context"
	"strings"
	"testing"
)

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
		BEGIN
			IF lower(OLD.url) LIKE '%packetstorm.news%' THEN
				RAISE EXCEPTION 'F208 forced delete failure';
			END IF;
			RETURN OLD;
		END
		$$;
		CREATE TRIGGER f208_reject_reference_delete
			BEFORE DELETE ON vulnerability_references
			FOR EACH ROW EXECUTE FUNCTION f208_reject_reference_delete()`); err != nil {
		t.Fatalf("create F208 fixtures: %v", err)
	}

	removed, err := store.RemovePacketStormReferences(ctx)
	if err == nil || !strings.Contains(err.Error(), "postgres: remove Packet Storm references") || !strings.Contains(err.Error(), "F208 forced delete failure") {
		t.Fatalf("RemovePacketStormReferences(forced failure) = %d, %v; want wrapped trigger error", removed, err)
	}
	if removed != 0 {
		t.Fatalf("RemovePacketStormReferences(forced failure) removed = %d, want 0", removed)
	}
	assertF208ReferenceCount(t, ctx, store, 4)

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
	assertF208ReferenceCount(t, ctx, store, 1)

	removed, err = store.RemovePacketStormReferences(ctx)
	if err != nil {
		t.Fatalf("RemovePacketStormReferences(no-op) error = %v", err)
	}
	if removed != 0 {
		t.Fatalf("RemovePacketStormReferences(no-op) = %d, want 0", removed)
	}
	assertF208ReferenceCount(t, ctx, store, 1)
}

func assertF208ReferenceCount(t *testing.T, ctx context.Context, store *Store, want int) {
	t.Helper()

	var got int
	if err := store.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM vulnerability_references
		WHERE vulnerability_id = 'F208-REFS'`).Scan(&got); err != nil {
		t.Fatalf("count F208 references: %v", err)
	}
	if got != want {
		t.Fatalf("F208 reference count = %d, want %d", got, want)
	}
}
