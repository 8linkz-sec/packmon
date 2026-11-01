//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestFeedImportsReportDatabaseDataRejectionsAsInvalidData drives values that
// pass every handler and store check but that PostgreSQL itself refuses. Each
// import must fail as db.ErrInvalidFeedImportData (a client error) and leave the
// stored enrichment untouched, instead of surfacing as an opaque store failure.
func TestFeedImportsReportDatabaseDataRejectionsAsInvalidData(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	id := seedEnrichmentCVE(t, store, "CVE-2026-7100")
	audit := func(int, int) db.AdminAuditEntry {
		return db.AdminAuditEntry{Action: "feed.import", IP: "127.0.0.1"}
	}

	// A score inside [0, 1] that is too small for the real column underflows.
	if _, _, err := store.ImportEPSSWithAudit(ctx, "epss", []db.EPSSEntry{{CVEID: id, Score: 1e-50, Percentile: 0.5}}, nil, audit); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("ImportEPSSWithAudit(underflowing score) error = %v, want ErrInvalidFeedImportData", err)
	}
	if _, _, _, err := store.ImportEPSSStreamWithAudit(ctx, "epss", func(yield func([]db.EPSSEntry) error) (*db.FeedSyncStatus, error) {
		return nil, yield([]db.EPSSEntry{{CVEID: id, Score: 0.5, Percentile: 1e-50}})
	}, audit); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("ImportEPSSStreamWithAudit(underflowing percentile) error = %v, want ErrInvalidFeedImportData", err)
	}
	if epss, percentile, _, _ := readEnrichment(t, store, id); epss != nil || percentile != nil {
		t.Fatalf("EPSS after rejected imports = (%v, %v), want untouched NULLs", epss, percentile)
	}

	// A NUL byte is valid JSON but not storable in a PostgreSQL text column.
	nulURL := "https://example.invalid/\x00"
	if _, err := store.ImportVulnCheckWithAudit(ctx, "vulncheck", []db.VulnCheckEntry{{CVEID: id, ExploitExists: true, SourceURL: nulURL}}, nil, audit); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("ImportVulnCheckWithAudit(NUL source URL) error = %v, want ErrInvalidFeedImportData", err)
	}
	if _, _, err := store.ImportVulnCheckStreamWithAudit(ctx, "vulncheck", func(yield func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error) {
		return nil, 1, yield([]db.VulnCheckEntry{{CVEID: id, ExploitExists: true, RawJSON: []byte(`{"note":"\u0000"}`)}})
	}, audit); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("ImportVulnCheckStreamWithAudit(NUL escape in raw_json) error = %v, want ErrInvalidFeedImportData", err)
	}
	if _, _, exploit, _ := readEnrichment(t, store, id); exploit {
		t.Fatal("exploit_exists committed by a rejected VulnCheck import")
	}

	// The CVE IDs are valid; the client-supplied status text is not storable.
	nulStatus := &db.FeedSyncStatus{FeedName: "cisakev", LastSyncStatus: "rejected", LastError: "bad\x00status"}
	if _, err := store.ImportCISAKEVWithAudit(ctx, "cisakev", []string{id}, nulStatus, audit); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("ImportCISAKEVWithAudit(NUL status) error = %v, want ErrInvalidFeedImportData", err)
	}
	if _, _, err := store.ReplaceCISAKEVWithAudit(ctx, "cisakev", []string{id}, nulStatus, audit); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("ReplaceCISAKEVWithAudit(NUL status) error = %v, want ErrInvalidFeedImportData", err)
	}
	if _, _, _, kev := readEnrichment(t, store, id); kev {
		t.Fatal("cisa_kev committed by a rejected CISA KEV import")
	}

	// A plain store failure must not be reclassified as a data problem.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ImportCISAKEVWithAudit(canceled, "cisakev", []string{id}, nil, audit); err == nil || errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("ImportCISAKEVWithAudit(canceled) error = %v, want a non-data failure", err)
	}
}
