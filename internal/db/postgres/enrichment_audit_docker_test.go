//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// seedEnrichmentCVE stores one advisory the enrichment importers can attach to,
// and returns its ID. Enrichment only updates existing rows, so without a seed
// every importer would legitimately report zero updates and the tests would pass
// without exercising anything.
func seedEnrichmentCVE(t *testing.T, store *Store, id string) string {
	t.Helper()

	now := time.Now().UTC()
	if _, _, err := store.ImportVulnerabilityFeed(context.Background(), "osv", []db.Vulnerability{{
		ID:        id,
		Summary:   "enrichment fixture",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: id}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npm",
			Name:      "enrichment-fixture",
		}},
	}}, nil, nil); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	return id
}

// readEnrichment reads the enrichment columns back. domain.Finding carries none
// of them, so the assertions have to query the row directly -- the same approach
// the older Docker-backed tests in this package use.
func readEnrichment(t *testing.T, store *Store, id string) (epss, percentile *float64, exploit, kev bool) {
	t.Helper()

	if err := store.pool.QueryRow(context.Background(),
		`SELECT epss_score::float8, epss_percentile::float8, exploit_exists, cisa_kev
		 FROM vulnerabilities WHERE id = $1`, id,
	).Scan(&epss, &percentile, &exploit, &kev); err != nil {
		t.Fatalf("read enrichment for %s: %v", id, err)
	}
	return epss, percentile, exploit, kev
}

// assertEnrichmentFloat compares a stored score against its expected value with
// a tolerance. The EPSS columns are single-precision, so 0.42 reads back as
// 0.41999998688697815 -- accurate to roughly 1e-7, which is well inside what EPSS
// itself publishes (five decimal places).
func assertEnrichmentFloat(t *testing.T, label string, got *float64, want float64) {
	t.Helper()

	if got == nil {
		t.Fatalf("%s is NULL, want %v", label, want)
	}
	if math.Abs(*got-want) > 1e-6 {
		t.Fatalf("%s = %v, want %v", label, *got, want)
	}
}

// TestImportVulnerabilityFeedWithAuditWritesAuditInsideTransaction covers the
// audited advisory import. The callback must see the counts the caller gets, and
// the audit row has to land in the same transaction as the advisories.
func TestImportVulnerabilityFeedWithAuditWritesAuditInsideTransaction(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	var seenImported, seenDeleted int
	imported, deleted, err := store.ImportVulnerabilityFeedWithAudit(ctx, "osv", []db.Vulnerability{{
		ID:        "GHSA-audited-import",
		Summary:   "audited import fixture",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "GHSA-audited-import"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npm",
			Name:      "audited-import",
		}},
	}}, nil, nil, func(imported, deleted int) db.AdminAuditEntry {
		seenImported, seenDeleted = imported, deleted
		return db.AdminAuditEntry{Action: "feed.vulnerability.import", IP: "127.0.0.1"}
	})
	if err != nil {
		t.Fatalf("ImportVulnerabilityFeedWithAudit: %v", err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1", imported)
	}
	if seenImported != imported || seenDeleted != deleted {
		t.Fatalf("audit callback saw (%d, %d), want the returned (%d, %d)",
			seenImported, seenDeleted, imported, deleted)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "feed.vulnerability.import") {
		t.Fatal("audited advisory import wrote no admin audit entry")
	}
}

// TestImportVulnerabilityFeedWithAuditRollsBackOnAuditFailure is the fail-closed
// half: if the audit row cannot be written, the advisories must not commit.
// Otherwise an advisory import could enter the database with no trace. The
// builder's return type rules out "no entry"; an entry with no action is what is
// still reachable, and is what this drives.
func TestImportVulnerabilityFeedWithAuditRollsBackOnAuditFailure(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, _, err := store.ImportVulnerabilityFeedWithAudit(ctx, "osv", []db.Vulnerability{{
		ID:        "GHSA-audit-rollback",
		Summary:   "audit rollback fixture",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "GHSA-audit-rollback"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npm",
			Name:      "audit-rollback",
		}},
	}}, nil, nil, func(int, int) db.AdminAuditEntry { return db.AdminAuditEntry{} })
	if err == nil {
		t.Fatal("ImportVulnerabilityFeedWithAudit(anonymous entry) error = nil, want a refusal")
	}
	if !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("error = %v, want it to match db.ErrAdminAuditLog", err)
	}

	found, err := store.FindVulnerabilities(ctx, "npm", "audit-rollback", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("import committed %d advisories despite the failed audit", len(found))
	}
}

// TestReplaceCISAKEVWithAuditMarksAndClearsTheFlag covers the audited KEV
// snapshot. It is a replace, not a merge: a CVE that drops out of the feed must
// lose its KEV flag, because a stale flag makes a finding look actively
// exploited when it no longer is.
func TestReplaceCISAKEVWithAuditMarksAndClearsTheFlag(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	cve := seedEnrichmentCVE(t, store, "CVE-2026-KEV-1")

	updated, cleared, err := store.ReplaceCISAKEVWithAudit(ctx, "cisa_kev", []string{cve}, nil,
		func(int, int) db.AdminAuditEntry {
			return db.AdminAuditEntry{Action: "feed.cisakev.replace", IP: "127.0.0.1"}
		})
	if err != nil {
		t.Fatalf("ReplaceCISAKEVWithAudit: %v", err)
	}
	if updated != 1 {
		t.Fatalf("updated = %d, want the seeded CVE flagged", updated)
	}
	if cleared != 0 {
		t.Fatalf("cleared = %d on the first snapshot, want 0", cleared)
	}
	if _, _, _, kev := readEnrichment(t, store, cve); !kev {
		t.Fatal("cisa_kev = false although the snapshot reported the CVE as updated")
	}

	// An empty snapshot means the CVE left the catalogue and must be un-flagged.
	updated, cleared, err = store.ReplaceCISAKEVWithAudit(ctx, "cisa_kev", nil, nil,
		func(int, int) db.AdminAuditEntry {
			return db.AdminAuditEntry{Action: "feed.cisakev.replace", IP: "127.0.0.1"}
		})
	if err != nil {
		t.Fatalf("ReplaceCISAKEVWithAudit(empty snapshot): %v", err)
	}
	if updated != 0 {
		t.Fatalf("updated = %d on an empty snapshot, want 0", updated)
	}
	if cleared != 1 {
		t.Fatalf("cleared = %d, want the stale KEV flag removed", cleared)
	}
	if _, _, _, kev := readEnrichment(t, store, cve); kev {
		t.Fatal("cisa_kev is still set after the CVE left the catalogue")
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "feed.cisakev.replace") {
		t.Fatal("audited KEV replace wrote no admin audit entry")
	}
}

// TestImportCISAKEVWithAuditMergesWithoutClearing covers the additive KEV import,
// the counterpart to ReplaceCISAKEVWithAudit. It must only ever set flags: a CVE
// missing from a partial batch keeps its flag, because an incremental update
// carries no evidence that the absent CVE left the catalogue.
func TestImportCISAKEVWithAuditMergesWithoutClearing(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	first := seedEnrichmentCVE(t, store, "CVE-2026-KEVMERGE-1")
	second := seedEnrichmentCVE(t, store, "CVE-2026-KEVMERGE-2")

	updated, err := store.ImportCISAKEVWithAudit(ctx, "cisa_kev", []string{first}, nil,
		func(int, int) db.AdminAuditEntry {
			return db.AdminAuditEntry{Action: "feed.cisakev.import", IP: "127.0.0.1"}
		})
	if err != nil {
		t.Fatalf("ImportCISAKEVWithAudit: %v", err)
	}
	if updated != 1 {
		t.Fatalf("updated = %d, want the first CVE flagged", updated)
	}

	// A second batch naming only the other CVE must not un-flag the first.
	if _, err := store.ImportCISAKEVWithAudit(ctx, "cisa_kev", []string{second}, nil, nil); err != nil {
		t.Fatalf("ImportCISAKEVWithAudit(second batch): %v", err)
	}
	if _, _, _, kev := readEnrichment(t, store, first); !kev {
		t.Fatal("an incremental KEV import cleared a CVE it did not mention")
	}
	if _, _, _, kev := readEnrichment(t, store, second); !kev {
		t.Fatal("the second batch did not flag its own CVE")
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "feed.cisakev.import") {
		t.Fatal("audited KEV import wrote no admin audit entry")
	}
}

// TestImportEPSSWithAuditStoresScoreAndPercentile covers the audited EPSS
// snapshot. Both numbers drive prioritisation in the report, so a dropped
// percentile silently changes how findings are ranked.
func TestImportEPSSWithAuditStoresScoreAndPercentile(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	// EPSS validates the identifier shape, so this fixture uses a real CVE form
	// rather than the free-form IDs the other enrichment importers accept.
	cve := seedEnrichmentCVE(t, store, "CVE-2026-10001")

	updated, cleared, err := store.ImportEPSSWithAudit(ctx, "epss", []db.EPSSEntry{{
		CVEID:      cve,
		Score:      0.42,
		Percentile: 0.97,
	}}, nil, func(int, int) db.AdminAuditEntry {
		return db.AdminAuditEntry{Action: "feed.epss.import", IP: "127.0.0.1"}
	})
	if err != nil {
		t.Fatalf("ImportEPSSWithAudit: %v", err)
	}
	if updated != 1 {
		t.Fatalf("updated = %d, want the seeded CVE scored", updated)
	}
	if cleared != 0 {
		t.Fatalf("cleared = %d on the first snapshot, want 0", cleared)
	}

	// The columns are numeric, so the round trip back to float64 is not bit-exact.
	score, percentile, _, _ := readEnrichment(t, store, cve)
	assertEnrichmentFloat(t, "EPSS score", score, 0.42)
	assertEnrichmentFloat(t, "EPSS percentile", percentile, 0.97)

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "feed.epss.import") {
		t.Fatal("audited EPSS import wrote no admin audit entry")
	}
}

// TestImportVulnCheckWithAuditStoresExploitEvidence covers the audited VulnCheck
// import. The exploit flag is one of the inputs that turns a finding into a
// blocking one, so it must survive the round trip.
func TestImportVulnCheckWithAuditStoresExploitEvidence(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	cve := seedEnrichmentCVE(t, store, "CVE-2026-VULNCHECK-1")

	updated, err := store.ImportVulnCheckWithAudit(ctx, "vulncheck", []db.VulnCheckEntry{{
		CVEID:         cve,
		ExploitExists: true,
		SourceURL:     "https://vulncheck.test/CVE-2026-VULNCHECK-1",
	}}, nil, func(int, int) db.AdminAuditEntry {
		return db.AdminAuditEntry{Action: "feed.vulncheck.import", IP: "127.0.0.1"}
	})
	if err != nil {
		t.Fatalf("ImportVulnCheckWithAudit: %v", err)
	}
	if updated != 1 {
		t.Fatalf("updated = %d, want the seeded CVE enriched", updated)
	}

	if _, _, exploit, _ := readEnrichment(t, store, cve); !exploit {
		t.Fatal("exploit_exists = false, want the imported exploit evidence retained")
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "feed.vulncheck.import") {
		t.Fatal("audited VulnCheck import wrote no admin audit entry")
	}
}

// TestImportVulnCheckStreamWithAuditAccumulatesEveryBatch covers the streaming
// variant used for large VulnCheck snapshots. The returned count must be the sum
// across batches, not the last batch -- an under-count would make a full import
// look like a partial one in the feed status.
func TestImportVulnCheckStreamWithAuditAccumulatesEveryBatch(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	first := seedEnrichmentCVE(t, store, "CVE-2026-STREAM-1")
	second := seedEnrichmentCVE(t, store, "CVE-2026-STREAM-2")

	updated, total, err := store.ImportVulnCheckStreamWithAudit(ctx, "vulncheck",
		func(emit func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error) {
			if err := emit([]db.VulnCheckEntry{{CVEID: first, ExploitExists: true}}); err != nil {
				return nil, 0, err
			}
			if err := emit([]db.VulnCheckEntry{{CVEID: second, ExploitExists: true}}); err != nil {
				return nil, 0, err
			}
			return nil, 2, nil
		},
		func(int, int) db.AdminAuditEntry {
			return db.AdminAuditEntry{Action: "feed.vulncheck.stream", IP: "127.0.0.1"}
		})
	if err != nil {
		t.Fatalf("ImportVulnCheckStreamWithAudit: %v", err)
	}
	if updated != 2 {
		t.Fatalf("updated = %d, want both batches counted", updated)
	}
	if total != 2 {
		t.Fatalf("total = %d, want the stream's own total reported back", total)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "feed.vulncheck.stream") {
		t.Fatal("audited VulnCheck stream wrote no admin audit entry")
	}
}

// TestImportVulnCheckStreamWithAuditRefusesAMissingStream covers the guard: an
// unconfigured stream must be reported, not treated as an empty import that
// would mark the feed as successfully synced with zero entries.
func TestImportVulnCheckStreamWithAuditRefusesAMissingStream(t *testing.T) {
	store, _ := startDockerPostgresStore(t)

	_, _, err := store.ImportVulnCheckStreamWithAudit(context.Background(), "vulncheck", nil, nil)
	if err == nil {
		t.Fatal("ImportVulnCheckStreamWithAudit(nil stream) error = nil, want a refusal")
	}
}

// TestImportVulnCheckStreamWithAuditRollsBackOnStreamFailure keeps a partially
// consumed stream out of the database: batches already applied must roll back
// with the failure, so the feed cannot end up half-imported.
func TestImportVulnCheckStreamWithAuditRollsBackOnStreamFailure(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	cve := seedEnrichmentCVE(t, store, "CVE-2026-STREAM-FAIL")
	streamErr := errors.New("stream aborted midway")

	_, _, err := store.ImportVulnCheckStreamWithAudit(ctx, "vulncheck",
		func(emit func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error) {
			if err := emit([]db.VulnCheckEntry{{CVEID: cve, ExploitExists: true}}); err != nil {
				return nil, 0, err
			}
			return nil, 1, streamErr
		}, nil)
	if err == nil {
		t.Fatal("ImportVulnCheckStreamWithAudit error = nil, want the stream failure surfaced")
	}
	if !errors.Is(err, streamErr) {
		t.Fatalf("error = %v, want it to wrap the stream failure", err)
	}

	if _, _, exploit, _ := readEnrichment(t, store, cve); exploit {
		t.Fatal("the aborted stream committed its first batch")
	}
}

// TestRecordNVDCVSSNegativeLookupIsIdempotentAndNormalises covers the negative
// cache for NVD lookups. It exists to stop the syncer re-querying NVD for a CVE
// that has no CVSS score, so it must tolerate repeats and treat a lower-case or
// padded ID as the same CVE.
func TestRecordNVDCVSSNegativeLookupIsIdempotentAndNormalises(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	for _, id := range []string{"CVE-2026-NVD-1", "  cve-2026-nvd-1  ", "CVE-2026-NVD-1"} {
		if err := store.RecordNVDCVSSNegativeLookup(ctx, id); err != nil {
			t.Fatalf("RecordNVDCVSSNegativeLookup(%q): %v", id, err)
		}
	}

	// A blank ID is not an error -- there is simply nothing to remember.
	for _, blank := range []string{"", "   "} {
		if err := store.RecordNVDCVSSNegativeLookup(ctx, blank); err != nil {
			t.Fatalf("RecordNVDCVSSNegativeLookup(%q) = %v, want a silent no-op", blank, err)
		}
	}
}
