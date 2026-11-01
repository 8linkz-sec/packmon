package v1

import (
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestSyncResponseFromExportCarriesSplitMarkers passes the split markers of
// an exported page to the /api/v1/sync response: the split advisory on every
// page of a split, and the start and completeness markers only together
// with it.
func TestSyncResponseFromExportCarriesSplitMarkers(t *testing.T) {
	t.Parallel()

	resp := syncResponseFromExport(&db.SyncExport{
		SyncedAt:                   time.Unix(1700000000, 0).UTC(),
		Vulnerabilities:            []db.SyncVulnerability{{ID: "GHSA-split", Ecosystem: "npm", Name: "a"}},
		Truncated:                  true,
		NextCursor:                 &db.SyncCursor{VulnerabilitiesCursor: db.EncodeSyncAdvisoryCursor("GHSA-split")},
		VulnerabilitySplitAdvisory: "GHSA-split",
		VulnerabilitySplitStart:    true,
		VulnerabilitySplitComplete: true,
	}, "healthy", nil)
	if resp.VulnerabilitySplitAdvisory != "GHSA-split" || !resp.VulnerabilitySplitStart || !resp.VulnerabilitySplitComplete {
		t.Fatalf("split markers = %q / %v / %v, want GHSA-split start and complete", resp.VulnerabilitySplitAdvisory, resp.VulnerabilitySplitStart, resp.VulnerabilitySplitComplete)
	}

	resp = syncResponseFromExport(&db.SyncExport{VulnerabilitySplitStart: true, VulnerabilitySplitComplete: true}, "healthy", nil)
	if resp.VulnerabilitySplitAdvisory != "" || resp.VulnerabilitySplitStart || resp.VulnerabilitySplitComplete {
		t.Fatalf("split markers without a split advisory = %q / %v / %v, want none", resp.VulnerabilitySplitAdvisory, resp.VulnerabilitySplitStart, resp.VulnerabilitySplitComplete)
	}
}
