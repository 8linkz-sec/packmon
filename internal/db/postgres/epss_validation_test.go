package postgres

import (
	"math"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestNormalizeEPSSSnapshotBatch(t *testing.T) {
	t.Parallel()

	normalized, err := normalizeEPSSSnapshotBatch([]db.EPSSEntry{{
		CVEID:      " cve-2026-0001 ",
		Score:      0.12,
		Percentile: 0.34,
	}}, 7)
	if err != nil {
		t.Fatalf("normalizeEPSSSnapshotBatch(valid) error = %v", err)
	}
	if len(normalized) != 1 || normalized[0].CVEID != "CVE-2026-0001" {
		t.Fatalf("normalized = %+v, want upper-trimmed CVE", normalized)
	}

	tests := []struct {
		name string
		in   db.EPSSEntry
		want string
	}{
		{
			name: "empty cve",
			in:   db.EPSSEntry{CVEID: " ", Score: 0.1, Percentile: 0.2},
			want: "entries[3].cve_id is invalid",
		},
		{
			name: "malformed cve",
			in:   db.EPSSEntry{CVEID: "not-a-cve", Score: 0.1, Percentile: 0.2},
			want: "entries[3].cve_id is invalid",
		},
		{
			name: "nan score",
			in:   db.EPSSEntry{CVEID: "CVE-2026-0001", Score: math.NaN(), Percentile: 0.2},
			want: "entries[3].score must be between 0 and 1",
		},
		{
			name: "percentile above one",
			in:   db.EPSSEntry{CVEID: "CVE-2026-0001", Score: 0.1, Percentile: 1.1},
			want: "entries[3].percentile must be between 0 and 1",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeEPSSSnapshotBatch([]db.EPSSEntry{tt.in}, 3); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("normalizeEPSSSnapshotBatch() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestReplaceEPSSScoresStreamStagesSnapshotBeforeTransaction(t *testing.T) {
	t.Parallel()

	source := postgresFunctionSource(t, "vulnerability_enrichment.go", "ReplaceEPSSScoresStream")
	stageIndex := strings.Index(source, "stageEPSSSnapshotStream(ctx, stream)")
	if stageIndex < 0 {
		t.Fatalf("ReplaceEPSSScoresStream must stage the EPSS snapshot before opening the update transaction:\n%s", source)
	}
	txIndex := strings.Index(source, "withTx(ctx, s.pool")
	if txIndex < 0 {
		t.Fatalf("ReplaceEPSSScoresStream missing withTx call:\n%s", source)
	}
	if stageIndex > txIndex {
		t.Fatalf("ReplaceEPSSScoresStream stages after opening the transaction:\n%s", source)
	}

	importSource := postgresFunctionSource(t, "vulnerability_enrichment.go", "ImportEPSSStreamWithAudit")
	importStageIndex := strings.Index(importSource, "stageEPSSSnapshotStream(ctx,")
	importApplyIndex := strings.Index(importSource, "s.applyEPSSSnapshotWithAudit(ctx, snapshot, status, audit)")
	if importStageIndex < 0 || importApplyIndex < 0 || importStageIndex > importApplyIndex {
		t.Fatalf("ImportEPSSStreamWithAudit must finish staging the stream (and its status) before applying the snapshot:\n%s", importSource)
	}
	applySource := postgresFunctionSource(t, "vulnerability_enrichment.go", "applyEPSSSnapshotWithAudit")
	for _, want := range []string{
		"withTx(ctx, s.pool",
		"replaceEPSSScoresStreamTx(ctx, tx, snapshot)",
		"upsertFeedSyncStatusTx(ctx, tx, status)",
		"insertAdminAuditLogTx(ctx, tx, &entry)",
	} {
		if !strings.Contains(applySource, want) {
			t.Fatalf("applyEPSSSnapshotWithAudit missing transactional fragment %q:\n%s", want, applySource)
		}
	}

	txSource := postgresFunctionSource(t, "vulnerability_enrichment.go", "replaceEPSSScoresStreamTx")
	if strings.Contains(txSource, "normalizeEPSSSnapshotBatch(") {
		t.Fatalf("replaceEPSSScoresStreamTx must consume pre-validated staged EPSS batches:\n%s", txSource)
	}
}
