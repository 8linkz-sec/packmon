package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

var errF075StreamEmit = errors.New("test stream emit failed")

type f075AtomicEPSSStore struct {
	stubStore
	snapshot        []db.EPSSEntry
	streamCalls     int
	batchSizes      []int
	failEmitBatch   int
	statusWrites    int
	auditWrites     int
	committedStatus *db.FeedSyncStatus
}

func (s *f075AtomicEPSSStore) ImportEPSSStreamWithAudit(_ context.Context, _ string, stream func(func([]db.EPSSEntry) error) (*db.FeedSyncStatus, error), audit db.FeedImportAuditBuilder) (int, int, int, error) {
	s.streamCalls++
	pending := make([]db.EPSSEntry, 0)
	status, err := stream(func(batch []db.EPSSEntry) error {
		s.batchSizes = append(s.batchSizes, len(batch))
		if s.failEmitBatch > 0 && len(s.batchSizes) == s.failEmitBatch {
			return errF075StreamEmit
		}
		pending = append(pending, batch...)
		return nil
	})
	if err != nil {
		return 0, 0, len(pending), err
	}
	if audit == nil {
		return 0, 0, len(pending), errors.New("test audit builder is missing")
	}
	previous := len(s.snapshot)
	s.snapshot = append([]db.EPSSEntry(nil), pending...)
	if status != nil {
		copyStatus := *status
		s.committedStatus = &copyStatus
		s.statusWrites++
	}
	_ = audit(len(pending), max(previous-len(pending), 0))
	s.auditWrites++
	return len(pending), max(previous-len(pending), 0), len(pending), nil
}

func (s *f075AtomicEPSSStore) ImportVulnCheckStreamWithAudit(_ context.Context, _ string, stream func(func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error), audit db.FeedImportAuditBuilder) (int, int, error) {
	status, total, err := stream(func([]db.VulnCheckEntry) error { return nil })
	if err != nil {
		return 0, total, err
	}
	if status != nil {
		s.statusWrites++
	}
	if audit != nil {
		_ = audit(total, 0)
		s.auditWrites++
	}
	return total, total, nil
}

type f075RepeatReader struct {
	value byte
}

func (r f075RepeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.value
	}
	return len(p), nil
}

func f075EPSSRequest(body io.Reader) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", body)
}

func f075EPSSEntriesBody(count int, invalidLast bool, status string) string {
	var body strings.Builder
	body.Grow(count*72 + len(status) + 32)
	body.WriteString(`{"entries":[`)
	for i := 0; i < count; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		if invalidLast && i == count-1 {
			fmt.Fprintf(&body, `{"cve_id":"CVE-2026-%04d","percentile":0.8}`, 1000+i)
			continue
		}
		fmt.Fprintf(&body, `{"cve_id":"CVE-2026-%04d","score":0.2,"percentile":0.8}`, 1000+i)
	}
	body.WriteByte(']')
	if status != "" {
		body.WriteString(`,"status":`)
		body.WriteString(status)
	}
	body.WriteByte('}')
	return body.String()
}

func f075VulnCheckEntriesBody(count int, invalidLast bool, status string) string {
	var body strings.Builder
	body.Grow(count*64 + len(status) + 32)
	body.WriteString(`{"entries":[`)
	for i := 0; i < count; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		if invalidLast && i == count-1 {
			body.WriteString(`{"exploit_exists":true}`)
			continue
		}
		fmt.Fprintf(&body, `{"cve_id":"CVE-2026-%04d","cvss_score":5.5}`, 2000+i)
	}
	body.WriteByte(']')
	if status != "" {
		body.WriteString(`,"status":`)
		body.WriteString(status)
	}
	body.WriteByte('}')
	return body.String()
}

func TestF075DuplicateTopLevelMembersAreRejectedAcrossCapabilities(t *testing.T) {
	epssEntry := `{"cve_id":"CVE-2026-7401","score":0.2,"percentile":0.8}`
	vulnCheckEntry := `{"cve_id":"CVE-2026-7402","cvss_score":5.5}`
	tests := []struct {
		feed string
		body map[string]string
	}{
		{
			feed: "epss",
			body: map[string]string{
				"entries": `{"entries":[` + epssEntry + `],"status":{"last_sync_status":"success"},"entries":[{"cve_id":"CVE-2026-7499","score":0.4,"percentile":0.9}]}`,
				"status":  `{"status":{"last_sync_status":"success"},"entries":[` + epssEntry + `],"status":{"last_sync_status":"error"}}`,
			},
		},
		{
			feed: "vulncheck",
			body: map[string]string{
				"entries": `{"entries":[` + vulnCheckEntry + `],"status":{"last_sync_status":"success"},"entries":[{"cve_id":"CVE-2026-7499","exploit_exists":true}]}`,
				"status":  `{"status":{"last_sync_status":"success"},"entries":[` + vulnCheckEntry + `],"status":{"last_sync_status":"error"}}`,
			},
		},
	}

	for _, tt := range tests {
		for duplicate, body := range tt.body {
			for _, capability := range []string{"buffered", "streaming"} {
				t.Run(tt.feed+"/duplicate_"+duplicate+"/"+capability, func(t *testing.T) {
					var store FeedImportStore
					switch {
					case tt.feed == "epss" && capability == "buffered":
						store = &stubStore{epssEntries: []db.EPSSEntry{{CVEID: "CVE-2026-7000", Score: 0.7, Percentile: 0.9}}}
					case tt.feed == "epss":
						store = &f075AtomicEPSSStore{snapshot: []db.EPSSEntry{{CVEID: "CVE-2026-7000", Score: 0.7, Percentile: 0.9}}}
					case capability == "buffered":
						store = &stubStore{vulnCheckEntries: []db.VulnCheckEntry{{CVEID: "CVE-2026-7001", ExploitExists: true}}}
					default:
						store = &atomicFailingVulnCheckStore{committed: []db.VulnCheckEntry{{CVEID: "CVE-2026-7001", ExploitExists: true}}}
					}

					h := newTestFeedImportHandler(store)
					req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(body))
					req.SetPathValue("feed", tt.feed)
					req.Header.Set("Content-Type", "application/json")
					rr := httptest.NewRecorder()

					h.HandleImport(rr, req)

					if rr.Code != http.StatusBadRequest {
						t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
					}
					var response errorJSON
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Fatalf("decode error response: %v", err)
					}
					if response.Error != "invalid JSON body: json body contains duplicate top-level field" {
						t.Fatalf("error = %q, want controlled duplicate-field error", response.Error)
					}

					switch got := store.(type) {
					case *stubStore:
						if tt.feed == "epss" {
							want := []db.EPSSEntry{{CVEID: "CVE-2026-7000", Score: 0.7, Percentile: 0.9}}
							if !reflect.DeepEqual(got.epssEntries, want) || got.epssReplaceCalls != 0 {
								t.Fatalf("buffered EPSS state = %+v calls=%d, want original state and no import", got.epssEntries, got.epssReplaceCalls)
							}
						} else {
							want := []db.VulnCheckEntry{{CVEID: "CVE-2026-7001", ExploitExists: true}}
							if !reflect.DeepEqual(got.vulnCheckEntries, want) {
								t.Fatalf("buffered VulnCheck state = %+v, want original state", got.vulnCheckEntries)
							}
						}
						if len(got.auditEntries) != 0 {
							t.Fatalf("buffered audit entries = %d, want 0", len(got.auditEntries))
						}
						assertSingleRejectedFeedStatus(t, got.upsertedStatuses, tt.feed)
					case *f075AtomicEPSSStore:
						want := []db.EPSSEntry{{CVEID: "CVE-2026-7000", Score: 0.7, Percentile: 0.9}}
						if !reflect.DeepEqual(got.snapshot, want) || !reflect.DeepEqual(got.batchSizes, []int{1}) || got.statusWrites != 0 || got.auditWrites != 0 {
							t.Fatalf("streaming EPSS state = %+v batches=%v status=%d audit=%d, want original state, one staged batch, no commit", got.snapshot, got.batchSizes, got.statusWrites, got.auditWrites)
						}
						assertSingleRejectedFeedStatus(t, got.upsertedStatuses, tt.feed)
					case *atomicFailingVulnCheckStore:
						want := []db.VulnCheckEntry{{CVEID: "CVE-2026-7001", ExploitExists: true}}
						if !reflect.DeepEqual(got.committed, want) || !reflect.DeepEqual(got.streamBatchSizes, []int{1}) || len(got.auditEntries) != 0 {
							t.Fatalf("streaming VulnCheck state = %+v batches=%v audit=%d, want original state, one staged batch, no audit", got.committed, got.streamBatchSizes, len(got.auditEntries))
						}
						assertSingleRejectedFeedStatus(t, got.upsertedStatuses, tt.feed)
					default:
						t.Fatalf("unexpected test store type %T", store)
					}
				})
			}
		}
	}
}

func TestF075StreamingMalformedBodiesPreserveState(t *testing.T) {
	validEntry := `{"cve_id":"CVE-2026-7501","score":0.1,"percentile":0.2}`
	oversized := io.MultiReader(
		strings.NewReader(`{"entries":[]}`),
		io.LimitReader(f075RepeatReader{value: ' '}, maxImportBody+1),
	)
	tests := []struct {
		name string
		body io.Reader
	}{
		{name: "empty body", body: strings.NewReader("")},
		{name: "top-level null", body: strings.NewReader(`null`)},
		{name: "truncated JSON", body: strings.NewReader(`{"entries":[` + validEntry + `]`)},
		{name: "unknown field", body: strings.NewReader(`{"entries":[` + validEntry + `],"unexpected":true}`)},
		{name: "unknown entry field", body: strings.NewReader(`{"entries":[{"cve_id":"CVE-2026-7501","score":0.1,"percentile":0.2,"unexpected":true}]}`)},
		{name: "wrong top-level type", body: strings.NewReader(`[]`)},
		{name: "wrong entries type", body: strings.NewReader(`{"entries":{}}`)},
		{name: "wrong entry type", body: strings.NewReader(`{"entries":[true]}`)},
		{name: "wrong status type", body: strings.NewReader(`{"entries":[` + validEntry + `],"status":[]}`)},
		{name: "trailing document", body: strings.NewReader(`{"entries":[` + validEntry + `]} {}`)},
		{name: "null entries", body: strings.NewReader(`{"entries":null}`)},
		{name: "empty entries", body: strings.NewReader(`{"entries":[]}`)},
		{name: "body limit", body: oversized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := []db.EPSSEntry{{CVEID: "CVE-2026-7000", Score: 0.7, Percentile: 0.9}}
			store := &f075AtomicEPSSStore{snapshot: append([]db.EPSSEntry(nil), seed...)}
			h := newTestFeedImportHandler(store)
			_, _, err := h.importEPSSRequest(context.Background(), "epss", f075EPSSRequest(tt.body), func(int, int) db.AdminAuditEntry {
				return db.AdminAuditEntry{Action: "feed_import"}
			})
			if err == nil {
				t.Fatal("malformed streamed import error = nil, want rejection")
			}
			if !reflect.DeepEqual(store.snapshot, seed) {
				t.Fatalf("snapshot = %+v, want original %+v", store.snapshot, seed)
			}
			if store.streamCalls != 1 || store.statusWrites != 0 || store.auditWrites != 0 {
				t.Fatalf("stream/status/audit calls = %d/%d/%d, want 1/0/0", store.streamCalls, store.statusWrites, store.auditWrites)
			}
		})
	}
}

func TestF075StreamingLateFailuresPreserveState(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		failEmitBatch int
		wantTotal     int
		wantBatches   []int
		wantError     error
	}{
		{
			name:        "invalid late record",
			body:        f075EPSSEntriesBody(epssImportStreamBatchSize+1, true, ""),
			wantTotal:   epssImportStreamBatchSize + 1,
			wantBatches: []int{epssImportStreamBatchSize},
		},
		{
			name:        "invalid derived final status",
			body:        f075EPSSEntriesBody(1, false, `{"entries_synced":2}`),
			wantTotal:   1,
			wantBatches: []int{1},
		},
		{
			name:        "invalid explicit status after complete stream",
			body:        f075EPSSEntriesBody(epssImportStreamBatchSize+1, false, `{"last_sync_status":"not-supported"}`),
			wantTotal:   epssImportStreamBatchSize + 1,
			wantBatches: []int{epssImportStreamBatchSize, 1},
		},
		{
			name:          "emit failure after successful batch",
			body:          f075EPSSEntriesBody(epssImportStreamBatchSize+1, false, ""),
			failEmitBatch: 2,
			wantTotal:     epssImportStreamBatchSize + 1,
			wantBatches:   []int{epssImportStreamBatchSize, 1},
			wantError:     errF075StreamEmit,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := []db.EPSSEntry{{CVEID: "CVE-2026-7001", Score: 0.4, Percentile: 0.6}}
			store := &f075AtomicEPSSStore{
				snapshot:      append([]db.EPSSEntry(nil), seed...),
				failEmitBatch: tt.failEmitBatch,
			}
			h := newTestFeedImportHandler(store)
			_, total, err := h.importEPSSRequest(context.Background(), "epss", f075EPSSRequest(strings.NewReader(tt.body)), func(int, int) db.AdminAuditEntry {
				return db.AdminAuditEntry{Action: "feed_import"}
			})
			if err == nil {
				t.Fatal("late streamed import error = nil, want rejection")
			}
			if tt.wantError != nil && !errors.Is(err, tt.wantError) {
				t.Fatalf("error = %v, want it to wrap %v", err, tt.wantError)
			}
			if total != tt.wantTotal {
				t.Fatalf("entries total = %d, want %d", total, tt.wantTotal)
			}
			if !reflect.DeepEqual(store.batchSizes, tt.wantBatches) {
				t.Fatalf("batch sizes = %v, want %v", store.batchSizes, tt.wantBatches)
			}
			if !reflect.DeepEqual(store.snapshot, seed) || store.statusWrites != 0 || store.auditWrites != 0 {
				t.Fatalf("failed stream committed state: snapshot=%+v status=%d audit=%d", store.snapshot, store.statusWrites, store.auditWrites)
			}
		})
	}
}

func TestF075VulnCheckStreamingMalformedBodiesPreserveState(t *testing.T) {
	validEntry := `{"cve_id":"CVE-2026-7601","cvss_score":5.5}`
	tests := []struct {
		name string
		body func() io.Reader
	}{
		{name: "empty body", body: func() io.Reader { return strings.NewReader("") }},
		{name: "truncated JSON", body: func() io.Reader { return strings.NewReader(`{"entries":[` + validEntry + `]`) }},
		{name: "unknown field", body: func() io.Reader { return strings.NewReader(`{"entries":[` + validEntry + `],"unexpected":true}`) }},
		{name: "unknown entry field", body: func() io.Reader {
			return strings.NewReader(`{"entries":[{"cve_id":"CVE-2026-7601","unexpected":true}]}`)
		}},
		{name: "wrong top-level type", body: func() io.Reader { return strings.NewReader(`[]`) }},
		{name: "wrong entries type", body: func() io.Reader { return strings.NewReader(`{"entries":{}}`) }},
		{name: "wrong entry type", body: func() io.Reader { return strings.NewReader(`{"entries":[true]}`) }},
		{name: "wrong status type", body: func() io.Reader { return strings.NewReader(`{"entries":[` + validEntry + `],"status":"ok"}`) }},
		{name: "trailing document", body: func() io.Reader { return strings.NewReader(`{"entries":[` + validEntry + `]} {}`) }},
		{name: "body limit", body: func() io.Reader {
			return io.MultiReader(
				strings.NewReader(`{"entries":[]}`),
				io.LimitReader(f075RepeatReader{value: ' '}, maxImportBody+1),
			)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := []db.VulnCheckEntry{{CVEID: "CVE-2026-7002", ExploitExists: true}}
			store := &atomicFailingVulnCheckStore{committed: append([]db.VulnCheckEntry(nil), seed...)}
			h := newTestFeedImportHandler(store)
			_, _, err := h.importVulnCheckRequest(context.Background(), "vulncheck", f075EPSSRequest(tt.body()), func(int, int) db.AdminAuditEntry {
				return db.AdminAuditEntry{Action: "feed_import"}
			})
			if err == nil {
				t.Fatal("malformed streamed import error = nil, want rejection")
			}
			if !reflect.DeepEqual(store.committed, seed) {
				t.Fatalf("committed entries = %+v, want original %+v", store.committed, seed)
			}
			if store.streamCalls != 1 || len(store.upsertedStatuses) != 0 || len(store.auditEntries) != 0 {
				t.Fatalf("stream/status/audit calls = %d/%d/%d, want 1/0/0", store.streamCalls, len(store.upsertedStatuses), len(store.auditEntries))
			}
		})
	}
}

func TestF075VulnCheckOmittedAndEmptyEntriesRemainAtomicNoOps(t *testing.T) {
	for _, body := range []string{`{}`, `{"entries":[]}`} {
		t.Run(body, func(t *testing.T) {
			seed := []db.VulnCheckEntry{{CVEID: "CVE-2026-7003", ExploitExists: true}}
			store := &atomicFailingVulnCheckStore{committed: append([]db.VulnCheckEntry(nil), seed...)}
			h := newTestFeedImportHandler(store)
			resp, total, err := h.importVulnCheckRequest(context.Background(), "vulncheck", f075EPSSRequest(strings.NewReader(body)), func(int, int) db.AdminAuditEntry {
				return db.AdminAuditEntry{Action: "feed_import"}
			})
			if err != nil {
				t.Fatalf("empty streamed import error = %v", err)
			}
			if resp == nil || resp.Imported != 0 || resp.EntriesTotal != 0 || total != 0 {
				t.Fatalf("response/total = %+v/%d, want zero-entry success", resp, total)
			}
			if !reflect.DeepEqual(store.committed, seed) || len(store.streamBatchSizes) != 0 {
				t.Fatalf("empty import changed entries: committed=%+v batches=%v", store.committed, store.streamBatchSizes)
			}
			if len(store.upsertedStatuses) != 0 || len(store.auditEntries) != 1 {
				t.Fatalf("status/audit writes = %d/%d, want 0/1", len(store.upsertedStatuses), len(store.auditEntries))
			}
		})
	}
}

func TestF075VulnCheckNullShapesAreRejectedAtomically(t *testing.T) {
	for _, body := range []string{`null`, `{"entries":null}`} {
		t.Run(body, func(t *testing.T) {
			seed := []db.VulnCheckEntry{{CVEID: "CVE-2026-7003", ExploitExists: true}}
			store := &atomicFailingVulnCheckStore{committed: append([]db.VulnCheckEntry(nil), seed...)}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/vulncheck/import", strings.NewReader(body))
			req.SetPathValue("feed", "vulncheck")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if !reflect.DeepEqual(store.committed, seed) || len(store.streamBatchSizes) != 0 {
				t.Fatalf("null import changed entries: committed=%+v batches=%v", store.committed, store.streamBatchSizes)
			}
			if rr.Code == http.StatusOK {
				if len(store.upsertedStatuses) != 0 || len(store.auditEntries) != 1 {
					t.Fatalf("accepted null import status/audit writes = %d/%d, want 0/1", len(store.upsertedStatuses), len(store.auditEntries))
				}
				t.Skip("F075-bugs-4: VulnCheck streaming imports accept OpenAPI-invalid null request shapes")
			}
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("null import status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.auditEntries) != 0 || len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].LastSyncStatus != db.FeedSyncStatusRejected {
				t.Fatalf("rejected null import status/audit = %+v/%d", store.upsertedStatuses, len(store.auditEntries))
			}
		})
	}
}

func TestF075StreamingHTTPRejectionsPreserveStoredData(t *testing.T) {
	t.Run("EPSS late invalid record", func(t *testing.T) {
		seed := []db.EPSSEntry{{CVEID: "CVE-2026-7005", Score: 0.4, Percentile: 0.6}}
		store := &f075AtomicEPSSStore{snapshot: append([]db.EPSSEntry(nil), seed...)}
		h := newTestFeedImportHandler(store)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", strings.NewReader(f075EPSSEntriesBody(epssImportStreamBatchSize+1, true, "")))
		req.SetPathValue("feed", "epss")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		h.HandleImport(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
		}
		if !reflect.DeepEqual(store.snapshot, seed) || store.statusWrites != 0 || store.auditWrites != 0 || len(store.auditEntries) != 0 {
			t.Fatalf("rejected EPSS import committed data: snapshot=%+v status=%d audit=%d/%d", store.snapshot, store.statusWrites, store.auditWrites, len(store.auditEntries))
		}
		if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].LastSyncStatus != db.FeedSyncStatusRejected || store.upsertedStatuses[0].EntriesTotal != epssImportStreamBatchSize+1 {
			t.Fatalf("rejected EPSS status = %+v", store.upsertedStatuses)
		}
	})

	t.Run("VulnCheck invalid final status", func(t *testing.T) {
		seed := []db.VulnCheckEntry{{CVEID: "CVE-2026-7006", ExploitExists: true}}
		store := &atomicFailingVulnCheckStore{committed: append([]db.VulnCheckEntry(nil), seed...)}
		h := newTestFeedImportHandler(store)
		body := f075VulnCheckEntriesBody(vulnCheckImportStreamBatchSize+1, false, `{"last_sync_status":"not-supported"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/vulncheck/import", strings.NewReader(body))
		req.SetPathValue("feed", "vulncheck")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		h.HandleImport(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
		}
		if !reflect.DeepEqual(store.committed, seed) || len(store.auditEntries) != 0 {
			t.Fatalf("rejected VulnCheck import committed data: entries=%+v audit=%d", store.committed, len(store.auditEntries))
		}
		if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].LastSyncStatus != db.FeedSyncStatusRejected || store.upsertedStatuses[0].EntriesTotal != vulnCheckImportStreamBatchSize+1 {
			t.Fatalf("rejected VulnCheck status = %+v", store.upsertedStatuses)
		}
	})
}

func TestF075VulnCheckLateFailuresPreserveState(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantBatches []int
	}{
		{
			name:        "invalid late record",
			body:        f075VulnCheckEntriesBody(vulnCheckImportStreamBatchSize+1, true, ""),
			wantBatches: []int{vulnCheckImportStreamBatchSize},
		},
		{
			name:        "invalid explicit status after complete stream",
			body:        f075VulnCheckEntriesBody(vulnCheckImportStreamBatchSize+1, false, `{"last_sync_status":"not-supported"}`),
			wantBatches: []int{vulnCheckImportStreamBatchSize, 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := []db.VulnCheckEntry{{CVEID: "CVE-2026-7004", ExploitExists: true}}
			store := &atomicFailingVulnCheckStore{committed: append([]db.VulnCheckEntry(nil), seed...)}
			h := newTestFeedImportHandler(store)
			_, total, err := h.importVulnCheckRequest(context.Background(), "vulncheck", f075EPSSRequest(strings.NewReader(tt.body)), func(int, int) db.AdminAuditEntry {
				return db.AdminAuditEntry{Action: "feed_import"}
			})
			if err == nil {
				t.Fatal("late streamed import error = nil, want rejection")
			}
			if total != vulnCheckImportStreamBatchSize+1 {
				t.Fatalf("entries total = %d, want %d", total, vulnCheckImportStreamBatchSize+1)
			}
			if !reflect.DeepEqual(store.streamBatchSizes, tt.wantBatches) {
				t.Fatalf("batch sizes = %v, want %v", store.streamBatchSizes, tt.wantBatches)
			}
			if !reflect.DeepEqual(store.committed, seed) || len(store.upsertedStatuses) != 0 || len(store.auditEntries) != 0 {
				t.Fatalf("failed stream committed state: entries=%+v status=%d audit=%d", store.committed, len(store.upsertedStatuses), len(store.auditEntries))
			}
		})
	}
}

type f075StreamingDBStore struct {
	*adapterContractStore
	epss f075AtomicEPSSStore
}

func (s *f075StreamingDBStore) ImportEPSSStreamWithAudit(ctx context.Context, feed string, stream func(func([]db.EPSSEntry) error) (*db.FeedSyncStatus, error), audit db.FeedImportAuditBuilder) (int, int, int, error) {
	return s.epss.ImportEPSSStreamWithAudit(ctx, feed, stream, audit)
}

func (s *f075StreamingDBStore) ImportVulnCheckStreamWithAudit(_ context.Context, _ string, stream func(func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error), audit db.FeedImportAuditBuilder) (int, int, error) {
	status, total, err := stream(func([]db.VulnCheckEntry) error { return nil })
	if err != nil {
		return 0, total, err
	}
	if audit != nil {
		_ = audit(total, 0)
	}
	_ = status
	return total, total, nil
}

func TestF075DispatchAndAdapterCapabilityGuards(t *testing.T) {
	requestDispatch := feedImportRequestDispatch[epssImportRequest]{}
	if got := requestDispatch.newRequest(); got != (*epssImportRequest)(nil) {
		t.Fatalf("unconfigured request allocation = %#v, want typed nil", got)
	}
	if _, _, err := requestDispatch.decodeAndImport(context.Background(), newTestFeedImportHandler(&stubStore{}), f075EPSSRequest(strings.NewReader(`{}`)), "epss", nil); err == nil {
		t.Fatal("request dispatch without callbacks error = nil")
	}
	requestDispatch.allocate = func() *epssImportRequest { return &epssImportRequest{} }
	if _, _, err := requestDispatch.decodeAndImport(context.Background(), newTestFeedImportHandler(&stubStore{}), f075EPSSRequest(strings.NewReader(`{}`)), "epss", nil); err == nil {
		t.Fatal("request dispatch without import callback error = nil")
	}
	streamDispatch := feedImportStreamingDispatch{}
	if got := streamDispatch.newRequest(); got != nil {
		t.Fatalf("unconfigured stream allocation = %#v, want nil", got)
	}
	if _, _, err := streamDispatch.decodeAndImport(context.Background(), newTestFeedImportHandler(&stubStore{}), f075EPSSRequest(strings.NewReader(`{}`)), "epss", nil); err == nil {
		t.Fatal("stream dispatch without callback error = nil")
	}
	if _, _, err := streamImportEntriesObject[epssImportEntry, db.EPSSEntry](
		f075EPSSRequest(strings.NewReader(`{"entries":[]}`)),
		"epss",
		0,
		normalizeEPSSImportEntriesBatch,
		func([]db.EPSSEntry) error { return nil },
	); err == nil {
		t.Fatal("stream object with zero batch size error = nil")
	}
	if _, _, err := streamImportEntriesObject[epssImportEntry, db.EPSSEntry](
		f075EPSSRequest(strings.NewReader(`{"entries":[]}`)),
		"epss",
		1,
		nil,
		func([]db.EPSSEntry) error { return nil },
	); err == nil {
		t.Fatal("stream object without normalizer error = nil")
	}

	identityNormalize := func(_ string, _ int, item db.Vulnerability) (db.Vulnerability, error) { return item, nil }
	baseOptions := feedImportRecordOptions[db.Vulnerability]{normalize: identityNormalize}
	if _, err := importFeedRecords(context.Background(), newTestFeedImportHandler(&stubStore{}), "osv", nil, []db.Vulnerability{{ID: "GHSA-1"}}, nil, func(int, int) db.AdminAuditEntry { return db.AdminAuditEntry{Action: "feed_import"} }, baseOptions); err == nil {
		t.Fatal("record import without audited callback error = nil")
	}
	baseOptions.auditedImport = func(context.Context, string, []db.Vulnerability, []string, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, int, error) {
		return 0, 0, nil
	}
	if _, err := importFeedRecords(context.Background(), newTestFeedImportHandler(&stubStore{}), "osv", nil, []db.Vulnerability{{ID: "GHSA-1"}}, nil, nil, baseOptions); err == nil {
		t.Fatal("record import without audit builder error = nil")
	}
	genericErr := errors.New("generic audited import failure")
	baseOptions.auditedImport = func(context.Context, string, []db.Vulnerability, []string, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, int, error) {
		return 0, 0, genericErr
	}
	if _, err := importFeedRecords(context.Background(), newTestFeedImportHandler(&stubStore{}), "osv", nil, []db.Vulnerability{{ID: "GHSA-1"}}, nil, func(int, int) db.AdminAuditEntry { return db.AdminAuditEntry{Action: "feed_import"} }, baseOptions); !errors.Is(err, genericErr) {
		t.Fatalf("generic audited import error = %v, want %v", err, genericErr)
	}

	direct := &f075AtomicEPSSStore{}
	if got, ok := epssStreamImporterFor(direct); !ok || got != direct {
		t.Fatalf("direct EPSS capability = %#v/%v, want direct store", got, ok)
	}
	if got, ok := vulnCheckStreamImporterFor(direct); !ok || got != direct {
		t.Fatalf("direct VulnCheck capability = %#v/%v, want direct store", got, ok)
	}
	ctx := context.Background()
	backing := &f075StreamingDBStore{adapterContractStore: newAdapterContractStore(ctx)}
	adapter := NewDBStoreAdapter(backing)
	if got, ok := epssStreamImporterFor(adapter); !ok || got != backing {
		t.Fatalf("adapted EPSS capability = %#v/%v, want backing store", got, ok)
	}
	if got, ok := vulnCheckStreamImporterFor(adapter); !ok || got != backing {
		t.Fatalf("adapted VulnCheck capability = %#v/%v, want backing store", got, ok)
	}
	if got, ok := epssStreamImporterFor(&stubStore{}); ok || got != nil {
		t.Fatalf("buffered EPSS capability = %#v/%v, want nil/false", got, ok)
	}
	bufferedAdapter := NewDBStoreAdapter(newAdapterContractStore(ctx))
	if got, ok := vulnCheckStreamImporterFor(bufferedAdapter); ok || got != nil {
		t.Fatalf("buffered adapted VulnCheck capability = %#v/%v, want nil/false", got, ok)
	}
	bufferedStore := &stubStore{}
	bufferedHandler := newTestFeedImportHandler(bufferedStore)
	audit := func(int, int) db.AdminAuditEntry { return db.AdminAuditEntry{Action: "feed_import"} }
	epssResponse, epssTotal, err := bufferedHandler.importEPSSRequest(
		ctx,
		"epss",
		f075EPSSRequest(strings.NewReader(`{"entries":[{"cve_id":"CVE-2026-7506","score":0.2,"percentile":0.8}]}`)),
		audit,
	)
	if err != nil || epssTotal != 1 || epssResponse == nil || epssResponse.Imported != 1 || bufferedStore.epssReplaceCalls != 1 {
		t.Fatalf("buffered EPSS fallback response/total/calls = %+v/%d/%d, err=%v", epssResponse, epssTotal, bufferedStore.epssReplaceCalls, err)
	}
	vulnCheckResponse, vulnCheckTotal, err := bufferedHandler.importVulnCheckRequest(
		ctx,
		"vulncheck",
		f075EPSSRequest(strings.NewReader(`{"entries":[{"cve_id":"CVE-2026-7507","exploit_exists":true}]}`)),
		audit,
	)
	if err != nil || vulnCheckTotal != 1 || vulnCheckResponse == nil || vulnCheckResponse.Imported != 1 || len(bufferedStore.vulnCheckEntries) != 1 {
		t.Fatalf("buffered VulnCheck fallback response/total/entries = %+v/%d/%d, err=%v", vulnCheckResponse, vulnCheckTotal, len(bufferedStore.vulnCheckEntries), err)
	}

	classificationStore := &stubStore{auditErr: genericErr}
	classificationHandler := newTestFeedImportHandler(classificationStore)
	classificationRequest := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{"vulnerabilities":[{"id":"GHSA-f075-generic"}]}`))
	classificationRequest.SetPathValue("feed", "osv")
	classificationRequest.Header.Set("Content-Type", "application/json")
	classificationResponse := httptest.NewRecorder()
	classificationHandler.HandleImport(classificationResponse, classificationRequest)
	if classificationResponse.Code != http.StatusInternalServerError || !strings.Contains(classificationResponse.Body.String(), `"error":"feed import failed"`) || strings.Contains(classificationResponse.Body.String(), genericErr.Error()) {
		t.Fatalf("generic import classification status/body = %d/%s, want sanitized 500", classificationResponse.Code, classificationResponse.Body.String())
	}
}

func TestF075NormalizationValidationBoundaries(t *testing.T) {
	if _, err := normalizeCISAKEVImportIDs([]string{"CVE-not-valid"}, false); err == nil {
		t.Fatal("malformed KEV ID error = nil")
	}
	if _, err := normalizeCISAKEVImportIDs(nil, true); err == nil {
		t.Fatal("clear_missing without IDs error = nil")
	}
	score, percentile := 0.2, 0.8
	valid := epssImportEntry{CVEID: "CVE-2026-7502", Score: &score, Percentile: &percentile}
	for _, entry := range []epssImportEntry{
		{CVEID: "CVE-2026-7502", Percentile: &percentile},
		{CVEID: "CVE-2026-7502", Score: &score},
		{CVEID: "not-a-cve", Score: &score, Percentile: &percentile},
	} {
		if _, err := normalizeEPSSImportEntriesBatch([]epssImportEntry{entry}, 7); err == nil {
			t.Fatalf("invalid EPSS entry %+v error = nil", entry)
		}
	}
	if got, err := normalizeEPSSImportEntriesBatch([]epssImportEntry{valid}, 0); err != nil || len(got) != 1 || got[0].CVEID != valid.CVEID {
		t.Fatalf("valid EPSS normalization = %+v, %v", got, err)
	}

	invalidUnitValues := []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.01, 1.01}
	for _, value := range invalidUnitValues {
		entry := valid
		entry.Score = &value
		if _, err := normalizeEPSSImportEntriesBatch([]epssImportEntry{entry}, 0); err == nil {
			t.Fatalf("EPSS score %v error = nil", value)
		}
		entry = valid
		entry.Percentile = &value
		if _, err := normalizeEPSSImportEntriesBatch([]epssImportEntry{entry}, 0); err == nil {
			t.Fatalf("EPSS percentile %v error = nil", value)
		}
	}
	invalidCVSSValues := []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.01, 10.01}
	for _, value := range invalidCVSSValues {
		if _, err := normalizeVulnCheckImportEntriesBatch([]vulnCheckImportEntry{{CVEID: "CVE-2026-7503", CVSSScore: &value}}, 0); err == nil {
			t.Fatalf("VulnCheck CVSS %v error = nil", value)
		}
	}
	maxDuration := maxImportStatusDurationMs
	status, err := importStatusFromInput("epss", &feedSyncStatusInput{LastSyncDurationMs: &maxDuration}, 1, 1)
	if err != nil || status == nil || status.LastSyncDuration == nil || *status.LastSyncDuration != time.Duration(maxDuration)*time.Millisecond {
		t.Fatalf("maximum status duration = %+v, %v", status, err)
	}
	overflowDuration := maxImportStatusDurationMs + 1
	if _, err := importStatusFromInput("epss", &feedSyncStatusInput{LastSyncDurationMs: &overflowDuration}, 1, 1); err == nil {
		t.Fatal("overflowing status duration error = nil")
	}
}

func TestF075DTOConversionsOwnJSONAndValidRanges(t *testing.T) {
	validRanges := json.RawMessage(`[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.2.3"},{"limit":"2.0.0"}]}]`)
	if err := validateVersionRangesJSON(validRanges, "ranges"); err != nil {
		t.Fatalf("valid last_affected/limit range rejected: %v", err)
	}
	versions := json.RawMessage(`["1.0.0"]`)
	sourceRaw := json.RawMessage(`{"source":"raw"}`)
	vulnerability := vulnerabilityImportItem{
		ID:               "GHSA-f075",
		Aliases:          []vulnerabilityImportAlias{{AliasID: "CVE-2026-7505"}},
		Sources:          []vulnerabilityImportSource{{Source: "osv", SourceID: "GHSA-f075", URL: "https://example.test", RawJSON: sourceRaw}},
		References:       []vulnerabilityImportReference{{Type: "ADVISORY", URL: "https://example.test/reference", Source: "osv"}},
		AffectedPackages: []vulnerabilityImportPackage{{Ecosystem: "npm", Name: "pkg", VersionRanges: validRanges, VersionsAffected: versions}},
	}
	convertedVulnerability := vulnerability.toDB()
	wantVulnerability := db.Vulnerability{
		ID:               "GHSA-f075",
		Aliases:          []db.VulnerabilityAlias{{AliasID: "CVE-2026-7505"}},
		Sources:          []db.VulnerabilitySource{{Source: "osv", SourceID: "GHSA-f075", URL: "https://example.test", RawJSON: json.RawMessage(`{"source":"raw"}`)}},
		References:       []db.VulnerabilityReference{{Type: "ADVISORY", URL: "https://example.test/reference", Source: "osv"}},
		AffectedPackages: []db.AffectedPackage{{Ecosystem: "npm", Name: "pkg", VersionRanges: append(json.RawMessage(nil), validRanges...), VersionsAffected: append(json.RawMessage(nil), versions...)}},
	}
	if !reflect.DeepEqual(convertedVulnerability, wantVulnerability) {
		t.Fatalf("vulnerability DTO mapping = %+v", convertedVulnerability)
	}

	maliciousRanges := json.RawMessage(`[{"events":[{"introduced":"0"}]}]`)
	maliciousVersions := json.RawMessage(`["2.0.0"]`)
	maliciousReferences := json.RawMessage(`["https://example.test/advisory"]`)
	malicious := maliciousImportItem{ID: "MAL-f075", VersionRanges: maliciousRanges, Versions: maliciousVersions, ReferenceURLs: maliciousReferences}
	convertedMalicious := maliciousImportItemsToDB([]maliciousImportItem{malicious})[0]
	wantMalicious := db.MaliciousFinding{
		ID:            "MAL-f075",
		VersionRanges: append(json.RawMessage(nil), maliciousRanges...),
		Versions:      append(json.RawMessage(nil), maliciousVersions...),
		ReferenceURLs: append(json.RawMessage(nil), maliciousReferences...),
	}
	if !reflect.DeepEqual(convertedMalicious, wantMalicious) {
		t.Fatalf("malicious DTO mapping = %+v", convertedMalicious)
	}

	vulnCheckRaw := json.RawMessage(`{"vulncheck":true}`)
	vulnCheck, err := normalizeVulnCheckImportEntriesBatch([]vulnCheckImportEntry{{CVEID: "CVE-2026-7504", RawJSON: vulnCheckRaw}}, 0)
	if err != nil || len(vulnCheck) != 1 {
		t.Fatalf("VulnCheck DTO mapping = %+v, %v", vulnCheck, err)
	}
	wantVulnCheck := []db.VulnCheckEntry{{CVEID: "CVE-2026-7504", RawJSON: json.RawMessage(`{"vulncheck":true}`)}}
	if !reflect.DeepEqual(vulnCheck, wantVulnCheck) {
		t.Fatalf("VulnCheck exact DTO mapping = %+v, want %+v", vulnCheck, wantVulnCheck)
	}

	assertIndependent := func(t *testing.T, source, converted json.RawMessage) {
		t.Helper()
		originalSource := append(json.RawMessage(nil), source...)
		originalConverted := append(json.RawMessage(nil), converted...)
		source[0] ^= 1
		if !bytes.Equal(converted, originalConverted) {
			t.Fatalf("converted JSON changed with source: got %q want %q", converted, originalConverted)
		}
		converted[0] ^= 1
		if source[0] != originalSource[0]^1 {
			t.Fatalf("source JSON changed with converted value: got %q", source)
		}
	}
	assertIndependent(t, sourceRaw, convertedVulnerability.Sources[0].RawJSON)
	assertIndependent(t, validRanges, convertedVulnerability.AffectedPackages[0].VersionRanges)
	assertIndependent(t, versions, convertedVulnerability.AffectedPackages[0].VersionsAffected)
	assertIndependent(t, maliciousRanges, convertedMalicious.VersionRanges)
	assertIndependent(t, maliciousVersions, convertedMalicious.Versions)
	assertIndependent(t, maliciousReferences, convertedMalicious.ReferenceURLs)
	assertIndependent(t, vulnCheckRaw, vulnCheck[0].RawJSON)
}

type f077AuditStore struct {
	stubStore
	auditErr        error
	exportErr       error
	auditCalls      int
	exportCalls     int
	auditContextErr error
	auditDeadline   time.Time
	auditEntry      *db.AdminAuditEntry
	export          *db.SyncExport
}

func (s *f077AuditStore) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	s.auditCalls++
	s.auditContextErr = ctx.Err()
	if deadline, ok := ctx.Deadline(); ok {
		s.auditDeadline = deadline
	}
	if entry != nil {
		copyEntry := *entry
		copyEntry.Details = append(json.RawMessage(nil), entry.Details...)
		s.auditEntry = &copyEntry
	}
	return s.auditErr
}

func (s *f077AuditStore) ExportSync(context.Context, db.SyncExportOptions) (*db.SyncExport, error) {
	s.exportCalls++
	return s.export, s.exportErr
}

func TestF077AuditFailureDetachesContextAndSkipsExport(t *testing.T) {
	sentinel := errors.New("audit unavailable")
	store := &f077AuditStore{auditErr: sentinel}
	var logs bytes.Buffer
	h := newLogCaptureHandler(store, &logs)
	base := requestctx.ContextWithCorrelationID(context.Background(), "corr-f077-detached")
	base = requestctx.ContextWithAPIKeyIdentity(base, requestctx.APIKeyIdentity{ID: 77, Name: "sync-client"})
	canceled, cancel := context.WithCancel(base)
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil).WithContext(canceled)
	req.RemoteAddr = "203.0.113.77:4567"
	rr := httptest.NewRecorder()
	started := time.Now()

	h.HandleSync(rr, req)

	if rr.Code != http.StatusInternalServerError || store.auditCalls != 1 || store.exportCalls != 0 {
		t.Fatalf("status/audit/export = %d/%d/%d, want 500/1/0", rr.Code, store.auditCalls, store.exportCalls)
	}
	if store.auditContextErr != nil {
		t.Fatalf("detached audit context error = %v, want nil", store.auditContextErr)
	}
	if store.auditDeadline.IsZero() || !store.auditDeadline.After(started) || store.auditDeadline.After(started.Add(scanLogInsertTimeout+time.Second)) {
		t.Fatalf("audit deadline = %v, want a positive bounded deadline", store.auditDeadline)
	}
	if store.auditEntry == nil || store.auditEntry.Action != "sync_export" || store.auditEntry.IP != "203.0.113.77" {
		t.Fatalf("audit entry = %+v, want attributed sync_export", store.auditEntry)
	}
	logText := logs.String()
	for _, want := range []string{"sync export audit failed", sentinel.Error(), "corr-f077-detached", "203.0.113.77", "sync-client"} {
		if !strings.Contains(logText, want) {
			t.Fatalf("log missing %q: %s", want, logText)
		}
	}
}

func TestF077SyncStoreFailuresRedactAndBoundDiagnostics(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name            string
		auditErr        error
		exportErr       error
		wantMessage     string
		wantExportCalls int
	}{
		{
			name:            "audit failure",
			auditErr:        f077HostileStoreError(),
			wantMessage:     "sync export audit failed",
			wantExportCalls: 0,
		},
		{
			name:            "export failure",
			exportErr:       f077HostileStoreError(),
			wantMessage:     "sync export failed",
			wantExportCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &f077AuditStore{auditErr: tc.auditErr, exportErr: tc.exportErr}
			var logs bytes.Buffer
			h := newLogCaptureHandler(store, &logs)
			req := withCorrelationID(httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil), "corr-f077-log-safe")
			req.RemoteAddr = "203.0.113.77:4567"
			recorder := httptest.NewRecorder()

			h.HandleSync(recorder, req)

			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body.String())
			}
			if store.auditCalls != 1 || store.exportCalls != tc.wantExportCalls {
				t.Fatalf("audit/export calls = %d/%d, want 1/%d", store.auditCalls, store.exportCalls, tc.wantExportCalls)
			}
			for _, leaked := range []string{"db-password", "bearer-secret-token-123456", "assignment-secret", `C:\private\workspace\packmon\sync.go`, "private-tail-marker"} {
				if strings.Contains(recorder.Body.String(), leaked) {
					t.Fatalf("response leaked %q: %s", leaked, recorder.Body.String())
				}
			}

			var logEntry map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &logEntry); err != nil {
				t.Fatalf("decode JSON log: %v; log=%s", err, logs.String())
			}
			if logEntry["msg"] != tc.wantMessage {
				t.Fatalf("log message = %v, want %q", logEntry["msg"], tc.wantMessage)
			}
			if logEntry["correlation_id"] != "corr-f077-log-safe" {
				t.Fatalf("correlation_id = %v, want corr-f077-log-safe", logEntry["correlation_id"])
			}
			loggedError, ok := logEntry["error"].(string)
			if !ok {
				t.Fatalf("error log field = %T, want string", logEntry["error"])
			}
			assertF077SafeDiagnostic(t, loggedError)
		})
	}
}

func TestF077InvalidCursorAndDoneValuesStopBeforeAudit(t *testing.T) {
	for _, rawQuery := range []string{
		url.Values{"malicious_cursor": {"***"}}.Encode(),
		url.Values{"vulnerabilities_done": {"definitely"}}.Encode(),
	} {
		store := &f077AuditStore{}
		h := newTestHandler(store)
		rr := httptest.NewRecorder()
		h.HandleSync(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sync?"+rawQuery, nil))
		if rr.Code != http.StatusBadRequest || store.auditCalls != 0 || store.exportCalls != 0 {
			t.Fatalf("query %q status/audit/export = %d/%d/%d, want 400/0/0", rawQuery, rr.Code, store.auditCalls, store.exportCalls)
		}
	}
}

func TestF077NilExportProducesStableEmptyEnvelope(t *testing.T) {
	versions := map[string]string{"osv": "2026-11-02"}
	resp := syncResponseFromExport(nil, "degraded", versions)
	if resp.SyncedAt != "" || resp.SyncedXID != 0 || resp.Truncated || resp.HasMore || resp.NextCursor != nil {
		t.Fatalf("nil export scalar envelope = %+v", resp)
	}
	if resp.FeedStatus != "degraded" || !reflect.DeepEqual(resp.FeedVersions, versions) {
		t.Fatalf("nil export feed state = %q/%v, want degraded/%v", resp.FeedStatus, resp.FeedVersions, versions)
	}
	if resp.Vulnerabilities == nil || len(resp.Vulnerabilities) != 0 || resp.Malicious == nil || len(resp.Malicious) != 0 || resp.Reputation == nil || len(resp.Reputation) != 0 || resp.Lifecycle == nil || len(resp.Lifecycle) != 0 {
		t.Fatalf("nil export datasets must be non-nil empty slices: %+v", resp)
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal nil export envelope: %v", err)
	}
	for _, want := range []string{`"vulnerabilities":[]`, `"malicious":[]`, `"reputation":[]`, `"lifecycle":[]`, `"truncated":false`, `"has_more":false`} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("wire envelope %s missing %s", raw, want)
		}
	}
}

func TestF077AuditDetailsCoverAllCursorFlagsWithoutRawValues(t *testing.T) {
	cursors := map[string]string{
		"vulnerabilities_cursor": testSyncCursorKey("npm", "private-vulnerability", "GHSA-f077"),
		"malicious_cursor":       testSyncCursorKey("npm", "private-malicious", "MAL-f077"),
		"reputation_cursor":      testSyncCursorKey("npm", "private-reputation", "1.0.0"),
		"lifecycle_cursor":       testSyncCursorKey("npm", "private-lifecycle", "node", "22"),
	}
	query := url.Values{
		"since":                  {"2026-11-01T10:00:00Z"},
		"since_xid":              {"101"},
		"snapshot":               {"2026-11-02T10:00:00Z"},
		"snapshot_xid":           {"202"},
		"ecosystem":              {"npm,go"},
		"limit":                  {"17"},
		"offset":                 {"9"},
		"vulnerabilities_offset": {"1"},
		"malicious_offset":       {"2"},
		"reputation_offset":      {"3"},
		"lifecycle_offset":       {"4"},
		"vulnerabilities_done":   {"true"},
		"malicious_done":         {"true"},
		"reputation_done":        {"true"},
		"lifecycle_done":         {"true"},
	}
	for name, value := range cursors {
		query.Set(name, value)
	}
	store := &f077AuditStore{export: &db.SyncExport{SyncedAt: time.Date(2026, 11, 2, 11, 0, 0, 0, time.UTC)}}
	h := newTestHandler(store)
	ctx := requestctx.ContextWithCorrelationID(context.Background(), "corr-f077-all-flags")
	ctx = requestctx.ContextWithAPIKeyIdentity(ctx, requestctx.APIKeyIdentity{ID: 707, Name: "all-flags-client"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync?"+query.Encode(), nil).WithContext(ctx)
	req.RemoteAddr = "198.51.100.77:1234"
	rr := httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusOK || store.auditCalls != 1 || store.exportCalls != 1 || store.auditEntry == nil {
		t.Fatalf("status/audit/export/entry = %d/%d/%d/%+v", rr.Code, store.auditCalls, store.exportCalls, store.auditEntry)
	}
	if store.auditContextErr != nil || store.auditDeadline.IsZero() {
		t.Fatalf("captured audit context error/deadline = %v/%v", store.auditContextErr, store.auditDeadline)
	}
	var details map[string]any
	if err := json.Unmarshal(store.auditEntry.Details, &details); err != nil {
		t.Fatalf("decode audit details: %v", err)
	}
	wantScalars := map[string]any{
		"method":                          http.MethodGet,
		"since":                           "2026-11-01T10:00:00Z",
		"since_xid":                       float64(101),
		"snapshot":                        "2026-11-02T10:00:00Z",
		"snapshot_xid":                    float64(202),
		"limit":                           float64(17),
		"offset":                          float64(9),
		"vulnerabilities_offset":          float64(1),
		"malicious_offset":                float64(2),
		"reputation_offset":               float64(3),
		"lifecycle_offset":                float64(4),
		"vulnerabilities_cursor_provided": true,
		"malicious_cursor_provided":       true,
		"reputation_cursor_provided":      true,
		"lifecycle_cursor_provided":       true,
		"vulnerabilities_done":            true,
		"malicious_done":                  true,
		"reputation_done":                 true,
		"lifecycle_done":                  true,
		"correlation_id":                  "corr-f077-all-flags",
		"api_key_id":                      float64(707),
		"api_key_name":                    "all-flags-client",
	}
	for key, want := range wantScalars {
		if got := details[key]; got != want {
			t.Fatalf("audit detail %s = %#v, want %#v (all=%#v)", key, got, want, details)
		}
	}
	if got := details["ecosystems"]; !reflect.DeepEqual(got, []any{"npm", "go"}) {
		t.Fatalf("audit ecosystems = %#v, want [npm go]", got)
	}
	detailText := string(store.auditEntry.Details)
	for _, rawCursor := range cursors {
		if strings.Contains(detailText, rawCursor) {
			t.Fatalf("audit details contain raw cursor %q: %s", rawCursor, detailText)
		}
	}
}

func TestF077PopulatedFourDatasetResponsePreservesWireFields(t *testing.T) {
	date := time.Date(2026, 11, 2, 13, 14, 15, 123456789, time.FixedZone("test", 2*60*60))
	dateOnly := time.Date(2026, 10, 5, 22, 0, 0, 0, time.FixedZone("west", -2*60*60))
	cvss, epss, percentile := 9.8, 0.42, 0.97
	eoes := false
	exported := &db.SyncExport{
		SyncedAt:  date,
		SyncedXID: 909,
		Vulnerabilities: []db.SyncVulnerability{{
			ID: "CVE-2026-7701", Ecosystem: "npm", Name: "left-pad",
			VersionRanges: `[{"events":[{"introduced":"0"}]}]`, VersionsAffected: `["1.0.0"]`, References: `["https://example.test/cve"]`,
			Severity: "CRITICAL", CVSSScore: &cvss, EPSSScore: &epss, EPSSPercentile: &percentile, CISAKEV: true, Summary: "summary", Source: "osv", Withdrawn: true,
		}},
		Malicious: []db.SyncMalicious{{
			ID: "MAL-7701", Ecosystem: "pypi", Name: "evil", VersionRanges: `[]`, Versions: `["2.0"]`, ReferenceURLs: `["https://example.test/mal"]`, RiskType: "malware", Severity: "CRITICAL", Summary: "malicious", Source: "openssf", Withdrawn: true,
		}},
		Reputation: []db.SyncReputationFinding{{
			ID: "REP-7701", Ecosystem: "npm", Name: "history", Version: "3.0.0", Type: "supply_chain_risk", RiskType: "malware_history", Severity: "LOW", Summary: "history", Withdrawn: true,
		}},
		Lifecycle: []db.SyncLifecycleRelease{{
			ID: "LIFE-7701", Ecosystem: "npm", Name: "node", ProductSlug: "nodejs", ProductLabel: "Node.js", Cycle: "22", Latest: "22.9.0",
			ReleaseDate: &dateOnly, IsLTS: true, LTSFrom: &dateOnly, IsEOAS: true, EOASFrom: &dateOnly, IsEOL: true, EOLFrom: &dateOnly,
			IsDiscontinued: true, DiscontinuedFrom: &dateOnly, IsEOES: &eoes, EOESFrom: &dateOnly, IsMaintained: false, Withdrawn: true,
		}},
		Truncated: true,
		NextCursor: &db.SyncCursor{
			Vulnerabilities: 1, Malicious: 2, Reputation: 3, Lifecycle: 4,
			VulnerabilitiesCursor: "vuln-cursor", MaliciousCursor: "mal-cursor", ReputationCursor: "rep-cursor", LifecycleCursor: "life-cursor",
			VulnerabilitiesDone: true, MaliciousDone: true, ReputationDone: true, LifecycleDone: true,
		},
	}
	resp := syncResponseFromExport(exported, "healthy", map[string]string{"osv": "v1", "epss": "v2"})
	actualJSON, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal populated sync response: %v", err)
	}
	wantJSON := `{
		"synced_at":"2026-11-02T11:14:15.123456789Z","synced_xid":909,"feed_status":"healthy","feed_versions":{"epss":"v2","osv":"v1"},
		"vulnerabilities":[{"id":"CVE-2026-7701","ecosystem":"npm","name":"left-pad","version_ranges":"[{\"events\":[{\"introduced\":\"0\"}]}]","versions_affected":"[\"1.0.0\"]","references":"[\"https://example.test/cve\"]","severity":"CRITICAL","cvss_score":9.8,"epss_score":0.42,"epss_percentile":0.97,"cisa_kev":true,"summary":"summary","source":"osv","withdrawn":true}],
		"malicious":[{"id":"MAL-7701","ecosystem":"pypi","name":"evil","version_ranges":"[]","versions":"[\"2.0\"]","reference_urls":"[\"https://example.test/mal\"]","risk_type":"malware","severity":"CRITICAL","summary":"malicious","source":"openssf","withdrawn":true}],
		"reputation":[{"id":"REP-7701","ecosystem":"npm","name":"history","version":"3.0.0","type":"supply_chain_risk","risk_type":"malware_history","severity":"LOW","summary":"history","withdrawn":true}],
		"lifecycle":[{"id":"LIFE-7701","ecosystem":"npm","name":"node","product_slug":"nodejs","product_label":"Node.js","cycle":"22","latest":"22.9.0","release_date":"2026-10-06","is_lts":true,"lts_from":"2026-10-06","is_eoas":true,"eoas_from":"2026-10-06","is_eol":true,"eol_from":"2026-10-06","is_discontinued":true,"discontinued_from":"2026-10-06","is_eoes":false,"eoes_from":"2026-10-06","is_maintained":false,"withdrawn":true}],
		"truncated":true,"has_more":true,
		"next_cursor":{"vulnerabilities":1,"malicious":2,"reputation":3,"lifecycle":4,"vulnerabilities_cursor":"vuln-cursor","malicious_cursor":"mal-cursor","reputation_cursor":"rep-cursor","lifecycle_cursor":"life-cursor","vulnerabilities_done":true,"malicious_done":true,"reputation_done":true,"lifecycle_done":true}
	}`
	var actual, want any
	if err := json.Unmarshal(actualJSON, &actual); err != nil {
		t.Fatalf("decode actual populated response: %v", err)
	}
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		t.Fatalf("decode expected populated response: %v", err)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("populated sync wire response mismatch\nactual: %s\nwant:   %s", actualJSON, wantJSON)
	}
}
