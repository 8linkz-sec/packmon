package osv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

type osvFailingTempArchive struct {
	writeErr error
	closeErr error
}

func (f *osvFailingTempArchive) Write([]byte) (int, error) { return 0, f.writeErr }
func (f *osvFailingTempArchive) Close() error              { return f.closeErr }
func (f *osvFailingTempArchive) Name() string              { return "osv-gap.zip" }

func TestOSVEmptyAndMalformedHelperBranches(t *testing.T) {
	t.Parallel()

	if synced, total := statusCounts(nil); synced != 0 || total != 0 {
		t.Fatalf("statusCounts(nil) = %d, %d", synced, total)
	}
	if _, ok := closureEventFromDatabaseSpecific(nil); ok {
		t.Fatal("closureEventFromDatabaseSpecific(nil) ok = true")
	}
	if _, ok := closureEventFromDatabaseSpecific(json.RawMessage("{")); ok {
		t.Fatal("closureEventFromDatabaseSpecific(invalid) ok = true")
	}
	if got := mapToMaliciousFindings(nil); got != nil {
		t.Fatalf("mapToMaliciousFindings(nil) = %+v", got)
	}
	if got := mapToMaliciousFindings(&osvEntry{Affected: []osvAffected{{
		Package:          osvPackage{Ecosystem: "unsupported", Name: "pkg"},
		DatabaseSpecific: json.RawMessage(`{"categories":["malicious"]}`),
	}}}); got != nil {
		t.Fatalf("mapToMaliciousFindings(unsupported) = %+v", got)
	}
	if affectedHasMaliciousCategory(osvAffected{}) {
		t.Fatal("affectedHasMaliciousCategory(empty) = true")
	}
	if got := affectedSource(osvAffected{}); got != "" {
		t.Fatalf("affectedSource(empty) = %q", got)
	}
	if got := extractCVSSScore([]osvSeverity{{Type: "OTHER", Score: "9.8"}, {Type: "CVSS_V3", Score: "invalid"}}); got != 0 {
		t.Fatalf("extractCVSSScore(unusable) = %v", got)
	}
}

func TestSaveEcosystemETagsWithoutStatusIsNonFatal(t *testing.T) {
	t.Parallel()

	store := &osvStoreStub{}
	NewSyncer(nil).saveEcosystemETags(context.Background(), store, map[string]string{"npm": "etag"})
	if store.status != nil {
		t.Fatalf("status = %+v, want no synthesized status", store.status)
	}
}

func TestDownloadTempCreationAndJoinedWriteCloseErrors(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "archive")
	}))
	defer server.Close()
	syncer := NewSyncer(nil, WithHTTPClient(server.Client()))

	createErr := errors.New("create failed")
	if _, _, err := syncer.downloadWithTempArchiveFileHooks(context.Background(), server.URL, "", tempArchiveFileHooks{
		create: func() (tempArchiveWriteFile, error) { return nil, createErr },
		remove: func(string) error { return nil },
	}); !errors.Is(err, createErr) {
		t.Fatalf("download(create error) = %v", err)
	}

	writeErr := errors.New("write failed")
	closeErr := errors.New("close failed")
	removed := false
	_, _, err := syncer.downloadWithTempArchiveFileHooks(context.Background(), server.URL, "", tempArchiveFileHooks{
		create: func() (tempArchiveWriteFile, error) {
			return &osvFailingTempArchive{writeErr: writeErr, closeErr: closeErr}, nil
		},
		remove: func(string) error { removed = true; return nil },
	})
	if !errors.Is(err, writeErr) || !errors.Is(err, closeErr) || !removed {
		t.Fatalf("download(write+close errors) = %v, removed=%v", err, removed)
	}
}

func TestSyncEcosystemDefaultsBaseURLAndRejectsInvalidArchive(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.URL.String(), DefaultBaseURL) {
			t.Fatalf("request URL = %q, want default base", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("not zip"))}, nil
	})}
	syncer := NewSyncer(nil, WithBaseURL(" "), WithHTTPClient(client))
	if _, _, _, err := syncer.syncEcosystem(context.Background(), &osvStoreStub{}, "npm", ""); err == nil || !strings.Contains(err.Error(), "open zip") {
		t.Fatalf("syncEcosystem(invalid zip) error = %v", err)
	}
}

func TestProcessOSVEntryMutationErrorBranches(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil)
	withdrawn := "2026-11-05T00:00:00Z"
	raw, err := json.Marshal(osvEntry{ID: "OSV-withdrawn", Withdrawn: &withdrawn})
	if err != nil {
		t.Fatal(err)
	}
	result := syncer.processOSVEntry(context.Background(), &osvStoreStub{deleteErr: errors.New("delete failed")}, zipEntry(t, "withdrawn.json", raw))
	if result.outcome != osvEntryOutcomeError || result.errors != 1 {
		t.Fatalf("withdrawn delete result = %+v", result)
	}

	maliciousRaw := []byte(`{"id":"OSV-malicious","affected":[{"package":{"ecosystem":"npm","name":"bad"},"database_specific":{"categories":["malicious"]}}]}`)
	result = syncer.processOSVEntry(context.Background(), &osvStoreStub{deleteErr: errors.New("delete failed"), maliciousErr: errors.New("write failed")}, zipEntry(t, "malicious.json", maliciousRaw))
	if result.outcome != osvEntryOutcomeError || result.errors != 2 || result.synced != 0 {
		t.Fatalf("malicious mutation result = %+v", result)
	}

	regularRaw := []byte(`{"id":"OSV-regular"}`)
	result = syncer.processOSVEntry(context.Background(), &osvStoreStub{vulnUpsertErrIDs: map[string]error{"OSV-regular": errors.New("write failed")}}, zipEntry(t, "regular.json", regularRaw))
	if result.outcome != osvEntryOutcomeError || result.errors != 1 {
		t.Fatalf("vulnerability mutation result = %+v", result)
	}
}

var _ db.Store = (*osvStoreStub)(nil)
