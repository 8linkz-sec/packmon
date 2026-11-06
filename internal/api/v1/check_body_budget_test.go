package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestHandleCheckMaxPackageCountWithEscapedCoordinates(t *testing.T) {
	packages := repeatedCheckPackages(
		strings.Repeat(`\`, checkcontract.MaxPackageNameLength/2),
		strings.Repeat("1", checkcontract.MaxPackageVersionLength/2),
	)
	body := marshalCheckPackages(t, packages)
	if int64(len(body)) >= maxRequestBody {
		t.Fatalf("escaped request body size = %d, want below limit %d", len(body), maxRequestBody)
	}

	store := &stubStore{}
	h := newTestHandler(store)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("escaped max-count request status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := len(store.vulnerabilityQueriesSnapshot()); got != 1 {
		t.Fatalf("deduplicated vulnerability lookups = %d, want 1", got)
	}
	if got := len(store.maliciousQueriesSnapshot()); got != 1 {
		t.Fatalf("deduplicated malicious lookups = %d, want 1", got)
	}
}

func TestHandleCheckContractMaximumEscapingFitsRawBodyBudget(t *testing.T) {
	packages := repeatedCheckPackages(
		strings.Repeat("<", checkcontract.MaxPackageNameLength),
		strings.Repeat("<", checkcontract.MaxPackageVersionLength),
	)
	body := marshalCheckPackages(t, packages)
	if !bytes.Contains(body, []byte(`\u003c`)) {
		t.Fatal("contract-maximum request does not exercise six-byte JSON escaping")
	}
	if int64(len(body)) <= maxRequestBody {
		t.Fatalf("escaped request body size = %d, want above generic limit %d", len(body), maxRequestBody)
	}
	if int64(len(body)) > maxCheckRequestBody {
		t.Fatalf("escaped request body size = %d, want within check limit %d", len(body), maxCheckRequestBody)
	}

	store := &stubStore{}
	h := newTestHandler(store)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("contract-maximum escaped request status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := len(store.vulnerabilityQueriesSnapshot()); got != 1 {
		t.Fatalf("deduplicated vulnerability lookups = %d, want 1", got)
	}
	if got := len(store.maliciousQueriesSnapshot()); got != 1 {
		t.Fatalf("deduplicated malicious lookups = %d, want 1", got)
	}
}

func repeatedCheckPackages(name, version string) []domain.Package {
	packages := make([]domain.Package, checkcontract.MaxPackagesPerCheck)
	for i := range packages {
		packages[i] = domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemNPM,
		}
	}
	return packages
}

func marshalCheckPackages(t *testing.T, packages []domain.Package) []byte {
	t.Helper()
	body, err := json.Marshal(domain.ScanRequest{Packages: packages})
	if err != nil {
		t.Fatalf("marshal check packages: %v", err)
	}
	return body
}
