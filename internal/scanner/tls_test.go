package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/parser"
)

const tlsNPMLock = `{
	"lockfileVersion": 3,
	"packages": {
		"": {"version":"1.0.0"},
		"node_modules/lodash": {"version":"4.17.15"}
	}
}`

func TestScannerHTTPClientRejectsHTTPSDowngradeRedirect(t *testing.T) {
	sc := New(nil, Config{Timeout: time.Second})
	req, err := http.NewRequest(http.MethodGet, "http://packmon.example/api/v1/check", nil)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := http.NewRequest(http.MethodGet, "https://packmon.example/api/v1/check", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	if err := sc.client.CheckRedirect(req, []*http.Request{prev}); err == nil {
		t.Fatal("CheckRedirect allowed HTTPS-to-HTTP downgrade")
	}
}

func TestScannerHTTPClientStripsAuthorizationOnCrossOriginRedirect(t *testing.T) {
	sc := New(nil, Config{Timeout: time.Second})
	req, err := http.NewRequest(http.MethodGet, "https://other.example/api/v1/check", nil)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := http.NewRequest(http.MethodGet, "https://packmon.example/api/v1/check", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	if err := sc.client.CheckRedirect(req, []*http.Request{prev}); err != nil {
		t.Fatalf("CheckRedirect same-scheme cross-origin error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization after cross-origin redirect = %q, want stripped", got)
	}
}

func writeTLSLock(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(tlsNPMLock), 0o600); err != nil {
		t.Fatal(err)
	}
}

// okFindingHandler returns a minimal valid scan response.
func okFindingHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := domain.ScanResult{
		Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
		Findings:     []domain.Finding{},
		FeedVersions: map[string]string{"osv": "2026-01-01"},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// writeServerCertPEM writes the leaf certificate(s) presented by an httptest
// TLS server to a PEM file, so a client can be configured to trust it via
// CACertFile.
func writeServerCertPEM(t *testing.T, srv *httptest.Server, path string) {
	t.Helper()
	if srv.TLS == nil || len(srv.TLS.Certificates) == 0 {
		t.Fatal("test server has no TLS certificate")
	}
	var buf []byte
	for _, c := range srv.TLS.Certificates {
		for _, der := range c.Certificate {
			buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
}

// tlsFakeLocalChecker records calls and returns a fixed set of findings.
type tlsFakeLocalChecker struct {
	findings []domain.Finding
	calls    int
}

func (c *tlsFakeLocalChecker) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	c.calls++
	return c.findings, nil
}

func (c *tlsFakeLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	c.calls++
	return nil, nil
}

func TestCheckRemote_RejectsHTTPByDefault(t *testing.T) {
	dir := t.TempDir()
	writeTLSLock(t, dir)

	cfg := Config{
		Path:      dir,
		Mode:      ModeRemote,
		ServerURL: "http://example.invalid",
		FailOn:    domain.SeverityCritical,
		Timeout:   2 * time.Second,
		// AllowInsecureHTTP defaults to false.
	}
	sc := New(parser.NewRegistry(), cfg)
	result, exitCode := sc.Run(context.Background())
	if exitCode != ExitOperational {
		t.Fatalf("exit=%d want=%d (http should be rejected)", exitCode, ExitOperational)
	}
	if result.FeedStatus == "" {
		t.Fatal("expected an error message in FeedStatus")
	}
}

func TestCheckRemote_AllowsHTTPWhenOptIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(okFindingHandler))
	defer server.Close()

	dir := t.TempDir()
	writeTLSLock(t, dir)

	cfg := Config{
		Path:              dir,
		Mode:              ModeRemote,
		ServerURL:         server.URL, // http://
		AllowInsecureHTTP: true,
		FailOn:            domain.SeverityCritical,
		Timeout:           5 * time.Second,
	}
	sc := New(parser.NewRegistry(), cfg)
	_, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("exit=%d want=%d (http opt-in should succeed)", exitCode, ExitOK)
	}
}

func TestCheckRemote_AllowsHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(okFindingHandler))
	defer server.Close()

	dir := t.TempDir()
	writeTLSLock(t, dir)

	caFile := filepath.Join(dir, "ca.pem")
	writeServerCertPEM(t, server, caFile)

	cfg := Config{
		Path:       dir,
		Mode:       ModeRemote,
		ServerURL:  server.URL, // https://
		CACertFile: caFile,
		FailOn:     domain.SeverityCritical,
		Timeout:    5 * time.Second,
	}
	sc := New(parser.NewRegistry(), cfg)
	_, exitCode := sc.Run(context.Background())
	if exitCode != ExitOK {
		t.Fatalf("exit=%d want=%d (https with custom CA should succeed)", exitCode, ExitOK)
	}
}

func TestCheckRemote_HTTPSFailsWithoutCustomCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(okFindingHandler))
	defer server.Close()

	dir := t.TempDir()
	writeTLSLock(t, dir)

	cfg := Config{
		Path:      dir,
		Mode:      ModeRemote,
		ServerURL: server.URL, // https:// with a cert signed by an untrusted CA
		FailOn:    domain.SeverityCritical,
		Timeout:   5 * time.Second,
		// No CACertFile: system roots do not trust httptest's cert.
	}
	sc := New(parser.NewRegistry(), cfg)
	_, exitCode := sc.Run(context.Background())
	if exitCode != ExitOperational {
		t.Fatalf("exit=%d want=%d (untrusted TLS cert should fail)", exitCode, ExitOperational)
	}
}

func TestNew_BadCACertFileSurfacesError(t *testing.T) {
	dir := t.TempDir()
	writeTLSLock(t, dir)

	badCA := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(badCA, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Path:       dir,
		Mode:       ModeRemote,
		ServerURL:  "https://example.invalid",
		CACertFile: badCA,
		FailOn:     domain.SeverityCritical,
		Timeout:    2 * time.Second,
	}
	sc := New(parser.NewRegistry(), cfg)
	if sc.clientErr == nil {
		t.Fatal("expected clientErr to be set for invalid CA bundle")
	}
	_, exitCode := sc.Run(context.Background())
	if exitCode != ExitOperational {
		t.Fatalf("exit=%d want=%d (invalid CA bundle should fail the scan)", exitCode, ExitOperational)
	}
}

func TestTransportHasMinVersionAndRootCAs(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	srv := httptest.NewTLSServer(http.HandlerFunc(okFindingHandler))
	defer srv.Close()
	writeServerCertPEM(t, srv, caFile)

	// With a CA file: RootCAs must be non-nil and MinVersion TLS 1.2.
	scWithCA := New(parser.NewRegistry(), Config{CACertFile: caFile, Timeout: time.Second})
	tr, ok := scWithCA.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion=%d want=%d", tr.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("RootCAs should be non-nil when CACertFile is set")
	}

	// Without a CA file: RootCAs nil (system roots), MinVersion still 1.2.
	scNoCA := New(parser.NewRegistry(), Config{Timeout: time.Second})
	trNo := scNoCA.client.Transport.(*http.Transport)
	if trNo.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion=%d want=%d", trNo.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
	if trNo.TLSClientConfig.RootCAs != nil {
		t.Fatal("RootCAs should be nil (system roots) without CACertFile")
	}
}

func TestRequireRemote_NoFallbackOnRemoteFailure(t *testing.T) {
	dir := t.TempDir()
	writeTLSLock(t, dir)

	fakeLocal := &tlsFakeLocalChecker{
		findings: []domain.Finding{{
			Name: "lodash", Version: "4.17.15", Ecosystem: "npm",
			Severity: domain.SeverityHigh, Type: domain.FindingTypeVulnerability,
		}},
	}

	cfg := Config{
		Path:              dir,
		Mode:              ModeAuto,
		ServerURL:         "http://127.0.0.1:1/api/v1/check",
		AllowInsecureHTTP: true, // get past HTTPS guard so we hit a real conn error
		RequireRemote:     true,
		FailOn:            domain.SeverityCritical,
		Timeout:           2 * time.Second,
	}
	sc := New(parser.NewRegistry(), cfg)
	sc.SetLocalChecker(fakeLocal)
	_, exitCode := sc.Run(context.Background())
	if exitCode != ExitOperational {
		t.Fatalf("exit=%d want=%d (require-remote must not fall back)", exitCode, ExitOperational)
	}
	if fakeLocal.calls != 0 {
		t.Fatalf("local checker was called %d times; require-remote must not fall back", fakeLocal.calls)
	}
}

func TestRequireRemote_FalseStillFallsBack(t *testing.T) {
	dir := t.TempDir()
	writeTLSLock(t, dir)

	fakeLocal := &tlsFakeLocalChecker{
		findings: []domain.Finding{{
			Name: "lodash", Version: "4.17.15", Ecosystem: "npm",
			Severity: domain.SeverityHigh, Type: domain.FindingTypeVulnerability,
		}},
	}

	cfg := Config{
		Path:              dir,
		Mode:              ModeAuto,
		ServerURL:         "http://127.0.0.1:1/api/v1/check",
		AllowInsecureHTTP: true,
		RequireRemote:     false,
		FailOn:            domain.SeverityCritical,
		Timeout:           2 * time.Second,
	}
	sc := New(parser.NewRegistry(), cfg)
	sc.SetLocalChecker(fakeLocal)
	_, exitCode := sc.Run(context.Background())
	// HIGH finding under CRITICAL threshold => under-threshold exit.
	if exitCode != ExitUnderThreshold {
		t.Fatalf("exit=%d want=%d (default should fall back to local)", exitCode, ExitUnderThreshold)
	}
	if fakeLocal.calls == 0 {
		t.Fatal("local checker should have been called on fallback")
	}
}
