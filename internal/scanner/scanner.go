package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
)

// LocalChecker is the interface required for local-mode scanning.
// It is satisfied by the sqlite.Store type.
type LocalChecker interface {
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
}

// Mode controls how the scanner resolves findings.
type Mode string

const (
	ModeAuto   Mode = "auto"
	ModeRemote Mode = "remote"
	ModeLocal  Mode = "local"
)

// Exit codes per DE-2.
const (
	ExitOK             = 0
	ExitBlocking       = 1
	ExitOperational    = 2
	ExitUnderThreshold = 3
	ExitParser         = 4
	ExitInternal       = 10
)

// Config holds all parameters needed for a single scan invocation.
type Config struct {
	Path       string
	Mode       Mode
	ServerURL  string
	APIKey     string
	Repo       *domain.RepoInfo
	FailOn     domain.Severity
	Ecosystems []string
	MaxDepth   int
	Timeout    time.Duration
	IncludeDev bool
	Quiet      bool
	NoColor    bool
	// CACertFile is an optional path to a PEM bundle (one or more certs)
	// used to verify the server's TLS certificate. When empty, the system
	// trust store is used.
	CACertFile string
	// AllowInsecureHTTP permits plain http:// server URLs in remote mode.
	// When false (default), a non-https server URL is rejected before any
	// request is sent so the bearer token never travels in cleartext.
	AllowInsecureHTTP bool
	// RequireRemote disables the silent local-DB fallback in auto mode: a
	// remote failure becomes a hard error instead of falling back.
	RequireRemote bool
	// Logger receives structured DEBUG/WARN diagnostics for the scan
	// pipeline. When nil, scan logging is discarded.
	Logger *slog.Logger
}

// Scanner orchestrates the walk-parse-check-format pipeline.
type Scanner struct {
	registry     *parser.Registry
	cfg          Config
	client       *http.Client
	clientErr    error
	localChecker LocalChecker
}

// New creates a Scanner with the given configuration.
//
// It builds an explicit HTTP transport that enforces a minimum TLS version of
// 1.2 and honors proxy environment variables. When cfg.CACertFile is set, the
// referenced PEM bundle is loaded into the transport's RootCAs. A bad CA file
// (unreadable, or containing no valid certificate) is recorded and surfaced as
// an error on the remote-check path rather than panicking at construction, so
// existing New(reg, cfg) callers keep compiling.
func New(reg *parser.Registry, cfg Config) *Scanner {
	pool, err := loadCAPool(cfg.CACertFile)

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		},
	}

	return &Scanner{
		registry:  reg,
		cfg:       cfg,
		clientErr: err,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: tr,
		},
	}
}

// loadCAPool builds a certificate pool from the given PEM file. When path is
// empty it returns (nil, nil), meaning "use the system trust store". When the
// file cannot be read or contains no valid certificate it returns an error.
func loadCAPool(path string) (*x509.CertPool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path) // #nosec G304 -- user-specified CA bundle path
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no valid certificate", path)
	}
	return pool, nil
}

// log returns the configured logger, or a discard logger when none is set.
func (s *Scanner) log() *slog.Logger {
	if s.cfg.Logger != nil {
		return s.cfg.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// SetLocalChecker assigns a local database for offline scanning.
// When set, the scanner can resolve findings in local and auto modes.
func (s *Scanner) SetLocalChecker(lc LocalChecker) {
	s.localChecker = lc
}

// Run executes the full scan pipeline and returns the result plus an exit code.
func (s *Scanner) Run(ctx context.Context) (*domain.ScanResult, int) {
	start := time.Now()
	scanID := generateScanID()

	// 1. Walk: discover lock files.
	walker := NewWalker(s.registry, s.cfg.MaxDepth, s.cfg.Ecosystems)
	lockFiles, err := walker.Walk(s.cfg.Path)
	if err != nil {
		return s.errorResult(scanID, start, fmt.Sprintf("walk error: %v", err)), ExitOperational
	}

	if len(lockFiles) == 0 {
		result := &domain.ScanResult{
			ScanID:          scanID,
			Mode:            string(s.resolveMode()),
			ScannedAt:       start.UTC(),
			DurationMs:      time.Since(start).Milliseconds(),
			PackagesScanned: 0,
			FindingsCount:   0,
			Summary:         emptySummary(),
			Findings:        []domain.Finding{},
			FeedVersions:    map[string]string{},
		}
		return result, ExitOK
	}

	// 2. Parse: extract packages from all lock files.
	var allPackages []domain.Package
	var parseErrors []string
	for _, lf := range lockFiles {
		s.log().Debug("found lock file",
			slog.String("path", lf.RelPath),
			slog.String("ecosystem", string(lf.Parser.Ecosystem())),
		)
		pkgs, parseErr := s.parseLockFile(lf)
		if parseErr != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: %v", lf.RelPath, parseErr))
			continue
		}
		s.log().Debug("parsed lock file",
			slog.String("path", lf.RelPath),
			slog.Int("packages", len(pkgs)),
		)
		allPackages = append(allPackages, pkgs...)
	}

	// Deduplicate packages.
	allPackages = dedup(allPackages)
	if !s.cfg.IncludeDev {
		allPackages = filterDevPackages(allPackages)
	}
	s.log().Debug("packages collected",
		slog.Int("total", len(allPackages)),
		slog.Bool("include_dev", s.cfg.IncludeDev),
	)

	// If all files had parse errors and we got zero packages, exit 4.
	if len(allPackages) == 0 && len(parseErrors) > 0 {
		return s.errorResult(scanID, start, strings.Join(parseErrors, "; ")), ExitParser
	}

	// 3. Check: resolve findings.
	mode := s.resolveMode()
	var findings []domain.Finding
	var feedVersions map[string]string
	var feedStatus string
	var checkErr error

	switch mode {
	case ModeRemote:
		findings, feedVersions, feedStatus, checkErr = s.checkRemote(ctx, allPackages)
		if checkErr != nil {
			return s.errorResult(scanID, start, fmt.Sprintf("remote check failed: %v", checkErr)), ExitOperational
		}
	case ModeLocal:
		if s.localChecker == nil {
			return s.errorResult(scanID, start, "local mode requested but no local database available (run 'packmon db sync' first)"), ExitOperational
		}
		findings, checkErr = s.checkLocal(ctx, allPackages)
		if checkErr != nil {
			return s.errorResult(scanID, start, fmt.Sprintf("local check failed: %v", checkErr)), ExitOperational
		}
		feedVersions = map[string]string{}
	case ModeAuto:
		findings, feedVersions, feedStatus, checkErr = s.checkRemote(ctx, allPackages)
		if checkErr != nil {
			s.log().Warn("remote check failed",
				slog.Bool("require_remote", s.cfg.RequireRemote),
				slog.String("error", checkErr.Error()),
			)
			// RequireRemote: do not mask a broken/insecure server channel by
			// silently falling back to a (possibly stale) local database.
			if s.cfg.RequireRemote {
				return s.errorResult(scanID, start, fmt.Sprintf("remote check failed and --require-remote is set: %v", checkErr)), ExitOperational
			}
			// Auto mode: fall back to local database.
			if s.localChecker == nil {
				return s.errorResult(scanID, start, fmt.Sprintf("remote check failed and no local database available: %v", checkErr)), ExitOperational
			}
			findings, checkErr = s.checkLocal(ctx, allPackages)
			if checkErr != nil {
				return s.errorResult(scanID, start, fmt.Sprintf("remote and local check failed: %v", checkErr)), ExitOperational
			}
			mode = ModeLocal
			feedVersions = map[string]string{}
		}
	}

	if findings == nil {
		findings = []domain.Finding{}
	}
	if feedVersions == nil {
		feedVersions = map[string]string{}
	}

	// 4. Determine blocking status.
	blocking := s.hasBlockingFindings(findings)

	// 5. Build result.
	result := &domain.ScanResult{
		ScanID:           scanID,
		Mode:             string(mode),
		ScannedAt:        start.UTC(),
		DurationMs:       time.Since(start).Milliseconds(),
		PackagesScanned:  len(allPackages),
		FindingsCount:    len(findings),
		FindingsBlocking: blocking,
		Summary:          buildSummary(findings),
		Findings:         findings,
		FeedStatus:       feedStatus,
		FeedVersions:     feedVersions,
	}

	// Sort findings: CRITICAL first, then HIGH, MEDIUM, LOW.
	sort.Slice(result.Findings, func(i, j int) bool {
		ri := result.Findings[i].Severity.Rank()
		rj := result.Findings[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		return result.Findings[i].Name < result.Findings[j].Name
	})

	exitCode := ExitOK
	switch {
	case blocking:
		exitCode = ExitBlocking
	case len(findings) > 0:
		// Findings exist but none reach the blocking threshold: signal them
		// distinctly from a clean scan so CI/automation can react (exit 3 is
		// treated as a passing/"green" outcome).
		exitCode = ExitUnderThreshold
	}
	// Partial parse errors: still return findings but note the errors.
	// We do not elevate exit code for partial parse errors when findings
	// were found -- the blocking/non-blocking logic takes precedence.
	return result, exitCode
}

func (s *Scanner) resolveMode() Mode {
	switch s.cfg.Mode {
	case ModeRemote:
		return ModeRemote
	case ModeLocal:
		return ModeLocal
	default:
		return ModeAuto
	}
}

func (s *Scanner) parseLockFile(lf LockFile) ([]domain.Package, error) {
	f, err := os.Open(lf.Path)
	if err != nil {
		return nil, err
	}
	defer closeSilently(f)
	return lf.Parser.Parse(f)
}

// checkRemote sends packages to the server's POST /api/v1/check endpoint.
func (s *Scanner) checkRemote(ctx context.Context, pkgs []domain.Package) ([]domain.Finding, map[string]string, string, error) {
	if s.cfg.ServerURL == "" {
		return nil, nil, "", fmt.Errorf("no server URL configured (set --server or PACKMON_SERVER)")
	}

	// Surface any deferred CA-bundle load error from New().
	if s.clientErr != nil {
		return nil, nil, "", s.clientErr
	}

	// Enforce HTTPS so the bearer token is never sent in cleartext. Plain
	// http:// is opt-in only via AllowInsecureHTTP / --insecure-allow-http.
	parsed, err := url.Parse(strings.TrimSpace(s.cfg.ServerURL))
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid server URL %q: %w", s.cfg.ServerURL, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !s.cfg.AllowInsecureHTTP {
		return nil, nil, "", fmt.Errorf("refusing to use insecure server URL %q: scheme must be https (set --insecure-allow-http / PACKMON_INSECURE_ALLOW_HTTP to override)", s.cfg.ServerURL)
	}

	endpoint := strings.TrimRight(s.cfg.ServerURL, "/") + "/api/v1/check"

	reqBody := domain.ScanRequest{
		Packages: pkgs,
		Repo:     s.cfg.Repo,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "packmon-cli/dev")
	req.Header.Set("X-Correlation-ID", generateCorrelationID())
	if strings.TrimSpace(s.cfg.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(s.cfg.APIKey))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("server request: %w", err)
	}
	defer closeSilently(resp.Body)

	// Limit response body to 500 MB to prevent unbounded reads from a
	// misbehaving or compromised server.
	const maxResponseSize = 500 << 20 // 500 MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, nil, "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, "", fmt.Errorf("server returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var result domain.ScanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, nil, "", fmt.Errorf("decode response: %w", err)
	}

	return result.Findings, result.FeedVersions, result.FeedStatus, nil
}

// checkLocal resolves findings against the local SQLite database.
func (s *Scanner) checkLocal(ctx context.Context, pkgs []domain.Package) ([]domain.Finding, error) {
	var allFindings []domain.Finding

	for _, pkg := range pkgs {
		eco := string(pkg.Ecosystem)

		vulns, err := s.localChecker.FindVulnerabilities(ctx, eco, pkg.Name, pkg.Version)
		if err != nil {
			return nil, fmt.Errorf("local vuln check %s/%s: %w", eco, pkg.Name, err)
		}
		allFindings = append(allFindings, vulns...)

		mals, err := s.localChecker.FindMalicious(ctx, eco, pkg.Name, pkg.Version)
		if err != nil {
			return nil, fmt.Errorf("local malicious check %s/%s: %w", eco, pkg.Name, err)
		}
		// Set the version on malicious findings for consistent output.
		for i := range mals {
			mals[i].Version = pkg.Version
		}
		allFindings = append(allFindings, mals...)
	}

	return allFindings, nil
}

// hasBlockingFindings checks if any finding is blocking per DE-2 rules:
// - Malware and supply-chain risk always block (regardless of fail-on threshold)
// - Vulnerabilities block if severity >= fail-on threshold
func (s *Scanner) hasBlockingFindings(findings []domain.Finding) bool {
	for _, f := range findings {
		if isAlwaysBlockingFinding(f) {
			return true
		}
		if s.cfg.FailOn != "NONE" && f.Severity.Blocks(s.cfg.FailOn) {
			return true
		}
	}
	return false
}

func isAlwaysBlockingFinding(f domain.Finding) bool {
	return f.Type == domain.FindingTypeMalicious || f.Type == domain.FindingTypeSupplyChainRisk
}

func (s *Scanner) errorResult(scanID string, start time.Time, msg string) *domain.ScanResult {
	return &domain.ScanResult{
		ScanID:       scanID,
		Mode:         string(s.resolveMode()),
		ScannedAt:    start.UTC(),
		DurationMs:   time.Since(start).Milliseconds(),
		FeedStatus:   msg,
		Summary:      emptySummary(),
		Findings:     []domain.Finding{},
		FeedVersions: map[string]string{},
	}
}

func generateScanID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func emptySummary() domain.ScanSummary {
	return domain.ScanSummary{
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
		BySource:   map[string]int{},
	}
}

func buildSummary(findings []domain.Finding) domain.ScanSummary {
	s := emptySummary()
	for _, f := range findings {
		s.BySeverity[string(f.Severity)]++
		s.ByType[string(f.Type)]++
		s.BySource[f.Source]++
	}
	return s
}

// dedup removes duplicate packages (same name+version+ecosystem).
func dedup(pkgs []domain.Package) []domain.Package {
	type key struct {
		name      string
		version   string
		ecosystem domain.Ecosystem
	}
	seen := make(map[key]int, len(pkgs))
	out := make([]domain.Package, 0, len(pkgs))
	for _, p := range pkgs {
		k := key{p.Name, p.Version, p.Ecosystem}
		if idx, ok := seen[k]; ok {
			if out[idx].Dev && !p.Dev {
				out[idx].Dev = false
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, p)
	}
	return out
}

func filterDevPackages(pkgs []domain.Package) []domain.Package {
	out := pkgs[:0]
	for _, pkg := range pkgs {
		if !pkg.Dev {
			out = append(out, pkg)
		}
	}
	return out
}

func generateCorrelationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			time.Now().UnixNano(),
			0,
			0x4000,
			0x8000,
			time.Now().UnixNano(),
		)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
