package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	ExitOK          = 0
	ExitBlocking    = 1
	ExitOperational = 2
	ExitParser      = 4
	ExitInternal    = 10
)

// Config holds all parameters needed for a single scan invocation.
type Config struct {
	Path       string
	Mode       Mode
	ServerURL  string
	APIKey     string
	FailOn     domain.Severity
	Ecosystems []string
	MaxDepth   int
	Timeout    time.Duration
	IncludeDev bool
	Quiet      bool
	NoColor    bool
}

// Scanner orchestrates the walk-parse-check-format pipeline.
type Scanner struct {
	registry     *parser.Registry
	cfg          Config
	client       *http.Client
	localChecker LocalChecker
}

// New creates a Scanner with the given configuration.
func New(reg *parser.Registry, cfg Config) *Scanner {
	return &Scanner{
		registry: reg,
		cfg:      cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
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
		pkgs, parseErr := s.parseLockFile(lf)
		if parseErr != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: %v", lf.RelPath, parseErr))
			continue
		}
		allPackages = append(allPackages, pkgs...)
	}

	// Deduplicate packages.
	allPackages = dedup(allPackages)

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
	if blocking {
		exitCode = ExitBlocking
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

	url := strings.TrimRight(s.cfg.ServerURL, "/") + "/api/v1/check"

	reqBody := domain.ScanRequest{
		Packages: pkgs,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "packmon-cli/dev")
	if strings.TrimSpace(s.cfg.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(s.cfg.APIKey))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("server request: %w", err)
	}
	defer closeSilently(resp.Body)

	body, err := io.ReadAll(resp.Body)
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
// - Malware always blocks (regardless of fail-on threshold)
// - Vulnerabilities block if severity >= fail-on threshold
func (s *Scanner) hasBlockingFindings(findings []domain.Finding) bool {
	for _, f := range findings {
		if f.Type == domain.FindingTypeMalicious {
			return true
		}
		if s.cfg.FailOn != "NONE" && f.Severity.Blocks(s.cfg.FailOn) {
			return true
		}
	}
	return false
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
	seen := make(map[key]struct{}, len(pkgs))
	out := make([]domain.Package, 0, len(pkgs))
	for _, p := range pkgs {
		k := key{p.Name, p.Version, p.Ecosystem}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	return out
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
