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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/httpclient"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/parser"
)

// LocalChecker is the interface required for local-mode scanning.
// It is satisfied by the sqlite.Store type.
type LocalChecker interface {
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
}

// BatchLocalChecker is an optional local checker extension that avoids per-
// package database roundtrips for stores that can query multiple packages at
// once.
type BatchLocalChecker interface {
	FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error)
	FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error)
}

// ReputationBatchChecker is an optional local checker extension for cached
// package reputation findings.
type ReputationBatchChecker interface {
	FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error)
}

// LifecycleChecker is an optional local checker extension for cached
// lifecycle/EOL findings.
type LifecycleChecker interface {
	FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error)
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

// remoteCheckChunkSize must stay at or below the server's /api/v1/check
// package limit.
const remoteCheckChunkSize = 5000

const (
	maxRemoteCheckResponseSize = 32 << 20
	maxRemoteErrorBodySize     = 8 << 10
)

// Config holds all parameters needed for a single scan invocation.
type Config struct {
	Path      string
	Mode      Mode
	ServerURL string
	APIKey    string
	Repo      *domain.RepoInfo
	// OmitRepoMetadata suppresses optional repository metadata in remote
	// /api/v1/check requests.
	OmitRepoMetadata bool
	FailOn           domain.Severity
	Ecosystems       []string
	SBOMFiles        []string
	MaxDepth         int
	Timeout          time.Duration
	IncludeDev       bool
	// InventoryAllPackages keeps dev/test packages in the collected package
	// collection for inventory/reporting while IncludeDev still controls the
	// package set sent to vulnerability and malicious checks.
	InventoryAllPackages bool
	Quiet                bool
	NoColor              bool
	Version              string
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
			Timeout:       cfg.Timeout,
			Transport:     tr,
			CheckRedirect: httpclient.SafeRedirectPolicy,
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
	result, exitCode, _ := s.RunWithCollection(ctx)
	return result, exitCode
}

// RunWithCollection executes the full scan pipeline and also returns the
// package collection produced during the walk/parse phase for callers that need
// inventory data without walking the repository again.
func (s *Scanner) RunWithCollection(ctx context.Context) (*domain.ScanResult, int, *PackageCollection) {
	start := time.Now()
	scanID := generateScanID()

	// 1. Collect packages from lockfiles and explicit SBOM inputs.
	collectIncludeDev := s.cfg.IncludeDev || s.cfg.InventoryAllPackages
	collection, err := CollectPackages(CollectConfig{
		Registry:   s.registry,
		Root:       s.cfg.Path,
		MaxDepth:   s.cfg.MaxDepth,
		Ecosystems: s.cfg.Ecosystems,
		SBOMFiles:  s.cfg.SBOMFiles,
		IncludeDev: collectIncludeDev,
	})
	if err != nil {
		return s.errorResult(scanID, start, fmt.Sprintf("collect packages: %v", err)), ExitOperational, nil
	}

	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		return s.emptyScanResult(scanID, start, collection.ParseErrors), ExitOK, collection
	}

	allPackages := collection.Packages
	checkPackages := scanCheckPackages(allPackages, s.cfg.IncludeDev)
	parseErrors := collection.ParseErrors
	s.log().Debug("packages collected",
		slog.Int("total", len(allPackages)),
		slog.Int("check_total", len(checkPackages)),
		slog.Int("lock_files", collection.LockFiles),
		slog.Int("sbom_files", collection.SBOMFiles),
		slog.Bool("include_dev", s.cfg.IncludeDev),
		slog.Bool("inventory_all_packages", s.cfg.InventoryAllPackages),
	)

	if len(collection.FatalParseErrors) > 0 {
		result := s.errorResultWithPackages(scanID, start, strings.Join(collection.FatalParseErrors, "; "), len(checkPackages))
		result.ParseErrors = append([]string(nil), parseErrors...)
		return result, ExitParser, collection
	}

	// If all files had parse errors and we got zero packages, exit 4.
	if len(allPackages) == 0 && len(parseErrors) > 0 {
		result := s.errorResult(scanID, start, strings.Join(parseErrors, "; "))
		result.ParseErrors = append([]string(nil), parseErrors...)
		return result, ExitParser, collection
	}

	if len(checkPackages) == 0 {
		return s.emptyScanResult(scanID, start, parseErrors), ExitOK, collection
	}

	// 3. Check: resolve findings.
	mode := s.resolveMode()
	var findings []domain.Finding
	var feedVersions map[string]string
	var feedStatus string
	var remoteResult remoteCheckResult
	var checkErr error

	switch mode {
	case ModeRemote:
		remoteResult, checkErr = s.checkRemoteResult(ctx, checkPackages)
		if checkErr != nil {
			return s.errorResult(scanID, start, fmt.Sprintf("remote check failed: %v", checkErr)), ExitOperational, collection
		}
		findings = remoteResult.Result.Findings
		feedVersions = remoteResult.Result.FeedVersions
		feedStatus = remoteResult.Result.FeedStatus
	case ModeLocal:
		if s.localChecker == nil {
			return s.errorResultWithPackages(scanID, start, "local advisory data unavailable (run 'packmon db sync' first)", len(checkPackages)), ExitOperational, collection
		}
		findings, checkErr = s.checkLocal(ctx, checkPackages)
		if checkErr != nil {
			return s.errorResultWithPackages(scanID, start, fmt.Sprintf("local check failed: %v", checkErr), len(checkPackages)), ExitOperational, collection
		}
		feedVersions = map[string]string{}
	case ModeAuto:
		remoteResult, checkErr = s.checkRemoteResult(ctx, checkPackages)
		if checkErr != nil {
			s.log().Warn("remote check failed",
				slog.Bool("require_remote", s.cfg.RequireRemote),
				slog.String("error", checkErr.Error()),
			)
			// RequireRemote: do not mask a broken/insecure server channel by
			// silently falling back to a (possibly stale) local database.
			if s.cfg.RequireRemote {
				return s.errorResult(scanID, start, fmt.Sprintf("remote check failed and --require-remote is set: %v", checkErr)), ExitOperational, collection
			}
			// Auto mode: fall back to local database.
			if s.localChecker == nil {
				return s.errorResultWithPackages(scanID, start, fmt.Sprintf("remote check failed and no local advisory data available: %v", checkErr), len(checkPackages)), ExitOperational, collection
			}
			findings, checkErr = s.checkLocal(ctx, checkPackages)
			if checkErr != nil {
				return s.errorResultWithPackages(scanID, start, fmt.Sprintf("remote and local check failed: %v", checkErr), len(checkPackages)), ExitOperational, collection
			}
			mode = ModeLocal
			feedVersions = map[string]string{}
		} else {
			findings = remoteResult.Result.Findings
			feedVersions = remoteResult.Result.FeedVersions
			feedStatus = remoteResult.Result.FeedStatus
			mode = ModeRemote
		}
	}

	if findings == nil {
		findings = []domain.Finding{}
	}
	if feedVersions == nil {
		feedVersions = map[string]string{}
	}
	feedStatus = normalizeScanFeedStatus(feedStatus)
	annotateFindingLocations(findings, collection.Entries)

	// 4. Determine blocking status.
	blocking := s.hasBlockingFindings(findings)

	// 5. Build result.
	resultScanID := scanID
	resultScannedAt := start.UTC()
	resultDurationMs := time.Since(start).Milliseconds()
	if remoteResult.PreserveIdentity {
		if remoteResult.Result.ScanID != "" {
			resultScanID = remoteResult.Result.ScanID
		}
		if !remoteResult.Result.ScannedAt.IsZero() {
			resultScannedAt = remoteResult.Result.ScannedAt
		}
		resultDurationMs = remoteResult.Result.DurationMs
	}
	result := &domain.ScanResult{
		ScanID:           resultScanID,
		Mode:             string(mode),
		ScannedAt:        resultScannedAt,
		DurationMs:       resultDurationMs,
		PackagesScanned:  len(checkPackages),
		FindingsCount:    len(findings),
		FindingsBlocking: blocking,
		BlockThreshold:   s.cfg.FailOn,
		Summary:          domain.BuildScanSummary(findings),
		Findings:         findings,
		ParseErrors:      append([]string(nil), parseErrors...),
		FeedStatus:       feedStatus,
		FeedVersions:     feedVersions,
		ManualCount:      domain.CountManualAdvisoryFindings(findings),
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
	// Partial parse errors mean scan coverage is incomplete. Blocking findings
	// already fail the gate; otherwise parser failure must take precedence over
	// clean or under-threshold outcomes so CI cannot pass on partial inventory.
	if len(parseErrors) > 0 && exitCode != ExitBlocking {
		exitCode = ExitParser
	}
	return result, exitCode, collection
}

func scanCheckPackages(packages []domain.Package, includeDev bool) []domain.Package {
	if includeDev {
		return packages
	}
	out := make([]domain.Package, 0, len(packages))
	for _, pkg := range packages {
		if !pkg.Dev {
			out = append(out, pkg)
		}
	}
	return out
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

type remoteCheckResult struct {
	Result           domain.ScanResult
	PreserveIdentity bool
}

// checkRemote sends packages to the server's POST /api/v1/check endpoint.
func (s *Scanner) checkRemote(ctx context.Context, pkgs []domain.Package) ([]domain.Finding, map[string]string, string, bool, error) {
	result, err := s.checkRemoteResult(ctx, pkgs)
	if err != nil {
		return nil, nil, "", false, err
	}
	return result.Result.Findings, result.Result.FeedVersions, result.Result.FeedStatus, result.Result.FindingsBlocking, nil
}

func (s *Scanner) checkRemoteResult(ctx context.Context, pkgs []domain.Package) (remoteCheckResult, error) {
	if s.cfg.ServerURL == "" {
		return remoteCheckResult{}, fmt.Errorf("no server URL configured (set --server or PACKMON_SERVER)")
	}

	// Surface any deferred CA-bundle load error from New().
	if s.clientErr != nil {
		return remoteCheckResult{}, s.clientErr
	}

	// Enforce HTTPS so the bearer token is never sent in cleartext. Plain
	// http:// is opt-in only via AllowInsecureHTTP / --insecure-allow-http.
	serverURL := strings.TrimSpace(s.cfg.ServerURL)
	displayServerURL := logsafe.RedactURL(serverURL)
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return remoteCheckResult{}, fmt.Errorf("invalid server URL %q: %w", displayServerURL, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !s.cfg.AllowInsecureHTTP {
		return remoteCheckResult{}, fmt.Errorf("refusing to use insecure server URL %q: scheme must be https (set --insecure-allow-http / PACKMON_INSECURE_ALLOW_HTTP to override)", displayServerURL)
	}

	endpoint := strings.TrimRight(serverURL, "/") + "/api/v1/check"
	requestPackages := remoteScanPackages(pkgs)

	if len(requestPackages) <= remoteCheckChunkSize {
		result, err := s.postRemoteCheck(ctx, endpoint, requestPackages)
		if err != nil {
			return remoteCheckResult{}, err
		}
		return remoteCheckResult{Result: result, PreserveIdentity: true}, nil
	}

	var allFindings []domain.Finding
	feedVersions := make(map[string]string)
	var feedStatus string
	var remoteBlocking bool
	for start := 0; start < len(requestPackages); start += remoteCheckChunkSize {
		end := start + remoteCheckChunkSize
		if end > len(requestPackages) {
			end = len(requestPackages)
		}
		result, err := s.postRemoteCheck(ctx, endpoint, requestPackages[start:end])
		if err != nil {
			return remoteCheckResult{}, err
		}
		allFindings = append(allFindings, result.Findings...)
		for feedName, version := range result.FeedVersions {
			feedVersions[feedName] = version
		}
		feedStatus = mergeRemoteFeedStatus(feedStatus, result.FeedStatus)
		remoteBlocking = remoteBlocking || result.FindingsBlocking
	}

	return remoteCheckResult{
		Result: domain.ScanResult{
			Mode:             string(ModeRemote),
			Findings:         allFindings,
			FindingsCount:    len(allFindings),
			FindingsBlocking: remoteBlocking,
			Summary:          domain.BuildScanSummary(allFindings),
			FeedStatus:       feedStatus,
			FeedVersions:     feedVersions,
			ManualCount:      domain.CountManualAdvisoryFindings(allFindings),
		},
	}, nil
}

func (s *Scanner) postRemoteCheck(ctx context.Context, endpoint string, pkgs []domain.Package) (domain.ScanResult, error) {
	repo := remoteScanRepo(s.cfg.Repo)
	if s.cfg.OmitRepoMetadata {
		repo = nil
	}
	reqBody := domain.ScanRequest{
		Packages: pkgs,
		Repo:     repo,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return domain.ScanResult{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return domain.ScanResult{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", remoteUserAgent(s.cfg.Version))
	req.Header.Set(correlation.Header, newCorrelationID())
	if strings.TrimSpace(s.cfg.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(s.cfg.APIKey))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return domain.ScanResult{}, fmt.Errorf("server request: %s", logsafe.RedactURLRequestError(err, "server URL"))
	}
	defer closeSilently(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, err := readRemoteErrorBody(resp.Body)
		if err != nil {
			return domain.ScanResult{}, fmt.Errorf("read response: %w", err)
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return domain.ScanResult{}, fmt.Errorf("server returned %d: %s (check PACKMON_API_KEY, --api-key, or api_key_env configuration)", resp.StatusCode, truncate(string(body), 200))
		}
		return domain.ScanResult{}, fmt.Errorf("server returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var result domain.ScanResult
	if err := decodeRemoteCheckResponse(resp.Body, &result); err != nil {
		return domain.ScanResult{}, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}

func decodeRemoteCheckResponse(r io.Reader, result *domain.ScanResult) error {
	limited := &io.LimitedReader{R: r, N: maxRemoteCheckResponseSize + 1}
	dec := json.NewDecoder(limited)
	if err := dec.Decode(result); err != nil {
		if limited.N <= 0 {
			return fmt.Errorf("response body exceeds %d bytes", maxRemoteCheckResponseSize)
		}
		return err
	}
	if limited.N <= 0 {
		return fmt.Errorf("response body exceeds %d bytes", maxRemoteCheckResponseSize)
	}
	return nil
}

func readRemoteErrorBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxRemoteErrorBodySize))
}

func remoteUserAgent(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		version = "dev"
	}
	return "packmon-cli/" + version
}

func mergeRemoteFeedStatus(current, next string) string {
	current = normalizeScanFeedStatus(current)
	next = normalizeScanFeedStatus(next)
	switch {
	case next == "healthy":
		return current
	case current == "healthy":
		return next
	case current == "error" || next == "error":
		return "error"
	case current == "degraded" || next == "degraded":
		return "degraded"
	default:
		return current
	}
}

func normalizeScanFeedStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "", "healthy":
		return "healthy"
	case "degraded":
		return "degraded"
	case "error":
		return "error"
	default:
		return "degraded"
	}
}

func remoteScanPackages(pkgs []domain.Package) []domain.Package {
	if len(pkgs) == 0 {
		return pkgs
	}
	out := make([]domain.Package, len(pkgs))
	for i, pkg := range pkgs {
		out[i] = domain.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
		}
	}
	return out
}

func remoteScanRepo(repo *domain.RepoInfo) *domain.RepoInfo {
	if repo == nil {
		return nil
	}
	name := strings.TrimSpace(repo.Name)
	if name == "" {
		return nil
	}
	return &domain.RepoInfo{Name: name}
}

func annotateFindingLocations(findings []domain.Finding, entries []CollectedPackage) {
	if len(findings) == 0 || len(entries) == 0 {
		return
	}
	byPackage := make(map[packageCollectionKey][]domain.FindingLocation)
	for _, entry := range entries {
		uri := strings.TrimSpace(filepath.ToSlash(entry.SourceFile))
		if uri == "" {
			continue
		}
		key := packageCollectionKey{
			name:      entry.Package.Name,
			version:   entry.Package.Version,
			ecosystem: entry.Package.Ecosystem,
		}
		location := domain.FindingLocation{URI: uri}
		if findingLocationsContain(byPackage[key], location) {
			continue
		}
		byPackage[key] = append(byPackage[key], location)
	}
	for i := range findings {
		key := packageCollectionKey{
			name:      findings[i].Name,
			version:   findings[i].Version,
			ecosystem: findings[i].Ecosystem,
		}
		for _, location := range byPackage[key] {
			if findingLocationsContain(findings[i].Locations, location) {
				continue
			}
			findings[i].Locations = append(findings[i].Locations, location)
		}
	}
}

func findingLocationsContain(locations []domain.FindingLocation, want domain.FindingLocation) bool {
	for _, location := range locations {
		if location.URI == want.URI {
			return true
		}
	}
	return false
}

// checkLocal resolves findings against the local SQLite database.
func (s *Scanner) checkLocal(ctx context.Context, pkgs []domain.Package) ([]domain.Finding, error) {
	var allFindings []domain.Finding
	queries := packageQueries(pkgs)

	if batchChecker, ok := s.localChecker.(BatchLocalChecker); ok {
		vulns, err := batchChecker.FindVulnerabilitiesBatch(ctx, queries)
		if err != nil {
			return nil, fmt.Errorf("local vuln batch check: %w", err)
		}
		allFindings = append(allFindings, vulns...)

		mals, err := batchChecker.FindMaliciousBatch(ctx, queries)
		if err != nil {
			return nil, fmt.Errorf("local malicious batch check: %w", err)
		}
		allFindings = append(allFindings, mals...)
	} else {
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
	}

	if reputationChecker, ok := s.localChecker.(ReputationBatchChecker); ok {
		reputation, err := reputationChecker.FindReputationFindingsBatch(ctx, queries, db.ReputationSourceReversingLabs)
		if err != nil {
			return nil, fmt.Errorf("local reputation batch check: %w", err)
		}
		allFindings = append(allFindings, reputation...)
	}

	if lifecycleChecker, ok := s.localChecker.(LifecycleChecker); ok {
		lifecycle, err := lifecycleChecker.FindLifecycleFindingsBatch(ctx, queries, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("local lifecycle check: %w", err)
		}
		allFindings = append(allFindings, lifecycle...)
	}

	return allFindings, nil
}

func packageQueries(pkgs []domain.Package) []db.PackageQuery {
	queries := make([]db.PackageQuery, 0, len(pkgs))
	for _, pkg := range pkgs {
		queries = append(queries, db.PackageQuery{
			Ecosystem: string(pkg.Ecosystem),
			Name:      pkg.Name,
			Version:   pkg.Version,
		})
	}
	return queries
}

// hasBlockingFindings checks if any finding is blocking per DE-2 rules:
// - Malware and supply-chain risk always block (regardless of fail-on threshold)
// - Vulnerabilities block if severity >= fail-on threshold
func (s *Scanner) hasBlockingFindings(findings []domain.Finding) bool {
	return domain.FindingsBlock(findings, s.cfg.FailOn)
}

func (s *Scanner) errorResult(scanID string, start time.Time, msg string) *domain.ScanResult {
	return s.errorResultWithPackages(scanID, start, msg, 0)
}

func (s *Scanner) errorResultWithPackages(scanID string, start time.Time, msg string, packagesScanned int) *domain.ScanResult {
	return &domain.ScanResult{
		ScanID:          scanID,
		Mode:            string(s.resolveMode()),
		ScannedAt:       start.UTC(),
		DurationMs:      time.Since(start).Milliseconds(),
		PackagesScanned: packagesScanned,
		BlockThreshold:  s.cfg.FailOn,
		FeedStatus:      "error",
		ScanError:       msg,
		Summary:         domain.EmptyScanSummary(),
		Findings:        []domain.Finding{},
		FeedVersions:    map[string]string{},
	}
}

func (s *Scanner) emptyScanResult(scanID string, start time.Time, parseErrors []string) *domain.ScanResult {
	return &domain.ScanResult{
		ScanID:          scanID,
		Mode:            string(s.resolveMode()),
		ScannedAt:       start.UTC(),
		DurationMs:      time.Since(start).Milliseconds(),
		PackagesScanned: 0,
		FindingsCount:   0,
		BlockThreshold:  s.cfg.FailOn,
		FeedStatus:      "healthy",
		Summary:         domain.EmptyScanSummary(),
		Findings:        []domain.Finding{},
		ParseErrors:     append([]string(nil), parseErrors...),
		FeedVersions:    map[string]string{},
	}
}

func generateScanID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func newCorrelationID() string {
	id, err := correlation.NewID()
	if err != nil {
		return correlation.FallbackID()
	}
	return id
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 0 {
		maxLen = 0
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
