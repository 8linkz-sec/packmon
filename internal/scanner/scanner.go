package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/httpclient"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/parser"
)

// LocalChecker is the complete capability required for local-mode scanning.
type LocalChecker interface {
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindReputationFindingsBatch(ctx context.Context, packages []PackageLookup, source string) ([]domain.Finding, error)
	FindLifecycleFindingsBatch(ctx context.Context, packages []PackageLookup, now time.Time) ([]domain.Finding, error)
}

// PackageLookup identifies one package lookup for scanner-owned local-checker
// ports.
type PackageLookup struct {
	Ecosystem string
	Name      string
	Version   string
}

// BatchLocalChecker is an optional local checker extension that avoids per-
// package database roundtrips for stores that can query multiple packages at
// once.
type BatchLocalChecker interface {
	FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error)
	FindMaliciousBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error)
}

// Mode controls which checker path the scanner is allowed to use. Empty or
// unrecognized Config.Mode values are normalized to ModeAuto before execution.
type Mode = domain.ScanMode

const (
	// ModeAuto tries the configured remote server first and, unless
	// Config.RequireRemote is set, can fall back to the local checker/database.
	// Result.Mode reports the actual execution path as ModeRemote or ModeLocal.
	ModeAuto = domain.ScanModeAuto
	// ModeRemote checks only through the Packmon server and requires remote
	// server configuration such as ServerURL and any required auth/TLS settings.
	ModeRemote = domain.ScanModeRemote
	// ModeLocal checks only through the configured local checker backed by the
	// local advisory database.
	ModeLocal = domain.ScanModeLocal
)

// ParseMode normalizes and validates a scan mode string. An empty value uses
// the CLI/server default of auto mode.
func ParseMode(raw string) (Mode, error) {
	mode := Mode(strings.ToLower(strings.TrimSpace(raw)))
	switch mode {
	case "":
		return ModeAuto, nil
	case ModeAuto, ModeRemote, ModeLocal:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid mode %q (want auto|local|remote)", mode)
	}
}

func normalizeMode(raw string) Mode {
	mode, err := ParseMode(raw)
	if err != nil {
		return ModeAuto
	}
	return mode
}

// Exit codes per DE-2.
const (
	ExitOK             = 0
	ExitBlocking       = 1
	ExitOperational    = 2
	ExitUnderThreshold = 3
	ExitParser         = 4
	ExitInternal       = 10
)

const (
	maxRemoteCheckResponseSize = 32 << 20
	maxRemoteErrorBodySize     = 8 << 10
)

const reversingLabsReputationSource = "reversinglabs"

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
// referenced PEM bundle is loaded lazily on the remote-check path so local-only
// scans do not fail on remote TLS configuration that they never use.
func New(reg *parser.Registry, cfg Config) *Scanner {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &Scanner{
		registry: reg,
		cfg:      cfg,
		client: &http.Client{
			Timeout:       cfg.Timeout,
			Transport:     tr,
			CheckRedirect: httpclient.SafeRedirectPolicy,
		},
	}
}

// log returns the configured logger, or a discard logger when none is set.
func (s *Scanner) log() *slog.Logger {
	if s.cfg.Logger != nil {
		return s.cfg.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// SetLocalChecker assigns a local database for offline scanning. When set, the
// checker must resolve vulnerability, malicious, reputation, and lifecycle
// findings in local and auto modes.
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

	collected, err := s.collectScanPackages()
	if err != nil {
		return s.errorResult(scanID, start, err.Error()), ExitOperational, nil
	}

	if result, exitCode, done := s.applyParseErrorPolicy(scanID, start, collected); done {
		return result, exitCode, collected.Collection
	}

	s.logCollectedPackages(collected)

	checkResult, err := s.selectAndRunChecker(ctx, collected.CheckPackages)
	if err != nil {
		return s.checkErrorResult(scanID, start, err), ExitOperational, collected.Collection
	}

	result := s.buildSuccessfulScanResult(scanID, start, collected, checkResult)
	return result, scanExitCode(result.FindingsBlocking, result.Findings, result.ParseErrors), collected.Collection
}

type collectedScanPackages struct {
	Collection    *PackageCollection
	AllPackages   []domain.Package
	CheckPackages []domain.Package
	ParseErrors   []string
}

func (s *Scanner) collectScanPackages() (collectedScanPackages, error) {
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
		return collectedScanPackages{}, fmt.Errorf("collect packages: %w", err)
	}

	allPackages := collection.Packages
	return collectedScanPackages{
		Collection:    collection,
		AllPackages:   allPackages,
		CheckPackages: scanCheckPackages(allPackages, s.cfg.IncludeDev),
		ParseErrors:   collection.ParseErrors,
	}, nil
}

func (s *Scanner) applyParseErrorPolicy(scanID string, start time.Time, collected collectedScanPackages) (*domain.ScanResult, int, bool) {
	collection := collected.Collection
	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		return s.emptyScanResult(scanID, start, collection.ParseErrors), ExitOK, true
	}

	if len(collection.FatalParseErrors) > 0 {
		result := s.errorResultWithPackages(scanID, start, strings.Join(collection.FatalParseErrors, "; "), len(collected.CheckPackages))
		result.ParseErrors = append([]string(nil), collected.ParseErrors...)
		return result, ExitParser, true
	}

	// If all files had parse errors and we got zero packages, exit 4.
	if len(collected.AllPackages) == 0 && len(collected.ParseErrors) > 0 {
		result := s.errorResult(scanID, start, strings.Join(collected.ParseErrors, "; "))
		result.ParseErrors = append([]string(nil), collected.ParseErrors...)
		return result, ExitParser, true
	}

	if len(collected.CheckPackages) == 0 {
		result := s.emptyScanResult(scanID, start, collected.ParseErrors)
		if len(collected.ParseErrors) > 0 {
			return result, ExitParser, true
		}
		return result, ExitOK, true
	}

	return nil, 0, false
}

func (s *Scanner) logCollectedPackages(collected collectedScanPackages) {
	s.log().Debug("packages collected",
		slog.Int("total", len(collected.AllPackages)),
		slog.Int("check_total", len(collected.CheckPackages)),
		slog.Int("lock_files", collected.Collection.LockFiles),
		slog.Int("sbom_files", collected.Collection.SBOMFiles),
		slog.Bool("include_dev", s.cfg.IncludeDev),
		slog.Bool("inventory_all_packages", s.cfg.InventoryAllPackages),
	)
}

type checkModeResult struct {
	Mode         Mode
	Findings     []domain.Finding
	FeedVersions map[string]string
	FeedStatus   string
	RemoteResult remoteCheckResult
}

type checkModeError struct {
	Message         string
	PackagesScanned int
}

func (e checkModeError) Error() string {
	return e.Message
}

func (s *Scanner) selectAndRunChecker(ctx context.Context, packages []domain.Package) (checkModeResult, error) {
	switch s.resolveMode() {
	case ModeRemote:
		remoteResult, err := s.checkRemoteResult(ctx, packages)
		if err != nil {
			return checkModeResult{}, checkModeError{Message: fmt.Sprintf("remote check failed: %v", err)}
		}
		return checkModeResult{
			Mode:         ModeRemote,
			Findings:     remoteResult.Result.Findings,
			FeedVersions: remoteResult.Result.FeedVersions,
			FeedStatus:   remoteResult.Result.FeedStatus,
			RemoteResult: remoteResult,
		}, nil
	case ModeLocal:
		findings, err := s.executeLocalCheckMode(ctx, packages)
		if err != nil {
			return checkModeResult{}, err
		}
		return checkModeResult{
			Mode:         ModeLocal,
			Findings:     findings,
			FeedVersions: map[string]string{},
		}, nil
	case ModeAuto:
		return s.executeAutoCheckMode(ctx, packages)
	default:
		return s.executeAutoCheckMode(ctx, packages)
	}
}

func (s *Scanner) executeLocalCheckMode(ctx context.Context, packages []domain.Package) ([]domain.Finding, error) {
	if s.localChecker == nil {
		return nil, checkModeError{
			Message:         "local advisory data unavailable (run 'packmon db sync' first)",
			PackagesScanned: len(packages),
		}
	}
	findings, err := s.checkLocal(ctx, packages)
	if err != nil {
		return nil, checkModeError{
			Message:         fmt.Sprintf("local check failed: %v", err),
			PackagesScanned: len(packages),
		}
	}
	return findings, nil
}

func (s *Scanner) executeAutoCheckMode(ctx context.Context, packages []domain.Package) (checkModeResult, error) {
	remoteResult, err := s.checkRemoteResult(ctx, packages)
	if err == nil {
		return checkModeResult{
			Mode:         ModeRemote,
			Findings:     remoteResult.Result.Findings,
			FeedVersions: remoteResult.Result.FeedVersions,
			FeedStatus:   remoteResult.Result.FeedStatus,
			RemoteResult: remoteResult,
		}, nil
	}

	s.log().Warn("remote check failed",
		slog.Bool("require_remote", s.cfg.RequireRemote),
		slog.String("error", err.Error()),
	)
	// RequireRemote: do not mask a broken/insecure server channel by
	// silently falling back to a (possibly stale) local database.
	if s.cfg.RequireRemote {
		return checkModeResult{}, checkModeError{
			Message: fmt.Sprintf("remote check failed and --require-remote is set: %v", err),
		}
	}
	// Auto mode: fall back to local database.
	if s.localChecker == nil {
		return checkModeResult{}, checkModeError{
			Message:         fmt.Sprintf("remote check failed and no local advisory data available: %v", err),
			PackagesScanned: len(packages),
		}
	}
	findings, localErr := s.checkLocal(ctx, packages)
	if localErr != nil {
		return checkModeResult{}, checkModeError{
			Message:         fmt.Sprintf("remote and local check failed: %v", localErr),
			PackagesScanned: len(packages),
		}
	}
	return checkModeResult{
		Mode:         ModeLocal,
		Findings:     findings,
		FeedVersions: map[string]string{},
	}, nil
}

func (s *Scanner) checkErrorResult(scanID string, start time.Time, err error) *domain.ScanResult {
	packagesScanned := 0
	if modeErr, ok := err.(checkModeError); ok {
		packagesScanned = modeErr.PackagesScanned
	}
	return s.errorResultWithPackages(scanID, start, err.Error(), packagesScanned)
}

func (s *Scanner) buildSuccessfulScanResult(scanID string, start time.Time, collected collectedScanPackages, checkResult checkModeResult) *domain.ScanResult {
	findings := checkResult.Findings
	if findings == nil {
		findings = []domain.Finding{}
	}
	feedVersions := checkResult.FeedVersions
	if feedVersions == nil {
		feedVersions = map[string]string{}
	}
	feedStatus := normalizeScanFeedStatus(checkResult.FeedStatus)
	annotateFindingLocations(findings, collected.Collection.Entries)

	blocking := s.hasBlockingFindings(findings)
	resultScanID := scanID
	resultScannedAt := start.UTC()
	resultDurationMs := time.Since(start).Milliseconds()
	if checkResult.RemoteResult.PreserveIdentity {
		if checkResult.RemoteResult.Result.ScanID != "" {
			resultScanID = checkResult.RemoteResult.Result.ScanID
		}
		if !checkResult.RemoteResult.Result.ScannedAt.IsZero() {
			resultScannedAt = checkResult.RemoteResult.Result.ScannedAt
		}
		resultDurationMs = checkResult.RemoteResult.Result.DurationMs
	}

	result := &domain.ScanResult{
		ScanID:                resultScanID,
		Mode:                  checkResult.Mode,
		ScannedAt:             resultScannedAt,
		DurationMs:            resultDurationMs,
		PackagesScanned:       len(collected.CheckPackages),
		FindingsCount:         len(findings),
		FindingsBlocking:      blocking,
		BlockThreshold:        s.cfg.FailOn,
		Summary:               domain.BuildScanSummary(findings),
		Findings:              findings,
		ParseErrors:           append([]string(nil), collected.ParseErrors...),
		FeedStatus:            feedStatus,
		FeedVersions:          feedVersions,
		ManualAdvisoriesCount: domain.CountManualAdvisoryFindings(findings),
	}
	sortScanFindings(result.Findings)
	return result
}

func sortScanFindings(findings []domain.Finding) {
	// Sort findings: CRITICAL first, then HIGH, MEDIUM, LOW.
	sort.Slice(findings, func(i, j int) bool {
		ri := findings[i].Severity.Rank()
		rj := findings[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		return findings[i].Name < findings[j].Name
	})
}

func scanExitCode(blocking bool, findings []domain.Finding, parseErrors []string) int {
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
	return exitCode
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
	return normalizeMode(string(s.cfg.Mode))
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

	if len(requestPackages) <= checkcontract.MaxPackagesPerCheck {
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
	for start := 0; start < len(requestPackages); start += checkcontract.MaxPackagesPerCheck {
		end := start + checkcontract.MaxPackagesPerCheck
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
			Mode:                  domain.ScanModeRemote,
			Findings:              allFindings,
			FindingsCount:         len(allFindings),
			FindingsBlocking:      remoteBlocking,
			Summary:               domain.BuildScanSummary(allFindings),
			FeedStatus:            feedStatus,
			FeedVersions:          feedVersions,
			ManualAdvisoriesCount: domain.CountManualAdvisoryFindings(allFindings),
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
	requestCorrelationID := newCorrelationID()
	req.Header.Set(correlation.Header, requestCorrelationID)
	if strings.TrimSpace(s.cfg.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(s.cfg.APIKey))
	}

	if err := s.ensureRemoteHTTPClient(); err != nil {
		return domain.ScanResult{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return domain.ScanResult{}, fmt.Errorf("server request: %s", logsafe.RedactURLRequestError(err, "server URL"))
	}
	defer ioutils.CloseSilently(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, err := readRemoteErrorBody(resp.Body)
		if err != nil {
			return domain.ScanResult{}, fmt.Errorf("read response: %w", err)
		}
		snippet := safeRemoteErrorSnippet(body)
		correlationSuffix := remoteErrorCorrelationSuffix(resp, requestCorrelationID)
		if resp.StatusCode == http.StatusUnauthorized {
			return domain.ScanResult{}, fmt.Errorf("server returned %d: %s%s (check PACKMON_API_KEY, --api-key, or api_key_env configuration)", resp.StatusCode, snippet, correlationSuffix)
		}
		if resp.StatusCode == http.StatusForbidden {
			return domain.ScanResult{}, fmt.Errorf("server returned %d: %s%s (check Packmon CLI version, User-Agent policy, or server request policy)", resp.StatusCode, snippet, correlationSuffix)
		}
		return domain.ScanResult{}, fmt.Errorf("server returned %d: %s%s", resp.StatusCode, snippet, correlationSuffix)
	}

	var result domain.ScanResult
	if err := decodeRemoteCheckResponse(resp.Body, &result); err != nil {
		return domain.ScanResult{}, fmt.Errorf("decode response: %w", err)
	}

	return result, nil
}

func (s *Scanner) ensureRemoteHTTPClient() error {
	if s.clientErr != nil {
		return s.clientErr
	}
	tr, ok := s.client.Transport.(*http.Transport)
	if !ok {
		return nil
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tr.TLSClientConfig.RootCAs != nil || strings.TrimSpace(s.cfg.CACertFile) == "" {
		return nil
	}
	pool, err := httpclient.LoadCAPool(s.cfg.CACertFile)
	if err != nil {
		s.clientErr = err
		return err
	}
	tr.TLSClientConfig.RootCAs = pool
	return nil
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
	var trailing any
	if err := dec.Decode(&trailing); err != nil {
		if err == io.EOF {
			return nil
		}
		if limited.N <= 0 {
			return fmt.Errorf("response body exceeds %d bytes", maxRemoteCheckResponseSize)
		}
		return err
	}
	if limited.N <= 0 {
		return fmt.Errorf("response body exceeds %d bytes", maxRemoteCheckResponseSize)
	}
	return fmt.Errorf("response body contains trailing data")
}

func readRemoteErrorBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxRemoteErrorBodySize))
}

func safeRemoteErrorSnippet(body []byte) string {
	return logsafe.RemoteErrorSnippet(body, 200)
}

func remoteErrorCorrelationSuffix(resp *http.Response, fallback string) string {
	id := fallback
	if resp != nil {
		if headerID := strings.TrimSpace(resp.Header.Get(correlation.Header)); correlation.Valid(headerID) {
			id = headerID
		}
	}
	if !correlation.Valid(id) {
		return ""
	}
	return " correlation_id=" + id
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
	case next == string(domain.ScanFeedStatusHealthy):
		return current
	case current == string(domain.ScanFeedStatusHealthy):
		return next
	case current == string(domain.ScanFeedStatusError) || next == string(domain.ScanFeedStatusError):
		return string(domain.ScanFeedStatusError)
	case current == string(domain.ScanFeedStatusDegraded) || next == string(domain.ScanFeedStatusDegraded):
		return string(domain.ScanFeedStatusDegraded)
	default:
		return current
	}
}

func normalizeScanFeedStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "", string(domain.ScanFeedStatusHealthy):
		return string(domain.ScanFeedStatusHealthy)
	case string(domain.ScanFeedStatusDegraded):
		return string(domain.ScanFeedStatusDegraded)
	case string(domain.ScanFeedStatusError):
		return string(domain.ScanFeedStatusError)
	default:
		return string(domain.ScanFeedStatusDegraded)
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

func remoteScanRepo(repo *domain.RepoInfo) *domain.RemoteRepoInfo {
	if repo == nil {
		return nil
	}
	name := strings.TrimSpace(repo.Name)
	if name == "" {
		return nil
	}
	return &domain.RemoteRepoInfo{Name: name}
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

// checkLocal resolves local vulnerability, malicious, reputation, and lifecycle
// findings against the local SQLite database.
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

	reputation, err := s.localChecker.FindReputationFindingsBatch(ctx, queries, reversingLabsReputationSource)
	if err != nil {
		return nil, fmt.Errorf("local reputation batch check: %w", err)
	}
	allFindings = append(allFindings, reputation...)

	lifecycle, err := s.localChecker.FindLifecycleFindingsBatch(ctx, queries, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("local lifecycle check: %w", err)
	}
	allFindings = append(allFindings, lifecycle...)

	return allFindings, nil
}

func packageQueries(pkgs []domain.Package) []PackageLookup {
	queries := make([]PackageLookup, 0, len(pkgs))
	for _, pkg := range pkgs {
		queries = append(queries, PackageLookup{
			Ecosystem: string(pkg.Ecosystem),
			Name:      pkg.Name,
			Version:   pkg.Version,
		})
	}
	return queries
}

// hasBlockingFindings delegates to domain.FindingsBlock, the shared source of
// truth for scan blocking policy:
// - malware and active supply-chain risk always block regardless of threshold
// - vulnerability and lifecycle findings block when severity meets fail-on
// - informational reputation findings never block
// - NONE disables severity-gated blocking only
func (s *Scanner) hasBlockingFindings(findings []domain.Finding) bool {
	return domain.FindingsBlock(findings, s.cfg.FailOn)
}

func (s *Scanner) errorResult(scanID string, start time.Time, msg string) *domain.ScanResult {
	return s.errorResultWithPackages(scanID, start, msg, 0)
}

func (s *Scanner) errorResultWithPackages(scanID string, start time.Time, msg string, packagesScanned int) *domain.ScanResult {
	return &domain.ScanResult{
		ScanID:          scanID,
		Mode:            s.resolveMode(),
		ScannedAt:       start.UTC(),
		DurationMs:      time.Since(start).Milliseconds(),
		PackagesScanned: packagesScanned,
		BlockThreshold:  s.cfg.FailOn,
		FeedStatus:      string(domain.ScanFeedStatusError),
		ScanError:       msg,
		Summary:         domain.EmptyScanSummary(),
		Findings:        []domain.Finding{},
		FeedVersions:    map[string]string{},
	}
}

func (s *Scanner) emptyScanResult(scanID string, start time.Time, parseErrors []string) *domain.ScanResult {
	return &domain.ScanResult{
		ScanID:          scanID,
		Mode:            s.resolveMode(),
		ScannedAt:       start.UTC(),
		DurationMs:      time.Since(start).Milliseconds(),
		PackagesScanned: 0,
		FindingsCount:   0,
		BlockThreshold:  s.cfg.FailOn,
		FeedStatus:      string(domain.ScanFeedStatusHealthy),
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
