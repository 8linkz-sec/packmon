// Package socket implements the async background worker for Socket.dev.
// Socket.dev provides malware detection, typosquatting detection, and
// supply-chain risk analysis for packages. The API is rate-limited to
// 500 calls per hour, so this worker reads jobs from the refresh_queue
// table and processes them one at a time with token-bucket rate limiting.
//
// The Socket.dev worker implements feed.AsyncWorker (not feed.FeedSyncer)
// because it processes the priority queue rather than doing bulk syncs.
// If no Socket.dev API key is configured the worker does not start.
package socket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	feedqueue "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/feed/packagefilter"
	"github.com/8linkz-sec/packmon/internal/feed/ratelimit"
	"github.com/8linkz-sec/packmon/internal/httpclient"
)

const (
	// FeedName is the canonical name used in feed_sync_status and
	// refresh_queue.source.
	FeedName = "socket"

	// DefaultBaseURL is the Socket.dev API base URL.
	DefaultBaseURL = "https://socket.dev/api/v1"

	// defaultRateLimit is the max calls per hour (Socket.dev free tier).
	defaultRateLimit = 500

	// defaultPollInterval is how often the worker checks for new jobs.
	defaultPollInterval = 10 * time.Second

	// maxResponseSize limits a single API response to 1 MB.
	maxResponseSize = 1 << 20

	// stuckThreshold is the time after which a 'processing' job is
	// considered stuck and reset to 'pending'.
	stuckThreshold = 5 * time.Minute

	// completeTimeout bounds queue-row finalization after a worker context is
	// cancelled during runtime reconfiguration or shutdown.
	completeTimeout = 2 * time.Second

	// dequeueTimeout bounds the queue claim query that marks a row processing.
	dequeueTimeout = 2 * time.Second

	resetStuckJobsTimeout = 2 * time.Second
)

var errRateLimited = errors.New("rate limited")

// RateLimiter holds Socket.dev token-bucket state. It can be shared by
// successive workers so runtime reconfiguration does not reset upstream
// capacity.
type RateLimiter = ratelimit.Bucket

// NewRateLimiter creates a token bucket for Socket.dev calls per hour.
func NewRateLimiter(callsPerHour int) *RateLimiter {
	return ratelimit.New(callsPerHour, defaultRateLimit)
}

// ecosystemMap translates canonical Packmon ecosystem names to Socket.dev
// API path segments. Socket.dev only supports certain ecosystems.
var ecosystemMap = map[string]string{
	"npm":      "npm",
	"pypi":     "pypi",
	"go":       "go",
	"maven":    "maven",
	"cargo":    "cargo",
	"nuget":    "nuget",
	"composer": "packagist",
	"gem":      "rubygems",
}

func SupportsEcosystem(ecosystem string) bool {
	_, ok := ecosystemMap[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

// scoreResponse is the top-level Socket.dev package score response.
type scoreResponse struct {
	Score   *scoreData   `json:"score"`
	Issues  []issueEntry `json:"issues"`
	Package *packageInfo `json:"package"`
}

// scoreData holds the overall risk assessment.
type scoreData struct {
	Overall       float64 `json:"overall"`
	Supply        float64 `json:"supplyChain"`
	Quality       float64 `json:"quality"`
	Maintenance   float64 `json:"maintenance"`
	Vulnerability float64 `json:"vulnerability"`
	License       float64 `json:"license"`
}

// issueEntry is one security or quality issue found by Socket.dev.
type issueEntry struct {
	Type             string   `json:"type"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Version          string   `json:"version"`
	PackageVersion   string   `json:"packageVersion"`
	Versions         []string `json:"versions"`
	AffectedVersions []string `json:"affectedVersions"`
}

// packageInfo holds basic package metadata from the Socket.dev response.
type packageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type socketCheckStatusResult struct {
	Source             string             `json:"source"`
	Status             string             `json:"status"`
	PackageVersion     string             `json:"package_version,omitempty"`
	IssueCount         int                `json:"issue_count,omitempty"`
	SecurityIssueCount int                `json:"security_issue_count,omitempty"`
	Score              *socketStatusScore `json:"score,omitempty"`
}

type socketStatusScore struct {
	Overall       float64 `json:"overall"`
	SupplyChain   float64 `json:"supply_chain"`
	Quality       float64 `json:"quality"`
	Maintenance   float64 `json:"maintenance"`
	Vulnerability float64 `json:"vulnerability"`
	License       float64 `json:"license"`
}

var socketIssueRiskTypes = map[string]string{
	"malware":            "malware",
	"installScripts":     "supply_chain",
	"networkAccess":      "supply_chain",
	"shellAccess":        "supply_chain",
	"filesystemAccess":   "supply_chain",
	"envVars":            "supply_chain",
	"obfuscatedCode":     "supply_chain",
	"typosquat":          "typosquatting",
	"protestware":        "malware",
	"criticalCVE":        "supply_chain",
	"highEntropyStrings": "supply_chain",
	"telemetry":          "supply_chain",
}

type socketStore interface {
	DequeueRefresh(context.Context, string) (*db.RefreshJob, error)
	CompleteClaimedRefresh(context.Context, int, *time.Time, error) error
	ResetStuckJobs(context.Context, string, time.Duration) (int, error)
	UpsertMaliciousFinding(context.Context, *db.MaliciousFinding) error
	UpsertPackageCheckStatus(context.Context, *db.PackageCheckStatus) error
}

// Worker processes the refresh_queue for Socket.dev checks.
// It implements feed.AsyncWorker.
type Worker struct {
	store        socketStore
	logger       *slog.Logger
	httpClient   *http.Client
	baseURL      string
	apiKey       string
	pollInterval time.Duration
	jobTimeout   time.Duration
	excluded     []string
	pollTicks    <-chan time.Time
	runReady     chan<- struct{}
	dequeueLogs  *feedqueue.RepeatedErrorLogger
	resetLogs    *feedqueue.RepeatedErrorLogger
	metrics      feedqueue.MetricsRecorder

	// Token bucket for rate limiting.
	*RateLimiter
}

// Option configures a Worker.
type Option func(*Worker)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(w *Worker) { w.httpClient = c }
}

// WithBaseURL overrides the default Socket.dev API base URL.
func WithBaseURL(url string) Option {
	return func(w *Worker) { w.baseURL = url }
}

// WithPollInterval overrides the default queue polling interval.
func WithPollInterval(d time.Duration) Option {
	return func(w *Worker) { w.pollInterval = d }
}

// WithRateLimit overrides the default calls-per-hour limit.
func WithRateLimit(callsPerHour int) Option {
	return func(w *Worker) {
		w.SetLimit(callsPerHour)
	}
}

// WithRateLimiter shares token-bucket state with another worker generation.
func WithRateLimiter(limiter *RateLimiter) Option {
	return func(w *Worker) {
		if limiter != nil {
			w.RateLimiter = limiter
		}
	}
}

func WithJobTimeout(d time.Duration) Option {
	return func(w *Worker) {
		if d > 0 {
			w.jobTimeout = d
		}
	}
}

func WithExcludedNamespaces(prefixes []string) Option {
	return func(w *Worker) {
		w.excluded = packagefilter.NormalizeNamespacePrefixes(prefixes)
	}
}

func WithMetricsRecorder(recorder feedqueue.MetricsRecorder) Option {
	return func(w *Worker) {
		w.metrics = feedqueue.MetricsRecorderOrNoop(recorder)
	}
}

// NewWorker creates a Socket.dev worker. If apiKey is empty, Run will
// return immediately (the worker is a no-op without a key).
func NewWorker(store socketStore, apiKey string, logger *slog.Logger, opts ...Option) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	w := &Worker{
		store:  store,
		logger: logger.With(slog.String("feed", FeedName)),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:      DefaultBaseURL,
		apiKey:       apiKey,
		pollInterval: defaultPollInterval,
		jobTimeout:   30 * time.Second,
		dequeueLogs:  feedqueue.NewRepeatedErrorLogger(feedqueue.DefaultRepeatedErrorLogWindow),
		resetLogs:    feedqueue.NewRepeatedErrorLogger(feedqueue.DefaultRepeatedErrorLogWindow),
		metrics:      feedqueue.NoopMetricsRecorder(),
		RateLimiter:  NewRateLimiter(defaultRateLimit),
	}
	for _, opt := range opts {
		opt(w)
	}
	w.httpClient = httpclient.CloneWithSafeRedirectPolicy(w.httpClient)
	return w
}

// Name implements feed.AsyncWorker. Returns the source identifier used
// in the refresh_queue.source column.
func (w *Worker) Name() string { return FeedName }

// Run implements feed.AsyncWorker. It starts the background worker loop
// and blocks until the context is cancelled. If no API key is configured,
// Run returns immediately.
func (w *Worker) Run(ctx context.Context) error {
	if w.apiKey == "" {
		w.logger.Info("Socket.dev API key not configured, worker not starting")
		return nil
	}

	w.logger.Info("Socket.dev worker started",
		slog.Duration("poll_interval", w.pollInterval),
		slog.Int("rate_limit", w.Limit()),
	)

	pollTicks := w.pollTicks
	if pollTicks == nil {
		ticker := time.NewTicker(w.pollInterval)
		defer ticker.Stop()
		pollTicks = ticker.C
	}
	if w.runReady != nil {
		close(w.runReady)
		w.runReady = nil
	}

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Socket.dev worker shutting down")
			return ctx.Err()
		case _, ok := <-pollTicks:
			if !ok {
				return nil
			}
			w.processAvailableJobs(ctx)
		}
	}
}

func (w *Worker) processAvailableJobs(ctx context.Context) {
	w.resetStuckJobs(ctx)
	for w.processNextJobWithoutReset(ctx) {
		if ctx.Err() != nil {
			return
		}
	}
}

// processNextJob dequeues and processes a single job if a rate-limit token is
// available. It returns whether it made queue progress.
func (w *Worker) processNextJob(ctx context.Context) bool {
	w.resetStuckJobs(ctx)
	return w.processNextJobWithoutReset(ctx)
}

func (w *Worker) processNextJobWithoutReset(ctx context.Context) bool {
	if !w.RateLimiter.Acquire() {
		return false
	}

	dequeueCtx, cancel := context.WithTimeout(ctx, dequeueTimeout)
	job, err := w.store.DequeueRefresh(dequeueCtx, FeedName)
	cancel()
	if err != nil {
		w.RateLimiter.Return()
		w.dequeueLogs.Error(w.logger, "failed to dequeue job", err)
		return false
	}
	if job == nil {
		// No pending jobs. Return the token since we did not make an API call.
		w.RateLimiter.Return()
		return false
	}
	if !SupportsEcosystem(job.Ecosystem) {
		// The job cannot result in an upstream Socket.dev request, so it must
		// not consume a worker rate-limit token.
		w.RateLimiter.Return()
		checkErr := unsupportedEcosystemError(job.Ecosystem)
		completeCtx, cancel := context.WithTimeout(context.Background(), completeTimeout)
		defer cancel()
		if completeErr := completeQueueJob(completeCtx, w.store, job, checkErr, w.metrics); completeErr != nil {
			w.logger.Error("failed to complete job",
				slog.Int("job_id", job.ID),
				slog.String("error", completeErr.Error()),
			)
		}
		w.metrics.IncQueueError(FeedName)
		w.logger.Warn("socket check failed",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.Int("job_id", job.ID),
			slog.String("error", feedqueue.SafeDiagnosticError(checkErr)),
		)
		return true
	}
	if packagefilter.ExcludedByNamespace(w.excluded, job.Ecosystem, job.Name) {
		w.RateLimiter.Return()
		checkErr := privateNamespaceError(job.Ecosystem, job.Name)
		completeCtx, cancel := context.WithTimeout(context.Background(), completeTimeout)
		defer cancel()
		if completeErr := completeQueueJob(completeCtx, w.store, job, checkErr, w.metrics); completeErr != nil {
			w.logger.Error("failed to complete job",
				slog.Int("job_id", job.ID),
				slog.String("error", completeErr.Error()),
			)
		}
		w.logger.Info("socket check skipped by private namespace policy",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
		)
		return true
	}

	w.logger.Info("processing socket check",
		slog.String("ecosystem", job.Ecosystem),
		slog.String("name", job.Name),
		slog.Int("priority", job.Priority),
		slog.Int("job_id", job.ID),
	)

	jobCtx, cancel := context.WithTimeout(ctx, w.jobTimeout)
	checkErr := w.checkPackage(jobCtx, job)
	cancel()
	if errors.Is(checkErr, errRateLimited) {
		w.metrics.IncQueueError(FeedName)
		w.logger.Warn("socket check rate limited; leaving job processing for retry",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.Int("job_id", job.ID),
			slog.String("error", feedqueue.SafeDiagnosticError(checkErr)),
		)
		return false
	}
	completeCtx, cancel := context.WithTimeout(context.Background(), completeTimeout)
	defer cancel()
	if completeErr := completeQueueJob(completeCtx, w.store, job, checkErr, w.metrics); completeErr != nil {
		w.logger.Error("failed to complete job",
			slog.Int("job_id", job.ID),
			slog.String("error", completeErr.Error()),
		)
	}

	if checkErr != nil {
		w.metrics.IncQueueError(FeedName)
		w.logger.Warn("socket check failed",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.Int("job_id", job.ID),
			slog.String("error", feedqueue.SafeDiagnosticError(checkErr)),
		)
	}
	return true
}

func completeQueueJob(ctx context.Context, store socketStore, job *db.RefreshJob, jobErr error, recorder feedqueue.MetricsRecorder) error {
	err := feedqueue.CompleteClaimedRefresh(ctx, store, job, jobErr)
	if err != nil || job == nil {
		return err
	}
	feedqueue.MetricsRecorderOrNoop(recorder).IncQueueJobCompleted(FeedName, queueJobCompletionResult(jobErr))
	return nil
}

func queueJobCompletionResult(jobErr error) string {
	if jobErr != nil {
		return feedqueue.QueueJobResultError
	}
	return feedqueue.QueueJobResultSuccess
}

// checkPackage calls the Socket.dev API for a single package and stores
// results in the database.
func (w *Worker) checkPackage(ctx context.Context, job *db.RefreshJob) error {
	socketEco, ok := ecosystemMap[job.Ecosystem]
	if !ok {
		return unsupportedEcosystemError(job.Ecosystem)
	}

	url := fmt.Sprintf("%s/%s/%s/score",
		strings.TrimRight(w.baseURL, "/"),
		socketEco,
		job.Name,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", feedqueue.FeedSyncUserAgent)

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// Package not known to Socket.dev. Record the check but do not error.
		return w.updateCheckStatus(ctx, job, normalizedSocketStatus("not_found", nil))
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// Rate limited. Drain tokens and let the job retry later.
		w.RateLimiter.Drain()
		return fmt.Errorf("%w by Socket.dev (429)", errRateLimited)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("authentication failed (status %d): check PACKMON_SOCKET_API_KEY", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var scoreResp scoreResponse
	if err := json.Unmarshal(body, &scoreResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Analyze issues for malicious indicators.
	if err := w.processIssues(ctx, job, &scoreResp); err != nil {
		return fmt.Errorf("process issues: %w", err)
	}

	// Update check status regardless of findings.
	return w.updateCheckStatus(ctx, job, normalizedSocketStatus("ok", &scoreResp))
}

func unsupportedEcosystemError(ecosystem string) error {
	return fmt.Errorf("unsupported ecosystem for Socket.dev: %s", ecosystem)
}

func privateNamespaceError(ecosystem, name string) error {
	return fmt.Errorf("package %s/%s excluded by private namespace policy for Socket.dev", ecosystem, name)
}

// processIssues examines Socket.dev issues and creates malicious_findings
// entries for security-relevant issues.
func (w *Worker) processIssues(ctx context.Context, job *db.RefreshJob, resp *scoreResponse) error {
	var writeErrs []error
	for _, issue := range resp.Issues {
		riskType, isMalicious := socketIssueRiskTypes[issue.Type]
		if !isMalicious {
			continue
		}

		severity := mapSocketSeverity(issue.Severity)

		findingID := fmt.Sprintf("socket:%s/%s:%s", job.Ecosystem, job.Name, issue.Type)
		summary := issue.Title
		if summary == "" {
			summary = fmt.Sprintf("Socket.dev: %s detected in %s", issue.Type, job.Name)
		}

		socketEco := ecosystemMap[job.Ecosystem]
		refURLs, _ := json.Marshal([]string{
			fmt.Sprintf("https://socket.dev/%s/package/%s", socketEco, job.Name),
		})

		mf := &db.MaliciousFinding{
			ID:            findingID,
			Ecosystem:     job.Ecosystem,
			Name:          job.Name,
			Versions:      socketIssueVersions(issue, resp.Package),
			Source:        FeedName,
			RiskType:      riskType,
			Severity:      severity,
			Summary:       summary,
			Description:   issue.Description,
			ReferenceURLs: refURLs,
			OriginRef:     issue.Type,
			CreatedBy:     "system",
		}

		if err := w.store.UpsertMaliciousFinding(ctx, mf); err != nil {
			w.logger.Warn("failed to upsert malicious finding",
				slog.String("finding_id", findingID),
				slog.String("error", err.Error()),
			)
			writeErrs = append(writeErrs, fmt.Errorf("upsert malicious finding %s: %w", findingID, err))
		}
	}

	return errors.Join(writeErrs...)
}

func normalizedSocketStatus(status string, resp *scoreResponse) json.RawMessage {
	result := socketCheckStatusResult{
		Source: FeedName,
		Status: status,
	}
	if resp != nil {
		result.IssueCount = len(resp.Issues)
		for _, issue := range resp.Issues {
			if _, ok := socketIssueRiskTypes[issue.Type]; ok {
				result.SecurityIssueCount++
			}
		}
		if resp.Package != nil {
			result.PackageVersion = strings.TrimSpace(resp.Package.Version)
		}
		if resp.Score != nil {
			result.Score = &socketStatusScore{
				Overall:       resp.Score.Overall,
				SupplyChain:   resp.Score.Supply,
				Quality:       resp.Score.Quality,
				Maintenance:   resp.Score.Maintenance,
				Vulnerability: resp.Score.Vulnerability,
				License:       resp.Score.License,
			}
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return []byte(`{"source":"socket","status":"error"}`)
	}
	return raw
}

func socketIssueVersions(issue issueEntry, pkg *packageInfo) json.RawMessage {
	values := make([]string, 0, 2+len(issue.Versions)+len(issue.AffectedVersions))
	values = append(values, issue.Version, issue.PackageVersion)
	if pkg != nil {
		values = append(values, pkg.Version)
	}
	values = append(values, issue.Versions...)
	values = append(values, issue.AffectedVersions...)

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	encoded, _ := json.Marshal(out)
	return encoded
}

// updateCheckStatus records that a package was checked, regardless of outcome.
func (w *Worker) updateCheckStatus(ctx context.Context, job *db.RefreshJob, rawResult []byte) error {
	now := time.Now()
	// Re-check after 7 days by default.
	nextCheck := now.Add(7 * 24 * time.Hour)

	status := &db.PackageCheckStatus{
		Ecosystem:     job.Ecosystem,
		Name:          job.Name,
		Source:        FeedName,
		LastCheckedAt: &now,
		NextCheckAt:   &nextCheck,
		LastResult:    rawResult,
	}

	if err := w.store.UpsertPackageCheckStatus(ctx, status); err != nil {
		w.logger.Warn("failed to update check status",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.String("error", err.Error()),
		)
		return err
	}
	return nil
}

// resetStuckJobs resets jobs that have been processing for too long.
func (w *Worker) resetStuckJobs(ctx context.Context) {
	resetCtx, cancel := context.WithTimeout(ctx, resetStuckJobsTimeout)
	count, err := w.store.ResetStuckJobs(resetCtx, FeedName, stuckThreshold)
	cancel()
	if err != nil {
		w.resetLogs.Warn(w.logger, "failed to reset stuck jobs", err)
		return
	}
	if count > 0 {
		w.metrics.AddQueueStuckRecovered(count)
		w.logger.Info("reset stuck jobs", slog.Int("count", count))
	}
}

// mapSocketSeverity translates Socket.dev severity strings to canonical
// Packmon severity values.
func mapSocketSeverity(socketSev string) string {
	switch strings.ToLower(socketSev) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		// Malicious packages default to CRITICAL when severity is unknown.
		return "CRITICAL"
	}
}
