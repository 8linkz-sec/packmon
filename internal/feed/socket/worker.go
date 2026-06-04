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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/telemetry"
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
)

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

// Worker processes the refresh_queue for Socket.dev checks.
// It implements feed.AsyncWorker.
type Worker struct {
	store        db.Store
	logger       *slog.Logger
	httpClient   *http.Client
	baseURL      string
	apiKey       string
	pollInterval time.Duration

	// Token bucket for rate limiting.
	tokensMu         sync.Mutex
	tokens           int
	maxTokens        int
	lastRefill       time.Time
	fractionalTokens float64 // accumulates sub-integer token fractions between refills
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
		w.maxTokens = callsPerHour
		w.tokens = callsPerHour
	}
}

// NewWorker creates a Socket.dev worker. If apiKey is empty, Run will
// return immediately (the worker is a no-op without a key).
func NewWorker(store db.Store, apiKey string, logger *slog.Logger, opts ...Option) *Worker {
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
		tokens:       defaultRateLimit,
		maxTokens:    defaultRateLimit,
		lastRefill:   time.Now(),
	}
	for _, opt := range opts {
		opt(w)
	}
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
		slog.Int("rate_limit", w.maxTokens),
	)

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	// Reset stuck jobs on startup.
	w.resetStuckJobs(ctx)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Socket.dev worker shutting down")
			return ctx.Err()
		case <-ticker.C:
			w.processNextJob(ctx)
		}
	}
}

// processNextJob dequeues and processes a single job if a rate-limit
// token is available.
func (w *Worker) processNextJob(ctx context.Context) {
	// Reset stuck jobs periodically (cheap query).
	w.resetStuckJobs(ctx)

	if !w.acquireToken() {
		return
	}

	job, err := w.store.DequeueRefresh(ctx, FeedName)
	if err != nil {
		w.logger.Error("failed to dequeue job", slog.String("error", err.Error()))
		return
	}
	if job == nil {
		// No pending jobs. Return the token since we did not make an API call.
		w.returnToken()
		return
	}

	w.logger.Info("processing socket check",
		slog.String("ecosystem", job.Ecosystem),
		slog.String("name", job.Name),
		slog.Int("priority", job.Priority),
		slog.Int("job_id", job.ID),
	)

	checkErr := w.checkPackage(ctx, job)
	if completeErr := w.store.CompleteRefresh(ctx, job.ID, checkErr); completeErr != nil {
		w.logger.Error("failed to complete job",
			slog.Int("job_id", job.ID),
			slog.String("error", completeErr.Error()),
		)
	}

	if checkErr != nil {
		telemetry.Default().IncQueueError(FeedName)
		w.logger.Warn("socket check failed",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.String("error", checkErr.Error()),
		)
	}
}

// checkPackage calls the Socket.dev API for a single package and stores
// results in the database.
func (w *Worker) checkPackage(ctx context.Context, job *db.RefreshJob) error {
	socketEco, ok := ecosystemMap[job.Ecosystem]
	if !ok {
		return fmt.Errorf("unsupported ecosystem for Socket.dev: %s", job.Ecosystem)
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
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

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
		w.updateCheckStatus(ctx, job, body)
		return nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// Rate limited. Drain tokens and let the job retry later.
		w.drainTokens()
		return fmt.Errorf("rate limited by Socket.dev (429)")
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
	w.updateCheckStatus(ctx, job, body)
	return nil
}

// processIssues examines Socket.dev issues and creates malicious_findings
// entries for security-relevant issues.
func (w *Worker) processIssues(ctx context.Context, job *db.RefreshJob, resp *scoreResponse) error {
	// Map of Socket.dev issue types to Packmon risk_type values.
	maliciousTypes := map[string]string{
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

	for _, issue := range resp.Issues {
		riskType, isMalicious := maliciousTypes[issue.Type]
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
			// Continue processing other issues.
		}
	}

	return nil
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
func (w *Worker) updateCheckStatus(ctx context.Context, job *db.RefreshJob, rawResult []byte) {
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
	}
}

// resetStuckJobs resets jobs that have been processing for too long.
func (w *Worker) resetStuckJobs(ctx context.Context) {
	count, err := w.store.ResetStuckJobs(ctx, FeedName, stuckThreshold)
	if err != nil {
		w.logger.Warn("failed to reset stuck jobs", slog.String("error", err.Error()))
		return
	}
	if count > 0 {
		telemetry.Default().AddQueueStuckRecovered(count)
		w.logger.Info("reset stuck jobs", slog.Int("count", count))
	}
}

// --- Token bucket rate limiter ---

// acquireToken attempts to take one token from the bucket. Tokens refill
// proportionally based on elapsed time since the last refill.
func (w *Worker) acquireToken() bool {
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()

	w.refillTokens()

	if w.tokens <= 0 {
		return false
	}
	w.tokens--
	return true
}

// returnToken puts one token back (used when no API call was made).
func (w *Worker) returnToken() {
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()
	if w.tokens < w.maxTokens {
		w.tokens++
	}
}

// drainTokens sets tokens to zero (used when rate-limited by upstream).
func (w *Worker) drainTokens() {
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()
	w.tokens = 0
	w.fractionalTokens = 0
	w.lastRefill = time.Now()
}

// refillTokens adds tokens proportional to the time elapsed since the
// last refill, up to the maximum. Must be called under tokensMu lock.
//
// Fractional tokens are accumulated across calls so that small elapsed
// durations do not lose precision through int truncation (FEED-M3).
func (w *Worker) refillTokens() {
	now := time.Now()
	elapsed := now.Sub(w.lastRefill)
	if elapsed <= 0 {
		return
	}

	// Tokens per second = maxTokens / 3600.
	raw := elapsed.Seconds() * float64(w.maxTokens) / 3600.0
	w.fractionalTokens += raw
	whole := int(w.fractionalTokens)
	w.fractionalTokens -= float64(whole)

	if whole <= 0 {
		return
	}

	w.tokens += whole
	if w.tokens > w.maxTokens {
		w.tokens = w.maxTokens
	}
	w.lastRefill = now
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
