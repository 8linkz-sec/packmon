package reversinglabs

import (
	"bytes"
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
	FeedName = db.ReputationSourceReversingLabs

	DefaultBaseURL = "https://data.reversinglabs.com/api/oss/community/v2/free"

	defaultPollInterval     = 10 * time.Second
	defaultRateLimitPerHour = 300
	defaultLookupTTL        = 24 * time.Hour
	defaultCacheRetention   = 7 * 24 * time.Hour
	defaultPruneInterval    = time.Hour
	defaultBatchSize        = 5
	maxBatchSize            = 5
	maxResponseSize         = 2 << 20
	stuckThreshold          = 5 * time.Minute
	completeTimeout         = 2 * time.Second
	dequeueTimeout          = 2 * time.Second
	resetStuckJobsTimeout   = 2 * time.Second
)

var (
	errRateLimited                       = errors.New("rate limited")
	errInvalidReversingLabsResponseShape = errors.New("invalid ReversingLabs response schema")
)

// RateLimiter holds ReversingLabs token-bucket state. It can be shared by
// successive workers so runtime reconfiguration does not reset upstream
// capacity.
type RateLimiter = ratelimit.Bucket

// NewRateLimiter creates a token bucket for ReversingLabs calls per hour.
func NewRateLimiter(callsPerHour int) *RateLimiter {
	return ratelimit.New(callsPerHour, defaultRateLimitPerHour)
}

type reputationStore interface {
	DequeueRefresh(context.Context, string) (*db.RefreshJob, error)
	CompleteClaimedRefresh(context.Context, int, *time.Time, error) error
	ResetStuckJobs(context.Context, string, time.Duration) (int, error)
	ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error)
	UpsertPackageReputation(context.Context, *db.PackageReputation) error
}

type reputationPruner interface {
	PrunePackageReputation(context.Context, string, time.Duration) (int, error)
}

type pollTicker interface {
	C() <-chan time.Time
	Stop()
}

type realPollTicker struct {
	ticker *time.Ticker
}

func newRealPollTicker(d time.Duration) pollTicker {
	return &realPollTicker{ticker: time.NewTicker(d)}
}

func (t *realPollTicker) C() <-chan time.Time {
	return t.ticker.C
}

func (t *realPollTicker) Stop() {
	t.ticker.Stop()
}

type Worker struct {
	store          reputationStore
	logger         *slog.Logger
	httpClient     *http.Client
	baseURL        string
	apiKey         string
	pollInterval   time.Duration
	lookupTTL      time.Duration
	batchSize      int
	jobTimeout     time.Duration
	cacheRetention time.Duration
	pruneInterval  time.Duration
	lastPrune      time.Time
	excluded       []string
	dequeueLogs    *feedqueue.RepeatedErrorLogger
	resetLogs      *feedqueue.RepeatedErrorLogger
	newPollTicker  func(time.Duration) pollTicker
	metrics        feedqueue.MetricsRecorder

	*RateLimiter
}

type Option func(*Worker)

func WithHTTPClient(c *http.Client) Option {
	return func(w *Worker) {
		if c != nil {
			w.httpClient = c
		}
	}
}

func WithBaseURL(url string) Option {
	return func(w *Worker) {
		url = strings.TrimSpace(url)
		if url != "" {
			w.baseURL = strings.TrimRight(url, "/")
		}
	}
}

func WithPollInterval(d time.Duration) Option {
	return func(w *Worker) {
		if d > 0 {
			w.pollInterval = d
		}
	}
}

func WithLookupTTL(d time.Duration) Option {
	return func(w *Worker) {
		if d > 0 {
			w.lookupTTL = d
		}
	}
}

func WithCacheRetention(d time.Duration) Option {
	return func(w *Worker) {
		if d > 0 {
			w.cacheRetention = d
		}
	}
}

func WithBatchSize(size int) Option {
	return func(w *Worker) {
		if size <= 0 {
			return
		}
		if size > maxBatchSize {
			size = maxBatchSize
		}
		w.batchSize = size
	}
}

func WithRateLimit(callsPerHour int) Option {
	return func(w *Worker) {
		if callsPerHour <= 0 {
			return
		}
		w.SetLimit(callsPerHour)
	}
}

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

func NewWorker(store reputationStore, apiKey string, logger *slog.Logger, opts ...Option) *Worker {
	return newWorker(store, apiKey, logger, opts...)
}

func newWorker(store reputationStore, apiKey string, logger *slog.Logger, opts ...Option) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	w := &Worker{
		store:  store,
		logger: logger.With(slog.String("feed", FeedName)),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:        DefaultBaseURL,
		apiKey:         apiKey,
		pollInterval:   defaultPollInterval,
		lookupTTL:      defaultLookupTTL,
		batchSize:      defaultBatchSize,
		jobTimeout:     30 * time.Second,
		cacheRetention: defaultCacheRetention,
		pruneInterval:  defaultPruneInterval,
		dequeueLogs:    feedqueue.NewRepeatedErrorLogger(feedqueue.DefaultRepeatedErrorLogWindow),
		resetLogs:      feedqueue.NewRepeatedErrorLogger(feedqueue.DefaultRepeatedErrorLogWindow),
		newPollTicker:  newRealPollTicker,
		metrics:        feedqueue.NoopMetricsRecorder(),
		RateLimiter:    NewRateLimiter(defaultRateLimitPerHour),
	}
	for _, opt := range opts {
		opt(w)
	}
	w.httpClient = httpclient.CloneWithSafeRedirectPolicy(w.httpClient)
	return w
}

func (w *Worker) Name() string { return FeedName }

func (w *Worker) Run(ctx context.Context) error {
	if strings.TrimSpace(w.apiKey) == "" {
		w.logger.Info("ReversingLabs API key not configured, worker not starting")
		return nil
	}

	w.logger.Info("ReversingLabs worker started",
		slog.Duration("poll_interval", w.pollInterval),
		slog.Int("rate_limit", w.Limit()),
		slog.Int("batch_size", w.batchSize),
	)

	ticker := w.newPollTicker(w.pollInterval)
	defer ticker.Stop()

	w.pruneCache(ctx)
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("ReversingLabs worker shutting down")
			return ctx.Err()
		case <-ticker.C():
			w.processNextJob(ctx)
		}
	}
}

func (w *Worker) processNextJob(ctx context.Context) {
	w.pruneCache(ctx)
	w.resetStuckJobs(ctx)

	if !w.RateLimiter.Acquire() {
		return
	}

	dequeueCtx, cancel := context.WithTimeout(ctx, dequeueTimeout)
	job, err := w.store.DequeueRefresh(dequeueCtx, FeedName)
	cancel()
	if err != nil {
		w.RateLimiter.Return()
		w.dequeueLogs.Error(w.logger, "failed to dequeue job", err)
		return
	}
	if job == nil {
		w.RateLimiter.Return()
		return
	}

	jobCtx, cancel := context.WithTimeout(ctx, w.jobTimeout)
	madeUpstreamRequest, checkErr := w.processJob(jobCtx, job)
	cancel()
	if !madeUpstreamRequest {
		w.RateLimiter.Return()
	}
	if errors.Is(checkErr, errRateLimited) {
		w.metrics.IncQueueError(FeedName)
		w.logger.Warn("ReversingLabs check rate limited; leaving job processing for retry",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.Int("job_id", job.ID),
			slog.String("error", feedqueue.SafeDiagnosticError(checkErr)),
		)
		return
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
		w.logger.Warn("ReversingLabs check failed",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.Int("job_id", job.ID),
			slog.String("error", feedqueue.SafeDiagnosticError(checkErr)),
		)
	}
}

func completeQueueJob(ctx context.Context, store reputationStore, job *db.RefreshJob, jobErr error, recorder feedqueue.MetricsRecorder) error {
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

func (w *Worker) pruneCache(ctx context.Context) {
	if w.cacheRetention <= 0 {
		return
	}
	if !w.lastPrune.IsZero() && time.Since(w.lastPrune) < w.pruneInterval {
		return
	}
	w.lastPrune = time.Now()
	pruner, ok := w.store.(reputationPruner)
	if !ok {
		return
	}
	pruneCtx, cancel := context.WithTimeout(ctx, completeTimeout)
	defer cancel()
	count, err := pruner.PrunePackageReputation(pruneCtx, FeedName, w.cacheRetention)
	if err != nil {
		w.logger.Warn("failed to prune ReversingLabs cache", slog.String("error", err.Error()))
		return
	}
	if count > 0 {
		w.logger.Info("pruned ReversingLabs cache",
			slog.Int("count", count),
			slog.Duration("older_than", w.cacheRetention),
		)
	}
}

func (w *Worker) processJob(ctx context.Context, job *db.RefreshJob) (bool, error) {
	due, err := w.store.ListDuePackageReputations(ctx, job.Ecosystem, job.Name, FeedName, w.batchSize)
	if err != nil {
		return false, err
	}
	if len(due) == 0 {
		return false, nil
	}

	var mappable []db.PackageReputation
	for i := range due {
		rep := due[i]
		if packagefilter.ExcludedByNamespace(w.excluded, rep.Ecosystem, rep.Name) {
			now := time.Now().UTC()
			rep.Status = "unsupported"
			rep.Severity = "CRITICAL"
			rep.Summary = "ReversingLabs: package excluded by private namespace policy"
			rep.LastCheckedAt = &now
			rep.NextCheckAt = nil
			rep.LastError = ""
			if err := w.store.UpsertPackageReputation(ctx, &rep); err != nil {
				return false, err
			}
			continue
		}
		if _, ok := BuildPURL(rep.Ecosystem, rep.Name, rep.Version); !ok {
			now := time.Now().UTC()
			rep.Status = "unsupported"
			rep.Severity = "CRITICAL"
			rep.Summary = "ReversingLabs: package ecosystem or version is unsupported"
			rep.LastCheckedAt = &now
			rep.NextCheckAt = nil
			rep.LastError = ""
			if err := w.store.UpsertPackageReputation(ctx, &rep); err != nil {
				return false, err
			}
			continue
		}
		mappable = append(mappable, rep)
	}
	if len(mappable) == 0 {
		return false, nil
	}

	results, lookupErr := w.lookupBatch(ctx, mappable)
	if lookupErr != nil {
		if errors.Is(lookupErr, errRateLimited) {
			return true, lookupErr
		}
		results = w.errorResults(mappable, lookupErr)
	}
	for i := range results {
		if err := w.store.UpsertPackageReputation(ctx, &results[i]); err != nil {
			return true, err
		}
	}
	return true, lookupErr
}

type findPackageRequest struct {
	UUID string `json:"uuid"`
	PURL string `json:"purl"`
}

type searchResponse struct {
	Community struct {
		Packages []searchPackage      `json:"packages"`
		Errors   []searchPackageError `json:"errors"`
	} `json:"community"`
}

type searchPackage struct {
	UUID    string            `json:"uuid"`
	Package searchPackageData `json:"package"`
}

type searchPackageError struct {
	UUID  string `json:"uuid"`
	Error struct {
		Code int    `json:"code"`
		Info string `json:"info"`
	} `json:"error"`
}

type searchPackageData struct {
	AllMalicious    bool                        `json:"all_malicious"`
	WasRemoved      bool                        `json:"was_removed"`
	Identity        searchIdentity              `json:"identity"`
	Assessments     searchAssessments           `json:"assessments"`
	Classifications []searchClassification      `json:"classifications"`
	Dependencies    map[string]searchDependency `json:"dependencies"`
	Incidents       searchIncidents             `json:"incidents"`
}

type searchIdentity struct {
	PURL       string `json:"purl"`
	Removed    bool   `json:"removed"`
	Homepage   string `json:"homepage"`
	Repository string `json:"repository"`
}

type searchAssessments struct {
	Malware struct {
		Status string `json:"status"`
	} `json:"malware"`
}

type searchClassification struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

type searchDependency struct {
	Classification struct {
		Status string `json:"status"`
		Result string `json:"result"`
	} `json:"classification"`
}

type searchIncident struct {
	Type  string `json:"type"`
	Count int    `json:"-"`
}

type searchIncidents map[string]searchIncident

func (i *searchIncidents) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '{' {
		var incidents map[string]searchIncident
		if err := json.Unmarshal(data, &incidents); err != nil {
			return err
		}
		*i = incidents
		return nil
	}
	if data[0] == '-' || (data[0] >= '0' && data[0] <= '9') {
		var count float64
		if err := json.Unmarshal(data, &count); err != nil {
			return err
		}
		*i = nil
		return nil
	}
	return errInvalidReversingLabsResponseShape
}

func (i *searchIncident) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '{' {
		var obj struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		i.Type = obj.Type
		return nil
	}
	if data[0] == '"' {
		var typ string
		if err := json.Unmarshal(data, &typ); err != nil {
			return err
		}
		i.Type = typ
		return nil
	}
	var count int
	if err := json.Unmarshal(data, &count); err != nil {
		return err
	}
	i.Count = count
	return nil
}

func (w *Worker) lookupBatch(ctx context.Context, reps []db.PackageReputation) ([]db.PackageReputation, error) {
	if len(reps) == 0 {
		return nil, nil
	}
	if len(reps) > w.batchSize {
		return w.lookupBatchChunks(ctx, reps)
	}

	requests, byUUID := buildLookupRequests(reps)
	if len(requests) == 0 {
		return nil, nil
	}

	statusCode, body, err := w.postLookupRequest(ctx, requests)
	if err != nil {
		return nil, err
	}
	if statusCode == http.StatusRequestEntityTooLarge {
		return w.lookupBatch413Fallback(ctx, reps)
	}
	if err := reversingLabsLookupStatusError(statusCode); err != nil {
		if errors.Is(err, errRateLimited) {
			w.RateLimiter.Drain()
		}
		return nil, err
	}

	return w.mapLookupResponse(body, reps, byUUID)
}

func (w *Worker) lookupBatchChunks(ctx context.Context, reps []db.PackageReputation) ([]db.PackageReputation, error) {
	results := make([]db.PackageReputation, 0, len(reps))
	for start := 0; start < len(reps); start += w.batchSize {
		end := start + w.batchSize
		if end > len(reps) {
			end = len(reps)
		}
		chunk, err := w.lookupBatch(ctx, reps[start:end])
		if err != nil {
			return nil, err
		}
		results = append(results, chunk...)
	}
	return results, nil
}

func buildLookupRequests(reps []db.PackageReputation) ([]findPackageRequest, map[string]db.PackageReputation) {
	requests := make([]findPackageRequest, 0, len(reps))
	byUUID := make(map[string]db.PackageReputation, len(reps))
	for _, rep := range reps {
		purl, ok := BuildPURL(rep.Ecosystem, rep.Name, rep.Version)
		if !ok {
			continue
		}
		uuid := reputationUUID(rep)
		requests = append(requests, findPackageRequest{UUID: uuid, PURL: purl})
		byUUID[uuid] = rep
	}
	return requests, byUUID
}

func (w *Worker) postLookupRequest(ctx context.Context, requests []findPackageRequest) (int, []byte, error) {
	payload, err := json.Marshal(requests)
	if err != nil {
		return 0, nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(w.baseURL, "/")+"/find/packages?compact=true", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("create request: %s", feedqueue.SafeDiagnosticError(err))
	}
	req.Header.Set("Authorization", "Bearer "+w.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", feedqueue.FeedSyncUserAgent)

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("http post: %s", feedqueue.SafeDiagnosticError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return 0, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, body, nil
}

func reversingLabsLookupStatusError(statusCode int) error {
	switch statusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("authentication failed (status %d): check PACKMON_REVERSINGLABS_API_KEY", statusCode)
	case http.StatusPaymentRequired:
		return fmt.Errorf("ReversingLabs capacity limit reached (402)")
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w by ReversingLabs (429)", errRateLimited)
	default:
		return fmt.Errorf("unexpected ReversingLabs status %d", statusCode)
	}
}

func (w *Worker) lookupBatch413Fallback(ctx context.Context, reps []db.PackageReputation) ([]db.PackageReputation, error) {
	if len(reps) <= 1 {
		return nil, fmt.Errorf("ReversingLabs request too large (413)")
	}
	results := make([]db.PackageReputation, 0, len(reps))
	for _, rep := range reps {
		if _, ok := BuildPURL(rep.Ecosystem, rep.Name, rep.Version); !ok {
			continue
		}
		if !w.RateLimiter.Acquire() {
			return nil, fmt.Errorf("%w by ReversingLabs local 413 fallback budget", errRateLimited)
		}
		one, oneErr := w.lookupBatch(ctx, []db.PackageReputation{rep})
		if oneErr != nil {
			return nil, oneErr
		}
		results = append(results, one...)
	}
	return results, nil
}

func (w *Worker) mapLookupResponse(body []byte, reps []db.PackageReputation, byUUID map[string]db.PackageReputation) ([]db.PackageReputation, error) {
	var decoded searchResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		if errors.Is(err, errInvalidReversingLabsResponseShape) {
			return nil, fmt.Errorf("parse response: %w", errInvalidReversingLabsResponseShape)
		}
		return nil, fmt.Errorf("parse response: %w", err)
	}

	now := time.Now().UTC()
	resultsByUUID := make(map[string]db.PackageReputation, len(reps))
	for _, pkg := range decoded.Community.Packages {
		rep, ok := byUUID[pkg.UUID]
		if !ok {
			continue
		}
		resultsByUUID[pkg.UUID] = w.resultFromPackage(rep, pkg.Package, now)
	}
	for _, pkgErr := range decoded.Community.Errors {
		rep, ok := byUUID[pkgErr.UUID]
		if !ok {
			continue
		}
		if pkgErr.Error.Code == http.StatusNotFound {
			resultsByUUID[pkgErr.UUID] = w.statusResult(rep, "not_found", "ReversingLabs: package version was not found", nil, now)
			continue
		}
		resultsByUUID[pkgErr.UUID] = w.errorResult(rep, fmt.Errorf("package lookup error %d: %s", pkgErr.Error.Code, pkgErr.Error.Info), now)
	}

	results := make([]db.PackageReputation, 0, len(reps))
	for _, rep := range reps {
		uuid := reputationUUID(rep)
		if result, ok := resultsByUUID[uuid]; ok {
			results = append(results, result)
			continue
		}
		results = append(results, w.statusResult(rep, "not_found", "ReversingLabs: package version was not found", nil, now))
	}
	return results, nil
}

func (w *Worker) resultFromPackage(rep db.PackageReputation, pkg searchPackageData, now time.Time) db.PackageReputation {
	if signals := maliciousSignals(pkg); len(signals) > 0 {
		return w.statusResult(rep, "malicious", "ReversingLabs: malware detected", signals, now)
	}
	if signals := removedSignals(pkg); len(signals) > 0 {
		return w.statusResult(rep, "removed", "ReversingLabs: package version was removed", signals, now)
	}
	// ReversingLabs incidents are historical context, not active package state.
	return w.statusResult(rep, "clean", "ReversingLabs: no malicious signals", nil, now)
}

func (w *Worker) statusResult(rep db.PackageReputation, status, summary string, signals []string, now time.Time) db.PackageReputation {
	purl, _ := BuildPURL(rep.Ecosystem, rep.Name, rep.Version)
	next := now.Add(w.lookupTTL)
	rep.Status = status
	rep.Severity = "CRITICAL"
	if status == "risk" {
		rep.Severity = "HIGH"
	}
	rep.Summary = summary
	rep.Description = ""
	rep.LastCheckedAt = &now
	rep.NextCheckAt = &next
	rep.LastError = ""
	rep.ReferenceURLs = []byte("[]")
	rep.Evidence = marshalEvidence(purl, status, signals)
	return rep
}

func (w *Worker) errorResults(reps []db.PackageReputation, err error) []db.PackageReputation {
	now := time.Now().UTC()
	results := make([]db.PackageReputation, 0, len(reps))
	for _, rep := range reps {
		results = append(results, w.errorResult(rep, err, now))
	}
	return results
}

func (w *Worker) errorResult(rep db.PackageReputation, err error, now time.Time) db.PackageReputation {
	next := now.Add(time.Hour)
	if !isDefinitiveStatus(rep.Status) {
		rep.Status = "error"
		rep.Severity = "CRITICAL"
		rep.Summary = "ReversingLabs: lookup failed"
	}
	rep.LastCheckedAt = &now
	rep.NextCheckAt = &next
	rep.LastError = feedqueue.SafeDiagnosticError(err)
	return rep
}

func isDefinitiveStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "malicious", "removed", "risk", "clean", "not_found":
		return true
	default:
		return false
	}
}

func maliciousSignals(pkg searchPackageData) []string {
	var signals []string
	if pkg.AllMalicious {
		signals = append(signals, "package.all_malicious")
	}
	if strings.EqualFold(pkg.Assessments.Malware.Status, "fail") {
		signals = append(signals, "assessments.malware.status")
	}
	for _, classification := range pkg.Classifications {
		if strings.EqualFold(classification.Status, "Malicious") {
			signals = append(signals, "classifications.status")
			break
		}
	}
	for _, dep := range pkg.Dependencies {
		if strings.EqualFold(dep.Classification.Status, "Malicious") {
			signals = append(signals, "dependencies.classification.status")
			break
		}
	}
	return signals
}

func removedSignals(pkg searchPackageData) []string {
	var signals []string
	if pkg.Identity.Removed {
		signals = append(signals, "identity.removed")
	}
	if pkg.WasRemoved {
		signals = append(signals, "package.was_removed")
	}
	return signals
}

func marshalEvidence(purl, assessment string, signals []string) json.RawMessage {
	evidence := map[string]any{
		"purl":       purl,
		"signals":    signals,
		"assessment": assessment,
		"checked_by": FeedName,
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

func reputationUUID(rep db.PackageReputation) string {
	return fmt.Sprintf("%s:%s@%s", rep.Ecosystem, rep.Name, rep.Version)
}

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
