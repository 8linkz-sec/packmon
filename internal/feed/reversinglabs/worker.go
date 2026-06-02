package reversinglabs

import (
	"bytes"
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
	FeedName = db.ReputationSourceReversingLabs

	DefaultBaseURL = "https://data.reversinglabs.com/api/oss/community/v2/free"

	defaultPollInterval     = 10 * time.Second
	defaultRateLimitPerHour = 300
	defaultLookupTTL        = 24 * time.Hour
	defaultBatchSize        = 5
	maxBatchSize            = 5
	maxResponseSize         = 2 << 20
	stuckThreshold          = 5 * time.Minute
)

type reputationStore interface {
	DequeueRefresh(context.Context, string) (*db.RefreshJob, error)
	CompleteRefresh(context.Context, int, error) error
	ResetStuckJobs(context.Context, string, time.Duration) (int, error)
	ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error)
	UpsertPackageReputation(context.Context, *db.PackageReputation) error
}

type Worker struct {
	store        reputationStore
	logger       *slog.Logger
	httpClient   *http.Client
	baseURL      string
	apiKey       string
	pollInterval time.Duration
	lookupTTL    time.Duration
	batchSize    int

	tokensMu         sync.Mutex
	tokens           int
	maxTokens        int
	lastRefill       time.Time
	fractionalTokens float64
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
		w.maxTokens = callsPerHour
		w.tokens = callsPerHour
	}
}

func NewWorker(store db.Store, apiKey string, logger *slog.Logger, opts ...Option) *Worker {
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
		baseURL:      DefaultBaseURL,
		apiKey:       apiKey,
		pollInterval: defaultPollInterval,
		lookupTTL:    defaultLookupTTL,
		batchSize:    defaultBatchSize,
		tokens:       defaultRateLimitPerHour,
		maxTokens:    defaultRateLimitPerHour,
		lastRefill:   time.Now(),
	}
	for _, opt := range opts {
		opt(w)
	}
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
		slog.Int("rate_limit", w.maxTokens),
		slog.Int("batch_size", w.batchSize),
	)

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	w.resetStuckJobs(ctx)
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("ReversingLabs worker shutting down")
			return ctx.Err()
		case <-ticker.C:
			w.processNextJob(ctx)
		}
	}
}

func (w *Worker) processNextJob(ctx context.Context) {
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
		w.returnToken()
		return
	}

	checkErr := w.processJob(ctx, job)
	if completeErr := w.store.CompleteRefresh(ctx, job.ID, checkErr); completeErr != nil {
		w.logger.Error("failed to complete job",
			slog.Int("job_id", job.ID),
			slog.String("error", completeErr.Error()),
		)
	}
	if checkErr != nil {
		telemetry.Default().IncQueueError(FeedName)
		w.logger.Warn("ReversingLabs check failed",
			slog.String("ecosystem", job.Ecosystem),
			slog.String("name", job.Name),
			slog.String("error", checkErr.Error()),
		)
	}
}

func (w *Worker) processJob(ctx context.Context, job *db.RefreshJob) error {
	due, err := w.store.ListDuePackageReputations(ctx, job.Ecosystem, job.Name, FeedName, w.batchSize)
	if err != nil {
		return err
	}
	if len(due) == 0 {
		return nil
	}

	var mappable []db.PackageReputation
	for i := range due {
		rep := due[i]
		if _, ok := BuildPURL(rep.Ecosystem, rep.Name, rep.Version); !ok {
			now := time.Now().UTC()
			rep.Status = "unsupported"
			rep.Severity = "CRITICAL"
			rep.Summary = "ReversingLabs: package ecosystem or version is unsupported"
			rep.LastCheckedAt = &now
			rep.NextCheckAt = nil
			rep.LastError = ""
			if err := w.store.UpsertPackageReputation(ctx, &rep); err != nil {
				return err
			}
			continue
		}
		mappable = append(mappable, rep)
	}
	if len(mappable) == 0 {
		return nil
	}

	results, lookupErr := w.lookupBatch(ctx, mappable)
	if lookupErr != nil {
		results = w.errorResults(mappable, lookupErr)
	}
	for i := range results {
		if err := w.store.UpsertPackageReputation(ctx, &results[i]); err != nil {
			return err
		}
	}
	return lookupErr
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
	Incidents       map[string]searchIncident   `json:"incidents"`
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
	if len(requests) == 0 {
		return nil, nil
	}

	payload, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(w.baseURL, "/")+"/find/packages?compact=true", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "packmon-feedsync/1.0")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("authentication failed (status %d): check PACKMON_REVERSINGLABS_API_KEY", resp.StatusCode)
	case http.StatusPaymentRequired:
		return nil, fmt.Errorf("ReversingLabs capacity limit reached (402)")
	case http.StatusRequestEntityTooLarge:
		if len(reps) <= 1 {
			return nil, fmt.Errorf("ReversingLabs request too large (413)")
		}
		results := make([]db.PackageReputation, 0, len(reps))
		for _, rep := range reps {
			one, oneErr := w.lookupBatch(ctx, []db.PackageReputation{rep})
			if oneErr != nil {
				return nil, oneErr
			}
			results = append(results, one...)
		}
		return results, nil
	case http.StatusTooManyRequests:
		w.drainTokens()
		return nil, fmt.Errorf("rate limited by ReversingLabs (429)")
	default:
		return nil, fmt.Errorf("unexpected ReversingLabs status %d", resp.StatusCode)
	}

	var decoded searchResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
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
	return w.statusResult(rep, "clean", "ReversingLabs: no malicious signals", nil, now)
}

func (w *Worker) statusResult(rep db.PackageReputation, status, summary string, signals []string, now time.Time) db.PackageReputation {
	purl, _ := BuildPURL(rep.Ecosystem, rep.Name, rep.Version)
	next := now.Add(w.lookupTTL)
	rep.Status = status
	rep.Severity = "CRITICAL"
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
	rep.LastError = err.Error()
	return rep
}

func isDefinitiveStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "malicious", "removed", "clean", "not_found":
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
	for key, incident := range pkg.Incidents {
		if incidentMatches(key, incident, "malware") {
			signals = append(signals, "incidents.type.malware")
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
	for key, incident := range pkg.Incidents {
		if incidentMatches(key, incident, "removal") {
			signals = append(signals, "incidents.type.removal")
			break
		}
	}
	return signals
}

func incidentMatches(key string, incident searchIncident, want string) bool {
	if strings.EqualFold(incident.Type, want) {
		return true
	}
	return incident.Count > 0 && strings.EqualFold(strings.TrimSpace(key), want)
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

func (w *Worker) returnToken() {
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()
	if w.tokens < w.maxTokens {
		w.tokens++
	}
}

func (w *Worker) drainTokens() {
	w.tokensMu.Lock()
	defer w.tokensMu.Unlock()
	w.tokens = 0
	w.lastRefill = time.Now()
}

func (w *Worker) refillTokens() {
	now := time.Now()
	elapsed := now.Sub(w.lastRefill)
	if elapsed <= 0 {
		return
	}

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
