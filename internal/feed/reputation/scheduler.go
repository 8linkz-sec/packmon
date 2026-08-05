// Package reputation schedules demand-driven package reputation cache refreshes.
//
// The scheduler API is intentionally persistence-only: it translates packages
// observed during a check request into package_reputation_cache rows and refresh
// queue jobs for workers such as ReversingLabs. It never performs upstream HTTP
// requests itself.
package reputation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed/packagefilter"
	"github.com/8linkz-sec/packmon/internal/feed/reputationpurl"
)

const (
	// DefaultReversingLabsMaxSchedulePerCheck caps the ReversingLabs work a
	// single check request can newly queue when no explicit limit is configured.
	DefaultReversingLabsMaxSchedulePerCheck = 100

	reversingLabsScheduleWorkers = 4
	reversingLabsScheduleTimeout = 30 * time.Second
	reversingLabsPanicValueMax   = 256
	reversingLabsStoreAttempts   = 3
	reversingLabsStoreRetryDelay = 10 * time.Millisecond
)

// Store is the scheduler persistence boundary.
//
// Store side effects: implementations may mutate package_reputation_cache and
// the refresh queue, but must not perform upstream HTTP requests. Methods are
// called with scheduler-supplied contexts, so implementations should honor
// cancellation and keep duplicate check-request mutations idempotent.
type Store interface {
	// MarkPackageReputationDue records a version-specific reputation row as due.
	//
	// Store side effects: implementations may create or update a
	// package_reputation_cache row for a ReversingLabs lookup. It returns true
	// only when the row is due under the TTL policy and a worker job should be
	// queued; false means the scheduler must suppress queueing because the row is
	// fresh, already terminal, or otherwise not due.
	MarkPackageReputationDue(context.Context, *db.PackageReputation) (bool, error)
	// UpsertPackageReputation persists scheduler-decided rows such as terminal
	// unsupported coordinates.
	//
	// Store side effects: unsupported packages are written as cache rows with no
	// next check time, so due queries exclude them and no worker performs HTTP
	// egress for coordinates the shared PURL predicate cannot map.
	UpsertPackageReputation(context.Context, *db.PackageReputation) error
	// EnqueueRefresh adds the package-wide worker job after scheduler egress
	// filters and per-check budget have been applied.
	//
	// Store side effects: implementations may insert, deduplicate, or reprioritize
	// a pending refresh job. The job is package-wide because the worker refreshes
	// all due versions for that package/source.
	EnqueueRefresh(context.Context, *db.RefreshJob) (bool, int, error)
}

type positionlessRefreshEnqueuer interface {
	EnqueueRefreshNoPosition(context.Context, *db.RefreshJob) (bool, error)
}

// Config controls demand-driven ReversingLabs scheduling from package check
// requests.
//
// Preconditions: callers should set ReversingLabsActive only after config
// validation has accepted self-managed ReversingLabs mode and confirmed that a
// worker API key is configured. The scheduler does not load secrets or validate
// external-mode rejection itself; it trusts the feed configuration layer.
type Config struct {
	// ReversingLabsActive enables scheduling only when ReversingLabs is
	// configured; inactive config prevents cache mutations and queued external
	// lookup work.
	ReversingLabsActive bool
	// ReversingLabsMaxSchedulePerCheck is the per-check budget for ReversingLabs
	// cache or queue work. Non-positive values use
	// DefaultReversingLabsMaxSchedulePerCheck. The budget is charged after
	// coverage suppression and namespace exclusions, before scheduler Store
	// mutations such as unsupported-row upserts, due-row marks, or queue writes.
	ReversingLabsMaxSchedulePerCheck int
	// ReversingLabsExcludedNamespaces lists namespace exclusions applied before a
	// package can be marked due or queued for ReversingLabs external lookup.
	ReversingLabsExcludedNamespaces []string
}

// Scheduler applies the ReversingLabs demand-scheduling egress policy for
// check requests. It does not call ReversingLabs directly; it records cache
// rows and refresh queue jobs for the worker after privacy filters pass.
//
// Preconditions: a non-nil Store is required for useful scheduling, while a nil
// Scheduler or nil Store is treated as a no-op boundary. The Scheduler expects
// callers to provide packages from one check request and the findings already
// collected for that request, so coverage suppression can avoid redundant
// ReversingLabs egress when another feed already covers a coordinate.
type Scheduler struct {
	store  Store
	logger *slog.Logger
	slots  chan struct{}

	mu  sync.RWMutex
	cfg Config
}

// NewScheduler creates a Scheduler and applies cfg.
//
// Preconditions: store should be non-nil for scheduling to have Store side
// effects, and cfg should already reflect validated feed configuration.
// ReversingLabs scheduling remains inactive until cfg carries active
// ReversingLabs configuration. NewScheduler starts no goroutines; async
// goroutine lifetime begins only when ScheduleReversingLabsAsync is called.
func NewScheduler(store Store, logger *slog.Logger, cfg Config) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Scheduler{
		store:  store,
		logger: logger.With("component", "reputation_scheduler"),
		slots:  make(chan struct{}, reversingLabsScheduleWorkers),
	}
	s.Configure(cfg)
	return s
}

// Configure updates Scheduler egress policy.
//
// Preconditions: cfg should come from the validated runtime feed settings.
// Configure is safe to call on a nil receiver, normalizes namespace exclusions,
// fills the default per-check budget, and has no Store side effects. It starts
// no worker job and performs no external lookup.
func (s *Scheduler) Configure(cfg Config) {
	if s == nil {
		return
	}
	if cfg.ReversingLabsMaxSchedulePerCheck <= 0 {
		cfg.ReversingLabsMaxSchedulePerCheck = DefaultReversingLabsMaxSchedulePerCheck
	}
	cfg.ReversingLabsExcludedNamespaces = packagefilter.NormalizeNamespacePrefixes(cfg.ReversingLabsExcludedNamespaces)

	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

// ScheduleReversingLabsAsync evaluates ReversingLabs scheduling for one check
// request in the background when active.
//
// Context expectations: pass a server-root or other request-detached context
// when scheduling should outlive the HTTP request; a canceled context suppresses
// scheduling, and a nil context is treated as context.Background. The method
// copies packages and findings before scheduling so callers can safely reuse
// their slices.
//
// Async goroutine lifetime: each background attempt is bounded by the caller
// context and an internal timeout. If the scheduler is already saturated, this
// method runs the same bounded scheduling path synchronously instead of starting
// another goroutine. In both paths, ScheduleReversingLabs enforces coverage
// suppression, namespace exclusions, unsupported packages, and per-check budget
// policy before any cache or queue mutation can be attempted.
func (s *Scheduler) ScheduleReversingLabsAsync(ctx context.Context, packages []domain.Package, findings []domain.Finding) {
	if s == nil || !s.reversingLabsActive() {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return
	}

	packages = append([]domain.Package(nil), packages...)
	findings = append([]domain.Finding(nil), findings...)

	select {
	case s.slots <- struct{}{}:
	default:
		s.logger.Warn("reversinglabs scheduler saturated; scheduling synchronously", "packages", len(packages))
		s.scheduleReversingLabsWithTimeout(ctx, packages, findings)
		return
	}

	go func() {
		defer func() { <-s.slots }()
		defer s.recoverReversingLabsSchedulePanic(len(packages))
		s.scheduleReversingLabsWithTimeout(ctx, packages, findings)
	}()
}

func (s *Scheduler) recoverReversingLabsSchedulePanic(packageCount int) {
	if recovered := recover(); recovered != nil {
		s.logger.Error("reversinglabs scheduler panic recovered",
			"packages", packageCount,
			"panic", boundedPanicDiagnostic(recovered),
		)
	}
}

func boundedPanicDiagnostic(recovered any) string {
	value := fmt.Sprint(recovered)
	runes := []rune(value)
	if len(runes) <= reversingLabsPanicValueMax {
		return value
	}
	return string(runes[:reversingLabsPanicValueMax]) + "...(truncated)"
}

func (s *Scheduler) scheduleReversingLabsWithTimeout(ctx context.Context, packages []domain.Package, findings []domain.Finding) {
	scheduleCtx, cancel := context.WithTimeout(ctx, reversingLabsScheduleTimeout)
	defer cancel()
	if err := scheduleCtx.Err(); err != nil {
		return
	}

	s.ScheduleReversingLabs(scheduleCtx, packages, findings)
}

// ScheduleReversingLabs applies the demand-driven ReversingLabs egress policy
// for packages observed in one check request.
//
// Preconditions: scheduling requires a non-nil Scheduler, a non-nil Store, and
// active ReversingLabs configuration. A nil context is treated as
// context.Background, but callers should pass a cancellable context tied to the
// intended lifetime of scheduler Store side effects.
//
// Coverage suppression: packages with same-version or package-wide findings
// from non-ReversingLabs sources are skipped, because another feed already
// covers the coordinate for this check request. ReversingLabs findings do not
// suppress scheduling.
//
// Namespace exclusions: configured namespace prefixes are evaluated before any
// due-row mutation or worker queueing, so private packages can be suppressed
// before external lookup.
//
// Unsupported packages: package coordinates that the shared ReversingLabs PURL
// predicate cannot map are written as terminal unsupported cache rows with no
// next check time and no HTTP egress when the per-check budget admits them.
//
// Per-check budget: ReversingLabsMaxSchedulePerCheck caps admitted scheduler
// Store mutations after deduplication, coverage suppression, and namespace
// exclusions. Budget exhaustion skips the remaining candidates before
// unsupported-row upserts, due-row marks, or queue writes, and logs one summary
// warning.
//
// Store side effects: this method may mark version-specific reputation rows due,
// upsert unsupported cache rows, and enqueue package-wide refresh jobs. The
// scheduler itself never calls ReversingLabs or performs other upstream HTTP
// requests.
func (s *Scheduler) ScheduleReversingLabs(ctx context.Context, packages []domain.Package, findings []domain.Finding) {
	if s == nil || s.store == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := s.snapshot()
	if !cfg.ReversingLabsActive {
		return
	}

	covered := nonReversingLabsCoverage(findings)
	seen := make(map[coverageKey]struct{}, len(packages))
	admitted := 0
	skippedBudget := 0

	for _, pkg := range packages {
		key := packageCoverageKey(string(pkg.Ecosystem), pkg.Name, pkg.Version)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if covered[key] || covered[packageCoverageKey(string(pkg.Ecosystem), pkg.Name, "")] {
			continue
		}

		rep := db.PackageReputation{
			Ecosystem: string(pkg.Ecosystem),
			Name:      strings.TrimSpace(pkg.Name),
			Version:   strings.TrimSpace(pkg.Version),
			Source:    db.ReputationSourceReversingLabs,
			Status:    "pending",
			Severity:  "CRITICAL",
		}

		if packagefilter.ExcludedByNamespace(cfg.ReversingLabsExcludedNamespaces, rep.Ecosystem, rep.Name) {
			continue
		}

		if admitted >= cfg.ReversingLabsMaxSchedulePerCheck {
			skippedBudget++
			continue
		}
		admitted++

		if !reputationpurl.SupportsReversingLabsPackage(rep.Ecosystem, rep.Name, rep.Version) {
			rep.Status = "unsupported"
			rep.NextCheckAt = nil
			if err := s.store.UpsertPackageReputation(ctx, &rep); err != nil {
				s.logger.Warn("failed to mark package reputation unsupported",
					"ecosystem", rep.Ecosystem,
					"name", rep.Name,
					"source", rep.Source,
					"error", err,
				)
			}
			continue
		}

		queued, err := s.markPackageReputationDue(ctx, &rep)
		if err != nil {
			s.logger.Warn("failed to mark package reputation due",
				"ecosystem", rep.Ecosystem,
				"name", rep.Name,
				"version", rep.Version,
				"source", rep.Source,
				"attempts", reversingLabsStoreAttempts,
				"error", err,
			)
			continue
		}
		if !queued {
			continue
		}

		job := &db.RefreshJob{
			Ecosystem: rep.Ecosystem,
			Name:      rep.Name,
			Source:    db.ReputationSourceReversingLabs,
			Priority:  db.RefreshPriorityUnknownPackage,
			Status:    "pending",
		}
		if err := s.enqueueRefresh(ctx, job); err != nil {
			s.logger.Warn("failed to enqueue package reputation refresh",
				"ecosystem", rep.Ecosystem,
				"name", rep.Name,
				"version", rep.Version,
				"source", rep.Source,
				"attempts", reversingLabsStoreAttempts,
				"error", err,
			)
		}
	}

	if skippedBudget > 0 {
		s.logger.Warn("reversinglabs scheduling budget exhausted",
			"admitted", admitted,
			"skipped", skippedBudget,
			"budget", cfg.ReversingLabsMaxSchedulePerCheck,
		)
	}
}

func (s *Scheduler) markPackageReputationDue(ctx context.Context, rep *db.PackageReputation) (bool, error) {
	var lastErr error
	for attempt := 1; attempt <= reversingLabsStoreAttempts; attempt++ {
		queued, err := s.store.MarkPackageReputationDue(ctx, rep)
		if err == nil {
			return queued, nil
		}
		lastErr = err
		if !waitBeforeStoreRetry(ctx, attempt) {
			break
		}
	}
	return false, lastErr
}

func (s *Scheduler) enqueueRefresh(ctx context.Context, job *db.RefreshJob) error {
	var lastErr error
	positionless, usePositionless := s.store.(positionlessRefreshEnqueuer)
	for attempt := 1; attempt <= reversingLabsStoreAttempts; attempt++ {
		var err error
		if usePositionless {
			_, err = positionless.EnqueueRefreshNoPosition(ctx, job)
		} else {
			_, _, err = s.store.EnqueueRefresh(ctx, job)
		}
		if err != nil {
			lastErr = err
			if !waitBeforeStoreRetry(ctx, attempt) {
				break
			}
			continue
		}
		return nil
	}
	return lastErr
}

func waitBeforeStoreRetry(ctx context.Context, attempt int) bool {
	if attempt >= reversingLabsStoreAttempts {
		return false
	}
	timer := time.NewTimer(time.Duration(attempt) * reversingLabsStoreRetryDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Scheduler) reversingLabsActive() bool {
	return s.snapshot().ReversingLabsActive
}

func (s *Scheduler) snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.cfg
	cfg.ReversingLabsExcludedNamespaces = append([]string(nil), cfg.ReversingLabsExcludedNamespaces...)
	return cfg
}

type coverageKey struct {
	ecosystem string
	name      string
	version   string
}

func nonReversingLabsCoverage(findings []domain.Finding) map[coverageKey]bool {
	covered := make(map[coverageKey]bool)
	for _, finding := range findings {
		if finding.Source == db.ReputationSourceReversingLabs {
			continue
		}
		covered[packageCoverageKey(string(finding.Ecosystem), finding.Name, finding.Version)] = true
	}
	return covered
}

func packageCoverageKey(ecosystem, name, version string) coverageKey {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	name = strings.TrimSpace(name)
	if ecosystem == "nuget" {
		name = strings.ToLower(name)
	}
	return coverageKey{
		ecosystem: ecosystem,
		name:      name,
		version:   strings.TrimSpace(version),
	}
}
