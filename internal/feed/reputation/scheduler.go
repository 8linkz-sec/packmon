package reputation

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed/packagefilter"
	reputationpurl "github.com/8linkz-sec/packmon/internal/feed/reputation/purl"
)

const (
	DefaultReversingLabsMaxSchedulePerCheck = 100

	reversingLabsScheduleWorkers = 4
	reversingLabsScheduleTimeout = 30 * time.Second
)

type Store interface {
	MarkPackageReputationDue(context.Context, *db.PackageReputation) (bool, error)
	UpsertPackageReputation(context.Context, *db.PackageReputation) error
	EnqueueRefresh(context.Context, *db.RefreshJob) (bool, int, error)
}

type Config struct {
	ReversingLabsActive              bool
	ReversingLabsMaxSchedulePerCheck int
	ReversingLabsExcludedNamespaces  []string
}

type Scheduler struct {
	store  Store
	logger *slog.Logger
	slots  chan struct{}

	mu  sync.RWMutex
	cfg Config
}

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

func (s *Scheduler) Configure(cfg Config) {
	if s == nil {
		return
	}
	if cfg.ReversingLabsMaxSchedulePerCheck <= 0 {
		cfg.ReversingLabsMaxSchedulePerCheck = DefaultReversingLabsMaxSchedulePerCheck
	}
	cfg.ReversingLabsExcludedNamespaces = normalizeNamespacePrefixes(cfg.ReversingLabsExcludedNamespaces)

	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

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
		s.logger.Warn("reversinglabs scheduling skipped: scheduler saturated", "packages", len(packages))
		return
	}

	go func() {
		defer func() { <-s.slots }()

		scheduleCtx, cancel := context.WithTimeout(ctx, reversingLabsScheduleTimeout)
		defer cancel()
		if err := scheduleCtx.Err(); err != nil {
			return
		}

		s.ScheduleReversingLabs(scheduleCtx, packages, findings)
	}()
}

func (s *Scheduler) ScheduleReversingLabs(ctx context.Context, packages []domain.Package, findings []domain.Finding) {
	if s == nil || s.store == nil {
		return
	}
	cfg := s.snapshot()
	if !cfg.ReversingLabsActive {
		return
	}

	covered := nonReversingLabsCoverage(findings)
	seen := make(map[coverageKey]struct{}, len(packages))
	scheduled := 0
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

		if scheduled >= cfg.ReversingLabsMaxSchedulePerCheck {
			skippedBudget++
			continue
		}

		queued, err := s.store.MarkPackageReputationDue(ctx, &rep)
		if err != nil {
			s.logger.Warn("failed to mark package reputation due",
				"ecosystem", rep.Ecosystem,
				"name", rep.Name,
				"source", rep.Source,
				"error", err,
			)
			continue
		}
		if !queued {
			continue
		}
		scheduled++

		job := &db.RefreshJob{
			Ecosystem: rep.Ecosystem,
			Name:      rep.Name,
			Source:    db.ReputationSourceReversingLabs,
			Priority:  1,
			Status:    "pending",
		}
		if _, _, err := s.store.EnqueueRefresh(ctx, job); err != nil {
			s.logger.Warn("failed to enqueue package reputation refresh",
				"ecosystem", rep.Ecosystem,
				"name", rep.Name,
				"source", rep.Source,
				"error", err,
			)
		}
	}

	if skippedBudget > 0 {
		s.logger.Warn("reversinglabs scheduling budget exhausted",
			"scheduled", scheduled,
			"skipped", skippedBudget,
			"budget", cfg.ReversingLabsMaxSchedulePerCheck,
		)
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

func normalizeNamespacePrefixes(prefixes []string) []string {
	out := make([]string, 0, len(prefixes))
	seen := make(map[string]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix == "" {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out
}
