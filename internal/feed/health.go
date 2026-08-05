package feed

import (
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// DefaultHealthStaleAfter is the shared stale-data window used by API, web,
// admin, and startup freshness checks.
const DefaultHealthStaleAfter = 48 * time.Hour

// HealthOptions controls time-sensitive feed health decisions. A zero Now uses
// the current UTC time, and a zero StaleAfter uses DefaultHealthStaleAfter.
type HealthOptions struct {
	Now        time.Time
	StaleAfter time.Duration
}

// HealthAssessment is the normalized health result for one feed.
type HealthAssessment struct {
	Status string
	Reason string
}

// RuntimeHealthConfig is the subset of runtime configuration needed to assess
// feeds that may not have written a feed_sync_status row yet.
type RuntimeHealthConfig struct {
	Enabled              bool
	Mode                 FeedMode
	RequiresAPIKey       bool
	APIKey               string
	SupportsSyncInterval bool
}

// FeedStatusHealth derives a normalized health assessment from a persisted
// feed_sync_status row.
func FeedStatusHealth(s db.FeedSyncStatus, opts HealthOptions) HealthAssessment {
	now, staleAfter := normalizedHealthOptions(opts)

	status := strings.ToLower(strings.TrimSpace(s.LastSyncStatus))
	switch status {
	case db.FeedSyncStatusError:
		return HealthAssessment{Status: "error", Reason: "last sync failed"}
	case db.FeedSyncStatusPermanentError:
		return HealthAssessment{Status: "error", Reason: "permanent feed error"}
	case db.FeedSyncStatusDisabled:
		return HealthAssessment{Status: "disabled", Reason: "feed disabled"}
	case db.FeedSyncStatusExternal:
		return HealthAssessment{Status: "configured", Reason: "external feed managed outside Packmon"}
	case db.FeedSyncStatusRunning:
		return HealthAssessment{Status: "pending", Reason: "sync running"}
	case db.FeedSyncStatusPending:
		return HealthAssessment{Status: "pending", Reason: "sync pending"}
	case db.FeedSyncStatusSkipped:
		return HealthAssessment{Status: "warning", Reason: "last sync skipped"}
	case db.FeedSyncStatusRejected:
		return HealthAssessment{Status: "error", Reason: "feed import rejected"}
	case "", db.FeedSyncStatusSuccess:
	default:
		return HealthAssessment{Status: "error", Reason: "unknown feed status: " + status}
	}

	if s.LastSyncAt == nil {
		return HealthAssessment{Status: "error", Reason: "never synced"}
	}
	lastSyncAt := s.LastSyncAt.UTC()
	if lastSyncAt.After(now) {
		return HealthAssessment{Status: "warning", Reason: "last sync timestamp is in the future"}
	}
	if now.Sub(lastSyncAt) > staleAfter {
		return HealthAssessment{Status: "warning", Reason: "stale: no sync in 48h+"}
	}
	if s.EntriesTotal == 0 && s.EntriesSynced == 0 {
		return HealthAssessment{Status: "warning", Reason: "no entries synced yet"}
	}
	return HealthAssessment{Status: "healthy"}
}

// RuntimeFeedHealth assesses a feed using runtime configuration first, then
// any persisted status row when present.
func RuntimeFeedHealth(cfg RuntimeHealthConfig, status *db.FeedSyncStatus, opts HealthOptions) HealthAssessment {
	if !cfg.Enabled {
		return HealthAssessment{Status: "disabled", Reason: "feed disabled"}
	}
	if status != nil {
		return FeedStatusHealth(*status, opts)
	}
	if cfg.Mode == FeedModeExternal {
		return HealthAssessment{Status: "configured", Reason: "external feed managed outside Packmon"}
	}
	if cfg.RequiresAPIKey && strings.TrimSpace(cfg.APIKey) == "" {
		return HealthAssessment{Status: "warning", Reason: "required API key not configured"}
	}
	if !cfg.SupportsSyncInterval {
		return HealthAssessment{Status: "configured", Reason: "feed configured"}
	}
	return HealthAssessment{Status: "pending", Reason: "never synced"}
}

// OverallFeedStatus returns the aggregate feed status used by check responses
// and /api/v1/feeds/status.
func OverallFeedStatus(statuses []db.FeedSyncStatus, opts HealthOptions) string {
	if len(statuses) == 0 {
		return "degraded"
	}

	active := false
	configuredOnly := false
	for _, status := range statuses {
		health := FeedStatusHealth(status, opts).Status
		if health == "disabled" {
			continue
		}
		if health == "configured" {
			configuredOnly = true
			continue
		}
		active = true
		if health == "pending" && HasFreshFeedEntries(status, opts) {
			continue
		}
		if health != "healthy" {
			return "degraded"
		}
	}
	if !active {
		if configuredOnly {
			return "healthy"
		}
		return "degraded"
	}
	return "healthy"
}

// HasFreshFeedEntries reports whether a status row still represents usable
// cached feed data.
func HasFreshFeedEntries(s db.FeedSyncStatus, opts HealthOptions) bool {
	if s.LastSyncAt == nil {
		return false
	}
	now, staleAfter := normalizedHealthOptions(opts)
	lastSyncAt := s.LastSyncAt.UTC()
	if lastSyncAt.After(now) {
		return false
	}
	if now.Sub(lastSyncAt) > staleAfter {
		return false
	}
	return s.EntriesTotal != 0 || s.EntriesSynced != 0
}

func normalizedHealthOptions(opts HealthOptions) (time.Time, time.Duration) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	staleAfter := opts.StaleAfter
	if staleAfter <= 0 {
		staleAfter = DefaultHealthStaleAfter
	}
	return now, staleAfter
}
