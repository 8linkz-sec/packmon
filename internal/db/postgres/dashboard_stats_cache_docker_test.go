//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestDashboardStatsCacheInvalidatesOnlyAfterCommittedMutation(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:        "GHSA-dashboard-cache-base",
		Summary:   "cache base",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "cache-base",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}); err != nil {
		t.Fatalf("seed dashboard cache: %v", err)
	}
	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("prime DashboardStats: %v", err)
	}
	if stats.TotalPackages != 1 || stats.TotalVulnerabilities != 1 {
		t.Fatalf("primed stats = %+v, want one vulnerability package", stats)
	}
	generation := dashboardStatsCacheGeneration(store)

	_, _, err = store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{{
		ID:        "GHSA-dashboard-cache-rollback",
		Summary:   "must roll back",
		Severity:  "CRITICAL",
		Published: now,
		Modified:  now,
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "cache-rollback",
			VersionRanges:    json.RawMessage(`[]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}}, nil, &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
		Metadata:       json.RawMessage(`{`),
	})
	if err == nil {
		t.Fatal("ImportVulnerabilityFeed rollback fixture returned nil error")
	}
	if got := dashboardStatsCacheGeneration(store); got != generation {
		t.Fatalf("cache generation after rollback = %d, want %d", got, generation)
	}
	stats, err = store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats after rollback: %v", err)
	}
	if stats.TotalPackages != 1 || stats.TotalVulnerabilities != 1 {
		t.Fatalf("stats after rollback = %+v, want cached committed snapshot", stats)
	}

	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "dbperf-dashboard-cache-malicious",
		Ecosystem:     "npm",
		Name:          "cache-malicious",
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Summary:       "committed mutation",
		ReferenceURLs: json.RawMessage(`[]`),
	}); err != nil {
		t.Fatalf("commit malicious mutation: %v", err)
	}
	if got := dashboardStatsCacheGeneration(store); got != generation+1 {
		t.Fatalf("cache generation after commit = %d, want %d", got, generation+1)
	}
	stats, err = store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats after commit: %v", err)
	}
	if stats.TotalPackages != 2 || stats.TotalMalicious != 1 || stats.BySeverity["CRITICAL"] != 1 {
		t.Fatalf("stats after committed invalidation = %+v", stats)
	}
}

func dashboardStatsCacheGeneration(store *Store) uint64 {
	store.dashboardStatsCache.mu.Lock()
	defer store.dashboardStatsCache.mu.Unlock()
	return store.dashboardStatsCache.generation
}
