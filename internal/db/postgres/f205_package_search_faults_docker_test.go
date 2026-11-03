//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF205PackageSearchFailureContractsAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	t.Run("collector task returns an initialized empty map on success", func(t *testing.T) {
		tasks := store.packageSearchTasks(
			[]packageSearchCollector{packageSearchCollectorMalicious},
			"%f205-no-match%",
			"",
			10,
		)
		if len(tasks) != 1 {
			t.Fatalf("packageSearchTasks() returned %d tasks, want 1", len(tasks))
		}
		got, err := tasks[0].run(ctx)
		if err != nil {
			t.Fatalf("task.run() error = %v", err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("task.run() results = %#v, want an initialized empty map", got)
		}
	})

	t.Run("every collector task returns no partial map after query failure", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()

		tasks := store.packageSearchTasks(
			packageSearchCollectorPlan(""),
			"%pkg%",
			"HIGH",
			10,
		)
		if len(tasks) != 6 {
			t.Fatalf("packageSearchTasks() returned %d tasks, want all 6", len(tasks))
		}
		for i, task := range tasks {
			got, err := task.run(canceled)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("tasks[%d] (%s) error = %v, want context cancellation", i, task.collector, err)
			}
			if got != nil {
				t.Fatalf("tasks[%d] (%s) results = %#v, want nil after collector failure", i, task.collector, got)
			}
		}
	})

	t.Run("SearchPackages returns nil after collector failure", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()

		got, err := store.SearchPackages(canceled, db.PackageSearchParams{
			Query:       "pkg",
			FindingType: "vulnerability",
			Limit:       10,
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("SearchPackages() error = %v, want context cancellation", err)
		}
		if got != nil {
			t.Fatalf("SearchPackages() results = %#v, want nil after collector failure", got)
		}
	})

	t.Run("query error is wrapped", func(t *testing.T) {
		got := make(map[string]*db.PackageSearchResult)
		err := store.collectSearchResults(ctx, got, `SELECT * FROM f205_missing_relation`)
		if err == nil || !strings.Contains(err.Error(), "postgres: search packages:") {
			t.Fatalf("collectSearchResults() error = %v, want query wrapper", err)
		}
		if len(got) != 0 {
			t.Fatalf("collectSearchResults() accumulated %#v after query failure", got)
		}
	})

	t.Run("scan error is wrapped and leaves accumulator unchanged", func(t *testing.T) {
		got := make(map[string]*db.PackageSearchResult)
		err := store.collectSearchResults(ctx, got, `
			SELECT
				'npm'::text,
				'bad-count'::text,
				''::text,
				'not-an-integer'::text,
				0::int,
				''::text,
				'osv'::text,
				'vulnerability'::text`)
		if err == nil || !strings.Contains(err.Error(), "postgres: scan package search row:") {
			t.Fatalf("collectSearchResults() error = %v, want scan wrapper", err)
		}
		if len(got) != 0 {
			t.Fatalf("collectSearchResults() accumulated %#v after scan failure", got)
		}
	})

	t.Run("duplicate rows merge into existing accumulator entry", func(t *testing.T) {
		got := map[string]*db.PackageSearchResult{
			"npm\x00pkg\x001.0.0": {
				Ecosystem:     "npm",
				Name:          "pkg",
				Version:       "1.0.0",
				FindingsCount: 1,
				Sources:       "manual",
				FindingTypes:  "malicious",
			},
		}
		err := store.collectSearchResults(ctx, got, `
			SELECT *
			FROM (VALUES
				('npm'::text, 'pkg'::text, '1.0.0'::text, 2::int, 1::int, 'CVE-2026-0002'::text, 'osv'::text, 'vulnerability'::text),
				('npm'::text, 'pkg'::text, '1.0.0'::text, 3::int, 1::int, 'CVE-2026-0001'::text, 'ghsa'::text, 'vulnerability'::text)
			) AS rows(ecosystem, name, version, findings_count, vulnerability_count, vulnerability_ids, sources, finding_types)`)
		if err != nil {
			t.Fatalf("collectSearchResults() error = %v", err)
		}
		result := got["npm\x00pkg\x001.0.0"]
		if result.FindingsCount != 6 || result.VulnerabilityCount != 2 {
			t.Fatalf("merged counts = (%d, %d), want (6, 2)", result.FindingsCount, result.VulnerabilityCount)
		}
		if result.VulnerabilityIDs != "CVE-2026-0001, CVE-2026-0002" ||
			result.Sources != "ghsa, manual, osv" ||
			result.FindingTypes != "malicious, vulnerability" {
			t.Fatalf("merged details = (%q, %q, %q), want sorted unions",
				result.VulnerabilityIDs, result.Sources, result.FindingTypes)
		}
	})

	t.Run("iteration error is wrapped after rows are opened", func(t *testing.T) {
		got := make(map[string]*db.PackageSearchResult)
		err := store.collectSearchResults(ctx, got, `
			SELECT
				'npm'::text,
				('iteration-' || i)::text,
				''::text,
				(10 / (2 - i))::int,
				0::int,
				''::text,
				'osv'::text,
				'vulnerability'::text
			FROM generate_series(1, 2) AS i`)
		if err == nil || !strings.Contains(err.Error(), "postgres: iterate package search rows:") {
			t.Fatalf("collectSearchResults() error = %v, want iteration wrapper", err)
		}
		if first := got["npm\x00iteration-1\x00"]; first == nil || first.FindingsCount != 10 {
			t.Fatalf("rows accumulated before iteration error = %#v, want first row retained", got)
		}
	})
}
