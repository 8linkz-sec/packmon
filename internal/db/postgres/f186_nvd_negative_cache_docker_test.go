//go:build integration

package postgres

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestF186NVDCVSSNegativeCachePersistenceAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	reset := func(t *testing.T) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, `TRUNCATE nvd_cvss_negative_cache, vulnerability_aliases, vulnerabilities CASCADE`); err != nil {
			t.Fatalf("reset NVD negative-cache fixtures: %v", err)
		}
	}
	seed := func(t *testing.T, id, cve string, updatedAt time.Time) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, `INSERT INTO vulnerabilities(id,summary,severity,published,modified,updated_at) VALUES ($1,'f186 negative-cache fixture','LOW',$2,$2,$2)`, id, updatedAt); err != nil {
			t.Fatalf("seed %s/%s: %v", id, cve, err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO vulnerability_aliases(vulnerability_id,alias_id) VALUES ($1,$2)`, id, cve); err != nil {
			t.Fatalf("seed alias %s/%s: %v", id, cve, err)
		}
	}
	isCandidate := func(t *testing.T, cve string) bool {
		t.Helper()
		ids, err := store.FindUnknownSeverityCVEIDs(ctx, "", 100)
		if err != nil {
			t.Fatalf("FindUnknownSeverityCVEIDs: %v", err)
		}
		return slices.Contains(ids, cve)
	}

	t.Run("normalised_persistence_refresh_defaults_and_constraints", func(t *testing.T) {
		reset(t)
		const cve = "CVE-2026-18601"
		updatedAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
		seed(t, "GO-2026-18601", cve, updatedAt)
		if err := store.RecordNVDCVSSNegativeLookup(ctx, "  cve-2026-18601  "); err != nil {
			t.Fatalf("RecordNVDCVSSNegativeLookup(normalised): %v", err)
		}
		var checkedAt, cachedUpdatedAt time.Time
		if err := store.pool.QueryRow(ctx, `SELECT checked_at,vulnerability_updated_at FROM nvd_cvss_negative_cache WHERE cve_id=$1`, cve).Scan(&checkedAt, &cachedUpdatedAt); err != nil {
			t.Fatalf("read persisted negative-cache row: %v", err)
		}
		if checkedAt.IsZero() || !cachedUpdatedAt.Equal(updatedAt) {
			t.Fatalf("persisted timestamps = checked:%v vulnerability:%v, want nonzero/%v", checkedAt, cachedUpdatedAt, updatedAt)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO nvd_cvss_negative_cache(cve_id) VALUES ('CVE-2026-18601-DEFAULTS')`); err != nil {
			t.Fatalf("insert negative-cache row through database defaults: %v", err)
		}
		var defaultCheckedAt, defaultUpdatedAt time.Time
		if err := store.pool.QueryRow(ctx, `SELECT checked_at,vulnerability_updated_at FROM nvd_cvss_negative_cache WHERE cve_id='CVE-2026-18601-DEFAULTS'`).Scan(&defaultCheckedAt, &defaultUpdatedAt); err != nil || defaultCheckedAt.IsZero() || defaultUpdatedAt.IsZero() {
			t.Fatalf("database-default timestamps = checked:%v vulnerability:%v, error=%v", defaultCheckedAt, defaultUpdatedAt, err)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE nvd_cvss_negative_cache SET checked_at='2025-01-01Z' WHERE cve_id=$1`, cve); err != nil {
			t.Fatalf("age persisted row: %v", err)
		}
		if err := store.RecordNVDCVSSNegativeLookup(ctx, cve); err != nil {
			t.Fatalf("RecordNVDCVSSNegativeLookup(refresh): %v", err)
		}
		var refreshed time.Time
		if err := store.pool.QueryRow(ctx, `SELECT checked_at FROM nvd_cvss_negative_cache WHERE cve_id=$1`, cve).Scan(&refreshed); err != nil || !refreshed.After(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("refreshed checked_at = %v, error=%v", refreshed, err)
		}
		if _, err := store.pool.Exec(ctx, `INSERT INTO nvd_cvss_negative_cache(cve_id) VALUES ($1)`, cve); err == nil {
			t.Fatal("duplicate negative-cache primary key was accepted")
		}
		for _, column := range []string{"cve_id", "checked_at", "vulnerability_updated_at"} {
			statement := `INSERT INTO nvd_cvss_negative_cache(cve_id,checked_at,vulnerability_updated_at) VALUES ('CVE-2026-NULL-',NOW(),NOW())`
			switch column {
			case "cve_id":
				statement = `INSERT INTO nvd_cvss_negative_cache(cve_id,checked_at,vulnerability_updated_at) VALUES (NULL,NOW(),NOW())`
			case "checked_at":
				statement = `INSERT INTO nvd_cvss_negative_cache(cve_id,checked_at,vulnerability_updated_at) VALUES ('CVE-2026-NULL-CHECKED',NULL,NOW())`
			case "vulnerability_updated_at":
				statement = `INSERT INTO nvd_cvss_negative_cache(cve_id,checked_at,vulnerability_updated_at) VALUES ('CVE-2026-NULL-UPDATED',NOW(),NULL)`
			}
			if _, err := store.pool.Exec(ctx, statement); err == nil {
				t.Fatalf("NULL %s was accepted", column)
			}
		}
	})

	t.Run("fresh_entries_suppress_and_expired_entries_reappear", func(t *testing.T) {
		reset(t)
		const cve = "CVE-2026-18602"
		seed(t, "GO-2026-18602", cve, time.Now().UTC().Add(-time.Hour))
		if !isCandidate(t, cve) {
			t.Fatalf("%s without a cache entry is not a candidate", cve)
		}
		if err := store.RecordNVDCVSSNegativeLookup(ctx, cve); err != nil {
			t.Fatalf("record fresh negative lookup: %v", err)
		}
		if isCandidate(t, cve) {
			t.Fatalf("%s with a fresh negative lookup is still a candidate", cve)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE nvd_cvss_negative_cache SET checked_at=NOW()-INTERVAL '31 days' WHERE cve_id=$1`, cve); err != nil {
			t.Fatalf("expire negative lookup: %v", err)
		}
		if !isCandidate(t, cve) {
			t.Fatalf("%s with an expired negative lookup did not reappear", cve)
		}
	})

	t.Run("newer_vulnerability_update_invalidates_fresh_entry", func(t *testing.T) {
		reset(t)
		const cve = "CVE-2026-18603"
		seed(t, "GO-2026-18603", cve, time.Now().UTC().Add(-2*time.Hour))
		if err := store.RecordNVDCVSSNegativeLookup(ctx, cve); err != nil {
			t.Fatalf("record negative lookup: %v", err)
		}
		if isCandidate(t, cve) {
			t.Fatalf("%s with a fresh unchanged cache entry is a candidate", cve)
		}
		if _, err := store.pool.Exec(ctx, `UPDATE vulnerabilities SET updated_at=NOW()+INTERVAL '1 minute' WHERE id='GO-2026-18603'`); err != nil {
			t.Fatalf("advance vulnerability update: %v", err)
		}
		if !isCandidate(t, cve) {
			t.Fatalf("%s did not reappear after the vulnerability became newer than its cache entry", cve)
		}
	})
}
