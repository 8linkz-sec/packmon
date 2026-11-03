package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

type f210ReputationScanner struct {
	scan func(...any) error
}

func (scanner f210ReputationScanner) Scan(dest ...any) error {
	return scanner.scan(dest...)
}

func TestF210ScanPackageReputationSuccessAndFailure(t *testing.T) {
	t.Parallel()

	updated := time.Date(2026, 11, 3, 10, 20, 30, 0, time.UTC)
	lastChecked := updated.Add(-time.Hour)
	rep, err := scanPackageReputation(f210ReputationScanner{scan: func(dest ...any) error {
		*dest[0].(*string) = "pypi"
		*dest[1].(*string) = "f210-package"
		*dest[2].(*string) = "1.2.3"
		*dest[3].(*string) = db.ReputationSourceReversingLabs
		*dest[4].(*string) = reputationStatusRisk
		*dest[5].(*string) = "HIGH"
		*dest[6].(*string) = "history"
		*dest[7].(*string) = "historical evidence"
		*dest[8].(*string) = `["https://example.test/f210"]`
		*dest[9].(*string) = `{"score":210}`
		*dest[10].(**time.Time) = &lastChecked
		*dest[11].(**time.Time) = nil
		*dest[12].(*string) = ""
		*dest[13].(*time.Time) = updated
		return nil
	}})
	if err != nil {
		t.Fatalf("scanPackageReputation() error = %v", err)
	}
	if rep.Ecosystem != "pypi" || rep.Name != "f210-package" || rep.Version != "1.2.3" || rep.Source != db.ReputationSourceReversingLabs || rep.Status != reputationStatusRisk || rep.Severity != "HIGH" || rep.Summary != "history" || rep.Description != "historical evidence" || string(rep.ReferenceURLs) != `["https://example.test/f210"]` || string(rep.Evidence) != `{"score":210}` || rep.LastCheckedAt == nil || !rep.LastCheckedAt.Equal(lastChecked) || rep.NextCheckAt != nil || !rep.UpdatedAt.Equal(updated) {
		t.Fatalf("scanPackageReputation() = %+v, want complete row with nullable next_check_at", rep)
	}

	sentinel := errors.New("f210 scan failure")
	got, err := scanPackageReputation(f210ReputationScanner{scan: func(...any) error { return sentinel }})
	if !errors.Is(err, sentinel) || !reflect.DeepEqual(got, db.PackageReputation{}) {
		t.Fatalf("scanPackageReputation(failure) = %+v, %v; want zero row and sentinel", got, err)
	}
}

func TestF210ReputationInputAndFindingBoundaries(t *testing.T) {
	t.Parallel()

	var store Store
	ctx := context.Background()

	if got, err := store.FindReputationFindingsBatch(ctx, nil, "source"); got != nil || err != nil {
		t.Fatalf("FindReputationFindingsBatch(nil) = %#v, %v; want nil, nil", got, err)
	}
	invalidPackages := []db.PackageQuery{
		{Ecosystem: " ", Name: "pkg", Version: "1"},
		{Ecosystem: "npm", Name: " ", Version: "1"},
		{Ecosystem: "npm", Name: "pkg", Version: " "},
	}
	if got, err := store.FindReputationFindingsBatch(ctx, invalidPackages, "source"); got != nil || err != nil {
		t.Fatalf("FindReputationFindingsBatch(invalid) = %#v, %v; want nil, nil", got, err)
	}
	for _, input := range [][3]string{{"", "pkg", "source"}, {"npm", "", "source"}, {"npm", "pkg", ""}} {
		if got, err := store.FindReputationFindings(ctx, input[0], input[1], input[2]); got != nil || err != nil {
			t.Fatalf("FindReputationFindings(%q, %q, %q) = %#v, %v; want nil, nil", input[0], input[1], input[2], got, err)
		}
	}

	if queued, err := store.MarkPackageReputationDue(ctx, nil); queued || err != nil {
		t.Fatalf("MarkPackageReputationDue(nil) = %v, %v; want false, nil", queued, err)
	}
	for _, rep := range []db.PackageReputation{
		{Ecosystem: "", Name: "pkg", Version: "1", Source: "source"},
		{Ecosystem: "npm", Name: "", Version: "1", Source: "source"},
		{Ecosystem: "npm", Name: "pkg", Version: "", Source: "source"},
		{Ecosystem: "npm", Name: "pkg", Version: "1", Source: ""},
	} {
		if queued, err := store.MarkPackageReputationDue(ctx, &rep); queued || err != nil {
			t.Fatalf("MarkPackageReputationDue(%+v) = %v, %v; want false, nil", rep, queued, err)
		}
	}
	if queued, err := store.MarkPackageReputationDue(ctx, &db.PackageReputation{Ecosystem: "invalid", Name: "pkg", Version: "1", Source: "source"}); queued || err == nil {
		t.Fatalf("MarkPackageReputationDue(invalid ecosystem) = %v, %v; want false and validation error", queued, err)
	}

	if err := store.UpsertPackageReputation(ctx, nil); err != nil {
		t.Fatalf("UpsertPackageReputation(nil) error = %v", err)
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{Ecosystem: "invalid"}); err == nil {
		t.Fatal("UpsertPackageReputation(invalid ecosystem) error = nil")
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{Ecosystem: "npm", Severity: "impossible"}); err == nil {
		t.Fatal("UpsertPackageReputation(invalid severity) error = nil")
	}
	for _, tc := range []struct {
		source string
		age    time.Duration
	}{
		{source: "", age: time.Hour},
		{source: "source", age: 0},
		{source: "source", age: -time.Second},
	} {
		if got, err := store.PrunePackageReputation(ctx, tc.source, tc.age); got != 0 || err != nil {
			t.Fatalf("PrunePackageReputation(%q, %v) = %d, %v; want 0, nil", tc.source, tc.age, got, err)
		}
	}

	finding, ok := reputationToFinding(db.PackageReputation{
		Ecosystem:     "npm",
		Name:          "f210-defaults",
		Version:       "2.1.0",
		Status:        " MALICIOUS ",
		Severity:      "unknown",
		ReferenceURLs: json.RawMessage(`["javascript:alert(1)","https://example.test/f210"]`),
	})
	if !ok {
		t.Fatal("reputationToFinding(defaults) returned !ok")
	}
	if finding.Type != domain.FindingTypeMalicious || finding.Severity != domain.SeverityCritical || finding.RiskType != "malware" || finding.Source != db.ReputationSourceReversingLabs || finding.Title != "ReversingLabs: malware detected" || finding.URL != "https://example.test/f210" || finding.AdvisoryID != "reversinglabs:npm/f210-defaults@2.1.0" {
		t.Fatalf("reputationToFinding(defaults) = %+v", finding)
	}
	if finding, ok := reputationToFinding(db.PackageReputation{Status: " clean "}); ok || !reflect.DeepEqual(finding, domain.Finding{}) {
		t.Fatalf("reputationToFinding(clean) = %+v, %v; want zero finding, false", finding, ok)
	}
}
