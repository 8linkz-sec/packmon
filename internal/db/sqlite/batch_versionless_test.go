package sqlite

import (
	"context"
	"slices"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestBatchLookupsKeepVersionlessRequestsBesideConcreteVersions guards the
// all-packages batch contract: a versionless request asks for every finding of
// the package, also when the same batch requests a concrete version of it.
func TestBatchLookupsKeepVersionlessRequestsBesideConcreteVersions(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, versions_affected, severity, summary)
		VALUES ('V-EMPTY|npm|lodash', 'V-EMPTY', 'npm', 'lodash', '["1.0.0"]', 'HIGH', 'only 1.0.0');
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES ('M-EMPTY', 'npm', 'evil', '["1.0.0"]', 'malware', 'CRITICAL', 'only 1.0.0')`); err != nil {
		t.Fatalf("insert rows: %v", err)
	}

	lookups := []struct {
		name string
		pkg  string
		find func(context.Context, []db.PackageQuery) ([]domain.Finding, error)
	}{
		{name: "vulnerabilities", pkg: "lodash", find: store.FindVulnerabilitiesBatch},
		{name: "malicious", pkg: "evil", find: store.FindMaliciousBatch},
	}
	for _, lookup := range lookups {
		alone, err := lookup.find(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: lookup.pkg}})
		if err != nil {
			t.Fatalf("%s versionless batch error = %v", lookup.name, err)
		}
		if len(alone) != 1 || alone[0].Version != "" {
			t.Fatalf("%s versionless batch = %+v, want one versionless finding", lookup.name, alone)
		}

		for _, batch := range [][]db.PackageQuery{
			{{Ecosystem: "npm", Name: lookup.pkg}, {Ecosystem: "npm", Name: lookup.pkg, Version: "2.0.0"}},
			{{Ecosystem: "npm", Name: lookup.pkg, Version: "2.0.0"}, {Ecosystem: "npm", Name: lookup.pkg}, {Ecosystem: "npm", Name: lookup.pkg}},
		} {
			mixed, err := lookup.find(ctx, batch)
			if err != nil {
				t.Fatalf("%s mixed batch error = %v", lookup.name, err)
			}
			if !slices.EqualFunc(mixed, alone, func(a, b domain.Finding) bool {
				return a.AdvisoryID == b.AdvisoryID && a.Version == b.Version
			}) {
				t.Fatalf("%s mixed batch %+v = %+v, want the versionless result %+v", lookup.name, batch, mixed, alone)
			}
		}
	}
}

func TestLocalPackagePredicateChunksKeepVersionlessRequestsInOrder(t *testing.T) {
	t.Parallel()

	chunks := localPackagePredicateChunks([]db.PackageQuery{
		{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "left-pad"},
		{Ecosystem: "npm", Name: "left-pad", Version: " 2.0.0 "},
		{Ecosystem: "npm", Name: "left-pad", Version: " "},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	}, localPackagePredicateChunkSize)
	if len(chunks) != 1 {
		t.Fatalf("localPackagePredicateChunks() returned %d chunks, want 1", len(chunks))
	}
	got := chunks[0].versionsByPackage[localPackageKey{ecosystem: "npm", name: "left-pad"}]
	if want := []string{"2.0.0", "", "1.0.0"}; !slices.Equal(got, want) {
		t.Fatalf("versionsByPackage = %q, want %q", got, want)
	}
}
