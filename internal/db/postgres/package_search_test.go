package postgres

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestMaliciousPackageSearchQueryUsesFixedParameterizedVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		like         string
		severity     string
		wantQuery    string
		wantArgs     []any
		wantSeverity bool
	}{
		{name: "unfiltered", wantQuery: maliciousPackageSearchUnfilteredSQL, wantArgs: []any{25}},
		{name: "name", like: "%left%", wantQuery: maliciousPackageSearchNameSQL, wantArgs: []any{"%left%", 25}},
		{name: "severity", severity: "CRITICAL", wantQuery: maliciousPackageSearchSeveritySQL, wantArgs: []any{"CRITICAL", 25}, wantSeverity: true},
		{name: "name and severity", like: "%left%", severity: "HIGH", wantQuery: maliciousPackageSearchNameSeveritySQL, wantArgs: []any{"%left%", "HIGH", 25}, wantSeverity: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			query, args := maliciousPackageSearchQuery(tt.like, tt.severity, 25)
			if query != tt.wantQuery || !reflect.DeepEqual(args, tt.wantArgs) {
				t.Fatalf("query selection = (%q, %#v), want (%q, %#v)", query, args, tt.wantQuery, tt.wantArgs)
			}
			if strings.Contains(query, "UPPER(") || strings.Contains(query, "COALESCE(severity") {
				t.Fatalf("query retained functional severity predicate: %s", query)
			}
			if got := strings.Contains(query, "severity = $"); got != tt.wantSeverity {
				t.Fatalf("direct severity predicate present = %v, want %v: %s", got, tt.wantSeverity, query)
			}
		})
	}
}

func TestPackageSearchCollectorPlanExpandsUnfilteredCategories(t *testing.T) {
	t.Parallel()

	got := packageSearchCollectorPlan("")
	want := []packageSearchCollector{
		packageSearchCollectorVulnerability,
		packageSearchCollectorMalicious,
		packageSearchCollectorReputationMalicious,
		packageSearchCollectorReputationSupplyChain,
		packageSearchCollectorLifecycleEOL,
		packageSearchCollectorLifecycleWarning,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packageSearchCollectorPlan(\"\") = %#v, want %#v", got, want)
	}
}

func TestPackageSearchCollectorPlanKeepsSingleCategoryForFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		findingType string
		want        []packageSearchCollector
	}{
		{
			name:        "vulnerability",
			findingType: "vulnerability",
			want:        []packageSearchCollector{packageSearchCollectorVulnerability},
		},
		{
			name:        "malicious",
			findingType: "malicious",
			want: []packageSearchCollector{
				packageSearchCollectorMalicious,
				packageSearchCollectorReputationMalicious,
			},
		},
		{
			name:        "supply chain risk",
			findingType: "supply_chain_risk",
			want: []packageSearchCollector{
				packageSearchCollectorReputationSupplyChain,
				packageSearchCollectorLifecycleEOL,
			},
		},
		{
			name:        "lifecycle",
			findingType: "lifecycle",
			want:        []packageSearchCollector{packageSearchCollectorLifecycleWarning},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := packageSearchCollectorPlan(tt.findingType); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("packageSearchCollectorPlan(%q) = %#v, want %#v", tt.findingType, got, tt.want)
			}
		})
	}
}

func TestRunPackageSearchCollectorsStartsUnfilteredCollectorsConcurrently(t *testing.T) {
	t.Parallel()

	const collectorCount = 6
	started := make(chan packageSearchCollector, collectorCount)
	release := make(chan struct{})

	tasks := make([]packageSearchTask, 0, collectorCount)
	for _, collector := range packageSearchCollectorPlan("") {
		collector := collector
		tasks = append(tasks, packageSearchTask{
			collector: collector,
			run: func(ctx context.Context) (map[string]*db.PackageSearchResult, error) {
				started <- collector
				select {
				case <-release:
					return nil, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		})
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := runPackageSearchCollectors(context.Background(), tasks, true)
		errCh <- err
	}()

	seen := make(map[packageSearchCollector]bool, collectorCount)
	for len(seen) < collectorCount {
		select {
		case collector := <-started:
			seen[collector] = true
		case err := <-errCh:
			t.Fatalf("runPackageSearchCollectors returned before all collectors started: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for collectors to start concurrently; saw %d of %d", len(seen), collectorCount)
		}
	}

	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("runPackageSearchCollectors() error = %v", err)
	}
}

func TestRunPackageSearchCollectorsCancelsRemainingCollectorsOnError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("collector failed")
	enteredBlockingCollector := make(chan struct{})
	errorCollectorStarted := make(chan struct{})

	tasks := []packageSearchTask{
		{
			collector: packageSearchCollectorVulnerability,
			run: func(ctx context.Context) (map[string]*db.PackageSearchResult, error) {
				close(enteredBlockingCollector)
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
		{
			collector: packageSearchCollectorMalicious,
			run: func(context.Context) (map[string]*db.PackageSearchResult, error) {
				<-enteredBlockingCollector
				close(errorCollectorStarted)
				return nil, wantErr
			},
		},
	}

	_, err := runPackageSearchCollectors(context.Background(), tasks, true)
	if !errors.Is(err, wantErr) {
		t.Fatalf("runPackageSearchCollectors() error = %v, want %v", err, wantErr)
	}
	select {
	case <-errorCollectorStarted:
	default:
		t.Fatal("error collector did not start")
	}
}
