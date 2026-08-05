package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

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
