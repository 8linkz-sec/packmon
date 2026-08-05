package feed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

var (
	errLegacyRefreshCompletion  = errors.New("legacy refresh completion failed")
	errClaimedRefreshCompletion = errors.New("claimed refresh completion failed")
)

type refreshCompletionCall struct {
	jobID     int
	claimedAt *time.Time
	jobErr    error
}

type refreshCompletionSpy struct {
	legacyCalls  []refreshCompletionCall
	claimedCalls []refreshCompletionCall
	legacyErr    error
	claimedErr   error
}

func (s *refreshCompletionSpy) CompleteRefresh(_ context.Context, jobID int, jobErr error) error {
	s.legacyCalls = append(s.legacyCalls, refreshCompletionCall{
		jobID:  jobID,
		jobErr: jobErr,
	})
	return s.legacyErr
}

func (s *refreshCompletionSpy) CompleteClaimedRefresh(_ context.Context, jobID int, claimedAt *time.Time, jobErr error) error {
	s.claimedCalls = append(s.claimedCalls, refreshCompletionCall{
		jobID:     jobID,
		claimedAt: claimedAt,
		jobErr:    jobErr,
	})
	return s.claimedErr
}

type legacyRefreshCompletionSpy struct {
	calls []refreshCompletionCall
	err   error
}

func (s *legacyRefreshCompletionSpy) CompleteRefresh(_ context.Context, jobID int, jobErr error) error {
	s.calls = append(s.calls, refreshCompletionCall{
		jobID:  jobID,
		jobErr: jobErr,
	})
	return s.err
}

func TestCompleteClaimedRefreshDispatchesByStoreCapabilityAndClaim(t *testing.T) {
	t.Parallel()

	claimedAt := time.Date(2026, 6, 28, 9, 0, 0, 0, time.UTC)
	jobErr := errors.New("lookup failed")

	tests := []struct {
		name        string
		store       any
		job         *db.RefreshJob
		wantLegacy  *refreshCompletionCall
		wantClaimed *refreshCompletionCall
	}{
		{
			name:  "claimed-capable store with claimed job uses claim-aware completion",
			store: &refreshCompletionSpy{},
			job: &db.RefreshJob{
				ID:          456,
				ProcessedAt: &claimedAt,
			},
			wantClaimed: &refreshCompletionCall{
				jobID:     456,
				claimedAt: &claimedAt,
				jobErr:    jobErr,
			},
		},
		{
			name:  "claimed-capable store with unclaimed job falls back to legacy completion",
			store: &refreshCompletionSpy{},
			job: &db.RefreshJob{
				ID: 789,
			},
			wantLegacy: &refreshCompletionCall{
				jobID:  789,
				jobErr: jobErr,
			},
		},
		{
			name:  "legacy store falls back to legacy completion",
			store: &legacyRefreshCompletionSpy{},
			job: &db.RefreshJob{
				ID:          123,
				ProcessedAt: &claimedAt,
			},
			wantLegacy: &refreshCompletionCall{
				jobID:  123,
				jobErr: jobErr,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store, ok := tt.store.(refreshCompleter)
			if !ok {
				t.Fatalf("%T does not implement refreshCompleter", tt.store)
			}

			err := CompleteClaimedRefresh(context.Background(), store, tt.job, jobErr)
			if err != nil {
				t.Fatalf("CompleteClaimedRefresh() error = %v", err)
			}
			assertRefreshCompletionCalls(t, tt.store, tt.wantLegacy, tt.wantClaimed)
		})
	}
}

func TestCompleteClaimedRefreshReturnsCompletionErrors(t *testing.T) {
	t.Parallel()

	claimedAt := time.Date(2026, 6, 28, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		store   any
		job     *db.RefreshJob
		wantErr error
	}{
		{
			name: "claim-aware completion error",
			store: &refreshCompletionSpy{
				claimedErr: errClaimedRefreshCompletion,
			},
			job: &db.RefreshJob{
				ID:          10,
				ProcessedAt: &claimedAt,
			},
			wantErr: errClaimedRefreshCompletion,
		},
		{
			name: "legacy completion error",
			store: &legacyRefreshCompletionSpy{
				err: errLegacyRefreshCompletion,
			},
			job:     &db.RefreshJob{ID: 20},
			wantErr: errLegacyRefreshCompletion,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store, ok := tt.store.(refreshCompleter)
			if !ok {
				t.Fatalf("%T does not implement refreshCompleter", tt.store)
			}

			err := CompleteClaimedRefresh(context.Background(), store, tt.job, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CompleteClaimedRefresh() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func assertRefreshCompletionCalls(t *testing.T, store any, wantLegacy, wantClaimed *refreshCompletionCall) {
	t.Helper()

	switch store := store.(type) {
	case *refreshCompletionSpy:
		assertRefreshCompletionCallList(t, "legacy", store.legacyCalls, wantLegacy)
		assertRefreshCompletionCallList(t, "claimed", store.claimedCalls, wantClaimed)
	case *legacyRefreshCompletionSpy:
		assertRefreshCompletionCallList(t, "legacy", store.calls, wantLegacy)
		if wantClaimed != nil {
			t.Fatalf("claimed calls unavailable on legacy store, want %+v", *wantClaimed)
		}
	default:
		t.Fatalf("unsupported store type %T", store)
	}
}

func assertRefreshCompletionCallList(t *testing.T, label string, got []refreshCompletionCall, want *refreshCompletionCall) {
	t.Helper()

	if want == nil {
		if len(got) != 0 {
			t.Fatalf("%s calls = %+v, want none", label, got)
		}
		return
	}
	if len(got) != 1 {
		t.Fatalf("%s calls = %+v, want one call", label, got)
	}
	if got[0] != *want {
		t.Fatalf("%s call = %+v, want %+v", label, got[0], *want)
	}
}
