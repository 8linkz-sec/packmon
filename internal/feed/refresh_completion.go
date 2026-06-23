package feed

import (
	"context"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type refreshCompleter interface {
	CompleteRefresh(context.Context, int, error) error
}

type claimedRefreshCompleter interface {
	CompleteClaimedRefresh(context.Context, int, *time.Time, error) error
}

func CompleteClaimedRefresh(ctx context.Context, store refreshCompleter, job *db.RefreshJob, jobErr error) error {
	if job == nil {
		return nil
	}
	if claimed, ok := store.(claimedRefreshCompleter); ok && job.ProcessedAt != nil {
		return claimed.CompleteClaimedRefresh(ctx, job.ID, job.ProcessedAt, jobErr)
	}
	return store.CompleteRefresh(ctx, job.ID, jobErr)
}
