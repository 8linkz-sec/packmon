package feed

import (
	"context"
	"errors"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

var errUnsupportedRefreshCompleter = errors.New("refresh store does not support completion")

type refreshCompleter interface {
	CompleteRefresh(context.Context, int, error) error
}

type claimedRefreshCompleter interface {
	CompleteClaimedRefresh(context.Context, int, *time.Time, error) error
}

func CompleteClaimedRefresh(ctx context.Context, store any, job *db.RefreshJob, jobErr error) error {
	if job == nil {
		return nil
	}
	if claimed, ok := store.(claimedRefreshCompleter); ok && job.ProcessedAt != nil {
		return claimed.CompleteClaimedRefresh(ctx, job.ID, job.ProcessedAt, jobErr)
	}
	if legacy, ok := store.(refreshCompleter); ok {
		return legacy.CompleteRefresh(ctx, job.ID, jobErr)
	}
	if claimed, ok := store.(claimedRefreshCompleter); ok {
		return claimed.CompleteClaimedRefresh(ctx, job.ID, job.ProcessedAt, jobErr)
	}
	return errUnsupportedRefreshCompleter
}
