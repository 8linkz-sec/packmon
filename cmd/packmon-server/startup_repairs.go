package main

import (
	"context"
	"log/slog"
	"time"
)

type caseInsensitivePackageNameRepairer interface {
	RepairCaseInsensitivePackageNames(ctx context.Context) (int, error)
}

var startupRepairTimeout = 30 * time.Second

func runStartupRepairs(ctx context.Context, store any, logger *slog.Logger) {
	runStartupRepairsWithTimeout(ctx, store, logger, startupRepairTimeout)
}

func runStartupRepairsWithTimeout(ctx context.Context, store any, logger *slog.Logger, timeout time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = startupRepairTimeout
	}

	if repairer, ok := store.(caseInsensitivePackageNameRepairer); ok {
		repairCtx, cancel := context.WithTimeout(ctx, timeout)
		repaired, err := repairer.RepairCaseInsensitivePackageNames(repairCtx)
		cancel()
		if err != nil {
			if logger != nil {
				logger.Warn("startup repair: failed to normalize package names",
					slog.String("error", err.Error()),
				)
			}
		} else if repaired > 0 && logger != nil {
			logger.Info("startup repair: normalized package names",
				slog.Int("repaired", repaired),
			)
		}
	}
}
