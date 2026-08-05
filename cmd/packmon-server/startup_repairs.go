package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type caseInsensitivePackageNameRepairer interface {
	RepairCaseInsensitivePackageNames(ctx context.Context) (int, error)
}

type auditedCaseInsensitivePackageNameRepairer interface {
	RepairCaseInsensitivePackageNamesWithAudit(ctx context.Context, audit *db.AdminAuditEntry) (int, error)
}

var startupRepairTimeout = 30 * time.Second

func (b *backgroundServices) startStartupRepairs(store any) {
	b.startBackgroundTask("startup repairs", func(ctx context.Context) error {
		runStartupRepairs(ctx, store, b.logger)
		return nil
	})
}

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

	if repairer, ok := store.(auditedCaseInsensitivePackageNameRepairer); ok {
		runPackageNameStartupRepair(ctx, timeout, logger, func(repairCtx context.Context) (int, error) {
			return repairer.RepairCaseInsensitivePackageNamesWithAudit(repairCtx, startupPackageNameRepairAuditEntry())
		})
		return
	}
	if repairer, ok := store.(caseInsensitivePackageNameRepairer); ok {
		runPackageNameStartupRepair(ctx, timeout, logger, repairer.RepairCaseInsensitivePackageNames)
	}
}

func runPackageNameStartupRepair(ctx context.Context, timeout time.Duration, logger *slog.Logger, repair func(context.Context) (int, error)) {
	repairCtx, cancel := context.WithTimeout(ctx, timeout)
	repaired, err := repair(repairCtx)
	cancel()
	if err != nil {
		if logger != nil {
			logger.Warn("startup repair: failed to normalize package names",
				slog.String("error", err.Error()),
			)
		}
	} else if logger != nil {
		logger.Info("startup repair: normalized package names",
			slog.Int("repaired", repaired),
		)
	}
}

func startupPackageNameRepairAuditEntry() *db.AdminAuditEntry {
	return &db.AdminAuditEntry{
		Action:  "startup_package_name_repair",
		Details: json.RawMessage(`{"repair":"case_insensitive_package_names"}`),
	}
}
