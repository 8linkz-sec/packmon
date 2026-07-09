package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/logsafe"
)

type auditRetentionStore interface {
	PruneScanLogs(ctx context.Context, retention time.Duration) (int, error)
	PruneAdminAuditLogs(ctx context.Context, retention time.Duration) (int, error)
	PruneRefreshQueue(ctx context.Context, retention time.Duration) (int, error)
	PrunePackageCheckStatus(ctx context.Context, retention time.Duration) (int, error)
	PruneDeletedAPIKeys(ctx context.Context, retention time.Duration) (int, error)
	PrunePackageReputation(ctx context.Context, source string, retention time.Duration) (int, error)
}

const auditRetentionPruneTimeout = 30 * time.Second

func (b *backgroundServices) startAuditRetentionWorker() {
	if b == nil || b.cfg == nil || b.rootCtx == nil || b.store == nil {
		return
	}
	interval := b.cfg.Retention.Interval
	if interval <= 0 {
		return
	}

	done := make(chan error, 1)
	b.retentionDone = done
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-b.rootCtx.Done():
				done <- b.rootCtx.Err()
				return
			case <-ticker.C:
				runAuditRetentionOnce(b.rootCtx, b.retentionSnapshot(), b.cfg.FeedsSnapshot(), b.store, b.logger)
			}
		}
	}()
}

func (b *backgroundServices) retentionSnapshot() config.RetentionConfig {
	if b == nil || b.cfg == nil {
		return config.RetentionConfig{}
	}
	retention := b.cfg.Retention
	if b.runtime != nil {
		runtimeRetention := b.runtime.Retention()
		retention.ScanLog = runtimeRetention.ScanLog
		retention.AdminAuditLog = runtimeRetention.AdminAuditLog
	}
	return retention
}

func auditRetentionEnabled(retention config.RetentionConfig, feeds config.FeedsConfig) bool {
	return retention.ScanLog > 0 ||
		retention.AdminAuditLog > 0 ||
		retention.RefreshQueue > 0 ||
		retention.PackageCheckStatus > 0 ||
		retention.DeletedAPIKeys > 0 ||
		feeds.ReversingLabsCacheRetention > 0
}

func runAuditRetentionOnce(ctx context.Context, retention config.RetentionConfig, feeds config.FeedsConfig, store auditRetentionStore, logger *slog.Logger) {
	if ctx == nil {
		ctx = context.Background()
	}

	if retention.ScanLog > 0 {
		runAuditRetentionPrune(ctx, logger, "scan_log", retention.ScanLog, func(pruneCtx context.Context) (int, error) {
			return store.PruneScanLogs(pruneCtx, retention.ScanLog)
		})
	}
	if ctx.Err() != nil {
		return
	}
	if retention.AdminAuditLog > 0 {
		runAuditRetentionPrune(ctx, logger, "admin_audit_log", retention.AdminAuditLog, func(pruneCtx context.Context) (int, error) {
			return store.PruneAdminAuditLogs(pruneCtx, retention.AdminAuditLog)
		})
	}
	if ctx.Err() != nil {
		return
	}
	if retention.RefreshQueue > 0 {
		runAuditRetentionPrune(ctx, logger, "refresh_queue", retention.RefreshQueue, func(pruneCtx context.Context) (int, error) {
			return store.PruneRefreshQueue(pruneCtx, retention.RefreshQueue)
		})
	}
	if ctx.Err() != nil {
		return
	}
	if retention.PackageCheckStatus > 0 {
		runAuditRetentionPrune(ctx, logger, "package_check_status", retention.PackageCheckStatus, func(pruneCtx context.Context) (int, error) {
			return store.PrunePackageCheckStatus(pruneCtx, retention.PackageCheckStatus)
		})
	}
	if ctx.Err() != nil {
		return
	}
	if retention.DeletedAPIKeys > 0 {
		runAuditRetentionPrune(ctx, logger, "deleted_api_keys", retention.DeletedAPIKeys, func(pruneCtx context.Context) (int, error) {
			return store.PruneDeletedAPIKeys(pruneCtx, retention.DeletedAPIKeys)
		})
	}
	if ctx.Err() != nil {
		return
	}
	if feeds.ReversingLabsCacheRetention > 0 {
		runAuditRetentionPrune(ctx, logger, "package_reputation_cache", feeds.ReversingLabsCacheRetention, func(pruneCtx context.Context) (int, error) {
			return store.PrunePackageReputation(pruneCtx, db.ReputationSourceReversingLabs, feeds.ReversingLabsCacheRetention)
		})
	}
}

func runAuditRetentionPrune(ctx context.Context, logger *slog.Logger, table string, retention time.Duration, prune func(context.Context) (int, error)) {
	pruneCtx, cancel := context.WithTimeout(ctx, auditRetentionPruneTimeout)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			logAuditRetentionPanic(logger, table, retention, recovered)
		}
	}()

	pruned, err := prune(pruneCtx)
	logAuditRetentionResult(logger, table, retention, pruned, err)
}

func logAuditRetentionPanic(logger *slog.Logger, table string, retention time.Duration, recovered any) {
	if logger == nil {
		return
	}
	logger.Warn("audit retention prune panicked",
		slog.String("table", table),
		slog.Duration("retention", retention),
		slog.String("panic", logsafe.BoundedDiagnosticValue(fmt.Sprint(recovered), 512)),
	)
}

func logAuditRetentionResult(logger *slog.Logger, table string, retention time.Duration, pruned int, err error) {
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn("audit retention prune failed",
			slog.String("table", table),
			slog.Duration("retention", retention),
			slog.String("error", err.Error()),
		)
		return
	}
	if pruned > 0 {
		logger.Info("audit retention pruned rows",
			slog.String("table", table),
			slog.Duration("retention", retention),
			slog.Int("rows", pruned),
		)
	}
}
