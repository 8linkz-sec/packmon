package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
)

type auditRetentionStore interface {
	PruneScanLogs(ctx context.Context, retention time.Duration) (int, error)
	PruneAdminAuditLogs(ctx context.Context, retention time.Duration) (int, error)
	PruneRefreshQueue(ctx context.Context, retention time.Duration) (int, error)
}

func (b *backgroundServices) startAuditRetentionWorker() {
	if b == nil || b.cfg == nil || b.rootCtx == nil || !auditRetentionEnabled(b.cfg.Retention) {
		return
	}
	if _, ok := b.store.(auditRetentionStore); !ok {
		return
	}

	interval := b.cfg.Retention.Interval
	if interval <= 0 {
		return
	}

	done := make(chan error, 1)
	b.retentionDone = done
	go func() {
		runAuditRetentionOnce(b.rootCtx, b.cfg.Retention, b.store, b.logger)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-b.rootCtx.Done():
				done <- b.rootCtx.Err()
				return
			case <-ticker.C:
				runAuditRetentionOnce(b.rootCtx, b.cfg.Retention, b.store, b.logger)
			}
		}
	}()
}

func auditRetentionEnabled(retention config.RetentionConfig) bool {
	return retention.ScanLog > 0 || retention.AdminAuditLog > 0 || retention.RefreshQueue > 0
}

func runAuditRetentionOnce(ctx context.Context, retention config.RetentionConfig, store any, logger *slog.Logger) {
	pruner, ok := store.(auditRetentionStore)
	if !ok {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if retention.ScanLog > 0 {
		pruned, err := pruner.PruneScanLogs(ctx, retention.ScanLog)
		logAuditRetentionResult(logger, "scan_log", retention.ScanLog, pruned, err)
	}
	if ctx.Err() != nil {
		return
	}
	if retention.AdminAuditLog > 0 {
		pruned, err := pruner.PruneAdminAuditLogs(ctx, retention.AdminAuditLog)
		logAuditRetentionResult(logger, "admin_audit_log", retention.AdminAuditLog, pruned, err)
	}
	if ctx.Err() != nil {
		return
	}
	if retention.RefreshQueue > 0 {
		pruned, err := pruner.PruneRefreshQueue(ctx, retention.RefreshQueue)
		logAuditRetentionResult(logger, "refresh_queue", retention.RefreshQueue, pruned, err)
	}
}

func logAuditRetentionResult(logger *slog.Logger, table string, retention time.Duration, pruned int, err error) {
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn("audit retention prune failed",
			slog.String("table", table),
			slog.String("retention", retention.String()),
			slog.String("error", err.Error()),
		)
		return
	}
	if pruned > 0 {
		logger.Info("audit retention pruned rows",
			slog.String("table", table),
			slog.String("retention", retention.String()),
			slog.Int("rows", pruned),
		)
	}
}
