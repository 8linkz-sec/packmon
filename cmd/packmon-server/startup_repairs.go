package main

import (
	"context"
	"log/slog"
)

type ghsaAffectedPackageRepairer interface {
	RepairGHSAAffectedPackages(ctx context.Context) (int, error)
}

type packetStormReferenceCleaner interface {
	RemovePacketStormReferences(ctx context.Context) (int, error)
}

func runStartupRepairs(ctx context.Context, store any, logger *slog.Logger) {
	if repairer, ok := store.(ghsaAffectedPackageRepairer); ok {
		repaired, err := repairer.RepairGHSAAffectedPackages(ctx)
		if err != nil {
			if logger != nil {
				logger.Warn("startup repair: failed to backfill GHSA affected packages",
					slog.String("error", err.Error()),
				)
			}
		} else if repaired > 0 && logger != nil {
			logger.Info("startup repair: backfilled GHSA affected packages",
				slog.Int("repaired", repaired),
			)
		}
	}

	if cleaner, ok := store.(packetStormReferenceCleaner); ok {
		removed, err := cleaner.RemovePacketStormReferences(ctx)
		if err != nil {
			if logger != nil {
				logger.Warn("startup cleanup: failed to remove Packet Storm references",
					slog.String("error", err.Error()),
				)
			}
		} else if removed > 0 && logger != nil {
			logger.Info("startup cleanup: removed Packet Storm references",
				slog.Int("removed", removed),
			)
		}
	}
}
