package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maliciousMutationLockKey int64 = 0x5041434b4d4f4e01
	openssfSnapshotLockKey   int64 = 0x5041434b4d4f4e02

	maliciousSnapshotTable  = "packmon_openssf_malicious_snapshot"
	maliciousWithdrawnTable = "packmon_openssf_malicious_withdrawn"
)

type maliciousSnapshotHooks struct {
	afterAcquire   func(context.Context, *pgxpool.Conn) error
	beforeFinalize func() error
	commit         func(context.Context, pgx.Tx) error
	cleanup        func(*pgxpool.Conn, bool) error
}

// acquireMaliciousMutationLockTx serializes every runtime mutation of
// malicious_findings. Per-record transaction locks are acquired after it; the
// OpenSSF builder's session lock is the sole outer lock and is acquired first.
func acquireMaliciousMutationLockTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, maliciousMutationLockKey); err != nil {
		return fmt.Errorf("postgres: acquire malicious finding mutation lock: %w", err)
	}
	return nil
}

// acquireMaliciousMutationLocksTx acquires locks in the only supported order:
// the OpenSSF source lock first when the mutation can touch OpenSSF rows, then
// the global malicious_findings mutation lock.
func acquireMaliciousMutationLocksTx(ctx context.Context, tx pgx.Tx, source string, allSources bool) error {
	if allSources || strings.EqualFold(strings.TrimSpace(source), "openssf") {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, openssfSnapshotLockKey); err != nil {
			return fmt.Errorf("postgres: acquire OpenSSF finding source lock: %w", err)
		}
	}
	return acquireMaliciousMutationLockTx(ctx, tx)
}

// ReplaceMaliciousFindingsSnapshot stages a complete source snapshot in
// bounded COPY batches, then atomically applies only effective content changes
// and withdraws active source rows absent from the validated snapshot.
func (s *Store) ReplaceMaliciousFindingsSnapshot(
	ctx context.Context,
	source string,
	stream func(yield func(active []db.MaliciousFinding, withdrawnIDs []string) error) error,
) (changed, withdrawn int, err error) {
	return s.replaceMaliciousFindingsSnapshot(ctx, source, stream, nil)
}

func (s *Store) replaceMaliciousFindingsSnapshot(
	ctx context.Context,
	source string,
	stream func(yield func(active []db.MaliciousFinding, withdrawnIDs []string) error) error,
	hooks *maliciousSnapshotHooks,
) (changed, withdrawn int, err error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return 0, 0, fmt.Errorf("postgres: malicious snapshot source is required")
	}
	if source != "openssf" {
		return 0, 0, fmt.Errorf("postgres: malicious snapshot source %q is unsupported", source)
	}
	if stream == nil {
		return 0, 0, fmt.Errorf("postgres: malicious snapshot stream is not configured")
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: acquire malicious snapshot connection: %w", err)
	}
	lockHeld := false
	committed := false
	defer func() {
		if !committed {
			discardMaliciousSnapshotConnection(conn)
			return
		}
		cleanup := cleanupMaliciousSnapshotConnection
		if hooks != nil && hooks.cleanup != nil {
			cleanup = hooks.cleanup
		}
		cleanupErr := cleanup(conn, lockHeld)
		if cleanupErr != nil {
			// The data transaction is already committed. Discarding the physical
			// connection guarantees that temporary tables and session locks cannot
			// leak into the pool, while preserving the successful snapshot result.
			discardMaliciousSnapshotConnection(conn)
			return
		}
		conn.Release()
	}()
	if hooks != nil && hooks.afterAcquire != nil {
		if err = hooks.afterAcquire(ctx, conn); err != nil {
			return 0, 0, fmt.Errorf("postgres: initialize malicious snapshot connection: %w", err)
		}
	}

	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, openssfSnapshotLockKey); err != nil {
		// A failed session-lock command has an ambiguous server-side outcome.
		// Closing the physical connection is the only safe way to guarantee that
		// no session lock can leak back into the pool.
		return 0, 0, fmt.Errorf("postgres: acquire OpenSSF snapshot lock: %w", err)
	}
	lockHeld = true

	if err = createMaliciousSnapshotTables(ctx, conn); err != nil {
		return 0, 0, err
	}

	stagedActive := 0
	err = stream(func(active []db.MaliciousFinding, withdrawnIDs []string) error {
		stagedActive += len(active)
		return stageMaliciousSnapshotBatch(ctx, conn, source, active, withdrawnIDs)
	})
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: stage malicious snapshot: %w", err)
	}
	if stagedActive == 0 {
		return 0, 0, fmt.Errorf("postgres: malicious snapshot must contain at least one active finding")
	}
	if hooks != nil && hooks.beforeFinalize != nil {
		if err = hooks.beforeFinalize(); err != nil {
			return 0, 0, fmt.Errorf("postgres: finalize malicious snapshot: %w", err)
		}
	}

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: begin malicious snapshot finalize: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if err = acquireMaliciousMutationLocksTx(ctx, tx, source, false); err != nil {
		return 0, 0, err
	}
	if err = validateStagedMaliciousSnapshot(ctx, tx, source); err != nil {
		return 0, 0, err
	}
	changed, err = mergeStagedMaliciousSnapshot(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	explicit, err := withdrawExplicitStagedMaliciousFindings(ctx, tx, source)
	if err != nil {
		return 0, 0, err
	}
	absent, err := withdrawAbsentStagedMaliciousFindings(ctx, tx, source)
	if err != nil {
		return 0, 0, err
	}
	withdrawn = explicit + absent

	commit := func(commitCtx context.Context, commitTx pgx.Tx) error {
		return commitTx.Commit(commitCtx)
	}
	if hooks != nil && hooks.commit != nil {
		commit = hooks.commit
	}
	if err = commit(ctx, tx); err != nil {
		return 0, 0, fmt.Errorf("postgres: commit malicious snapshot: %w", err)
	}
	committed = true
	s.invalidateDashboardStats()
	return changed, withdrawn, nil
}

func createMaliciousSnapshotTables(ctx context.Context, conn *pgxpool.Conn) error {
	const query = `
		DROP TABLE IF EXISTS pg_temp.packmon_openssf_malicious_snapshot;
		DROP TABLE IF EXISTS pg_temp.packmon_openssf_malicious_withdrawn;
		CREATE TEMP TABLE pg_temp.packmon_openssf_malicious_snapshot (
			id text PRIMARY KEY,
			ecosystem text NOT NULL,
			name text NOT NULL,
			version_ranges jsonb,
			versions jsonb,
			source text NOT NULL,
			risk_type text NOT NULL,
			severity text NOT NULL,
			summary text NOT NULL,
			description text,
			reference_urls jsonb NOT NULL,
			origin_ref text,
			published timestamptz,
			created_by text
		) ON COMMIT PRESERVE ROWS;
		CREATE TEMP TABLE pg_temp.packmon_openssf_malicious_withdrawn (
			id text PRIMARY KEY
		) ON COMMIT PRESERVE ROWS`
	if _, err := conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("postgres: create malicious snapshot staging tables: %w", err)
	}
	return nil
}

func stageMaliciousSnapshotBatch(ctx context.Context, conn *pgxpool.Conn, source string, active []db.MaliciousFinding, withdrawnIDs []string) error {
	if len(active)+len(withdrawnIDs) > db.MaliciousSnapshotBatchSize {
		return fmt.Errorf("malicious snapshot batch has %d entries; maximum is %d", len(active)+len(withdrawnIDs), db.MaliciousSnapshotBatchSize)
	}
	if len(active) > 0 {
		rows := make([][]any, 0, len(active))
		for i := range active {
			normalized, err := normalizeMaliciousFinding(&active[i])
			if err != nil {
				return fmt.Errorf("normalize active malicious snapshot entry %d: %w", i, err)
			}
			if normalized.Source != source {
				return fmt.Errorf("malicious snapshot entry %s has source %q; expected %q", normalized.ID, normalized.Source, source)
			}
			rows = append(rows, []any{
				normalized.ID, normalized.Ecosystem, normalized.Name,
				normalized.VersionRanges, normalized.Versions, normalized.Source,
				normalized.RiskType, normalized.Severity, normalized.Summary,
				normalized.Description, normalized.ReferenceURLs, normalized.OriginRef,
				normalized.Published, normalized.CreatedBy,
			})
		}
		copied, err := conn.CopyFrom(
			ctx,
			pgx.Identifier{"pg_temp", maliciousSnapshotTable},
			[]string{"id", "ecosystem", "name", "version_ranges", "versions", "source", "risk_type", "severity", "summary", "description", "reference_urls", "origin_ref", "published", "created_by"},
			pgx.CopyFromRows(rows),
		)
		if err != nil {
			return fmt.Errorf("copy active malicious snapshot batch: %w", err)
		}
		if copied != int64(len(rows)) {
			return fmt.Errorf("copy active malicious snapshot batch: copied %d of %d rows", copied, len(rows))
		}
	}
	if len(withdrawnIDs) > 0 {
		rows := make([][]any, 0, len(withdrawnIDs))
		for _, id := range withdrawnIDs {
			id = strings.TrimSpace(id)
			if id == "" {
				return fmt.Errorf("malicious snapshot withdrawn ID is empty")
			}
			rows = append(rows, []any{id})
		}
		copied, err := conn.CopyFrom(ctx, pgx.Identifier{"pg_temp", maliciousWithdrawnTable}, []string{"id"}, pgx.CopyFromRows(rows))
		if err != nil {
			return fmt.Errorf("copy withdrawn malicious snapshot batch: %w", err)
		}
		if copied != int64(len(rows)) {
			return fmt.Errorf("copy withdrawn malicious snapshot batch: copied %d of %d rows", copied, len(rows))
		}
	}
	return nil
}

func validateStagedMaliciousSnapshot(ctx context.Context, tx pgx.Tx, source string) error {
	var id string
	err := tx.QueryRow(ctx, `
		SELECT a.id
		FROM pg_temp.packmon_openssf_malicious_snapshot a
		INNER JOIN pg_temp.packmon_openssf_malicious_withdrawn w USING (id)
		LIMIT 1`).Scan(&id)
	if err == nil {
		return fmt.Errorf("postgres: malicious snapshot ID %s is both active and withdrawn", id)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: validate malicious snapshot active/withdrawn sets: %w", err)
	}

	var existingSource string
	err = tx.QueryRow(ctx, `
		WITH staged_ids AS (
			SELECT id FROM pg_temp.packmon_openssf_malicious_snapshot
			UNION
			SELECT id FROM pg_temp.packmon_openssf_malicious_withdrawn
		)
		SELECT mf.id, mf.source
		FROM malicious_findings mf
		INNER JOIN staged_ids s USING (id)
		WHERE mf.source <> $1
		LIMIT 1`, source).Scan(&id, &existingSource)
	if err == nil {
		return fmt.Errorf("postgres: malicious snapshot ID %s is owned by source %s, not %s", id, existingSource, source)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: validate malicious snapshot source ownership: %w", err)
	}
	return nil
}

func mergeStagedMaliciousSnapshot(ctx context.Context, tx pgx.Tx) (int, error) {
	const query = `
		INSERT INTO malicious_findings (
			id, ecosystem, name, version_ranges, versions, source, risk_type, severity,
			summary, description, reference_urls, origin_ref, published, created_by
		)
		SELECT
			id, ecosystem, name, version_ranges, versions, source, risk_type, severity,
			summary, description, reference_urls, origin_ref, published, created_by
		FROM pg_temp.packmon_openssf_malicious_snapshot
		ON CONFLICT (id) DO UPDATE SET
			ecosystem = EXCLUDED.ecosystem,
			name = EXCLUDED.name,
			version_ranges = EXCLUDED.version_ranges,
			versions = EXCLUDED.versions,
			source = EXCLUDED.source,
			risk_type = EXCLUDED.risk_type,
			severity = EXCLUDED.severity,
			summary = EXCLUDED.summary,
			description = EXCLUDED.description,
			reference_urls = EXCLUDED.reference_urls,
			origin_ref = EXCLUDED.origin_ref,
			published = EXCLUDED.published,
			created_by = EXCLUDED.created_by,
			removed_at = NULL,
			updated_at = NOW()
		WHERE malicious_findings.removed_at IS NOT NULL
		   OR ROW(
			malicious_findings.ecosystem, malicious_findings.name,
			malicious_findings.version_ranges, malicious_findings.versions,
			malicious_findings.source, malicious_findings.risk_type,
			malicious_findings.severity, malicious_findings.summary,
			malicious_findings.description, malicious_findings.reference_urls,
			malicious_findings.origin_ref, malicious_findings.published,
			malicious_findings.created_by
		   ) IS DISTINCT FROM ROW(
			EXCLUDED.ecosystem, EXCLUDED.name,
			EXCLUDED.version_ranges, EXCLUDED.versions,
			EXCLUDED.source, EXCLUDED.risk_type,
			EXCLUDED.severity, EXCLUDED.summary,
			EXCLUDED.description, EXCLUDED.reference_urls,
			EXCLUDED.origin_ref, EXCLUDED.published,
			EXCLUDED.created_by
		   )`
	tag, err := tx.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("postgres: merge malicious snapshot: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func withdrawExplicitStagedMaliciousFindings(ctx context.Context, tx pgx.Tx, source string) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE malicious_findings mf
		SET removed_at = COALESCE(mf.removed_at, NOW()),
		    updated_at = NOW()
		FROM pg_temp.packmon_openssf_malicious_withdrawn w
		WHERE mf.id = w.id
		  AND mf.source = $1
		  AND mf.removed_at IS NULL`, source)
	if err != nil {
		return 0, fmt.Errorf("postgres: withdraw explicit malicious snapshot rows: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func withdrawAbsentStagedMaliciousFindings(ctx context.Context, tx pgx.Tx, source string) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE malicious_findings mf
		SET removed_at = COALESCE(mf.removed_at, NOW()),
		    updated_at = NOW()
		WHERE mf.source = $1
		  AND mf.removed_at IS NULL
		  AND NOT EXISTS (
			SELECT 1
			FROM pg_temp.packmon_openssf_malicious_snapshot staged
			WHERE staged.id = mf.id
		  )`, source)
	if err != nil {
		return 0, fmt.Errorf("postgres: withdraw absent malicious snapshot rows: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func cleanupMaliciousSnapshotConnection(conn *pgxpool.Conn, unlock bool) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(cleanupCtx, `
		DROP TABLE IF EXISTS pg_temp.packmon_openssf_malicious_snapshot;
		DROP TABLE IF EXISTS pg_temp.packmon_openssf_malicious_withdrawn`); err != nil {
		return fmt.Errorf("postgres: clean malicious snapshot staging tables: %w", err)
	}
	if unlock {
		var unlocked bool
		if err := conn.QueryRow(cleanupCtx, `SELECT pg_advisory_unlock($1)`, openssfSnapshotLockKey).Scan(&unlocked); err != nil {
			return fmt.Errorf("postgres: release OpenSSF snapshot lock: %w", err)
		}
		if !unlocked {
			return fmt.Errorf("postgres: release OpenSSF snapshot lock: lock was not held")
		}
	}
	return nil
}

func discardMaliciousSnapshotConnection(conn *pgxpool.Conn) {
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = conn.Hijack().Close(closeCtx)
}
