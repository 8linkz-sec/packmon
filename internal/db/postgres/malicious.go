package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5"
)

func validateMaliciousFindingVersions(id string, raw json.RawMessage) error {
	return validateStoredStringArrayJSON(id, "versions", raw, true)
}

func normalizeNullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	return []byte(raw)
}

func (s *Store) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	name = normalizePackageName(ecosystem, name)
	const query = `
		SELECT id, severity, summary, risk_type, source,
			COALESCE(version_ranges::text, ''),
			COALESCE(versions::text, ''),
			reference_urls::text
		FROM malicious_findings
		WHERE ecosystem = $1 AND name = $2
		  AND removed_at IS NULL
		ORDER BY updated_at DESC, id DESC`

	rows, err := s.pool.Query(ctx, query, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("postgres: find malicious findings: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	findings := make([]domain.Finding, 0)
	for rows.Next() {
		var (
			id               string
			severity         string
			summary          string
			riskType         string
			source           string
			versionRangesRaw string
			versionsRaw      string
			referenceURLsRaw string
		)

		if err := rows.Scan(&id, &severity, &summary, &riskType, &source, &versionRangesRaw, &versionsRaw, &referenceURLsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious row: %w", err)
		}
		if !maliciousFindingAffectsVersion(ecosystem, version, versionRangesRaw, versionsRaw) {
			continue
		}

		title := summary
		if title == "" {
			title = fmt.Sprintf("malicious package: %s (%s)", name, riskType)
		}
		if source == "" {
			source = "unknown"
		}

		findings = append(findings, domain.Finding{
			Name:       name,
			Version:    version,
			Ecosystem:  domain.Ecosystem(ecosystem),
			Type:       db.FindingTypeForMaliciousRiskType(riskType),
			Severity:   domain.Severity(normalizeSeverity(severity)),
			AdvisoryID: id,
			Title:      title,
			URL:        extractFirstURL(referenceURLsRaw),
			RiskType:   riskType,
			Source:     source,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate malicious findings: %w", err)
	}
	return findings, nil
}

func maliciousFindingAffectsVersion(ecosystem, version, rangesJSON, versionsJSON string) bool {
	if strings.TrimSpace(version) == "" {
		return true
	}
	affected, err := versionAffectedWithEcosystem(version, rangesJSON, versionsJSON, ecosystem)
	if err != nil {
		return true
	}
	return affected
}

func (s *Store) FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	type ecoName struct{ ecosystem, name string }
	seen := make(map[ecoName]struct{}, len(packages))
	var args []any
	var placeholders []string
	paramIdx := 1
	for _, pkg := range packages {
		normalizedName := normalizePackageName(pkg.Ecosystem, pkg.Name)
		key := ecoName{ecosystem: pkg.Ecosystem, name: normalizedName}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d)", paramIdx, paramIdx+1))
		args = append(args, pkg.Ecosystem, normalizedName)
		paramIdx += 2
	}

	query := `
		SELECT id, ecosystem, name, severity, summary, risk_type, source,
			COALESCE(version_ranges::text, ''),
			COALESCE(versions::text, ''),
			COALESCE(reference_urls::text, '[]')
		FROM malicious_findings
		WHERE (ecosystem, name) IN (VALUES ` + strings.Join(placeholders, ", ") + `)
		  AND removed_at IS NULL
		ORDER BY updated_at DESC, id DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: find malicious batch: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	type pkgVersions struct{ versions []string }
	versionMap := make(map[ecoName]*pkgVersions, len(packages))
	for _, pkg := range packages {
		key := ecoName{ecosystem: pkg.Ecosystem, name: normalizePackageName(pkg.Ecosystem, pkg.Name)}
		entry, ok := versionMap[key]
		if !ok {
			entry = &pkgVersions{}
			versionMap[key] = entry
		}
		if pkg.Version != "" {
			entry.versions = append(entry.versions, pkg.Version)
		}
	}

	var findings []domain.Finding
	for rows.Next() {
		var id, ecosystem, name, severity, summary, riskType, source, versionRangesRaw, versionsRaw, referenceURLsRaw string
		if err := rows.Scan(&id, &ecosystem, &name, &severity, &summary, &riskType, &source, &versionRangesRaw, &versionsRaw, &referenceURLsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious batch row: %w", err)
		}
		title := summary
		if title == "" {
			title = fmt.Sprintf("malicious package: %s (%s)", name, riskType)
		}
		if source == "" {
			source = "unknown"
		}

		key := ecoName{ecosystem: ecosystem, name: normalizePackageName(ecosystem, name)}
		entry := versionMap[key]
		if entry != nil && len(entry.versions) > 0 {
			for _, version := range entry.versions {
				if !maliciousFindingAffectsVersion(ecosystem, version, versionRangesRaw, versionsRaw) {
					continue
				}
				findings = append(findings, domain.Finding{
					Name: name, Version: version, Ecosystem: domain.Ecosystem(ecosystem),
					Type: db.FindingTypeForMaliciousRiskType(riskType), Severity: domain.Severity(normalizeSeverity(severity)),
					AdvisoryID: id, Title: title, URL: extractFirstURL(referenceURLsRaw), RiskType: riskType, Source: source,
				})
			}
		} else {
			findings = append(findings, domain.Finding{
				Name: name, Ecosystem: domain.Ecosystem(ecosystem),
				Type: db.FindingTypeForMaliciousRiskType(riskType), Severity: domain.Severity(normalizeSeverity(severity)),
				AdvisoryID: id, Title: title, URL: extractFirstURL(referenceURLsRaw), RiskType: riskType, Source: source,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate malicious batch: %w", err)
	}
	return findings, nil
}

func (s *Store) UpsertMaliciousFinding(ctx context.Context, mf *db.MaliciousFinding) error {
	normalized, err := normalizeMaliciousFinding(mf)
	if err != nil {
		return err
	}
	err = withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, normalized.Source, false); err != nil {
			return err
		}
		return upsertNormalizedMaliciousFindingTx(ctx, tx, normalized)
	})
	if err == nil {
		s.invalidateDashboardStats()
	}
	return err
}

func (s *Store) ImportMaliciousFeed(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	return s.importMaliciousFeed(ctx, feed, items, deleteIDs, status, nil)
}

func (s *Store) ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	return s.importMaliciousFeed(ctx, feed, items, deleteIDs, status, audit)
}

func (s *Store) importMaliciousFeed(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	imported := 0
	deleted := 0
	lockSource := feed
	for i := range items {
		if strings.EqualFold(strings.TrimSpace(items[i].Source), "openssf") {
			lockSource = "openssf"
			break
		}
	}
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, lockSource, false); err != nil {
			return err
		}
		for i := range items {
			if err := upsertMaliciousFindingTx(ctx, tx, &items[i]); err != nil {
				return fmt.Errorf("import malicious finding %s: %w", items[i].ID, err)
			}
			imported++
		}
		for _, id := range deleteIDs {
			if err := deleteMaliciousFindingForSourceTx(ctx, tx, id, feed); err != nil {
				return fmt.Errorf("delete imported malicious finding %s: %w", id, err)
			}
			deleted++
		}
		if status != nil {
			if err := upsertFeedSyncStatusTx(ctx, tx, status); err != nil {
				return err
			}
		}
		if audit != nil {
			entry := audit(imported, deleted)
			if err := insertAdminAuditLogTx(ctx, tx, &entry); err != nil {
				return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
			}
		}
		return nil
	})
	if err == nil {
		s.invalidateDashboardStats()
	}
	return imported, deleted, err
}

func upsertMaliciousFindingTx(ctx context.Context, tx pgx.Tx, mf *db.MaliciousFinding) error {
	normalized, err := normalizeMaliciousFinding(mf)
	if err != nil {
		return err
	}

	return upsertNormalizedMaliciousFindingTx(ctx, tx, normalized)
}

type normalizedMaliciousFinding struct {
	ID            string
	Ecosystem     string
	Name          string
	VersionRanges []byte
	Versions      []byte
	Source        string
	RiskType      string
	Severity      string
	Summary       string
	Description   any
	ReferenceURLs []byte
	OriginRef     any
	Published     *time.Time
	CreatedBy     any
}

func normalizeMaliciousFinding(mf *db.MaliciousFinding) (*normalizedMaliciousFinding, error) {
	if mf == nil {
		return nil, fmt.Errorf("postgres: malicious finding is nil")
	}
	if err := validateStoredVersionRangesJSON("malicious finding "+mf.ID, "version_ranges", mf.VersionRanges, true); err != nil {
		return nil, err
	}
	if err := validateStoredStringArrayJSON("malicious finding "+mf.ID, "versions", mf.Versions, true); err != nil {
		return nil, err
	}
	ecosystem, err := normalizeStoredEcosystem(mf.Ecosystem)
	if err != nil {
		return nil, err
	}
	riskType, err := normalizeMaliciousRiskType(mf.RiskType)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(mf.Source), "manual") {
		if _, err := normalizeManualAdvisoryID(mf.ID); err != nil {
			return nil, err
		}
	}
	severity, err := normalizeMaliciousSeverity(mf.Severity)
	if err != nil {
		return nil, err
	}
	var versionRanges []byte
	if normalized := normalizeNullableJSON(mf.VersionRanges); normalized != nil {
		versionRanges = append([]byte(nil), normalized.([]byte)...)
	}
	var versions []byte
	if normalized := normalizeNullableJSON(mf.Versions); normalized != nil {
		versions = append([]byte(nil), normalized.([]byte)...)
	}

	return &normalizedMaliciousFinding{
		ID:            mf.ID,
		Ecosystem:     ecosystem,
		Name:          normalizePackageName(ecosystem, mf.Name),
		VersionRanges: versionRanges,
		Versions:      versions,
		Source:        mf.Source,
		RiskType:      riskType,
		Severity:      severity,
		Summary:       mf.Summary,
		Description:   nullableString(mf.Description),
		ReferenceURLs: append([]byte(nil), normalizeJSON(mf.ReferenceURLs, []byte("[]")).([]byte)...),
		OriginRef:     nullableString(mf.OriginRef),
		Published:     mf.Published,
		CreatedBy:     nullableString(mf.CreatedBy),
	}, nil
}

func upsertNormalizedMaliciousFindingTx(ctx context.Context, tx pgx.Tx, mf *normalizedMaliciousFinding) error {
	var existingSource string
	err := tx.QueryRow(ctx, `SELECT source FROM malicious_findings WHERE id = $1`, mf.ID).Scan(&existingSource)
	if err == nil && existingSource != mf.Source {
		return fmt.Errorf("postgres: malicious finding %s is owned by source %s, not %s", mf.ID, existingSource, mf.Source)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("postgres: check malicious finding %s source ownership: %w", mf.ID, err)
	}

	const query = `
		INSERT INTO malicious_findings (
			id, ecosystem, name, version_ranges, versions, source, risk_type, severity,
			summary, description, reference_urls, origin_ref, published, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14
		)
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
			updated_at = NOW()`

	_, err = tx.Exec(ctx, query,
		mf.ID,
		mf.Ecosystem,
		mf.Name,
		mf.VersionRanges,
		mf.Versions,
		mf.Source,
		mf.RiskType,
		mf.Severity,
		mf.Summary,
		mf.Description,
		mf.ReferenceURLs,
		mf.OriginRef,
		mf.Published,
		mf.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert malicious finding %s: %w", mf.ID, err)
	}
	return nil
}

func (s *Store) DeleteMaliciousFinding(ctx context.Context, id string) error {
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, "", true); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			UPDATE malicious_findings
			SET removed_at = COALESCE(removed_at, NOW()),
			    updated_at = NOW()
			WHERE id = $1
			  AND removed_at IS NULL`, id)
		return err
	})
	if err != nil {
		return fmt.Errorf("postgres: delete malicious finding %s: %w", id, err)
	}
	s.invalidateDashboardStats()
	return nil
}

func (s *Store) DeleteMaliciousFindingForSource(ctx context.Context, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("postgres: source-scoped malicious finding delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}

	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, source, false); err != nil {
			return err
		}
		return deleteMaliciousFindingForSourceTx(ctx, tx, id, source)
	})
	if err == nil {
		s.invalidateDashboardStats()
	}
	return err
}

func deleteMaliciousFindingForSourceTx(ctx context.Context, execer postgresExecer, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("postgres: source-scoped malicious finding delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}

	query := `
		UPDATE malicious_findings
		SET removed_at = COALESCE(removed_at, NOW()),
		    updated_at = NOW()
		WHERE id = $1
		  AND removed_at IS NULL`
	args := []any{id}
	query += ` AND source = $2`
	args = append(args, source)
	if _, err := execer.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("postgres: delete malicious finding %s for source %s: %w", id, source, err)
	}
	return nil
}

func (s *Store) DeleteMaliciousFindingsNotInSource(ctx context.Context, source string, ids []string) (int, error) {
	var count int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, source, false); err != nil {
			return err
		}
		cmd, err := tx.Exec(ctx, `
			UPDATE malicious_findings
			SET removed_at = COALESCE(removed_at, NOW()),
			    updated_at = NOW()
			WHERE source = $1
			  AND removed_at IS NULL
			  AND NOT (id = ANY($2))`, source, ids)
		count = int(cmd.RowsAffected())
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: prune malicious findings for source %s: %w", source, err)
	}
	s.invalidateDashboardStats()
	return count, nil
}

func (s *Store) PruneMaliciousFindingsForSourceUpdatedBefore(ctx context.Context, source string, updatedBefore time.Time) (int, error) {
	var count int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, source, false); err != nil {
			return err
		}
		cmd, err := tx.Exec(ctx, `
			UPDATE malicious_findings
			SET removed_at = COALESCE(removed_at, NOW()),
			    updated_at = NOW()
			WHERE source = $1
			  AND removed_at IS NULL
			  AND updated_at < $2`, source, updatedBefore)
		count = int(cmd.RowsAffected())
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: prune stale malicious findings for source %s: %w", source, err)
	}
	s.invalidateDashboardStats()
	return count, nil
}

func (s *Store) ListMaliciousFindings(ctx context.Context, source string, limit int) ([]db.MaliciousFinding, error) {
	limit = clampLimit(limit, 100, 500)

	query := `
		SELECT
			id, ecosystem, name, COALESCE(version_ranges::text, ''), COALESCE(versions::text, ''), source, risk_type, severity,
			summary, description, COALESCE(reference_urls::text, '[]'), origin_ref, published, created_by
		FROM malicious_findings`
	args := []any{}
	if source != "" {
		query += ` WHERE source = $1 AND removed_at IS NULL`
		args = append(args, source)
	} else {
		query += ` WHERE removed_at IS NULL`
	}
	query += fmt.Sprintf(` ORDER BY updated_at DESC, created_at DESC, id DESC LIMIT $%d`, len(args)+1)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list malicious findings: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.MaliciousFinding, 0)
	for rows.Next() {
		var (
			item             db.MaliciousFinding
			versionRangesRaw *string
			versionsRaw      *string
			referenceURLsRaw *string
			description      *string
			originRef        *string
			createdBy        *string
			published        *time.Time
		)

		if err := rows.Scan(
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&versionRangesRaw,
			&versionsRaw,
			&item.Source,
			&item.RiskType,
			&item.Severity,
			&item.Summary,
			&description,
			&referenceURLsRaw,
			&originRef,
			&published,
			&createdBy,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious finding row: %w", err)
		}

		if versionRangesRaw != nil {
			item.VersionRanges = json.RawMessage(*versionRangesRaw)
		}
		if versionsRaw != nil {
			item.Versions = json.RawMessage(*versionsRaw)
		}
		if referenceURLsRaw != nil {
			item.ReferenceURLs = json.RawMessage(*referenceURLsRaw)
		}
		if description != nil {
			item.Description = *description
		}
		if originRef != nil {
			item.OriginRef = *originRef
		}
		if published != nil {
			item.Published = published
		}
		if createdBy != nil {
			item.CreatedBy = *createdBy
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate malicious findings: %w", err)
	}
	return out, nil
}
