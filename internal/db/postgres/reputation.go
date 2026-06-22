package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

const (
	reputationStatusPending     = "pending"
	reputationStatusMalicious   = "malicious"
	reputationStatusRemoved     = "removed"
	reputationStatusRisk        = "risk"
	reputationStatusUnsupported = "unsupported"
)

func (s *Store) FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	type pkgKey struct {
		ecosystem string
		name      string
		version   string
	}

	seen := make(map[pkgKey]struct{}, len(packages))
	args := []any{source}
	placeholders := make([]string, 0, len(packages))
	paramIdx := 2
	for _, pkg := range packages {
		if strings.TrimSpace(pkg.Ecosystem) == "" || strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		key := pkgKey{
			ecosystem: pkg.Ecosystem,
			name:      normalizePackageName(pkg.Ecosystem, pkg.Name),
			version:   pkg.Version,
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d, $%d)", paramIdx, paramIdx+1, paramIdx+2))
		args = append(args, key.ecosystem, key.name, key.version)
		paramIdx += 3
	}
	if len(placeholders) == 0 {
		return nil, nil
	}

	query := `
		SELECT
			ecosystem, name, version, source, status, severity, summary, description,
			reference_urls::text, evidence::text, last_checked_at, next_check_at, last_error, updated_at
		FROM package_reputation_cache
		WHERE source = $1
		  AND status IN ('malicious', 'removed', 'risk')
		  AND (ecosystem, name, version) IN (VALUES ` + strings.Join(placeholders, ", ") + `)
		ORDER BY updated_at DESC, ecosystem, name, version`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: find reputation findings batch: %w", err)
	}
	defer closeSilently(rows)

	findings := make([]domain.Finding, 0)
	for rows.Next() {
		rep, err := scanPackageReputation(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan reputation row: %w", err)
		}
		if finding, ok := reputationToFinding(rep); ok {
			findings = append(findings, finding)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate reputation findings: %w", err)
	}
	return findings, nil
}

func (s *Store) FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error) {
	if strings.TrimSpace(ecosystem) == "" || strings.TrimSpace(name) == "" || strings.TrimSpace(source) == "" {
		return nil, nil
	}

	const query = `
		SELECT
			ecosystem, name, version, source, status, severity, summary, description,
			reference_urls::text, evidence::text, last_checked_at, next_check_at, last_error, updated_at
		FROM package_reputation_cache
		WHERE source = $1
		  AND status IN ('malicious', 'removed', 'risk')
		  AND ecosystem = $2
		  AND name = $3
		ORDER BY version ASC, updated_at DESC`

	rows, err := s.pool.Query(ctx, query, source, ecosystem, normalizePackageName(ecosystem, name))
	if err != nil {
		return nil, fmt.Errorf("postgres: find reputation findings: %w", err)
	}
	defer closeSilently(rows)

	findings := make([]domain.Finding, 0)
	for rows.Next() {
		rep, err := scanPackageReputation(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan reputation row: %w", err)
		}
		if finding, ok := reputationToFinding(rep); ok {
			findings = append(findings, finding)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate reputation findings: %w", err)
	}
	return findings, nil
}

func (s *Store) MarkPackageReputationDue(ctx context.Context, rep *db.PackageReputation) (bool, error) {
	if rep == nil {
		return false, nil
	}
	if strings.TrimSpace(rep.Ecosystem) == "" || strings.TrimSpace(rep.Name) == "" || strings.TrimSpace(rep.Version) == "" || strings.TrimSpace(rep.Source) == "" {
		return false, nil
	}

	name := normalizePackageName(rep.Ecosystem, rep.Name)
	severity := normalizeReputationSeverity(rep.Severity)

	const query = `
		WITH upsert AS (
			INSERT INTO package_reputation_cache (
				ecosystem, name, version, source, status, severity, next_check_at
			) VALUES (
				$1, $2, $3, $4, 'pending', $5, NOW()
			)
			ON CONFLICT (ecosystem, name, version, source) DO UPDATE SET
				next_check_at = NOW(),
				updated_at = NOW()
			WHERE package_reputation_cache.status <> 'unsupported'
			  AND (
				package_reputation_cache.next_check_at IS NULL
				OR package_reputation_cache.next_check_at <= NOW()
			  )
			RETURNING 1
		)
		SELECT EXISTS(SELECT 1 FROM upsert)`

	var queued bool
	if err := s.pool.QueryRow(ctx, query, rep.Ecosystem, name, rep.Version, rep.Source, severity).Scan(&queued); err != nil {
		return false, fmt.Errorf("postgres: mark package reputation due: %w", err)
	}
	return queued, nil
}

func (s *Store) ListDuePackageReputations(ctx context.Context, ecosystem, name, source string, limit int) ([]db.PackageReputation, error) {
	limit = clampLimit(limit, 5, 100)
	name = normalizePackageName(ecosystem, name)

	const query = `
		SELECT
			ecosystem, name, version, source, status, severity, summary, description,
			reference_urls::text, evidence::text, last_checked_at, next_check_at, last_error, updated_at
		FROM package_reputation_cache
		WHERE ecosystem = $1
		  AND name = $2
		  AND source = $3
		  AND status <> 'unsupported'
		  AND next_check_at IS NOT NULL
		  AND next_check_at <= NOW()
		ORDER BY next_check_at ASC, version ASC
		LIMIT $4`

	rows, err := s.pool.Query(ctx, query, ecosystem, name, source, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list due package reputations: %w", err)
	}
	defer closeSilently(rows)

	reps := make([]db.PackageReputation, 0)
	for rows.Next() {
		rep, err := scanPackageReputation(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan due reputation row: %w", err)
		}
		reps = append(reps, rep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate due reputation rows: %w", err)
	}
	return reps, nil
}

func (s *Store) UpsertPackageReputation(ctx context.Context, rep *db.PackageReputation) error {
	if rep == nil {
		return nil
	}
	name := normalizePackageName(rep.Ecosystem, rep.Name)
	status := strings.ToLower(strings.TrimSpace(rep.Status))
	if status == "" {
		status = reputationStatusPending
	}
	severity := normalizeReputationSeverity(rep.Severity)
	summary := strings.TrimSpace(rep.Summary)
	description := strings.TrimSpace(rep.Description)

	const query = `
		INSERT INTO package_reputation_cache (
			ecosystem, name, version, source, status, severity, summary, description,
			reference_urls, evidence, last_checked_at, next_check_at, last_error
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (ecosystem, name, version, source) DO UPDATE SET
			status = EXCLUDED.status,
			severity = EXCLUDED.severity,
			summary = EXCLUDED.summary,
			description = EXCLUDED.description,
			reference_urls = EXCLUDED.reference_urls,
			evidence = EXCLUDED.evidence,
			last_checked_at = EXCLUDED.last_checked_at,
			next_check_at = EXCLUDED.next_check_at,
			last_error = EXCLUDED.last_error,
			updated_at = NOW()`

	if _, err := s.pool.Exec(ctx, query,
		rep.Ecosystem,
		name,
		rep.Version,
		rep.Source,
		status,
		severity,
		summary,
		description,
		normalizeJSON(rep.ReferenceURLs, []byte("[]")),
		normalizeJSON(rep.Evidence, []byte("{}")),
		rep.LastCheckedAt,
		rep.NextCheckAt,
		rep.LastError,
	); err != nil {
		return fmt.Errorf("postgres: upsert package reputation: %w", err)
	}
	return nil
}

func reputationToFinding(rep db.PackageReputation) (domain.Finding, bool) {
	var (
		findingType domain.FindingType
		riskType    string
		title       string
	)

	switch strings.ToLower(strings.TrimSpace(rep.Status)) {
	case reputationStatusMalicious:
		findingType = domain.FindingTypeMalicious
		riskType = "malware"
		title = "ReversingLabs: malware detected"
	case reputationStatusRemoved:
		findingType = domain.FindingTypeSupplyChainRisk
		riskType = "removed_package"
		title = "ReversingLabs: package version was removed"
	case reputationStatusRisk:
		return domain.Finding{}, false
	default:
		return domain.Finding{}, false
	}

	if strings.TrimSpace(rep.Summary) != "" {
		title = strings.TrimSpace(rep.Summary)
	}
	source := strings.TrimSpace(rep.Source)
	if source == "" {
		source = db.ReputationSourceReversingLabs
	}
	referenceURLs := string(rep.ReferenceURLs)

	return domain.Finding{
		Name:       rep.Name,
		Version:    rep.Version,
		Ecosystem:  domain.Ecosystem(rep.Ecosystem),
		Type:       findingType,
		Severity:   domain.Severity(normalizeReputationSeverity(rep.Severity)),
		AdvisoryID: reputationFindingID(rep.Ecosystem, rep.Name, rep.Version),
		Title:      title,
		URL:        extractFirstURL(referenceURLs),
		RiskType:   riskType,
		Source:     source,
	}, true
}

func reputationFindingID(ecosystem, name, version string) string {
	return fmt.Sprintf("reversinglabs:%s/%s@%s", ecosystem, name, version)
}

func normalizeReputationSeverity(severity string) string {
	normalized := normalizeSeverity(severity)
	if normalized == "UNKNOWN" {
		return "CRITICAL"
	}
	return normalized
}

type reputationScanner interface {
	Scan(dest ...any) error
}

func scanPackageReputation(row reputationScanner) (db.PackageReputation, error) {
	var (
		rep              db.PackageReputation
		referenceURLsRaw string
		evidenceRaw      string
	)

	if err := row.Scan(
		&rep.Ecosystem,
		&rep.Name,
		&rep.Version,
		&rep.Source,
		&rep.Status,
		&rep.Severity,
		&rep.Summary,
		&rep.Description,
		&referenceURLsRaw,
		&evidenceRaw,
		&rep.LastCheckedAt,
		&rep.NextCheckAt,
		&rep.LastError,
		&rep.UpdatedAt,
	); err != nil {
		return db.PackageReputation{}, err
	}

	rep.ReferenceURLs = []byte(referenceURLsRaw)
	rep.Evidence = []byte(evidenceRaw)
	return rep, nil
}
