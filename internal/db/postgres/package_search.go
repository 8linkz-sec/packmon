package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
)

type packageSearchCollector string

const (
	packageSearchCollectorVulnerability         packageSearchCollector = "vulnerability"
	packageSearchCollectorMalicious             packageSearchCollector = "malicious"
	packageSearchCollectorReputationMalicious   packageSearchCollector = "reputation_malicious"
	packageSearchCollectorReputationSupplyChain packageSearchCollector = "reputation_supply_chain"
	packageSearchCollectorLifecycleEOL          packageSearchCollector = "lifecycle_eol"
	packageSearchCollectorLifecycleWarning      packageSearchCollector = "lifecycle_warning"
)

func packageSearchCollectorPlan(findingType string) []packageSearchCollector {
	switch findingType {
	case "":
		return []packageSearchCollector{
			packageSearchCollectorVulnerability,
			packageSearchCollectorMalicious,
			packageSearchCollectorReputationMalicious,
			packageSearchCollectorReputationSupplyChain,
			packageSearchCollectorLifecycleEOL,
			packageSearchCollectorLifecycleWarning,
		}
	case "vulnerability":
		return []packageSearchCollector{packageSearchCollectorVulnerability}
	case "malicious":
		return []packageSearchCollector{
			packageSearchCollectorMalicious,
			packageSearchCollectorReputationMalicious,
		}
	case "supply_chain_risk":
		return []packageSearchCollector{
			packageSearchCollectorReputationSupplyChain,
			packageSearchCollectorLifecycleEOL,
		}
	case "lifecycle":
		return []packageSearchCollector{packageSearchCollectorLifecycleWarning}
	default:
		return nil
	}
}

type packageSearchTask struct {
	collector packageSearchCollector
	run       func(context.Context) (map[string]*db.PackageSearchResult, error)
}

func (s *Store) SearchPackages(ctx context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	query := strings.TrimSpace(params.Query)
	severity := strings.ToUpper(strings.TrimSpace(params.Severity))
	if severity != "" {
		severity = normalizeSeverity(severity)
	}
	findingType := strings.ToLower(strings.TrimSpace(params.FindingType))
	limit := clampLimit(params.Limit, 50, 200)
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}
	collectorLimit := packageSearchCollectorLimit(limit, offset)
	if query == "" && severity == "" && findingType == "" {
		return []db.PackageSearchResult{}, nil
	}

	like := ""
	if query != "" {
		like = "%" + query + "%"
	}

	tasks := s.packageSearchTasks(packageSearchCollectorPlan(findingType), like, severity, collectorLimit)
	results, err := runPackageSearchCollectors(ctx, tasks, findingType == "")
	if err != nil {
		return nil, err
	}

	return finishPackageSearchResults(results, limit, offset), nil
}

func (s *Store) packageSearchTasks(collectors []packageSearchCollector, like, severity string, limit int) []packageSearchTask {
	tasks := make([]packageSearchTask, 0, len(collectors))
	for _, collector := range collectors {
		collector := collector
		var collect func(context.Context, map[string]*db.PackageSearchResult) error
		switch collector {
		case packageSearchCollectorVulnerability:
			collect = func(ctx context.Context, results map[string]*db.PackageSearchResult) error {
				return s.collectVulnerabilityPackageSearch(ctx, results, like, severity, limit)
			}
		case packageSearchCollectorMalicious:
			collect = func(ctx context.Context, results map[string]*db.PackageSearchResult) error {
				return s.collectMaliciousPackageSearch(ctx, results, like, severity, limit)
			}
		case packageSearchCollectorReputationMalicious:
			collect = func(ctx context.Context, results map[string]*db.PackageSearchResult) error {
				return s.collectReputationMaliciousPackageSearch(ctx, results, like, severity, limit)
			}
		case packageSearchCollectorReputationSupplyChain:
			collect = func(ctx context.Context, results map[string]*db.PackageSearchResult) error {
				return s.collectReputationSupplyChainPackageSearch(ctx, results, like, severity, limit)
			}
		case packageSearchCollectorLifecycleEOL:
			collect = func(ctx context.Context, results map[string]*db.PackageSearchResult) error {
				return s.collectLifecycleEOLPackageSearch(ctx, results, like, severity, limit)
			}
		case packageSearchCollectorLifecycleWarning:
			collect = func(ctx context.Context, results map[string]*db.PackageSearchResult) error {
				return s.collectLifecycleWarningPackageSearch(ctx, results, like, severity, limit)
			}
		default:
			continue
		}
		tasks = append(tasks, packageSearchTask{
			collector: collector,
			run: func(ctx context.Context) (map[string]*db.PackageSearchResult, error) {
				results := make(map[string]*db.PackageSearchResult)
				if err := collect(ctx, results); err != nil {
					return nil, err
				}
				return results, nil
			},
		})
	}
	return tasks
}

func runPackageSearchCollectors(ctx context.Context, tasks []packageSearchTask, concurrent bool) (map[string]*db.PackageSearchResult, error) {
	results := make(map[string]*db.PackageSearchResult)
	if len(tasks) == 0 {
		return results, nil
	}
	if !concurrent || len(tasks) == 1 {
		for _, task := range tasks {
			partial, err := task.run(ctx)
			if err != nil {
				return nil, err
			}
			mergePackageSearchResultMaps(results, partial)
		}
		return results, nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type taskResult struct {
		order   int
		results map[string]*db.PackageSearchResult
		err     error
	}

	var wg sync.WaitGroup
	resultCh := make(chan taskResult, len(tasks))
	for i, task := range tasks {
		i, task := i, task
		wg.Add(1)
		go func() {
			defer wg.Done()
			partial, err := task.run(runCtx)
			if err != nil {
				cancel()
			}
			resultCh <- taskResult{order: i, results: partial, err: err}
		}()
	}

	wg.Wait()
	close(resultCh)

	partials := make([]map[string]*db.PackageSearchResult, len(tasks))
	firstErrOrder := len(tasks)
	var firstErr error
	firstNonContextErrOrder := len(tasks)
	var firstNonContextErr error
	for result := range resultCh {
		partials[result.order] = result.results
		if result.err == nil {
			continue
		}
		if result.order < firstErrOrder {
			firstErrOrder = result.order
			firstErr = result.err
		}
		if !isContextCancellationError(result.err) && result.order < firstNonContextErrOrder {
			firstNonContextErrOrder = result.order
			firstNonContextErr = result.err
		}
	}
	if firstNonContextErr != nil {
		return nil, firstNonContextErr
	}
	if firstErr != nil {
		return nil, firstErr
	}

	for _, partial := range partials {
		mergePackageSearchResultMaps(results, partial)
	}
	return results, nil
}

func isContextCancellationError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func mergePackageSearchResultMaps(dst, src map[string]*db.PackageSearchResult) {
	for key, result := range src {
		if result == nil {
			continue
		}
		if existing, ok := dst[key]; ok {
			existing.FindingsCount += result.FindingsCount
			existing.VulnerabilityCount += result.VulnerabilityCount
			existing.VulnerabilityIDs = mergeCSV(existing.VulnerabilityIDs, result.VulnerabilityIDs)
			existing.Sources = mergeCSV(existing.Sources, result.Sources)
			existing.FindingTypes = mergeCSV(existing.FindingTypes, result.FindingTypes)
			continue
		}
		cloned := *result
		dst[key] = &cloned
	}
}

func (s *Store) collectVulnerabilityPackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int) error {
	const vulnerabilityQuery = `
		SELECT
			ap.ecosystem,
			ap.name,
			''::text AS version,
			COUNT(DISTINCT ap.vulnerability_id)::int,
			COUNT(DISTINCT ap.vulnerability_id)::int,
			COALESCE((
				SELECT string_agg(preview_id, ', ' ORDER BY preview_id)
				FROM (
					SELECT DISTINCT v_preview.id AS preview_id
					FROM affected_packages ap_preview
					INNER JOIN vulnerabilities v_preview ON v_preview.id = ap_preview.vulnerability_id
					WHERE ap_preview.ecosystem = ap.ecosystem
					  AND ap_preview.name = ap.name
					  AND ($1 = '' OR ap_preview.name ILIKE $1)
					  AND ($2 = '' OR UPPER(COALESCE(v_preview.severity, 'UNKNOWN')) = $2)
					  AND v_preview.withdrawn IS NULL
					ORDER BY v_preview.id
					LIMIT $4
				) preview
			), ''),
			COALESCE(string_agg(DISTINCT COALESCE(vs.source, 'unknown'), ', ' ORDER BY COALESCE(vs.source, 'unknown')), ''),
			'vulnerability'::text
		FROM affected_packages ap
		INNER JOIN vulnerabilities v ON v.id = ap.vulnerability_id
		LEFT JOIN vulnerability_sources vs ON vs.vulnerability_id = ap.vulnerability_id
		WHERE ($1 = '' OR ap.name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(v.severity, 'UNKNOWN')) = $2)
		  AND v.withdrawn IS NULL
		GROUP BY ap.ecosystem, ap.name
		ORDER BY ap.name ASC, ap.ecosystem ASC
		LIMIT $3`

	return s.collectSearchResults(ctx, results, vulnerabilityQuery, like, severity, limit, db.SearchVulnerabilityIDPreviewLimit)
}

func (s *Store) collectMaliciousPackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int) error {
	const maliciousQuery = `
		SELECT
			ecosystem,
			name,
			''::text AS version,
			COUNT(*)::int,
			0::int,
			''::text,
			COALESCE(string_agg(DISTINCT source, ', ' ORDER BY source), ''),
			'malicious'::text
		FROM malicious_findings
		WHERE ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(severity, 'UNKNOWN')) = $2)
		  AND removed_at IS NULL
		GROUP BY ecosystem, name
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	return s.collectSearchResults(ctx, results, maliciousQuery, like, severity, limit)
}

func (s *Store) collectReputationPackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int, findingType string) error {
	if findingType == "" || findingType == "malicious" {
		if err := s.collectReputationMaliciousPackageSearch(ctx, results, like, severity, limit); err != nil {
			return err
		}
	}
	if findingType == "" || findingType == "supply_chain_risk" {
		if err := s.collectReputationSupplyChainPackageSearch(ctx, results, like, severity, limit); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) collectReputationMaliciousPackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int) error {
	const reputationMaliciousQuery = `
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			COALESCE(string_agg(DISTINCT source, ', ' ORDER BY source), ''),
			'malicious'::text
		FROM package_reputation_cache
		WHERE status = 'malicious'
		  AND ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(severity, 'UNKNOWN')) = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	return s.collectSearchResults(ctx, results, reputationMaliciousQuery, like, severity, limit)
}

func (s *Store) collectReputationSupplyChainPackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int) error {
	const supplyChainQuery = `
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			COALESCE(string_agg(DISTINCT source, ', ' ORDER BY source), ''),
			'supply_chain_risk'::text
		FROM package_reputation_cache
		WHERE status IN ('removed', 'risk')
		  AND ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(severity, 'UNKNOWN')) = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	return s.collectSearchResults(ctx, results, supplyChainQuery, like, severity, limit)
}

func (s *Store) collectLifecyclePackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int, findingType string) error {
	if findingType == "" || findingType == "supply_chain_risk" {
		if err := s.collectLifecycleEOLPackageSearch(ctx, results, like, severity, limit); err != nil {
			return err
		}
	}
	if findingType == "" || findingType == "lifecycle" {
		if err := s.collectLifecycleWarningPackageSearch(ctx, results, like, severity, limit); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) collectLifecycleEOLPackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int) error {
	const lifecycleSupplyChainQuery = `
		WITH lifecycle_findings AS (
			SELECT
				m.ecosystem,
				m.name,
				COALESCE(NULLIF(r.latest, ''), r.cycle) AS version,
				$4::text AS severity
			FROM lifecycle_package_map m
			INNER JOIN lifecycle_releases r ON r.product_slug = m.product_slug
			WHERE r.is_eol OR (r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE)
		)
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			'endoflife.date'::text,
			'supply_chain_risk'::text
		FROM lifecycle_findings
		WHERE ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR severity = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	return s.collectSearchResults(ctx, results, lifecycleSupplyChainQuery,
		like, severity, limit, string(lifecyclepolicy.SeverityEOL))
}

func (s *Store) collectLifecycleWarningPackageSearch(ctx context.Context, results map[string]*db.PackageSearchResult, like, severity string, limit int) error {
	const lifecycleQuery = `
		WITH lifecycle_findings AS (
			SELECT
				m.ecosystem,
				m.name,
				COALESCE(NULLIF(r.latest, ''), r.cycle) AS version,
				CASE
					WHEN r.eol_from IS NOT NULL AND r.eol_from > CURRENT_DATE AND r.eol_from <= CURRENT_DATE + ($4::int * INTERVAL '1 day') THEN $5::text
					WHEN r.is_eoas OR (r.eoas_from IS NOT NULL AND r.eoas_from <= CURRENT_DATE) THEN $6::text
					ELSE ''
				END AS severity
			FROM lifecycle_package_map m
			INNER JOIN lifecycle_releases r ON r.product_slug = m.product_slug
			WHERE NOT (r.is_eol OR (r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE))
		)
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			'endoflife.date'::text,
			'lifecycle'::text
		FROM lifecycle_findings
		WHERE severity <> ''
		  AND ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR severity = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	return s.collectSearchResults(ctx, results, lifecycleQuery,
		like, severity, limit,
		lifecyclepolicy.EOLSoonDays,
		string(lifecyclepolicy.SeverityEOLSoon),
		string(lifecyclepolicy.SeveritySecuritySupportOnly))
}

func finishPackageSearchResults(results map[string]*db.PackageSearchResult, limit, offset int) []db.PackageSearchResult {
	out := make([]db.PackageSearchResult, 0, len(results))
	for _, result := range results {
		result.VulnerabilityIDs = joinSortedCSV(result.VulnerabilityIDs)
		result.VulnerabilityIDs = db.FormatSearchVulnerabilityIDPreview(result.VulnerabilityIDs, result.VulnerabilityCount)
		result.Sources = joinSortedCSV(result.Sources)
		result.FindingTypes = joinSortedCSV(result.FindingTypes)
		out = append(out, *result)
	}
	sortSearchResults(out)
	if offset < 0 {
		offset = 0
	}
	if offset >= len(out) {
		return []db.PackageSearchResult{}
	}
	if offset > 0 {
		out = out[offset:]
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func packageSearchCollectorLimit(limit, offset int) int {
	if offset <= 0 {
		return limit
	}
	maxInt := int(^uint(0) >> 1)
	if limit > maxInt-offset {
		return maxInt
	}
	return limit + offset
}

func (s *Store) collectSearchResults(ctx context.Context, acc map[string]*db.PackageSearchResult, query string, args ...any) error {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("postgres: search packages: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			ecosystem          string
			name               string
			version            string
			findingsCount      int
			vulnerabilityCount int
			vulnerabilityIDs   string
			sources            string
			findingTypes       string
		)
		if err := rows.Scan(&ecosystem, &name, &version, &findingsCount, &vulnerabilityCount, &vulnerabilityIDs, &sources, &findingTypes); err != nil {
			return fmt.Errorf("postgres: scan package search row: %w", err)
		}

		key := ecosystem + "\x00" + name + "\x00" + version
		if existing, ok := acc[key]; ok {
			existing.FindingsCount += findingsCount
			existing.VulnerabilityCount += vulnerabilityCount
			existing.VulnerabilityIDs = mergeCSV(existing.VulnerabilityIDs, vulnerabilityIDs)
			existing.Sources = mergeCSV(existing.Sources, sources)
			existing.FindingTypes = mergeCSV(existing.FindingTypes, findingTypes)
			continue
		}
		acc[key] = &db.PackageSearchResult{
			Ecosystem:          ecosystem,
			Name:               name,
			Version:            version,
			FindingsCount:      findingsCount,
			VulnerabilityCount: vulnerabilityCount,
			VulnerabilityIDs:   vulnerabilityIDs,
			Sources:            sources,
			FindingTypes:       findingTypes,
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: iterate package search rows: %w", err)
	}
	return nil
}
