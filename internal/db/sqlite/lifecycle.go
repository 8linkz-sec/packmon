package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
)

func (s *Store) FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	chunks := localPackagePredicateChunks(packages, localPackagePredicateChunkSize)
	if len(chunks) == 0 {
		return nil, nil
	}

	normalizedPackages := make([]db.PackageQuery, 0, len(packages))
	for _, pkg := range packages {
		queryPkg, ok := normalizeLifecyclePackageQuery(pkg)
		if !ok {
			continue
		}
		normalizedPackages = append(normalizedPackages, queryPkg)
	}

	rowsByPackage := make(map[localPackageKey][]lifecyclepolicy.ReleaseRow, len(normalizedPackages))
	for _, chunk := range chunks {
		if err := s.collectLifecycleReleaseRows(ctx, chunk, rowsByPackage); err != nil {
			return nil, fmt.Errorf("sqlite: lifecycle releases for %s: %w", localPackageChunkContext(chunk), err)
		}
	}

	allFindings := make([]domain.Finding, 0)
	for _, queryPkg := range normalizedPackages {
		key := localPackageKey{ecosystem: queryPkg.Ecosystem, name: queryPkg.Name}
		for _, row := range lifecyclepolicy.LongestMatchingReleases(rowsByPackage[key], queryPkg.Version) {
			finding, ok := lifecyclepolicy.FindingForRelease(lifecyclePackageQuery(queryPkg), row, now)
			if ok {
				allFindings = append(allFindings, finding)
			}
		}
	}
	return allFindings, nil
}

func (s *Store) collectLifecycleReleaseRows(ctx context.Context, chunk localPackagePredicateChunk, rowsByPackage map[localPackageKey][]lifecyclepolicy.ReleaseRow) error {
	query := `
		WITH requested(ecosystem, name) AS (VALUES ` + chunk.values + `)
		SELECT
			l.id, l.ecosystem, l.name, l.product_slug, l.product_label, l.cycle, l.latest,
			l.release_date, l.is_lts, l.lts_from, l.is_eoas, l.eoas_from, l.is_eol, l.eol_from,
			l.is_discontinued, l.discontinued_from, l.is_eoes, l.eoes_from, l.is_maintained
		FROM lifecycle_releases_local AS l
		JOIN requested AS r ON r.ecosystem = l.ecosystem AND r.name = l.name
		ORDER BY l.ecosystem ASC, l.name ASC, l.product_slug ASC, length(l.cycle) DESC, l.cycle DESC` // #nosec G202 -- localPackagePredicateChunks uses fixed SQL fragments and bound args.

	rows, err := s.db.QueryContext(ctx, query, chunk.args...)
	if err != nil {
		return fmt.Errorf("sqlite: query lifecycle releases batch: %w", err)
	}
	defer closeSilently(rows)

	for rows.Next() {
		var (
			row                        lifecyclepolicy.ReleaseRow
			releaseDate, ltsFrom       sql.NullString
			eoasFrom, eolFrom          sql.NullString
			discontinuedFrom           sql.NullString
			isEOES                     sql.NullInt64
			eoesFrom                   sql.NullString
			isLTS, isEOAS, isEOL       int
			isDiscontinued, maintained int
		)
		if err := rows.Scan(
			&row.ID,
			&row.Ecosystem,
			&row.PackageName,
			&row.ProductSlug,
			&row.ProductName,
			&row.Release.Cycle,
			&row.Release.Latest,
			&releaseDate,
			&isLTS,
			&ltsFrom,
			&isEOAS,
			&eoasFrom,
			&isEOL,
			&eolFrom,
			&isDiscontinued,
			&discontinuedFrom,
			&isEOES,
			&eoesFrom,
			&maintained,
		); err != nil {
			return fmt.Errorf("sqlite: scan lifecycle release batch row: %w", err)
		}
		row.Release.ReleaseDate = parseSQLiteDate(releaseDate)
		row.Release.IsLTS = isLTS != 0
		row.Release.LTSFrom = parseSQLiteDate(ltsFrom)
		row.Release.IsEOAS = isEOAS != 0
		row.Release.EOASFrom = parseSQLiteDate(eoasFrom)
		row.Release.IsEOL = isEOL != 0
		row.Release.EOLFrom = parseSQLiteDate(eolFrom)
		row.Release.IsDiscontinued = isDiscontinued != 0
		row.Release.DiscontinuedFrom = parseSQLiteDate(discontinuedFrom)
		if isEOES.Valid {
			value := isEOES.Int64 != 0
			row.Release.IsEOES = &value
		}
		row.Release.EOESFrom = parseSQLiteDate(eoesFrom)
		row.Release.IsMaintained = maintained != 0

		key := localPackageKey{ecosystem: row.Ecosystem, name: row.PackageName}
		rowsByPackage[key] = append(rowsByPackage[key], row)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: iterate lifecycle release batch rows: %w", err)
	}
	return nil
}

func lifecyclePackageQuery(pkg db.PackageQuery) lifecyclepolicy.PackageQuery {
	return lifecyclepolicy.PackageQuery{
		Ecosystem: pkg.Ecosystem,
		Name:      pkg.Name,
		Version:   pkg.Version,
	}
}

func localPackageChunkContext(chunk localPackagePredicateChunk) string {
	total := len(chunk.args) / 2
	if total == 0 {
		return "requested packages"
	}
	parts := make([]string, 0, min(total, 3))
	for i := 0; i+1 < len(chunk.args) && len(parts) < 3; i += 2 {
		ecosystem, _ := chunk.args[i].(string)
		name, _ := chunk.args[i+1].(string)
		if ecosystem == "" && name == "" {
			continue
		}
		parts = append(parts, ecosystem+"/"+name)
	}
	if len(parts) == 0 {
		return "requested packages"
	}
	if total > len(parts) {
		parts = append(parts, fmt.Sprintf("+%d more", total-len(parts)))
	}
	return strings.Join(parts, ", ")
}

func normalizeLifecyclePackageQuery(pkg db.PackageQuery) (db.PackageQuery, bool) {
	ecosystem := strings.TrimSpace(pkg.Ecosystem)
	name := normalizePackageName(ecosystem, strings.TrimSpace(pkg.Name))
	if ecosystem == "" || name == "" {
		return db.PackageQuery{}, false
	}
	return db.PackageQuery{
		Ecosystem: ecosystem,
		Name:      name,
		Version:   strings.TrimSpace(pkg.Version),
	}, true
}

func parseSQLiteDate(value sql.NullString) *time.Time {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil
	}
	if date, err := time.Parse(time.DateOnly, strings.TrimSpace(value.String)); err == nil {
		return &date
	}
	if date, err := time.Parse(time.RFC3339, strings.TrimSpace(value.String)); err == nil {
		return &date
	}
	return nil
}
