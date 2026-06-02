package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

const lifecycleSource = "endoflife.date"

func (s *Store) FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	allFindings := make([]domain.Finding, 0)
	for _, pkg := range packages {
		queryPkg, ok := normalizeLifecyclePackageQuery(pkg)
		if !ok {
			continue
		}
		rows, err := s.lifecycleRows(ctx, queryPkg.Ecosystem, queryPkg.Name)
		if err != nil {
			return nil, err
		}
		for _, row := range longestLifecycleMatches(rows, queryPkg.Version) {
			finding, ok := lifecycleFindingForRelease(queryPkg, row, now)
			if ok {
				allFindings = append(allFindings, finding)
			}
		}
	}
	return allFindings, nil
}

func (s *Store) lifecycleRows(ctx context.Context, ecosystem, name string) ([]lifecycleReleaseRow, error) {
	const query = `
		SELECT
			id, ecosystem, name, product_slug, product_label, cycle, latest,
			release_date, is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			is_discontinued, discontinued_from, is_eoes, eoes_from, is_maintained
		FROM lifecycle_releases_local
		WHERE ecosystem = ? AND name = ?
		ORDER BY product_slug ASC, length(cycle) DESC, cycle DESC`

	rows, err := s.db.QueryContext(ctx, query, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("sqlite: query lifecycle releases: %w", err)
	}
	defer closeSilently(rows)

	out := make([]lifecycleReleaseRow, 0)
	for rows.Next() {
		var (
			row                        lifecycleReleaseRow
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
			&row.ProductLabel,
			&row.Cycle,
			&row.Latest,
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
			return nil, fmt.Errorf("sqlite: scan lifecycle release: %w", err)
		}
		row.ReleaseDate = parseSQLiteDate(releaseDate)
		row.IsLTS = isLTS != 0
		row.LTSFrom = parseSQLiteDate(ltsFrom)
		row.IsEOAS = isEOAS != 0
		row.EOASFrom = parseSQLiteDate(eoasFrom)
		row.IsEOL = isEOL != 0
		row.EOLFrom = parseSQLiteDate(eolFrom)
		row.IsDiscontinued = isDiscontinued != 0
		row.DiscontinuedFrom = parseSQLiteDate(discontinuedFrom)
		if isEOES.Valid {
			value := isEOES.Int64 != 0
			row.IsEOES = &value
		}
		row.EOESFrom = parseSQLiteDate(eoesFrom)
		row.IsMaintained = maintained != 0
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate lifecycle releases: %w", err)
	}
	return out, nil
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

type lifecycleReleaseRow struct {
	ID               string
	Ecosystem        string
	PackageName      string
	ProductSlug      string
	ProductLabel     string
	Cycle            string
	Latest           string
	ReleaseDate      *time.Time
	IsLTS            bool
	LTSFrom          *time.Time
	IsEOAS           bool
	EOASFrom         *time.Time
	IsEOL            bool
	EOLFrom          *time.Time
	IsDiscontinued   bool
	DiscontinuedFrom *time.Time
	IsEOES           *bool
	EOESFrom         *time.Time
	IsMaintained     bool
}

func longestLifecycleMatches(rows []lifecycleReleaseRow, version string) []lifecycleReleaseRow {
	if strings.TrimSpace(version) == "" {
		return nil
	}
	best := make(map[string]lifecycleReleaseRow)
	for _, row := range rows {
		if !lifecycleCycleMatches(version, row.Cycle) {
			continue
		}
		current, ok := best[row.ProductSlug]
		if !ok || len(row.Cycle) > len(current.Cycle) {
			best[row.ProductSlug] = row
		}
	}
	matches := make([]lifecycleReleaseRow, 0, len(best))
	for _, row := range best {
		matches = append(matches, row)
	}
	return matches
}

func lifecycleCycleMatches(version, cycle string) bool {
	version = strings.TrimSpace(version)
	cycle = strings.TrimSpace(cycle)
	if version == "" || cycle == "" {
		return false
	}
	return version == cycle || strings.HasPrefix(version, cycle+".")
}

func lifecycleFindingForRelease(pkg db.PackageQuery, row lifecycleReleaseRow, now time.Time) (domain.Finding, bool) {
	if row.IsEOL || dateOnOrBefore(row.EOLFrom, now) {
		return buildLifecycleFinding(pkg, row, domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol", "is end-of-life"), true
	}
	if dateWithin(row.EOLFrom, now, 90*24*time.Hour) {
		return buildLifecycleFinding(pkg, row, domain.FindingTypeLifecycle, domain.SeverityMedium, "eol_soon", "reaches end-of-life soon"), true
	}
	if row.IsEOAS || dateOnOrBefore(row.EOASFrom, now) {
		return buildLifecycleFinding(pkg, row, domain.FindingTypeLifecycle, domain.SeverityLow, "security_support_only", "is in security support only"), true
	}
	return domain.Finding{}, false
}

func buildLifecycleFinding(pkg db.PackageQuery, row lifecycleReleaseRow, typ domain.FindingType, severity domain.Severity, riskType, phrase string) domain.Finding {
	productName := strings.TrimSpace(row.ProductLabel)
	if productName == "" {
		productName = row.ProductSlug
	}
	url := fmt.Sprintf("https://endoflife.date/%s", row.ProductSlug)
	return domain.Finding{
		Name:       pkg.Name,
		Version:    pkg.Version,
		Ecosystem:  domain.Ecosystem(pkg.Ecosystem),
		Type:       typ,
		Severity:   severity,
		AdvisoryID: fmt.Sprintf("endoflife:%s:%s:%s", row.ProductSlug, row.Cycle, riskType),
		Title:      fmt.Sprintf("%s %s %s", productName, row.Cycle, phrase),
		URL:        url,
		Resources: []domain.ResourceLink{
			{Label: lifecycleSource, URL: url},
		},
		RiskType: riskType,
		Source:   lifecycleSource,
	}
}

func dateOnOrBefore(date *time.Time, now time.Time) bool {
	return date != nil && !date.After(now)
}

func dateWithin(date *time.Time, now time.Time, window time.Duration) bool {
	return date != nil && date.After(now) && !date.After(now.Add(window))
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
