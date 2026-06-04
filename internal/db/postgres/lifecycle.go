package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
	"github.com/jackc/pgx/v5"
)

const lifecycleSource = "endoflife.date"

func (s *Store) UpsertLifecycleProducts(ctx context.Context, products []db.LifecycleProduct) error {
	if len(products) == 0 {
		return nil
	}

	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		for _, product := range products {
			productSlug := strings.TrimSpace(product.ProductSlug)
			if productSlug == "" {
				continue
			}
			name := strings.TrimSpace(product.Name)
			if name == "" {
				name = productSlug
			}

			if _, err := tx.Exec(ctx, `
				INSERT INTO lifecycle_products (
					product_slug, name, category, source, identifiers, raw, updated_at
				) VALUES (
					$1, $2, $3, $4, $5, $6, now()
				)
				ON CONFLICT (product_slug) DO UPDATE SET
					name = EXCLUDED.name,
					category = EXCLUDED.category,
					source = EXCLUDED.source,
					identifiers = EXCLUDED.identifiers,
					raw = EXCLUDED.raw,
					updated_at = now()`,
				productSlug,
				name,
				product.Category,
				lifecycleSource,
				normalizeJSON(product.Identifiers, []byte("[]")),
				normalizeJSON(product.Raw, []byte("{}")),
			); err != nil {
				return fmt.Errorf("postgres: upsert lifecycle product %s: %w", productSlug, err)
			}

			if _, err := tx.Exec(ctx, `DELETE FROM lifecycle_releases WHERE product_slug = $1`, productSlug); err != nil {
				return fmt.Errorf("postgres: delete lifecycle releases for %s: %w", productSlug, err)
			}
			if _, err := tx.Exec(ctx, `DELETE FROM lifecycle_package_map WHERE product_slug = $1`, productSlug); err != nil {
				return fmt.Errorf("postgres: delete lifecycle package maps for %s: %w", productSlug, err)
			}

			for _, release := range product.Releases {
				cycle := strings.TrimSpace(release.Cycle)
				if cycle == "" {
					continue
				}
				releaseProductSlug := strings.TrimSpace(release.ProductSlug)
				if releaseProductSlug == "" {
					releaseProductSlug = productSlug
				}
				if _, err := tx.Exec(ctx, `
					INSERT INTO lifecycle_releases (
						product_slug, cycle, latest, release_date, is_lts, lts_from,
						is_eoas, eoas_from, is_eol, eol_from, is_discontinued,
						discontinued_from, is_eoes, eoes_from, is_maintained, raw, updated_at
					) VALUES (
						$1, $2, $3, $4, $5, $6,
						$7, $8, $9, $10, $11,
						$12, $13, $14, $15, $16, now()
					)
					ON CONFLICT (product_slug, cycle) DO UPDATE SET
						latest = EXCLUDED.latest,
						release_date = EXCLUDED.release_date,
						is_lts = EXCLUDED.is_lts,
						lts_from = EXCLUDED.lts_from,
						is_eoas = EXCLUDED.is_eoas,
						eoas_from = EXCLUDED.eoas_from,
						is_eol = EXCLUDED.is_eol,
						eol_from = EXCLUDED.eol_from,
						is_discontinued = EXCLUDED.is_discontinued,
						discontinued_from = EXCLUDED.discontinued_from,
						is_eoes = EXCLUDED.is_eoes,
						eoes_from = EXCLUDED.eoes_from,
						is_maintained = EXCLUDED.is_maintained,
						raw = EXCLUDED.raw,
						updated_at = now()`,
					releaseProductSlug,
					cycle,
					release.Latest,
					release.ReleaseDate,
					release.IsLTS,
					release.LTSFrom,
					release.IsEOAS,
					release.EOASFrom,
					release.IsEOL,
					release.EOLFrom,
					release.IsDiscontinued,
					release.DiscontinuedFrom,
					release.IsEOES,
					release.EOESFrom,
					release.IsMaintained,
					normalizeJSON(release.Raw, []byte("{}")),
				); err != nil {
					return fmt.Errorf("postgres: upsert lifecycle release %s/%s: %w", releaseProductSlug, cycle, err)
				}
			}

			for _, packageMap := range product.PackageMaps {
				ecosystem := strings.TrimSpace(packageMap.Ecosystem)
				name := normalizePackageName(ecosystem, strings.TrimSpace(packageMap.Name))
				if ecosystem == "" || name == "" {
					continue
				}
				mapProductSlug := strings.TrimSpace(packageMap.ProductSlug)
				if mapProductSlug == "" {
					mapProductSlug = productSlug
				}
				source := strings.TrimSpace(packageMap.Source)
				if source == "" {
					source = lifecycleSource
				}
				if _, err := tx.Exec(ctx, `
					INSERT INTO lifecycle_package_map (
						ecosystem, name, product_slug, purl_type, purl_namespace,
						purl_name, source, updated_at
					) VALUES (
						$1, $2, $3, $4, $5, $6, $7, now()
					)
					ON CONFLICT (ecosystem, name, product_slug) DO UPDATE SET
						purl_type = EXCLUDED.purl_type,
						purl_namespace = EXCLUDED.purl_namespace,
						purl_name = EXCLUDED.purl_name,
						source = EXCLUDED.source,
						updated_at = now()`,
					ecosystem,
					name,
					mapProductSlug,
					packageMap.PURLType,
					packageMap.PURLNamespace,
					packageMap.PURLName,
					source,
				); err != nil {
					return fmt.Errorf("postgres: upsert lifecycle package map %s/%s: %w", ecosystem, name, err)
				}
			}
		}
		return nil
	})
}

func (s *Store) DeleteLifecycleProductsNotIn(ctx context.Context, productSlugs []string) (int, error) {
	if len(productSlugs) == 0 {
		return 0, nil
	}
	result, err := s.pool.Exec(ctx, `
		DELETE FROM lifecycle_products
		WHERE source = $1
		  AND NOT (product_slug = ANY($2))`,
		lifecycleSource,
		productSlugs,
	)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete stale lifecycle products: %w", err)
	}
	return int(result.RowsAffected()), nil
}

func (s *Store) FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	type ecoName struct{ ecosystem, name string }
	seen := make(map[ecoName]struct{}, len(packages))
	versionMap := make(map[ecoName][]db.PackageQuery, len(packages))
	args := make([]any, 0)
	placeholders := make([]string, 0)
	paramIdx := 1
	for _, pkg := range packages {
		ecosystem := strings.TrimSpace(pkg.Ecosystem)
		name := normalizePackageName(ecosystem, strings.TrimSpace(pkg.Name))
		if ecosystem == "" || name == "" {
			continue
		}
		key := ecoName{ecosystem: ecosystem, name: name}
		versionMap[key] = append(versionMap[key], db.PackageQuery{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   strings.TrimSpace(pkg.Version),
		})
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d)", paramIdx, paramIdx+1))
		args = append(args, ecosystem, name)
		paramIdx += 2
	}
	if len(placeholders) == 0 {
		return nil, nil
	}

	query := `
		SELECT
			m.ecosystem,
			m.name,
			p.product_slug,
			p.name,
			r.cycle,
			r.latest,
			r.release_date,
			r.is_lts,
			r.lts_from,
			r.is_eoas,
			r.eoas_from,
			r.is_eol,
			r.eol_from,
			r.is_discontinued,
			r.discontinued_from,
			r.is_eoes,
			r.eoes_from,
			r.is_maintained
		FROM lifecycle_package_map m
		INNER JOIN lifecycle_products p ON p.product_slug = m.product_slug
		INNER JOIN lifecycle_releases r ON r.product_slug = p.product_slug
		WHERE (m.ecosystem, m.name) IN (VALUES ` + strings.Join(placeholders, ", ") + `)
		ORDER BY m.ecosystem ASC, m.name ASC, p.product_slug ASC, length(r.cycle) DESC, r.cycle DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: find lifecycle findings batch: %w", err)
	}
	defer closeSilently(rows)

	rowsByPackage := make(map[ecoName][]lifecycleReleaseRow)
	for rows.Next() {
		var row lifecycleReleaseRow
		if err := rows.Scan(
			&row.Ecosystem,
			&row.PackageName,
			&row.ProductSlug,
			&row.ProductName,
			&row.Release.Cycle,
			&row.Release.Latest,
			&row.Release.ReleaseDate,
			&row.Release.IsLTS,
			&row.Release.LTSFrom,
			&row.Release.IsEOAS,
			&row.Release.EOASFrom,
			&row.Release.IsEOL,
			&row.Release.EOLFrom,
			&row.Release.IsDiscontinued,
			&row.Release.DiscontinuedFrom,
			&row.Release.IsEOES,
			&row.Release.EOESFrom,
			&row.Release.IsMaintained,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan lifecycle row: %w", err)
		}
		row.Release.ProductSlug = row.ProductSlug
		key := ecoName{ecosystem: row.Ecosystem, name: row.PackageName}
		rowsByPackage[key] = append(rowsByPackage[key], row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate lifecycle rows: %w", err)
	}

	findings := make([]domain.Finding, 0)
	for key, packageVersions := range versionMap {
		rows := rowsByPackage[key]
		for _, pkg := range packageVersions {
			matchesByProduct := longestLifecycleMatches(rows, pkg.Version)
			for _, row := range matchesByProduct {
				finding, ok := lifecycleFindingForRelease(pkg, row, now)
				if ok {
					findings = append(findings, finding)
				}
			}
		}
	}
	return findings, nil
}

type lifecycleReleaseRow struct {
	Ecosystem   string
	PackageName string
	ProductSlug string
	ProductName string
	Release     db.LifecycleRelease
}

func longestLifecycleMatches(rows []lifecycleReleaseRow, version string) []lifecycleReleaseRow {
	if strings.TrimSpace(version) == "" {
		return nil
	}

	best := make(map[string]lifecycleReleaseRow)
	for _, row := range rows {
		if !lifecycleCycleMatches(version, row.Release.Cycle) {
			continue
		}
		current, ok := best[row.ProductSlug]
		if !ok || len(row.Release.Cycle) > len(current.Release.Cycle) {
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
	release := row.Release
	if release.IsEOL || dateOnOrBefore(release.EOLFrom, now) {
		return buildLifecycleFinding(pkg, row, domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol", "is end-of-life"), true
	}
	if dateWithin(release.EOLFrom, now, 90*24*time.Hour) {
		return buildLifecycleFinding(pkg, row, domain.FindingTypeLifecycle, domain.SeverityMedium, "eol_soon", "reaches end-of-life soon"), true
	}
	if release.IsEOAS || dateOnOrBefore(release.EOASFrom, now) {
		return buildLifecycleFinding(pkg, row, domain.FindingTypeLifecycle, domain.SeverityLow, "security_support_only", "is in security support only"), true
	}
	return domain.Finding{}, false
}

func buildLifecycleFinding(pkg db.PackageQuery, row lifecycleReleaseRow, typ domain.FindingType, severity domain.Severity, riskType, phrase string) domain.Finding {
	productName := strings.TrimSpace(row.ProductName)
	if productName == "" {
		productName = row.ProductSlug
	}
	url := fmt.Sprintf("https://endoflife.date/%s", row.ProductSlug)
	title := fmt.Sprintf("%s %s %s", productName, row.Release.Cycle, phrase)

	return domain.Finding{
		Name:       pkg.Name,
		Version:    pkg.Version,
		Ecosystem:  domain.Ecosystem(pkg.Ecosystem),
		Type:       typ,
		Severity:   severity,
		AdvisoryID: fmt.Sprintf("endoflife:%s:%s:%s", row.ProductSlug, row.Release.Cycle, riskType),
		Title:      title,
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
