package postgres

import (
	"context"
	"fmt"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
	"github.com/jackc/pgx/v5"
)

const lifecycleSource = "endoflife.date"

func (s *Store) ReplaceLifecycleProducts(ctx context.Context, products []db.LifecycleProduct) (int, error) {
	slugs := lifecycleProductSlugs(products)

	var deleted int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := upsertLifecycleProductsTx(ctx, tx, products); err != nil {
			return err
		}
		var err error
		deleted, err = deleteLifecycleProductsNotInTx(ctx, tx, slugs)
		return err
	})
	return deleted, err
}

func lifecycleProductSlugs(products []db.LifecycleProduct) []string {
	slugs := make([]string, 0, len(products))
	seen := make(map[string]struct{}, len(products))
	for _, product := range products {
		slug := strings.TrimSpace(product.ProductSlug)
		if slug == "" {
			continue
		}
		if _, ok := seen[slug]; ok {
			continue
		}
		seen[slug] = struct{}{}
		slugs = append(slugs, slug)
	}
	return slugs
}

func upsertLifecycleProductsTx(ctx context.Context, tx pgx.Tx, products []db.LifecycleProduct) error {
	if len(products) == 0 {
		return nil
	}

	for _, product := range products {
		productSlug, ok, err := upsertLifecycleProductPhaseTx(ctx, tx, product)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}

		if err := recordLifecycleTombstonesForProduct(ctx, tx, productSlug); err != nil {
			return err
		}
		if err := deleteLifecycleProductChildrenTx(ctx, tx, productSlug); err != nil {
			return err
		}
		if err := upsertLifecycleReleasePhaseTx(ctx, tx, productSlug, product.Releases); err != nil {
			return err
		}
		if err := upsertLifecyclePackageMapPhaseTx(ctx, tx, productSlug, product.PackageMaps); err != nil {
			return err
		}

		if err := clearCurrentLifecycleTombstonesForProduct(ctx, tx, productSlug); err != nil {
			return err
		}
	}
	return nil
}

func upsertLifecycleProductPhaseTx(ctx context.Context, tx pgx.Tx, product db.LifecycleProduct) (string, bool, error) {
	productSlug := strings.TrimSpace(product.ProductSlug)
	if productSlug == "" {
		return "", false, nil
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
		return "", false, fmt.Errorf("postgres: upsert lifecycle product %s: %w", productSlug, err)
	}
	return productSlug, true, nil
}

func deleteLifecycleProductChildrenTx(ctx context.Context, tx pgx.Tx, productSlug string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM lifecycle_releases WHERE product_slug = $1`, productSlug); err != nil {
		return fmt.Errorf("postgres: delete lifecycle releases for %s: %w", productSlug, err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM lifecycle_package_map WHERE product_slug = $1`, productSlug); err != nil {
		return fmt.Errorf("postgres: delete lifecycle package maps for %s: %w", productSlug, err)
	}
	return nil
}

func upsertLifecycleReleasePhaseTx(ctx context.Context, tx pgx.Tx, productSlug string, releases []db.LifecycleRelease) error {
	for _, release := range releases {
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
	return nil
}

func upsertLifecyclePackageMapPhaseTx(ctx context.Context, tx pgx.Tx, productSlug string, packageMaps []db.LifecyclePackageMap) error {
	for _, packageMap := range packageMaps {
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
	return nil
}

func deleteLifecycleProductsNotInTx(ctx context.Context, tx pgx.Tx, productSlugs []string) (int, error) {
	rows, err := tx.Query(ctx, `
			SELECT product_slug
			FROM lifecycle_products
			WHERE source = $1
			  AND NOT (product_slug = ANY($2))`,
		lifecycleSource,
		productSlugs,
	)
	if err != nil {
		return 0, fmt.Errorf("postgres: select stale lifecycle products: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	staleSlugs := make([]string, 0)
	for rows.Next() {
		var productSlug string
		if err := rows.Scan(&productSlug); err != nil {
			return 0, fmt.Errorf("postgres: scan stale lifecycle product: %w", err)
		}
		staleSlugs = append(staleSlugs, productSlug)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("postgres: iterate stale lifecycle products: %w", err)
	}

	for _, productSlug := range staleSlugs {
		if err := recordLifecycleTombstonesForProduct(ctx, tx, productSlug); err != nil {
			return 0, err
		}
	}

	result, err := tx.Exec(ctx, `
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

func recordLifecycleTombstonesForProduct(ctx context.Context, tx pgx.Tx, productSlug string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO lifecycle_sync_tombstones (id, ecosystem, name, product_slug, cycle, updated_at)
		SELECT
			'endoflife:' || m.ecosystem || ':' || m.name || ':' || p.product_slug || ':' || r.cycle,
			m.ecosystem,
			m.name,
			p.product_slug,
			r.cycle,
			NOW()
		FROM lifecycle_package_map m
		INNER JOIN lifecycle_products p ON p.product_slug = m.product_slug
		INNER JOIN lifecycle_releases r ON r.product_slug = p.product_slug
		WHERE p.product_slug = $1
		ON CONFLICT (id) DO UPDATE SET
			ecosystem = EXCLUDED.ecosystem,
			name = EXCLUDED.name,
			product_slug = EXCLUDED.product_slug,
			cycle = EXCLUDED.cycle,
			updated_at = EXCLUDED.updated_at`,
		productSlug,
	); err != nil {
		return fmt.Errorf("postgres: record lifecycle tombstones for %s: %w", productSlug, err)
	}
	return nil
}

func clearCurrentLifecycleTombstonesForProduct(ctx context.Context, tx pgx.Tx, productSlug string) error {
	if _, err := tx.Exec(ctx, `
		DELETE FROM lifecycle_sync_tombstones t
		USING lifecycle_package_map m
		INNER JOIN lifecycle_products p ON p.product_slug = m.product_slug
		INNER JOIN lifecycle_releases r ON r.product_slug = p.product_slug
		WHERE p.product_slug = $1
		  AND t.id = 'endoflife:' || m.ecosystem || ':' || m.name || ':' || p.product_slug || ':' || r.cycle`,
		productSlug,
	); err != nil {
		return fmt.Errorf("postgres: clear current lifecycle tombstones for %s: %w", productSlug, err)
	}
	return nil
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
	defer ioutils.CloseSilently(rows)

	rowsByPackage := make(map[ecoName][]lifecyclepolicy.ReleaseRow)
	for rows.Next() {
		var row lifecyclepolicy.ReleaseRow
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
			matchesByProduct := lifecyclepolicy.LongestMatchingReleases(rows, pkg.Version)
			for _, row := range matchesByProduct {
				finding, ok := lifecyclepolicy.FindingForRelease(lifecyclePackageQuery(pkg), row, now)
				if ok {
					findings = append(findings, finding)
				}
			}
		}
	}
	return findings, nil
}

func lifecyclePackageQuery(pkg db.PackageQuery) lifecyclepolicy.PackageQuery {
	return lifecyclepolicy.PackageQuery{
		Ecosystem: pkg.Ecosystem,
		Name:      pkg.Name,
		Version:   pkg.Version,
	}
}
