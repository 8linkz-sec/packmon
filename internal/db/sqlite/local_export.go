package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

// LocalDatabaseCounts contains aggregate local database counts for CLI info
// and freshness reporting without exposing the SQLite schema to cmd packages.
type LocalDatabaseCounts struct {
	Vulnerabilities int
	Malicious       int
	Reputation      int
	Lifecycle       int
	HistoryEntries  int
}

// LocalVulnerabilityEntry is one vulnerability row from the local SQLite
// read-model export.
type LocalVulnerabilityEntry struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// VersionRanges contains the version constraint JSON synced from the
	// server's vulnerability affected-package data.
	VersionRanges  json.RawMessage `json:"version_ranges"`
	Severity       string          `json:"severity"`
	CVSSScore      *float64        `json:"cvss_score,omitempty"`
	EPSSScore      *float64        `json:"epss_score,omitempty"`
	EPSSPercentile *float64        `json:"epss_percentile,omitempty"`
	CISAKEV        bool            `json:"cisa_kev"`
	Summary        string          `json:"summary"`
	Source         string          `json:"source"`
}

// LocalMaliciousEntry is one malicious-package finding row from the local
// SQLite read-model export.
type LocalMaliciousEntry struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// VersionRanges contains optional version constraint JSON for the malicious
	// finding.
	VersionRanges json.RawMessage `json:"version_ranges,omitempty"`
	// Versions contains optional exact affected-version JSON, encoded as an
	// array of version strings.
	Versions json.RawMessage `json:"versions,omitempty"`
	// RiskType is the machine-readable malicious risk category.
	RiskType string `json:"risk_type"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Source   string `json:"source"`
}

// LocalReputationEntry is one synced package reputation finding row from the
// local SQLite read-model export.
type LocalReputationEntry struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Type is the canonical finding type string derived from reputation status.
	Type string `json:"type"`
	// RiskType is the machine-readable reputation risk category.
	RiskType string `json:"risk_type"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// LocalLifecycleEntry is one synced lifecycle release row from the local SQLite
// read-model export.
type LocalLifecycleEntry struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	// ProductSlug is the lifecycle product identifier used by the upstream
	// lifecycle feed.
	ProductSlug string `json:"product_slug"`
	// ProductLabel is the lifecycle product display label.
	ProductLabel string `json:"product_label"`
	// Cycle is the lifecycle release cycle identifier for the product.
	Cycle  string `json:"cycle"`
	Latest string `json:"latest"`
	// ReleaseDate is the lifecycle release date, when known, as YYYY-MM-DD.
	ReleaseDate *string `json:"release_date,omitempty"`
	// IsLTS and LTSFrom describe long-term-support state and its start date.
	IsLTS   bool    `json:"is_lts"`
	LTSFrom *string `json:"lts_from,omitempty"`
	// IsEOAS and EOASFrom describe end-of-active-support state and its date.
	IsEOAS   bool    `json:"is_eoas"`
	EOASFrom *string `json:"eoas_from,omitempty"`
	// IsEOL and EOLFrom describe end-of-life state and its date.
	IsEOL   bool    `json:"is_eol"`
	EOLFrom *string `json:"eol_from,omitempty"`
	// IsDiscontinued and DiscontinuedFrom describe discontinued state and its
	// date.
	IsDiscontinued   bool    `json:"is_discontinued"`
	DiscontinuedFrom *string `json:"discontinued_from,omitempty"`
	// IsEOES and EOESFrom describe optional end-of-extended-support state and
	// its date.
	IsEOES   *bool   `json:"is_eoes,omitempty"`
	EOESFrom *string `json:"eoes_from,omitempty"`
	// IsMaintained reports whether the lifecycle feed currently marks the cycle
	// as maintained.
	IsMaintained bool `json:"is_maintained"`
}

func (s *Store) LocalDatabaseCounts(ctx context.Context) (*LocalDatabaseCounts, error) {
	counts := &LocalDatabaseCounts{}
	if err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(DISTINCT id) FROM vulnerabilities_local),
			(SELECT COUNT(*) FROM malicious_local),
			(SELECT COUNT(*) FROM reputation_findings_local),
			(SELECT COUNT(*) FROM lifecycle_releases_local),
			(SELECT COUNT(*) FROM scan_history)`,
	).Scan(&counts.Vulnerabilities, &counts.Malicious, &counts.Reputation, &counts.Lifecycle, &counts.HistoryEntries); err != nil {
		return nil, fmt.Errorf("read local database counts: %w", err)
	}
	return counts, nil
}

func (s *Store) StreamLocalVulnerabilities(ctx context.Context, emit func(LocalVulnerabilityEntry) error) error {
	if emit == nil {
		return fmt.Errorf("local vulnerability export emitter is nil")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, epss_percentile, cisa_kev, summary, source
		FROM vulnerabilities_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local vulnerabilities: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			item           LocalVulnerabilityEntry
			versionRanges  sql.NullString
			severity       sql.NullString
			cvss           sql.NullFloat64
			epss           sql.NullFloat64
			epssPercentile sql.NullFloat64
			cisaKEV        int
			summary        sql.NullString
			source         sql.NullString
		)

		if err := rows.Scan(&item.ID, &item.Ecosystem, &item.Name, &versionRanges, &severity, &cvss, &epss, &epssPercentile, &cisaKEV, &summary, &source); err != nil {
			return fmt.Errorf("scan local vulnerability row: %w", err)
		}

		item.VersionRanges = json.RawMessage("[]")
		if versionRanges.Valid && strings.TrimSpace(versionRanges.String) != "" {
			item.VersionRanges = json.RawMessage(versionRanges.String)
		}
		item.Severity = strings.TrimSpace(severity.String)
		item.Summary = summary.String
		item.Source = localExportSource(source.String)
		item.CISAKEV = cisaKEV > 0
		if cvss.Valid {
			value := cvss.Float64
			item.CVSSScore = &value
		}
		if epss.Valid {
			value := epss.Float64
			item.EPSSScore = &value
		}
		if epssPercentile.Valid {
			value := epssPercentile.Float64
			item.EPSSPercentile = &value
		}

		if err := emit(item); err != nil {
			return fmt.Errorf("write local vulnerability row: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local vulnerabilities: %w", err)
	}
	return nil
}

func (s *Store) StreamLocalMalicious(ctx context.Context, emit func(LocalMaliciousEntry) error) error {
	if emit == nil {
		return fmt.Errorf("local malicious export emitter is nil")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, name, version_ranges, versions, risk_type, severity, summary, source
		FROM malicious_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local malicious findings: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			item     LocalMaliciousEntry
			ranges   sql.NullString
			versions sql.NullString
			severity sql.NullString
			summary  sql.NullString
			source   sql.NullString
		)

		if err := rows.Scan(&item.ID, &item.Ecosystem, &item.Name, &ranges, &versions, &item.RiskType, &severity, &summary, &source); err != nil {
			return fmt.Errorf("scan local malicious row: %w", err)
		}

		item.Severity = strings.TrimSpace(severity.String)
		item.Summary = summary.String
		item.Source = localExportSource(source.String)
		if ranges.Valid && strings.TrimSpace(ranges.String) != "" {
			item.VersionRanges = json.RawMessage(ranges.String)
		}
		if versions.Valid && strings.TrimSpace(versions.String) != "" {
			item.Versions = json.RawMessage(versions.String)
		}

		if err := emit(item); err != nil {
			return fmt.Errorf("write local malicious row: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local malicious findings: %w", err)
	}
	return nil
}

func (s *Store) StreamLocalReputation(ctx context.Context, emit func(LocalReputationEntry) error) error {
	if emit == nil {
		return fmt.Errorf("local reputation export emitter is nil")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, name, version, type, risk_type, severity, summary
		FROM reputation_findings_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local reputation findings: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			item     LocalReputationEntry
			severity sql.NullString
			summary  sql.NullString
		)

		if err := rows.Scan(&item.ID, &item.Ecosystem, &item.Name, &item.Version, &item.Type, &item.RiskType, &severity, &summary); err != nil {
			return fmt.Errorf("scan local reputation row: %w", err)
		}

		item.Severity = string(domain.NormalizeFindingSeverity(domain.Finding{
			Type:     domain.FindingType(item.Type),
			RiskType: item.RiskType,
			Severity: domain.Severity(strings.TrimSpace(severity.String)),
		}))
		item.Summary = summary.String
		if err := emit(item); err != nil {
			return fmt.Errorf("write local reputation row: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local reputation findings: %w", err)
	}
	return nil
}

func (s *Store) StreamLocalLifecycle(ctx context.Context, emit func(LocalLifecycleEntry) error) error {
	if emit == nil {
		return fmt.Errorf("local lifecycle export emitter is nil")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			id, ecosystem, name, product_slug, product_label, cycle, latest,
			release_date, is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			is_discontinued, discontinued_from, is_eoes, eoes_from, is_maintained
		FROM lifecycle_releases_local
		ORDER BY ecosystem, name, product_slug, cycle, id`)
	if err != nil {
		return fmt.Errorf("query local lifecycle releases: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			item             LocalLifecycleEntry
			releaseDate      sql.NullString
			isLTS            int
			ltsFrom          sql.NullString
			isEOAS           int
			eoasFrom         sql.NullString
			isEOL            int
			eolFrom          sql.NullString
			isDiscontinued   int
			discontinuedFrom sql.NullString
			isEOES           sql.NullInt64
			eoesFrom         sql.NullString
			isMaintained     int
		)

		if err := rows.Scan(
			&item.ID, &item.Ecosystem, &item.Name, &item.ProductSlug, &item.ProductLabel, &item.Cycle, &item.Latest,
			&releaseDate, &isLTS, &ltsFrom, &isEOAS, &eoasFrom, &isEOL, &eolFrom,
			&isDiscontinued, &discontinuedFrom, &isEOES, &eoesFrom, &isMaintained,
		); err != nil {
			return fmt.Errorf("scan local lifecycle row: %w", err)
		}

		item.ReleaseDate = localDBStringPtr(releaseDate)
		item.IsLTS = isLTS > 0
		item.LTSFrom = localDBStringPtr(ltsFrom)
		item.IsEOAS = isEOAS > 0
		item.EOASFrom = localDBStringPtr(eoasFrom)
		item.IsEOL = isEOL > 0
		item.EOLFrom = localDBStringPtr(eolFrom)
		item.IsDiscontinued = isDiscontinued > 0
		item.DiscontinuedFrom = localDBStringPtr(discontinuedFrom)
		item.IsEOES = localDBBoolPtr(isEOES)
		item.EOESFrom = localDBStringPtr(eoesFrom)
		item.IsMaintained = isMaintained > 0

		if err := emit(item); err != nil {
			return fmt.Errorf("write local lifecycle row: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local lifecycle releases: %w", err)
	}
	return nil
}

func (s *Store) StreamLocalScanHistory(ctx context.Context, emit func(ScanEntry) error) error {
	if emit == nil {
		return fmt.Errorf("local scan-history export emitter is nil")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, repo_name, branch, "commit", scanned_at, packages_count, findings_count, finding_ids, finding_severities
		FROM scan_history
		ORDER BY scanned_at DESC`)
	if err != nil {
		return fmt.Errorf("query local scan history: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			entry        ScanEntry
			repoName     *string
			branch       *string
			commit       *string
			scannedAtStr string
			idsJSON      *string
			sevsJSON     *string
		)

		if err := rows.Scan(
			&entry.ID, &repoName, &branch, &commit, &scannedAtStr,
			&entry.PackagesCount, &entry.FindingsCount,
			&idsJSON, &sevsJSON,
		); err != nil {
			return fmt.Errorf("scan local scan-history row: %w", err)
		}

		if repoName != nil {
			entry.RepoName = *repoName
		}
		if branch != nil {
			entry.Branch = *branch
		}
		if commit != nil {
			entry.Commit = *commit
		}

		parsedAt, err := time.Parse(time.RFC3339, scannedAtStr)
		if err != nil {
			return fmt.Errorf("decode local scan-history row %d scanned_at: %w", entry.ID, err)
		}
		entry.ScannedAt = parsedAt

		if idsJSON != nil && *idsJSON != "" {
			if err := json.Unmarshal([]byte(*idsJSON), &entry.FindingIDs); err != nil {
				return fmt.Errorf("decode local scan-history row %d finding_ids: %w", entry.ID, err)
			}
		}
		if sevsJSON != nil && *sevsJSON != "" {
			if err := json.Unmarshal([]byte(*sevsJSON), &entry.FindingSeverities); err != nil {
				return fmt.Errorf("decode local scan-history row %d finding_severities: %w", entry.ID, err)
			}
		}

		if err := emit(entry); err != nil {
			return fmt.Errorf("write local scan-history row: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local scan history: %w", err)
	}
	return nil
}

func localExportSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "local"
	}
	return source
}

func localDBStringPtr(value sql.NullString) *string {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil
	}
	out := value.String
	return &out
}

func localDBBoolPtr(value sql.NullInt64) *bool {
	if !value.Valid {
		return nil
	}
	out := value.Int64 > 0
	return &out
}
