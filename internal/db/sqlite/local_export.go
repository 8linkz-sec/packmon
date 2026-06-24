package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
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

// LocalDatabaseExport contains the local database rows exposed by
// `packmon db export`.
type LocalDatabaseExport struct {
	Vulnerabilities []LocalVulnerabilityEntry
	Malicious       []LocalMaliciousEntry
	Reputation      []LocalReputationEntry
	Lifecycle       []LocalLifecycleEntry
	ScanHistory     []ScanEntry
}

type LocalVulnerabilityEntry struct {
	ID             string          `json:"id"`
	Ecosystem      string          `json:"ecosystem"`
	Name           string          `json:"name"`
	VersionRanges  json.RawMessage `json:"version_ranges"`
	Severity       string          `json:"severity"`
	CVSSScore      *float64        `json:"cvss_score,omitempty"`
	EPSSScore      *float64        `json:"epss_score,omitempty"`
	EPSSPercentile *float64        `json:"epss_percentile,omitempty"`
	CISAKEV        bool            `json:"cisa_kev"`
	Summary        string          `json:"summary"`
	Source         string          `json:"source"`
}

type LocalMaliciousEntry struct {
	ID            string          `json:"id"`
	Ecosystem     string          `json:"ecosystem"`
	Name          string          `json:"name"`
	VersionRanges json.RawMessage `json:"version_ranges,omitempty"`
	Versions      json.RawMessage `json:"versions,omitempty"`
	RiskType      string          `json:"risk_type"`
	Severity      string          `json:"severity"`
	Summary       string          `json:"summary"`
	Source        string          `json:"source"`
}

type LocalReputationEntry struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	RiskType  string `json:"risk_type"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
}

type LocalLifecycleEntry struct {
	ID               string  `json:"id"`
	Ecosystem        string  `json:"ecosystem"`
	Name             string  `json:"name"`
	ProductSlug      string  `json:"product_slug"`
	ProductLabel     string  `json:"product_label"`
	Cycle            string  `json:"cycle"`
	Latest           string  `json:"latest"`
	ReleaseDate      *string `json:"release_date,omitempty"`
	IsLTS            bool    `json:"is_lts"`
	LTSFrom          *string `json:"lts_from,omitempty"`
	IsEOAS           bool    `json:"is_eoas"`
	EOASFrom         *string `json:"eoas_from,omitempty"`
	IsEOL            bool    `json:"is_eol"`
	EOLFrom          *string `json:"eol_from,omitempty"`
	IsDiscontinued   bool    `json:"is_discontinued"`
	DiscontinuedFrom *string `json:"discontinued_from,omitempty"`
	IsEOES           *bool   `json:"is_eoes,omitempty"`
	EOESFrom         *string `json:"eoes_from,omitempty"`
	IsMaintained     bool    `json:"is_maintained"`
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

func (s *Store) ExportLocalDatabase(ctx context.Context) (*LocalDatabaseExport, error) {
	payload := &LocalDatabaseExport{
		Vulnerabilities: make([]LocalVulnerabilityEntry, 0),
		Malicious:       make([]LocalMaliciousEntry, 0),
		Reputation:      make([]LocalReputationEntry, 0),
		Lifecycle:       make([]LocalLifecycleEntry, 0),
		ScanHistory:     make([]ScanEntry, 0),
	}

	scanHistory, err := s.GetRecentScans(ctx, "", -1)
	if err != nil {
		return nil, fmt.Errorf("query local scan history: %w", err)
	}
	payload.ScanHistory = scanHistory

	if err := s.exportLocalVulnerabilities(ctx, payload); err != nil {
		return nil, err
	}
	if err := s.exportLocalMalicious(ctx, payload); err != nil {
		return nil, err
	}
	if err := s.exportLocalReputation(ctx, payload); err != nil {
		return nil, err
	}
	if err := s.exportLocalLifecycle(ctx, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (s *Store) exportLocalVulnerabilities(ctx context.Context, payload *LocalDatabaseExport) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, epss_percentile, cisa_kev, summary, source
		FROM vulnerabilities_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local vulnerabilities: %w", err)
	}
	defer closeSilently(rows)

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

		payload.Vulnerabilities = append(payload.Vulnerabilities, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local vulnerabilities: %w", err)
	}
	return nil
}

func (s *Store) exportLocalMalicious(ctx context.Context, payload *LocalDatabaseExport) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, name, version_ranges, versions, risk_type, severity, summary, source
		FROM malicious_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local malicious findings: %w", err)
	}
	defer closeSilently(rows)

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

		payload.Malicious = append(payload.Malicious, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local malicious findings: %w", err)
	}
	return nil
}

func (s *Store) exportLocalReputation(ctx context.Context, payload *LocalDatabaseExport) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, name, version, type, risk_type, severity, summary
		FROM reputation_findings_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local reputation findings: %w", err)
	}
	defer closeSilently(rows)

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
		payload.Reputation = append(payload.Reputation, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local reputation findings: %w", err)
	}
	return nil
}

func (s *Store) exportLocalLifecycle(ctx context.Context, payload *LocalDatabaseExport) error {
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
	defer closeSilently(rows)

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

		payload.Lifecycle = append(payload.Lifecycle, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate local lifecycle releases: %w", err)
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
