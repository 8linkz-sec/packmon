package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db/sqlite"
	"github.com/8linkz/packmon/internal/domain"
)

const defaultDBWarnAfterDays = 7

type localDBInfo struct {
	Path            string     `json:"path"`
	Exists          bool       `json:"exists"`
	FileSizeBytes   int64      `json:"file_size_bytes"`
	Vulnerabilities int        `json:"vulnerabilities"`
	Malicious       int        `json:"malicious"`
	HistoryEntries  int        `json:"history_entries"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty"`
	DBAgeDays       *int       `json:"db_age_days,omitempty"`
	DBStale         bool       `json:"db_stale"`
}

type localDBExport struct {
	GeneratedAt     time.Time                 `json:"generated_at"`
	Info            *localDBInfo              `json:"info"`
	Vulnerabilities []localVulnerabilityEntry `json:"vulnerabilities"`
	Malicious       []localMaliciousEntry     `json:"malicious"`
}

type localVulnerabilityEntry struct {
	ID            string          `json:"id"`
	Ecosystem     string          `json:"ecosystem"`
	Name          string          `json:"name"`
	VersionRanges json.RawMessage `json:"version_ranges"`
	Severity      string          `json:"severity"`
	CVSSScore     *float64        `json:"cvss_score,omitempty"`
	EPSSScore     *float64        `json:"epss_score,omitempty"`
	CISAKEV       bool            `json:"cisa_kev"`
	Summary       string          `json:"summary"`
}

type localMaliciousEntry struct {
	ID        string          `json:"id"`
	Ecosystem string          `json:"ecosystem"`
	Name      string          `json:"name"`
	Versions  json.RawMessage `json:"versions,omitempty"`
	RiskType  string          `json:"risk_type"`
	Severity  string          `json:"severity"`
	Summary   string          `json:"summary"`
}

func dbWarnAfterDays() int {
	raw := strings.TrimSpace(os.Getenv("PACKMON_DB_WARN_AFTER_DAYS"))
	if raw == "" {
		return defaultDBWarnAfterDays
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return defaultDBWarnAfterDays
	}
	return value
}

func inspectLocalDB(ctx context.Context, path string) (*localDBInfo, error) {
	info := &localDBInfo{Path: path}

	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return info, nil
		}
		return nil, fmt.Errorf("stat local database: %w", err)
	}

	store, err := sqlite.New(path)
	if err != nil {
		return nil, fmt.Errorf("open local database: %w", err)
	}
	defer store.Close()

	info.Exists = true
	info.FileSizeBytes = fileInfo.Size()

	loaded, err := loadLocalDBInfo(ctx, store)
	if err != nil {
		return nil, err
	}
	loaded.Exists = true
	loaded.FileSizeBytes = fileInfo.Size()
	return loaded, nil
}

func loadLocalDBInfo(ctx context.Context, store *sqlite.Store) (*localDBInfo, error) {
	info := &localDBInfo{
		Path:   store.Path(),
		Exists: true,
	}

	if err := store.DB().QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(DISTINCT id) FROM vulnerabilities_local),
			(SELECT COUNT(*) FROM malicious_local),
			(SELECT COUNT(*) FROM scan_history)`,
	).Scan(&info.Vulnerabilities, &info.Malicious, &info.HistoryEntries); err != nil {
		return nil, fmt.Errorf("read local database counts: %w", err)
	}

	lastSyncAt, dbAgeDays, err := readLocalSyncAge(ctx, store)
	if err != nil {
		return nil, err
	}
	info.LastSyncAt = lastSyncAt
	info.DBAgeDays = dbAgeDays
	info.DBStale = dbAgeDays != nil && *dbAgeDays >= dbWarnAfterDays()

	return info, nil
}

func readLocalSyncAge(ctx context.Context, store *sqlite.Store) (*time.Time, *int, error) {
	raw, err := store.GetSyncMeta(ctx, "last_sync_at")
	if err != nil {
		return nil, nil, fmt.Errorf("read local sync timestamp: %w", err)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, nil, nil
	}

	lastSyncAt, err := parseTimestamp(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local sync timestamp %q: %w", raw, err)
	}

	ageDays := int(time.Since(lastSyncAt).Hours() / 24)
	if ageDays < 0 {
		ageDays = 0
	}
	return &lastSyncAt, &ageDays, nil
}

func parseTimestamp(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp format")
}

func applyLocalDBFreshness(ctx context.Context, store *sqlite.Store, result *domain.ScanResult) error {
	if store == nil || result == nil || result.Mode != "local" {
		return nil
	}

	info, err := loadLocalDBInfo(ctx, store)
	if err != nil {
		return err
	}

	result.DBAgeDays = info.DBAgeDays
	result.DBStale = info.DBStale
	return nil
}

func exportLocalDB(ctx context.Context, store *sqlite.Store, writer io.Writer) error {
	info, err := loadLocalDBInfo(ctx, store)
	if err != nil {
		return err
	}

	payload := &localDBExport{
		GeneratedAt:     time.Now().UTC(),
		Info:            info,
		Vulnerabilities: make([]localVulnerabilityEntry, 0),
		Malicious:       make([]localMaliciousEntry, 0),
	}

	vulnRows, err := store.DB().QueryContext(ctx, `
		SELECT id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, cisa_kev, summary
		FROM vulnerabilities_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local vulnerabilities: %w", err)
	}
	defer vulnRows.Close()

	for vulnRows.Next() {
		var (
			item          localVulnerabilityEntry
			versionRanges sql.NullString
			severity      sql.NullString
			cvss          sql.NullFloat64
			epss          sql.NullFloat64
			cisaKEV       int
			summary       sql.NullString
		)

		if err := vulnRows.Scan(&item.ID, &item.Ecosystem, &item.Name, &versionRanges, &severity, &cvss, &epss, &cisaKEV, &summary); err != nil {
			return fmt.Errorf("scan local vulnerability row: %w", err)
		}

		item.VersionRanges = json.RawMessage("[]")
		if versionRanges.Valid && strings.TrimSpace(versionRanges.String) != "" {
			item.VersionRanges = json.RawMessage(versionRanges.String)
		}
		item.Severity = strings.TrimSpace(severity.String)
		item.Summary = summary.String
		item.CISAKEV = cisaKEV > 0
		if cvss.Valid {
			value := cvss.Float64
			item.CVSSScore = &value
		}
		if epss.Valid {
			value := epss.Float64
			item.EPSSScore = &value
		}

		payload.Vulnerabilities = append(payload.Vulnerabilities, item)
	}
	if err := vulnRows.Err(); err != nil {
		return fmt.Errorf("iterate local vulnerabilities: %w", err)
	}

	malRows, err := store.DB().QueryContext(ctx, `
		SELECT id, ecosystem, name, versions, risk_type, severity, summary
		FROM malicious_local
		ORDER BY ecosystem, name, id`)
	if err != nil {
		return fmt.Errorf("query local malicious findings: %w", err)
	}
	defer malRows.Close()

	for malRows.Next() {
		var (
			item     localMaliciousEntry
			versions sql.NullString
			severity sql.NullString
			summary  sql.NullString
		)

		if err := malRows.Scan(&item.ID, &item.Ecosystem, &item.Name, &versions, &item.RiskType, &severity, &summary); err != nil {
			return fmt.Errorf("scan local malicious row: %w", err)
		}

		item.Severity = strings.TrimSpace(severity.String)
		item.Summary = summary.String
		if versions.Valid && strings.TrimSpace(versions.String) != "" {
			item.Versions = json.RawMessage(versions.String)
		}

		payload.Malicious = append(payload.Malicious, item)
	}
	if err := malRows.Err(); err != nil {
		return fmt.Errorf("iterate local malicious findings: %w", err)
	}

	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}

	return nil
}
