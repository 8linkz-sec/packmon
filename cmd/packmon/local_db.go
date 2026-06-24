package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
)

const defaultDBWarnAfterDays = 7

const localDBSyncMetaFeedStatus = "feed_status"

const localDBSyncMetaFeedVersions = "feed_versions"

type localDBInfo struct {
	Path            string     `json:"path"`
	Exists          bool       `json:"exists"`
	FileSizeBytes   int64      `json:"file_size_bytes"`
	Vulnerabilities int        `json:"vulnerabilities"`
	Malicious       int        `json:"malicious"`
	Reputation      int        `json:"reputation"`
	Lifecycle       int        `json:"lifecycle"`
	HistoryEntries  int        `json:"history_entries"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty"`
	DBAgeDays       *int       `json:"db_age_days,omitempty"`
	DBStale         bool       `json:"db_stale"`
}

type localDBExport struct {
	GeneratedAt     time.Time                        `json:"generated_at"`
	Info            *localDBInfo                     `json:"info"`
	Vulnerabilities []sqlite.LocalVulnerabilityEntry `json:"vulnerabilities"`
	Malicious       []sqlite.LocalMaliciousEntry     `json:"malicious"`
	Reputation      []sqlite.LocalReputationEntry    `json:"reputation"`
	Lifecycle       []sqlite.LocalLifecycleEntry     `json:"lifecycle"`
	ScanHistory     []sqlite.ScanEntry               `json:"scan_history"`
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
	defer closeSilently(store)

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

	counts, err := store.LocalDatabaseCounts(ctx)
	if err != nil {
		return nil, err
	}
	info.Vulnerabilities = counts.Vulnerabilities
	info.Malicious = counts.Malicious
	info.Reputation = counts.Reputation
	info.Lifecycle = counts.Lifecycle
	info.HistoryEntries = counts.HistoryEntries

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
	if result.ScanError != "" {
		return nil
	}

	feedStatus, feedVersions, err := readLocalFeedState(ctx, store)
	if err != nil {
		return err
	}
	if feedStatus != "" {
		result.FeedStatus = feedStatus
		result.FeedVersions = feedVersions
	}
	return nil
}

func readLocalFeedState(ctx context.Context, store *sqlite.Store) (string, map[string]string, error) {
	status, err := store.GetSyncMeta(ctx, localDBSyncMetaFeedStatus)
	if err != nil {
		return "", nil, fmt.Errorf("read local feed status: %w", err)
	}
	status = strings.TrimSpace(status)
	if status == "" {
		return "", nil, nil
	}

	rawVersions, err := store.GetSyncMeta(ctx, localDBSyncMetaFeedVersions)
	if err != nil {
		return "", nil, fmt.Errorf("read local feed versions: %w", err)
	}
	versions := map[string]string{}
	if strings.TrimSpace(rawVersions) != "" {
		if err := json.Unmarshal([]byte(rawVersions), &versions); err != nil {
			return "", nil, fmt.Errorf("parse local feed versions: %w", err)
		}
	}
	if versions == nil {
		versions = map[string]string{}
	}
	return status, versions, nil
}

func exportLocalDB(ctx context.Context, store *sqlite.Store, writer io.Writer) error {
	info, err := loadLocalDBInfo(ctx, store)
	if err != nil {
		return err
	}

	exportData, err := store.ExportLocalDatabase(ctx)
	if err != nil {
		return err
	}

	payload := &localDBExport{
		GeneratedAt:     time.Now().UTC(),
		Info:            exportLocalDBInfo(info),
		Vulnerabilities: exportData.Vulnerabilities,
		Malicious:       exportData.Malicious,
		Reputation:      exportData.Reputation,
		Lifecycle:       exportData.Lifecycle,
		ScanHistory:     exportData.ScanHistory,
	}

	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}

	return nil
}

func exportLocalDBInfo(info *localDBInfo) *localDBInfo {
	if info == nil {
		return nil
	}
	copyValue := *info
	if strings.TrimSpace(copyValue.Path) != "" {
		copyValue.Path = filepath.Base(copyValue.Path)
	}
	return &copyValue
}
