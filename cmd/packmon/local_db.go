package main

import (
	"bytes"
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
	"github.com/8linkz-sec/packmon/internal/ioutils"
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

func dbWarnAfterDays() (int, error) {
	raw := strings.TrimSpace(os.Getenv("PACKMON_DB_WARN_AFTER_DAYS"))
	if raw == "" {
		return defaultDBWarnAfterDays, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("PACKMON_DB_WARN_AFTER_DAYS must be a non-negative integer")
	}
	return value, nil
}

func inspectLocalDB(ctx context.Context, path string) (*localDBInfo, error) {
	warnAfterDays, err := dbWarnAfterDays()
	if err != nil {
		return nil, err
	}

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
	defer ioutils.CloseSilently(store)

	info.Exists = true
	info.FileSizeBytes = fileInfo.Size()

	loaded, err := loadLocalDBInfoWithWarnAfterDays(ctx, store, warnAfterDays)
	if err != nil {
		return nil, err
	}
	loaded.Exists = true
	loaded.FileSizeBytes = fileInfo.Size()
	return loaded, nil
}

func loadLocalDBInfo(ctx context.Context, store *sqlite.Store) (*localDBInfo, error) {
	warnAfterDays, err := dbWarnAfterDays()
	if err != nil {
		return nil, err
	}
	return loadLocalDBInfoWithWarnAfterDays(ctx, store, warnAfterDays)
}

func loadLocalDBInfoWithWarnAfterDays(ctx context.Context, store *sqlite.Store, warnAfterDays int) (*localDBInfo, error) {
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
	info.DBStale = dbAgeDays != nil && *dbAgeDays >= warnAfterDays

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
	if store == nil || result == nil || result.Mode != domain.ScanModeLocal {
		return nil
	}

	info, err := loadLocalDBInfo(ctx, store)
	if err != nil {
		markLocalDBFreshnessUnknown(result)
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

func markLocalDBFreshnessUnknown(result *domain.ScanResult) {
	if result == nil || result.Mode != domain.ScanModeLocal {
		return
	}
	result.DBAgeDays = nil
	result.DBStale = true
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

	stream := newLocalDBExportJSONStream(writer)
	if err := stream.begin(time.Now().UTC(), exportLocalDBInfo(info)); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}
	if err := stream.writeArrayField("vulnerabilities", func(emit func(any) error) error {
		return store.StreamLocalVulnerabilities(ctx, func(item sqlite.LocalVulnerabilityEntry) error {
			return emit(item)
		})
	}); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}
	if err := stream.writeArrayField("malicious", func(emit func(any) error) error {
		return store.StreamLocalMalicious(ctx, func(item sqlite.LocalMaliciousEntry) error {
			return emit(item)
		})
	}); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}
	if err := stream.writeArrayField("reputation", func(emit func(any) error) error {
		return store.StreamLocalReputation(ctx, func(item sqlite.LocalReputationEntry) error {
			return emit(item)
		})
	}); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}
	if err := stream.writeArrayField("lifecycle", func(emit func(any) error) error {
		return store.StreamLocalLifecycle(ctx, func(item sqlite.LocalLifecycleEntry) error {
			return emit(item)
		})
	}); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}
	if err := stream.writeArrayField("scan_history", func(emit func(any) error) error {
		return store.StreamLocalScanHistory(ctx, func(item sqlite.ScanEntry) error {
			return emit(item)
		})
	}); err != nil {
		return fmt.Errorf("encode local database export: %w", err)
	}
	if err := stream.end(); err != nil {
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

type localDBExportJSONStream struct {
	writer     io.Writer
	fieldCount int
}

func newLocalDBExportJSONStream(writer io.Writer) *localDBExportJSONStream {
	return &localDBExportJSONStream{writer: writer}
}

func (s *localDBExportJSONStream) begin(generatedAt time.Time, info *localDBInfo) error {
	if _, err := io.WriteString(s.writer, "{\n"); err != nil {
		return err
	}
	if err := s.writeValueField("generated_at", generatedAt); err != nil {
		return err
	}
	if err := s.writeValueField("info", info); err != nil {
		return err
	}
	return nil
}

func (s *localDBExportJSONStream) writeValueField(name string, value any) error {
	if err := s.writeFieldPrefix(name); err != nil {
		return err
	}
	return writeLocalDBExportJSONValue(s.writer, value, "  ")
}

func (s *localDBExportJSONStream) writeArrayField(name string, stream func(func(any) error) error) error {
	if stream == nil {
		return fmt.Errorf("stream function for %s is nil", name)
	}
	if err := s.writeFieldPrefix(name); err != nil {
		return err
	}
	if _, err := io.WriteString(s.writer, "["); err != nil {
		return err
	}

	count := 0
	if err := stream(func(item any) error {
		if count == 0 {
			if _, err := io.WriteString(s.writer, "\n"); err != nil {
				return err
			}
		} else if _, err := io.WriteString(s.writer, ",\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(s.writer, "    "); err != nil {
			return err
		}
		if err := writeLocalDBExportJSONValue(s.writer, item, "    "); err != nil {
			return err
		}
		count++
		return nil
	}); err != nil {
		return err
	}

	if count > 0 {
		_, err := io.WriteString(s.writer, "\n  ]")
		return err
	}
	_, err := io.WriteString(s.writer, "]")
	return err
}

func (s *localDBExportJSONStream) writeFieldPrefix(name string) error {
	if s.fieldCount > 0 {
		if _, err := io.WriteString(s.writer, ",\n"); err != nil {
			return err
		}
	}
	fieldName, err := json.Marshal(name)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(s.writer, "  "); err != nil {
		return err
	}
	if _, err := s.writer.Write(fieldName); err != nil {
		return err
	}
	if _, err := io.WriteString(s.writer, ": "); err != nil {
		return err
	}
	s.fieldCount++
	return nil
}

func (s *localDBExportJSONStream) end() error {
	_, err := io.WriteString(s.writer, "\n}\n")
	return err
}

func writeLocalDBExportJSONValue(writer io.Writer, value any, continuationPrefix string) error {
	data, err := marshalLocalDBExportJSON(value)
	if err != nil {
		return err
	}
	if continuationPrefix != "" {
		data = bytes.ReplaceAll(data, []byte("\n"), []byte("\n"+continuationPrefix))
	}
	_, err = writer.Write(data)
	return err
}

func marshalLocalDBExportJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
