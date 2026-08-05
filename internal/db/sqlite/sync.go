package sqlite

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/httpclient"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/synccontract"
)

// syncMetaKeyLastSync is the sync_meta key storing the ISO 8601 timestamp
// of the last successful sync.
const syncMetaKeyLastSync = "last_sync_at"

const syncMetaKeyLastSyncXID = "last_sync_xid"

const syncMetaKeyFeedStatus = "feed_status"

const syncMetaKeyFeedVersions = "feed_versions"

const (
	syncPageLimit       = synccontract.MaxLimit
	maxSyncResponseSize = 32 * 1024 * 1024
	maxSyncFutureSkew   = 5 * time.Minute
	syncMax429Retries   = 5
	syncDefault429Delay = time.Second
)

// SyncConfig holds parameters for a client-to-server sync operation.
type SyncConfig struct {
	ServerURL         string
	APIKey            string
	Ecosystems        []string
	Full              bool
	Timeout           time.Duration
	CACertFile        string
	AllowInsecureHTTP bool
	Stats             *SyncStats
}

type SyncStats struct {
	FullCleared      SyncRemovalStats
	TombstoneDeleted SyncRemovalStats
}

type SyncRemovalStats struct {
	Vulnerabilities int64
	Malicious       int64
	Reputation      int64
	Lifecycle       int64
}

type syncApplyMetadata struct {
	LastSyncAt  string
	LastSyncXID string
	FeedState   *syncResponse
}

type syncCursorState struct {
	Since    string
	SinceXID string
}

type syncPageSnapshot struct {
	SyncedAt  string
	SyncedXID string
}

func (s SyncRemovalStats) Any() bool {
	return s.Vulnerabilities > 0 || s.Malicious > 0 || s.Reputation > 0 || s.Lifecycle > 0
}

func (s SyncStats) AnyRemoved() bool {
	return s.FullCleared.Any() || s.TombstoneDeleted.Any()
}

type (
	syncVulnerability    = synccontract.Vulnerability
	syncMalicious        = synccontract.Malicious
	syncReputation       = synccontract.Reputation
	syncLifecycleRelease = synccontract.Lifecycle
	syncResponse         = synccontract.Response
	syncCursor           = synccontract.Cursor
)

// Sync fetches server-side vulnerability, malicious, reputation, and lifecycle
// data plus feed-state metadata from the Packmon server and writes them into
// the local SQLite database page by page. Freshness and feed-state metadata are
// persisted only with the final successful page so a failed paginated sequence
// never advances the durable sync cursor.
//
// Protocol (DE-13):
//
//	GET /api/v1/sync
//
// Delta sync sends the last durable since timestamp plus an optional since_xid,
// while full sync omits both and clears local tables before applying the
// result. Paginated responses pin snapshot/snapshot_xid and advance
// per-dataset next_cursor fields; see the OpenAPI sync contract for the full
// query and response shape. Feed status/version metadata is persisted only
// when the returned synced_at value is safe to use as local freshness.
func Sync(ctx context.Context, store *Store, cfg SyncConfig) error {
	cfg, err := validateSyncConfig(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	client, err := newSyncHTTPClientWithCA(cfg.Timeout, cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	unlockSync, err := acquireSQLiteSyncLock(ctx, store.Path())
	if err != nil {
		return err
	}
	defer unlockSync()

	cursorState, err := loadSyncCursorState(ctx, store, cfg.Full)
	if err != nil {
		return err
	}

	stats, err := syncPaginatedResponses(ctx, store, client, cfg, cursorState, time.Now().UTC())
	if err != nil {
		return err
	}
	if cfg.Stats != nil {
		*cfg.Stats = stats
	}

	return nil
}

func validateSyncConfig(cfg SyncConfig) (SyncConfig, error) {
	if cfg.ServerURL == "" {
		return SyncConfig{}, fmt.Errorf("sync: no server URL configured")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Full && len(cfg.Ecosystems) > 0 {
		return SyncConfig{}, fmt.Errorf("sync: filtered full sync is not supported because local freshness is global; run an unfiltered full sync or an incremental filtered sync")
	}
	if err := validateSyncServerURL(cfg.ServerURL, cfg.AllowInsecureHTTP); err != nil {
		return SyncConfig{}, err
	}

	return cfg, nil
}

func loadSyncCursorState(ctx context.Context, store *Store, full bool) (syncCursorState, error) {
	if full {
		return syncCursorState{}, nil
	}

	since, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		return syncCursorState{}, fmt.Errorf("sync: read last sync timestamp: %w", err)
	}
	sinceXID, err := store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
	if err != nil {
		return syncCursorState{}, fmt.Errorf("sync: read last sync xid: %w", err)
	}
	return syncCursorState{Since: since, SinceXID: sinceXID}, nil
}

func syncPaginatedResponses(ctx context.Context, store *Store, client *http.Client, cfg SyncConfig, cursorState syncCursorState, now time.Time) (SyncStats, error) {
	cursor := syncCursor{}
	snapshot := syncPageSnapshot{}
	feedState := &syncResponse{}
	correlationID := newSyncCorrelationID()
	fullPage := cfg.Full
	var stats SyncStats

	// Loop to handle paginated responses.
	for {
		resp, err := fetchSyncPageWithCorrelationID(ctx, client, cfg, cursorState.Since, cursorState.SinceXID, cursor, snapshot.SyncedAt, snapshot.SyncedXID, correlationID)
		if err != nil {
			return SyncStats{}, err
		}

		if resp.SyncedAt != "" && snapshot.SyncedAt == "" {
			snapshot.SyncedAt = resp.SyncedAt
		}
		if resp.SyncedXID > 0 && snapshot.SyncedXID == "" {
			snapshot.SyncedXID = strconv.FormatUint(resp.SyncedXID, 10)
		}

		if resp.Truncated && snapshot.SyncedAt == "" {
			return SyncStats{}, fmt.Errorf("sync: truncated response missing synced_at")
		}

		mergeSyncFeedState(feedState, resp)

		if err := validateSyncResponseBeforeApply(fullPage, resp); err != nil {
			return SyncStats{}, err
		}

		metadata := syncApplyMetadata{}
		if !resp.Truncated {
			metadata, err = freshSyncApplyMetadata(snapshot, feedState, now)
			if err != nil {
				return SyncStats{}, err
			}
		}

		pageStats, err := applySyncWithMetadata(ctx, store, fullPage, resp, metadata)
		if err != nil {
			return SyncStats{}, err
		}
		addSyncStats(&stats, pageStats)
		fullPage = false

		if !resp.Truncated {
			break
		}

		if resp.NextCursor != nil {
			nextCursor := *resp.NextCursor
			if nextCursor == cursor {
				return SyncStats{}, fmt.Errorf("sync: truncated response did not advance next_cursor")
			}
			cursor = nextCursor
		} else {
			return SyncStats{}, fmt.Errorf("sync: truncated response missing next_cursor")
		}
	}

	return stats, nil
}

func freshSyncApplyMetadata(snapshot syncPageSnapshot, feedState *syncResponse, now time.Time) (syncApplyMetadata, error) {
	if snapshot.SyncedAt == "" {
		return syncApplyMetadata{}, nil
	}
	freshnessSafe, err := syncTimestampSafeForFreshness(snapshot.SyncedAt, now)
	if err != nil {
		return syncApplyMetadata{}, fmt.Errorf("sync: parse synced_at %q: %w", snapshot.SyncedAt, err)
	}
	if !freshnessSafe {
		return syncApplyMetadata{}, nil
	}
	return syncApplyMetadata{
		LastSyncAt:  snapshot.SyncedAt,
		LastSyncXID: snapshot.SyncedXID,
		FeedState:   syncFeedStateForMetadata(feedState),
	}, nil
}

func validateSyncResponseBeforeApply(full bool, resp *syncResponse) error {
	if resp == nil {
		return fmt.Errorf("sync: missing response")
	}
	if strings.TrimSpace(resp.SyncedAt) == "" {
		return fmt.Errorf("sync: response missing synced_at")
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(resp.SyncedAt)); err != nil {
		return fmt.Errorf("sync: parse synced_at %q: %w", resp.SyncedAt, err)
	}
	if full && syncResponseEmpty(resp) && strings.TrimSpace(resp.FeedStatus) == "" && len(resp.FeedVersions) == 0 {
		return fmt.Errorf("sync: full response missing feed_status or data")
	}
	return nil
}

func syncResponseEmpty(resp *syncResponse) bool {
	return resp == nil ||
		(len(resp.Vulnerabilities) == 0 &&
			len(resp.Malicious) == 0 &&
			len(resp.Reputation) == 0 &&
			len(resp.Lifecycle) == 0)
}

func syncTimestampSafeForFreshness(raw string, now time.Time) (bool, error) {
	ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return false, err
	}
	return !ts.UTC().After(now.UTC().Add(maxSyncFutureSkew)), nil
}

func mergeSyncFeedState(dst, src *syncResponse) {
	if dst == nil || src == nil {
		return
	}
	if dst.FeedStatus == "" {
		dst.FeedStatus = src.FeedStatus
	}
	if src.FeedVersions != nil {
		if dst.FeedVersions == nil {
			dst.FeedVersions = make(map[string]string, len(src.FeedVersions))
		}
		for feedName, version := range src.FeedVersions {
			dst.FeedVersions[feedName] = version
		}
	}
}

func syncFeedStateForMetadata(feedState *syncResponse) *syncResponse {
	if feedState == nil || (strings.TrimSpace(feedState.FeedStatus) == "" && feedState.FeedVersions == nil) {
		return nil
	}
	return feedState
}

func addSyncStats(dst *SyncStats, src SyncStats) {
	dst.FullCleared.Vulnerabilities += src.FullCleared.Vulnerabilities
	dst.FullCleared.Malicious += src.FullCleared.Malicious
	dst.FullCleared.Reputation += src.FullCleared.Reputation
	dst.FullCleared.Lifecycle += src.FullCleared.Lifecycle
	dst.TombstoneDeleted.Vulnerabilities += src.TombstoneDeleted.Vulnerabilities
	dst.TombstoneDeleted.Malicious += src.TombstoneDeleted.Malicious
	dst.TombstoneDeleted.Reputation += src.TombstoneDeleted.Reputation
	dst.TombstoneDeleted.Lifecycle += src.TombstoneDeleted.Lifecycle
}

func storeSyncedFeedState(ctx context.Context, tx *sql.Tx, resp *syncResponse) error {
	if resp == nil {
		return nil
	}
	status := strings.TrimSpace(resp.FeedStatus)
	if status == "" && resp.FeedVersions == nil {
		return nil
	}
	if status != "" {
		if err := setSyncMetaTx(ctx, tx, syncMetaKeyFeedStatus, status); err != nil {
			return fmt.Errorf("sync: store feed status: %w", err)
		}
	}
	if resp.FeedVersions != nil || status != "" {
		versions := make(map[string]string, len(resp.FeedVersions))
		for feedName, version := range resp.FeedVersions {
			feedName = strings.TrimSpace(feedName)
			version = strings.TrimSpace(version)
			if feedName == "" || version == "" {
				continue
			}
			versions[feedName] = version
		}
		payload, err := json.Marshal(versions)
		if err != nil {
			return fmt.Errorf("sync: encode feed versions: %w", err)
		}
		if err := setSyncMetaTx(ctx, tx, syncMetaKeyFeedVersions, string(payload)); err != nil {
			return fmt.Errorf("sync: store feed versions: %w", err)
		}
	}
	return nil
}

func storeFreshSyncMetadata(ctx context.Context, tx *sql.Tx, metadata syncApplyMetadata) error {
	if metadata.LastSyncAt != "" {
		if err := setSyncMetaTx(ctx, tx, syncMetaKeyLastSync, metadata.LastSyncAt); err != nil {
			return fmt.Errorf("sync: store sync timestamp: %w", err)
		}
	}
	if metadata.LastSyncXID != "" {
		if err := setSyncMetaTx(ctx, tx, syncMetaKeyLastSyncXID, metadata.LastSyncXID); err != nil {
			return fmt.Errorf("sync: store sync xid: %w", err)
		}
	}
	if metadata.FeedState != nil {
		if err := storeSyncedFeedState(ctx, tx, metadata.FeedState); err != nil {
			return err
		}
	}
	return nil
}

func setSyncMetaTx(ctx context.Context, tx *sql.Tx, key, value string) error {
	const upsert = `INSERT INTO sync_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	_, err := tx.ExecContext(ctx, upsert, key, value)
	if err != nil {
		return fmt.Errorf("sqlite: set sync meta %q: %w", key, err)
	}
	return nil
}

func validateSyncServerURL(serverURL string, allowInsecureHTTP bool) error {
	serverURL = strings.TrimSpace(serverURL)
	displayServerURL := logsafe.RedactURL(serverURL)
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("sync: parse server URL %q: %w", displayServerURL, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !allowInsecureHTTP {
		return fmt.Errorf("sync: refusing to use insecure server URL %q: scheme must be https (set --insecure-allow-http / PACKMON_INSECURE_ALLOW_HTTP to override)", displayServerURL)
	}
	return nil
}

func newSyncHTTPClient(timeout time.Duration) *http.Client {
	client, _ := newSyncHTTPClientWithCA(timeout, "")
	return client
}

func newSyncHTTPClientWithCA(timeout time.Duration, caCertFile string) (*http.Client, error) {
	pool, err := httpclient.LoadCAPool(caCertFile)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		},
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: httpclient.SafeRedirectPolicy,
	}, nil
}

func fetchSyncPage(ctx context.Context, client *http.Client, cfg SyncConfig, since, sinceXID string, cursor syncCursor, snapshot, snapshotXID string) (*syncResponse, error) {
	return fetchSyncPageWithCorrelationID(ctx, client, cfg, since, sinceXID, cursor, snapshot, snapshotXID, newSyncCorrelationID())
}

func fetchSyncPageWithCorrelationID(ctx context.Context, client *http.Client, cfg SyncConfig, since, sinceXID string, cursor syncCursor, snapshot, snapshotXID, correlationID string) (*syncResponse, error) {
	if !correlation.Valid(correlationID) {
		correlationID = newSyncCorrelationID()
	}
	for attempt := 0; ; attempt++ {
		resp, retryAfter, err := fetchSyncPageOnce(ctx, client, cfg, since, sinceXID, cursor, snapshot, snapshotXID, correlationID)
		if err == nil {
			return resp, nil
		}
		if retryAfter <= 0 || attempt >= syncMax429Retries {
			return nil, err
		}
		if waitErr := waitForSyncRetry(ctx, retryAfter); waitErr != nil {
			return nil, waitErr
		}
	}
}

func newSyncCorrelationID() string {
	id, err := correlation.NewID()
	if err != nil {
		return correlation.FallbackID()
	}
	return id
}

// fetchSyncPageOnce makes a single HTTP request to the server sync endpoint.
func fetchSyncPageOnce(ctx context.Context, client *http.Client, cfg SyncConfig, since, sinceXID string, cursor syncCursor, snapshot, snapshotXID, correlationID string) (*syncResponse, time.Duration, error) {
	displayServerURL := logsafe.RedactURL(cfg.ServerURL)
	u, err := url.Parse(strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/sync")
	if err != nil {
		return nil, 0, fmt.Errorf("sync: parse server URL %q: %w", displayServerURL, err)
	}

	q := u.Query()
	if since != "" {
		q.Set("since", since)
	}
	if sinceXID != "" {
		q.Set("since_xid", sinceXID)
	}
	if snapshot != "" {
		q.Set("snapshot", snapshot)
	}
	if snapshotXID != "" {
		q.Set("snapshot_xid", snapshotXID)
	}
	q.Set("limit", strconv.Itoa(syncPageLimit))
	if !cursor.IsZero() {
		setSyncCursorQuery(q, cursor)
	}
	if len(cfg.Ecosystems) > 0 {
		q.Set("ecosystem", strings.Join(cfg.Ecosystems, ","))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("sync: create request for server URL %q: %s", displayServerURL, logsafe.RedactDiagnosticMessage(err.Error()))
	}
	req.Header.Set("User-Agent", "packmon-cli/dev")
	req.Header.Set(correlation.Header, correlationID)
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("sync: server request: %s", logsafe.RedactURLRequestError(err, "server URL"))
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := readLimitedSyncResponse(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("sync: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		retryAfter := time.Duration(0)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter = parseSyncRetryAfter(resp.Header.Get("Retry-After"))
			if retryAfter <= 0 {
				retryAfter = syncDefault429Delay
			}
		}
		return nil, retryAfter, fmt.Errorf("sync: server returned %d: %s", resp.StatusCode, safeSyncErrorSnippet(body))
	}

	var syncResp syncResponse
	if err := json.Unmarshal(body, &syncResp); err != nil {
		return nil, 0, fmt.Errorf("sync: decode response: %w", err)
	}

	return &syncResp, 0, nil
}

func parseSyncRetryAfter(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if retryAt, err := http.ParseTime(raw); err == nil {
		delay := time.Until(retryAt)
		if delay < 0 {
			return 0
		}
		return delay
	}
	return 0
}

func waitForSyncRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("sync: context cancelled during rate limit wait: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func setSyncCursorQuery(q url.Values, cursor syncCursor) {
	if cursor.Vulnerabilities > 0 {
		q.Set("vulnerabilities_offset", strconv.Itoa(cursor.Vulnerabilities))
	}
	if cursor.Malicious > 0 {
		q.Set("malicious_offset", strconv.Itoa(cursor.Malicious))
	}
	if cursor.Reputation > 0 {
		q.Set("reputation_offset", strconv.Itoa(cursor.Reputation))
	}
	if cursor.Lifecycle > 0 {
		q.Set("lifecycle_offset", strconv.Itoa(cursor.Lifecycle))
	}
	if cursor.VulnerabilitiesCursor != "" {
		q.Set("vulnerabilities_cursor", cursor.VulnerabilitiesCursor)
	}
	if cursor.MaliciousCursor != "" {
		q.Set("malicious_cursor", cursor.MaliciousCursor)
	}
	if cursor.ReputationCursor != "" {
		q.Set("reputation_cursor", cursor.ReputationCursor)
	}
	if cursor.LifecycleCursor != "" {
		q.Set("lifecycle_cursor", cursor.LifecycleCursor)
	}
	if cursor.VulnerabilitiesDone {
		q.Set("vulnerabilities_done", "true")
	}
	if cursor.MaliciousDone {
		q.Set("malicious_done", "true")
	}
	if cursor.ReputationDone {
		q.Set("reputation_done", "true")
	}
	if cursor.LifecycleDone {
		q.Set("lifecycle_done", "true")
	}
}

func readLimitedSyncResponse(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxSyncResponseSize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxSyncResponseSize {
		return nil, fmt.Errorf("response too large: exceeds %d bytes", maxSyncResponseSize)
	}
	return body, nil
}

func safeSyncErrorSnippet(body []byte) string {
	return logsafe.RemoteErrorSnippet(body, 200)
}

func applySync(ctx context.Context, store *Store, full bool, resp *syncResponse) (SyncStats, error) {
	return applySyncWithMetadata(ctx, store, full, resp, syncApplyMetadata{})
}

// applySyncWithMetadata writes one sync page and optional freshness metadata
// into the local database inside a single transaction. On the first full-sync
// page it drops existing rows before inserting.
func applySyncWithMetadata(ctx context.Context, store *Store, full bool, resp *syncResponse, metadata syncApplyMetadata) (SyncStats, error) {
	var stats SyncStats
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		return SyncStats{}, fmt.Errorf("sync: begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on commit is a no-op

	if full {
		cleared, err := clearSyncTables(ctx, tx)
		if err != nil {
			return SyncStats{}, err
		}
		stats.FullCleared = cleared
	}

	deleted, err := applySyncVulnerabilities(ctx, tx, resp.Vulnerabilities)
	if err != nil {
		return SyncStats{}, err
	}
	stats.TombstoneDeleted.Vulnerabilities += deleted

	deleted, err = applySyncMalicious(ctx, tx, resp.Malicious)
	if err != nil {
		return SyncStats{}, err
	}
	stats.TombstoneDeleted.Malicious += deleted

	deleted, err = applySyncReputation(ctx, tx, resp.Reputation)
	if err != nil {
		return SyncStats{}, err
	}
	stats.TombstoneDeleted.Reputation += deleted

	deleted, err = applySyncLifecycle(ctx, tx, resp.Lifecycle)
	if err != nil {
		return SyncStats{}, err
	}
	stats.TombstoneDeleted.Lifecycle += deleted

	if err := storeFreshSyncMetadata(ctx, tx, metadata); err != nil {
		return SyncStats{}, err
	}

	if err := tx.Commit(); err != nil {
		return SyncStats{}, fmt.Errorf("sync: commit transaction: %w", err)
	}

	return stats, nil
}

func clearSyncTables(ctx context.Context, tx *sql.Tx) (SyncRemovalStats, error) {
	var stats SyncRemovalStats

	result, err := tx.ExecContext(ctx, `DELETE FROM vulnerabilities_local`)
	if err != nil {
		return SyncRemovalStats{}, fmt.Errorf("sync: clear vulnerabilities: %w", err)
	}
	stats.Vulnerabilities += rowsAffected(result)

	result, err = tx.ExecContext(ctx, `DELETE FROM malicious_local`)
	if err != nil {
		return SyncRemovalStats{}, fmt.Errorf("sync: clear malicious: %w", err)
	}
	stats.Malicious += rowsAffected(result)

	result, err = tx.ExecContext(ctx, `DELETE FROM reputation_findings_local`)
	if err != nil {
		return SyncRemovalStats{}, fmt.Errorf("sync: clear reputation findings: %w", err)
	}
	stats.Reputation += rowsAffected(result)

	result, err = tx.ExecContext(ctx, `DELETE FROM lifecycle_releases_local`)
	if err != nil {
		return SyncRemovalStats{}, fmt.Errorf("sync: clear lifecycle releases: %w", err)
	}
	stats.Lifecycle += rowsAffected(result)

	return stats, nil
}

func applySyncVulnerabilities(ctx context.Context, tx *sql.Tx, vulnerabilities []syncVulnerability) (int64, error) {
	vulnStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, references_json, severity, cvss_score, epss_score, epss_percentile, cisa_kev, summary, source)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(row_key) DO UPDATE SET
			id             = excluded.id,
			ecosystem      = excluded.ecosystem,
			name           = excluded.name,
			version_ranges = excluded.version_ranges,
			versions_affected = excluded.versions_affected,
			references_json = excluded.references_json,
			severity       = excluded.severity,
			cvss_score     = excluded.cvss_score,
			epss_score     = excluded.epss_score,
			epss_percentile = excluded.epss_percentile,
			cisa_kev       = excluded.cisa_kev,
			summary        = excluded.summary,
			source         = excluded.source`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare vuln upsert: %w", err)
	}
	defer ioutils.CloseSilently(vulnStmt)

	vulnDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM vulnerabilities_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare vuln delete: %w", err)
	}
	defer ioutils.CloseSilently(vulnDelStmt)

	var deleted int64
	for _, v := range vulnerabilities {
		if v.Withdrawn {
			result, err := vulnDelStmt.ExecContext(ctx, v.ID)
			if err != nil {
				return 0, fmt.Errorf("sync: delete withdrawn vuln %s: %w", v.ID, err)
			}
			deleted += rowsAffected(result)
			continue
		}
		if err := validateLocalVersionRanges(v.ID, "version_ranges", v.VersionRanges, false); err != nil {
			return 0, fmt.Errorf("sync: invalid vulnerability version_ranges %s: %w", v.ID, err)
		}
		if err := validateLocalStringArray(v.ID, "versions_affected", v.VersionsAffected, false); err != nil {
			return 0, fmt.Errorf("sync: invalid vulnerability versions_affected %s: %w", v.ID, err)
		}

		var cvss, epss, epssPercentile interface{}
		if v.CVSSScore != nil {
			cvss = *v.CVSSScore
		}
		if v.EPSSScore != nil {
			epss = *v.EPSSScore
		}
		if v.EPSSPercentile != nil {
			epssPercentile = *v.EPSSPercentile
		}
		cisaKEV := 0
		if v.CISAKEV {
			cisaKEV = 1
		}

		name := normalizePackageName(v.Ecosystem, v.Name)
		if _, err := vulnStmt.ExecContext(ctx,
			syncVulnerabilityRowKey(v.ID, v.Ecosystem, name), v.ID, v.Ecosystem, name, v.VersionRanges,
			v.VersionsAffected, v.References, v.Severity, cvss, epss, epssPercentile, cisaKEV, v.Summary, syncFindingSource(v.Source),
		); err != nil {
			return 0, fmt.Errorf("sync: upsert vuln %s: %w", v.ID, err)
		}
	}

	return deleted, nil
}

func applySyncMalicious(ctx context.Context, tx *sql.Tx, malicious []syncMalicious) (int64, error) {
	malStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO malicious_local(id, ecosystem, name, version_ranges, versions, reference_urls, risk_type, severity, summary, source)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ecosystem      = excluded.ecosystem,
			name           = excluded.name,
			version_ranges = excluded.version_ranges,
			versions       = excluded.versions,
			reference_urls = excluded.reference_urls,
			risk_type      = excluded.risk_type,
			severity       = excluded.severity,
			summary        = excluded.summary,
			source         = excluded.source`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare malicious upsert: %w", err)
	}
	defer ioutils.CloseSilently(malStmt)

	malDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM malicious_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare malicious delete: %w", err)
	}
	defer ioutils.CloseSilently(malDelStmt)

	var deleted int64
	for _, m := range malicious {
		if m.Withdrawn {
			result, err := malDelStmt.ExecContext(ctx, m.ID)
			if err != nil {
				return 0, fmt.Errorf("sync: delete withdrawn malicious %s: %w", m.ID, err)
			}
			deleted += rowsAffected(result)
			continue
		}

		if err := validateLocalVersionRanges(m.ID, "version_ranges", m.VersionRanges, true); err != nil {
			return 0, fmt.Errorf("sync: invalid malicious version_ranges %s: %w", m.ID, err)
		}
		if err := validateLocalMaliciousVersions(m.ID, m.Versions); err != nil {
			return 0, fmt.Errorf("sync: invalid malicious versions %s: %w", m.ID, err)
		}

		var versions interface{}
		if m.Versions != "" {
			versions = m.Versions
		}
		var versionRanges interface{}
		if m.VersionRanges != "" {
			versionRanges = m.VersionRanges
		}

		name := normalizePackageName(m.Ecosystem, m.Name)
		if _, err := malStmt.ExecContext(ctx,
			m.ID, m.Ecosystem, name, versionRanges, versions,
			m.ReferenceURLs, m.RiskType, m.Severity, m.Summary, syncFindingSource(m.Source),
		); err != nil {
			return 0, fmt.Errorf("sync: upsert malicious %s: %w", m.ID, err)
		}
	}

	return deleted, nil
}

func applySyncReputation(ctx context.Context, tx *sql.Tx, reputation []syncReputation) (int64, error) {
	repStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ecosystem = excluded.ecosystem,
			name      = excluded.name,
			version   = excluded.version,
			type      = excluded.type,
			risk_type = excluded.risk_type,
			severity  = excluded.severity,
			summary   = excluded.summary`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare reputation upsert: %w", err)
	}
	defer ioutils.CloseSilently(repStmt)

	repDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM reputation_findings_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare reputation delete: %w", err)
	}
	defer ioutils.CloseSilently(repDelStmt)

	var deleted int64
	for _, rep := range reputation {
		if rep.Withdrawn {
			result, err := repDelStmt.ExecContext(ctx, rep.ID)
			if err != nil {
				return 0, fmt.Errorf("sync: delete withdrawn reputation %s: %w", rep.ID, err)
			}
			deleted += rowsAffected(result)
			continue
		}

		name := normalizePackageName(rep.Ecosystem, rep.Name)
		severity := string(domain.NormalizeFindingSeverity(domain.Finding{
			Type:     domain.FindingType(rep.Type),
			RiskType: rep.RiskType,
			Severity: domain.Severity(rep.Severity),
		}))
		if _, err := repStmt.ExecContext(ctx,
			rep.ID, rep.Ecosystem, name, rep.Version,
			rep.Type, rep.RiskType, severity, rep.Summary,
		); err != nil {
			return 0, fmt.Errorf("sync: upsert reputation %s: %w", rep.ID, err)
		}
	}

	return deleted, nil
}

func applySyncLifecycle(ctx context.Context, tx *sql.Tx, lifecycleReleases []syncLifecycleRelease) (int64, error) {
	lifecycleStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO lifecycle_releases_local(
			id, ecosystem, name, product_slug, product_label, cycle, latest,
			release_date, is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			is_discontinued, discontinued_from, is_eoes, eoes_from, is_maintained
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ecosystem         = excluded.ecosystem,
			name              = excluded.name,
			product_slug      = excluded.product_slug,
			product_label     = excluded.product_label,
			cycle             = excluded.cycle,
			latest            = excluded.latest,
			release_date      = excluded.release_date,
			is_lts            = excluded.is_lts,
			lts_from          = excluded.lts_from,
			is_eoas           = excluded.is_eoas,
			eoas_from         = excluded.eoas_from,
			is_eol            = excluded.is_eol,
			eol_from          = excluded.eol_from,
			is_discontinued   = excluded.is_discontinued,
			discontinued_from = excluded.discontinued_from,
			is_eoes           = excluded.is_eoes,
			eoes_from         = excluded.eoes_from,
			is_maintained     = excluded.is_maintained`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare lifecycle upsert: %w", err)
	}
	defer ioutils.CloseSilently(lifecycleStmt)

	lifecycleDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM lifecycle_releases_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare lifecycle delete: %w", err)
	}
	defer ioutils.CloseSilently(lifecycleDelStmt)

	var deleted int64
	for _, lifecycle := range lifecycleReleases {
		if lifecycle.Withdrawn {
			result, err := lifecycleDelStmt.ExecContext(ctx, lifecycle.ID)
			if err != nil {
				return 0, fmt.Errorf("sync: delete withdrawn lifecycle %s: %w", lifecycle.ID, err)
			}
			deleted += rowsAffected(result)
			continue
		}

		releaseDate, err := syncDateValue("release_date", lifecycle.ReleaseDate)
		if err != nil {
			return 0, fmt.Errorf("sync: invalid lifecycle date %s: %w", lifecycle.ID, err)
		}
		ltsFrom, err := syncDateValue("lts_from", lifecycle.LTSFrom)
		if err != nil {
			return 0, fmt.Errorf("sync: invalid lifecycle date %s: %w", lifecycle.ID, err)
		}
		eoasFrom, err := syncDateValue("eoas_from", lifecycle.EOASFrom)
		if err != nil {
			return 0, fmt.Errorf("sync: invalid lifecycle date %s: %w", lifecycle.ID, err)
		}
		eolFrom, err := syncDateValue("eol_from", lifecycle.EOLFrom)
		if err != nil {
			return 0, fmt.Errorf("sync: invalid lifecycle date %s: %w", lifecycle.ID, err)
		}
		discontinuedFrom, err := syncDateValue("discontinued_from", lifecycle.DiscontinuedFrom)
		if err != nil {
			return 0, fmt.Errorf("sync: invalid lifecycle date %s: %w", lifecycle.ID, err)
		}
		eoesFrom, err := syncDateValue("eoes_from", lifecycle.EOESFrom)
		if err != nil {
			return 0, fmt.Errorf("sync: invalid lifecycle date %s: %w", lifecycle.ID, err)
		}

		if _, err := lifecycleStmt.ExecContext(ctx,
			lifecycle.ID,
			lifecycle.Ecosystem,
			normalizePackageName(lifecycle.Ecosystem, lifecycle.Name),
			lifecycle.ProductSlug,
			lifecycle.ProductLabel,
			lifecycle.Cycle,
			lifecycle.Latest,
			releaseDate,
			boolInt(lifecycle.IsLTS),
			ltsFrom,
			boolInt(lifecycle.IsEOAS),
			eoasFrom,
			boolInt(lifecycle.IsEOL),
			eolFrom,
			boolInt(lifecycle.IsDiscontinued),
			discontinuedFrom,
			nullableBoolInt(lifecycle.IsEOES),
			eoesFrom,
			boolInt(lifecycle.IsMaintained),
		); err != nil {
			return 0, fmt.Errorf("sync: upsert lifecycle %s: %w", lifecycle.ID, err)
		}
	}

	return deleted, nil
}

func rowsAffected(result sql.Result) int64 {
	if result == nil {
		return 0
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0
	}
	return affected
}

func syncFindingSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "local"
	}
	return source
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 0 {
		maxLen = 0
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

func syncVulnerabilityRowKey(id, ecosystem, name string) string {
	return id + "|" + ecosystem + "|" + name
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableBoolInt(value *bool) any {
	if value == nil {
		return nil
	}
	return boolInt(*value)
}

func syncDateValue(field string, value *string) (any, error) {
	if value == nil {
		return nil, nil
	}
	raw := strings.TrimSpace(*value)
	if raw == "" {
		return nil, nil
	}
	if parsed, err := time.Parse(time.DateOnly, raw); err == nil {
		return parsed.Format(time.DateOnly), nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed.UTC().Format(time.DateOnly), nil
	}
	return nil, fmt.Errorf("%s must be YYYY-MM-DD", field)
}
