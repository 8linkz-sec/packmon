package sqlite

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/httpclient"
	"github.com/8linkz-sec/packmon/internal/logsafe"
)

// syncMetaKeyLastSync is the sync_meta key storing the ISO 8601 timestamp
// of the last successful sync.
const syncMetaKeyLastSync = "last_sync_at"

const syncMetaKeyLastSyncXID = "last_sync_xid"

const (
	syncPageLimit       = 1000
	maxSyncResponseSize = 32 * 1024 * 1024
	maxSyncFutureSkew   = 5 * time.Minute
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

func (s SyncRemovalStats) Any() bool {
	return s.Vulnerabilities > 0 || s.Malicious > 0 || s.Reputation > 0 || s.Lifecycle > 0
}

func (s SyncStats) AnyRemoved() bool {
	return s.FullCleared.Any() || s.TombstoneDeleted.Any()
}

// syncVulnerability is the wire format for a single vulnerability
// delivered by the server's GET /api/v1/sync endpoint.
type syncVulnerability struct {
	ID               string   `json:"id"`
	Ecosystem        string   `json:"ecosystem"`
	Name             string   `json:"name"`
	VersionRanges    string   `json:"version_ranges"`    // JSON string
	VersionsAffected string   `json:"versions_affected"` // JSON string
	References       string   `json:"references"`        // JSON string
	Severity         string   `json:"severity"`
	CVSSScore        *float64 `json:"cvss_score"`
	EPSSScore        *float64 `json:"epss_score"`
	EPSSPercentile   *float64 `json:"epss_percentile"`
	CISAKEV          bool     `json:"cisa_kev"`
	Summary          string   `json:"summary"`
	Source           string   `json:"source"`
	Withdrawn        bool     `json:"withdrawn"`
}

// syncMalicious is the wire format for a single malicious finding
// delivered by the server's GET /api/v1/sync endpoint.
type syncMalicious struct {
	ID            string `json:"id"`
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	VersionRanges string `json:"version_ranges"` // JSON string, empty = all when Versions is empty
	Versions      string `json:"versions"`       // JSON string, empty = all
	ReferenceURLs string `json:"reference_urls"`
	RiskType      string `json:"risk_type"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
	Source        string `json:"source"`
	Withdrawn     bool   `json:"withdrawn"`
}

// syncReputation is the wire format for a cached reputation finding or
// tombstone delivered by the server's GET /api/v1/sync endpoint.
type syncReputation struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	RiskType  string `json:"risk_type"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Withdrawn bool   `json:"withdrawn"`
}

// syncLifecycleRelease is the wire format for one lifecycle cache row
// delivered by the server's GET /api/v1/sync endpoint.
type syncLifecycleRelease struct {
	ID               string  `json:"id"`
	Ecosystem        string  `json:"ecosystem"`
	Name             string  `json:"name"`
	ProductSlug      string  `json:"product_slug"`
	ProductLabel     string  `json:"product_label"`
	Cycle            string  `json:"cycle"`
	Latest           string  `json:"latest"`
	ReleaseDate      *string `json:"release_date"`
	IsLTS            bool    `json:"is_lts"`
	LTSFrom          *string `json:"lts_from"`
	IsEOAS           bool    `json:"is_eoas"`
	EOASFrom         *string `json:"eoas_from"`
	IsEOL            bool    `json:"is_eol"`
	EOLFrom          *string `json:"eol_from"`
	IsDiscontinued   bool    `json:"is_discontinued"`
	DiscontinuedFrom *string `json:"discontinued_from"`
	IsEOES           *bool   `json:"is_eoes"`
	EOESFrom         *string `json:"eoes_from"`
	IsMaintained     bool    `json:"is_maintained"`
	Withdrawn        bool    `json:"withdrawn"`
}

// syncResponse is the JSON envelope returned by the server sync endpoint.
type syncResponse struct {
	SyncedAt        string                 `json:"synced_at"`
	SyncedXID       uint64                 `json:"synced_xid"`
	Vulnerabilities []syncVulnerability    `json:"vulnerabilities"`
	Malicious       []syncMalicious        `json:"malicious"`
	Reputation      []syncReputation       `json:"reputation"`
	Lifecycle       []syncLifecycleRelease `json:"lifecycle"`
	// Truncated is true when more data is available and the client should call
	// again with the same since/snapshot parameters and the next cursor.
	Truncated  bool        `json:"truncated"`
	NextCursor *syncCursor `json:"next_cursor"`
}

type syncCursor struct {
	Vulnerabilities int `json:"vulnerabilities"`
	Malicious       int `json:"malicious"`
	Reputation      int `json:"reputation"`
	Lifecycle       int `json:"lifecycle"`

	VulnerabilitiesCursor string `json:"vulnerabilities_cursor"`
	MaliciousCursor       string `json:"malicious_cursor"`
	ReputationCursor      string `json:"reputation_cursor"`
	LifecycleCursor       string `json:"lifecycle_cursor"`

	VulnerabilitiesDone bool `json:"vulnerabilities_done"`
	MaliciousDone       bool `json:"malicious_done"`
	ReputationDone      bool `json:"reputation_done"`
	LifecycleDone       bool `json:"lifecycle_done"`
}

func (c syncCursor) isZero() bool {
	return c.Vulnerabilities == 0 &&
		c.Malicious == 0 &&
		c.Reputation == 0 &&
		c.Lifecycle == 0 &&
		c.VulnerabilitiesCursor == "" &&
		c.MaliciousCursor == "" &&
		c.ReputationCursor == "" &&
		c.LifecycleCursor == "" &&
		!c.VulnerabilitiesDone &&
		!c.MaliciousDone &&
		!c.ReputationDone &&
		!c.LifecycleDone
}

// Sync fetches vulnerability and malicious data from the packmon server
// and writes it into the local SQLite database. The entire write is
// wrapped in a transaction so a crash or interrupt leaves the DB in the
// previous consistent state.
//
// Protocol (DE-13):
//
//	GET /api/v1/sync?since=<timestamp>&ecosystem=<eco>
//
// The server returns a page of changes since the given timestamp. If
// "full" is true the since parameter is omitted and the server sends
// all data (the client drops existing rows first).
func Sync(ctx context.Context, store *Store, cfg SyncConfig) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("sync: no server URL configured")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.Full && len(cfg.Ecosystems) > 0 {
		return fmt.Errorf("sync: filtered full sync is not supported because local freshness is global; run an unfiltered full sync or an incremental filtered sync")
	}
	if err := validateSyncServerURL(cfg.ServerURL, cfg.AllowInsecureHTTP); err != nil {
		return err
	}

	client, err := newSyncHTTPClientWithCA(cfg.Timeout, cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	// Determine the since timestamp for delta sync.
	var since string
	var sinceXID string
	if !cfg.Full {
		since, err = store.GetSyncMeta(ctx, syncMetaKeyLastSync)
		if err != nil {
			return fmt.Errorf("sync: read last sync timestamp: %w", err)
		}
		sinceXID, err = store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
		if err != nil {
			return fmt.Errorf("sync: read last sync xid: %w", err)
		}
	}

	legacyOffset := 0
	cursor := syncCursor{}
	snapshot := ""
	snapshotXID := ""
	merged := &syncResponse{}

	// Loop to handle paginated responses.
	for {
		resp, err := fetchSyncPage(ctx, client, cfg, since, sinceXID, cursor, legacyOffset, snapshot, snapshotXID)
		if err != nil {
			return err
		}

		if resp.SyncedAt != "" && snapshot == "" {
			snapshot = resp.SyncedAt
		}
		if resp.SyncedXID > 0 && snapshotXID == "" {
			snapshotXID = strconv.FormatUint(resp.SyncedXID, 10)
		}

		mergeSyncResponse(merged, resp)

		if !resp.Truncated {
			break
		}

		if snapshot == "" {
			return fmt.Errorf("sync: truncated response missing synced_at")
		}
		if resp.NextCursor != nil {
			nextCursor := *resp.NextCursor
			if nextCursor == cursor {
				return fmt.Errorf("sync: truncated response did not advance next_cursor")
			}
			cursor = nextCursor
			legacyOffset = 0
		} else {
			legacyOffset += syncPageLimit
		}
	}

	stats, err := applySync(ctx, store, cfg.Full, merged)
	if err != nil {
		return err
	}
	if cfg.Stats != nil {
		*cfg.Stats = stats
	}

	storeSnapshot := snapshot
	storeSnapshotXID := snapshotXID
	if snapshot != "" {
		freshnessSafe, err := syncTimestampSafeForFreshness(snapshot, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("sync: parse synced_at %q: %w", snapshot, err)
		}
		if !freshnessSafe {
			storeSnapshot = ""
			storeSnapshotXID = ""
		}
	}

	if storeSnapshot != "" {
		if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, storeSnapshot); err != nil {
			return fmt.Errorf("sync: store sync timestamp: %w", err)
		}
	}
	if storeSnapshotXID != "" {
		if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, storeSnapshotXID); err != nil {
			return fmt.Errorf("sync: store sync xid: %w", err)
		}
	}

	return nil
}

func syncTimestampSafeForFreshness(raw string, now time.Time) (bool, error) {
	ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return false, err
	}
	return !ts.UTC().After(now.UTC().Add(maxSyncFutureSkew)), nil
}

func mergeSyncResponse(dst, src *syncResponse) {
	if dst.SyncedAt == "" {
		dst.SyncedAt = src.SyncedAt
	}
	if dst.SyncedXID == 0 {
		dst.SyncedXID = src.SyncedXID
	}
	dst.Vulnerabilities = append(dst.Vulnerabilities, src.Vulnerabilities...)
	dst.Malicious = append(dst.Malicious, src.Malicious...)
	dst.Reputation = append(dst.Reputation, src.Reputation...)
	dst.Lifecycle = append(dst.Lifecycle, src.Lifecycle...)
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
	pool, err := loadSyncCAPool(caCertFile)
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

func loadSyncCAPool(path string) (*x509.CertPool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path) // #nosec G304 -- user-specified CA bundle path
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no valid certificate", path)
	}
	return pool, nil
}

// fetchSyncPage makes a single HTTP request to the server sync endpoint.
func fetchSyncPage(ctx context.Context, client *http.Client, cfg SyncConfig, since, sinceXID string, cursor syncCursor, legacyOffset int, snapshot, snapshotXID string) (*syncResponse, error) {
	displayServerURL := logsafe.RedactURL(cfg.ServerURL)
	u, err := url.Parse(strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/sync")
	if err != nil {
		return nil, fmt.Errorf("sync: parse server URL %q: %w", displayServerURL, err)
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
	if !cursor.isZero() {
		setSyncCursorQuery(q, cursor)
	} else if legacyOffset > 0 {
		q.Set("offset", strconv.Itoa(legacyOffset))
	}
	if len(cfg.Ecosystems) > 0 {
		q.Set("ecosystem", strings.Join(cfg.Ecosystems, ","))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("sync: create request for server URL %q: %s", displayServerURL, logsafe.RedactDiagnosticMessage(err.Error()))
	}
	req.Header.Set("User-Agent", "packmon-cli/dev")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sync: server request: %s", logsafe.RedactURLRequestError(err, "server URL"))
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := readLimitedSyncResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sync: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sync: server returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var syncResp syncResponse
	if err := json.Unmarshal(body, &syncResp); err != nil {
		return nil, fmt.Errorf("sync: decode response: %w", err)
	}

	return &syncResp, nil
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

// applySync writes one page of sync data into the local database inside
// a single transaction. On full sync the first page drops all existing
// rows before inserting.
func applySync(ctx context.Context, store *Store, full bool, resp *syncResponse) (SyncStats, error) {
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
	defer closeSilently(vulnStmt)

	vulnDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM vulnerabilities_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare vuln delete: %w", err)
	}
	defer closeSilently(vulnDelStmt)

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
	defer closeSilently(malStmt)

	malDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM malicious_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare malicious delete: %w", err)
	}
	defer closeSilently(malDelStmt)

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
	defer closeSilently(repStmt)

	repDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM reputation_findings_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare reputation delete: %w", err)
	}
	defer closeSilently(repDelStmt)

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
		if _, err := repStmt.ExecContext(ctx,
			rep.ID, rep.Ecosystem, name, rep.Version,
			rep.Type, rep.RiskType, rep.Severity, rep.Summary,
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
	defer closeSilently(lifecycleStmt)

	lifecycleDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM lifecycle_releases_local WHERE id = ?`)
	if err != nil {
		return 0, fmt.Errorf("sync: prepare lifecycle delete: %w", err)
	}
	defer closeSilently(lifecycleDelStmt)

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
	return s[:maxLen] + "..."
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
