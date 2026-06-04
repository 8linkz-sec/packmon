package sqlite

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// syncMetaKeyLastSync is the sync_meta key storing the ISO 8601 timestamp
// of the last successful sync.
const syncMetaKeyLastSync = "last_sync_at"

const syncPageLimit = 1000

// SyncConfig holds parameters for a client-to-server sync operation.
type SyncConfig struct {
	ServerURL         string
	APIKey            string
	Ecosystems        []string
	Full              bool
	Timeout           time.Duration
	AllowInsecureHTTP bool
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
	CISAKEV          bool     `json:"cisa_kev"`
	Summary          string   `json:"summary"`
	Withdrawn        bool     `json:"withdrawn"`
}

// syncMalicious is the wire format for a single malicious finding
// delivered by the server's GET /api/v1/sync endpoint.
type syncMalicious struct {
	ID            string `json:"id"`
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Versions      string `json:"versions"` // JSON string, empty = all
	ReferenceURLs string `json:"reference_urls"`
	RiskType      string `json:"risk_type"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
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
	ID               string     `json:"id"`
	Ecosystem        string     `json:"ecosystem"`
	Name             string     `json:"name"`
	ProductSlug      string     `json:"product_slug"`
	ProductLabel     string     `json:"product_label"`
	Cycle            string     `json:"cycle"`
	Latest           string     `json:"latest"`
	ReleaseDate      *time.Time `json:"release_date"`
	IsLTS            bool       `json:"is_lts"`
	LTSFrom          *time.Time `json:"lts_from"`
	IsEOAS           bool       `json:"is_eoas"`
	EOASFrom         *time.Time `json:"eoas_from"`
	IsEOL            bool       `json:"is_eol"`
	EOLFrom          *time.Time `json:"eol_from"`
	IsDiscontinued   bool       `json:"is_discontinued"`
	DiscontinuedFrom *time.Time `json:"discontinued_from"`
	IsEOES           *bool      `json:"is_eoes"`
	EOESFrom         *time.Time `json:"eoes_from"`
	IsMaintained     bool       `json:"is_maintained"`
	Withdrawn        bool       `json:"withdrawn"`
}

// syncResponse is the JSON envelope returned by the server sync endpoint.
type syncResponse struct {
	SyncedAt        string                 `json:"synced_at"`
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
}

func (c syncCursor) isZero() bool {
	return c.Vulnerabilities == 0 && c.Malicious == 0 && c.Reputation == 0 && c.Lifecycle == 0
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
	if err := validateSyncServerURL(cfg.ServerURL, cfg.AllowInsecureHTTP); err != nil {
		return err
	}

	client := newSyncHTTPClient(cfg.Timeout)

	// Determine the since timestamp for delta sync.
	var since string
	if !cfg.Full {
		var err error
		since, err = store.GetSyncMeta(ctx, syncMetaKeyLastSync)
		if err != nil {
			return fmt.Errorf("sync: read last sync timestamp: %w", err)
		}
	}

	legacyOffset := 0
	cursor := syncCursor{}
	snapshot := ""
	firstPage := true

	// Loop to handle paginated responses.
	for {
		resp, err := fetchSyncPage(ctx, client, cfg, since, cursor, legacyOffset, snapshot)
		if err != nil {
			return err
		}

		if resp.SyncedAt != "" && snapshot == "" {
			snapshot = resp.SyncedAt
		}

		if err := applySync(ctx, store, cfg.Full && firstPage, resp); err != nil {
			return err
		}
		firstPage = false

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

	if snapshot != "" {
		if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, snapshot); err != nil {
			return fmt.Errorf("sync: store sync timestamp: %w", err)
		}
	}

	return nil
}

func validateSyncServerURL(serverURL string, allowInsecureHTTP bool) error {
	parsed, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil {
		return fmt.Errorf("sync: parse server URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !allowInsecureHTTP {
		return fmt.Errorf("sync: refusing to use insecure server URL %q: scheme must be https (set --insecure-allow-http / PACKMON_INSECURE_ALLOW_HTTP to override)", serverURL)
	}
	return nil
}

func newSyncHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// fetchSyncPage makes a single HTTP request to the server sync endpoint.
func fetchSyncPage(ctx context.Context, client *http.Client, cfg SyncConfig, since string, cursor syncCursor, legacyOffset int, snapshot string) (*syncResponse, error) {
	u, err := url.Parse(strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/sync")
	if err != nil {
		return nil, fmt.Errorf("sync: parse server URL: %w", err)
	}

	q := u.Query()
	if since != "" {
		q.Set("since", since)
	}
	if snapshot != "" {
		q.Set("snapshot", snapshot)
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
		return nil, fmt.Errorf("sync: create request: %w", err)
	}
	req.Header.Set("User-Agent", "packmon-cli/dev")
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sync: server request: %w", err)
	}
	defer closeSilently(resp.Body)

	body, err := io.ReadAll(resp.Body)
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
}

// applySync writes one page of sync data into the local database inside
// a single transaction. On full sync the first page drops all existing
// rows before inserting.
func applySync(ctx context.Context, store *Store, full bool, resp *syncResponse) error {
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sync: begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback on commit is a no-op

	// Full sync: clear existing data.
	if full {
		if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerabilities_local`); err != nil {
			return fmt.Errorf("sync: clear vulnerabilities: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM malicious_local`); err != nil {
			return fmt.Errorf("sync: clear malicious: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM reputation_findings_local`); err != nil {
			return fmt.Errorf("sync: clear reputation findings: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM lifecycle_releases_local`); err != nil {
			return fmt.Errorf("sync: clear lifecycle releases: %w", err)
		}
	}

	// Upsert vulnerabilities.
	vulnStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, references_json, severity, cvss_score, epss_score, cisa_kev, summary)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
			cisa_kev       = excluded.cisa_kev,
			summary        = excluded.summary`)
	if err != nil {
		return fmt.Errorf("sync: prepare vuln upsert: %w", err)
	}
	defer closeSilently(vulnStmt)

	vulnDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM vulnerabilities_local WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("sync: prepare vuln delete: %w", err)
	}
	defer closeSilently(vulnDelStmt)

	for _, v := range resp.Vulnerabilities {
		if v.Withdrawn {
			// Tombstone: remove from local DB.
			if _, err := vulnDelStmt.ExecContext(ctx, v.ID); err != nil {
				return fmt.Errorf("sync: delete withdrawn vuln %s: %w", v.ID, err)
			}
			continue
		}

		var cvss, epss interface{}
		if v.CVSSScore != nil {
			cvss = *v.CVSSScore
		}
		if v.EPSSScore != nil {
			epss = *v.EPSSScore
		}
		cisaKEV := 0
		if v.CISAKEV {
			cisaKEV = 1
		}

		if _, err := vulnStmt.ExecContext(ctx,
			syncVulnerabilityRowKey(v.ID, v.Ecosystem, v.Name), v.ID, v.Ecosystem, v.Name, v.VersionRanges,
			v.VersionsAffected, v.References, v.Severity, cvss, epss, cisaKEV, v.Summary,
		); err != nil {
			return fmt.Errorf("sync: upsert vuln %s: %w", v.ID, err)
		}
	}

	// Upsert malicious findings.
	malStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO malicious_local(id, ecosystem, name, versions, reference_urls, risk_type, severity, summary)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ecosystem = excluded.ecosystem,
			name      = excluded.name,
			versions  = excluded.versions,
			reference_urls = excluded.reference_urls,
			risk_type = excluded.risk_type,
			severity  = excluded.severity,
			summary   = excluded.summary`)
	if err != nil {
		return fmt.Errorf("sync: prepare malicious upsert: %w", err)
	}
	defer closeSilently(malStmt)

	malDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM malicious_local WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("sync: prepare malicious delete: %w", err)
	}
	defer closeSilently(malDelStmt)

	for _, m := range resp.Malicious {
		if m.Withdrawn {
			if _, err := malDelStmt.ExecContext(ctx, m.ID); err != nil {
				return fmt.Errorf("sync: delete withdrawn malicious %s: %w", m.ID, err)
			}
			continue
		}

		var versions interface{}
		if m.Versions != "" {
			versions = m.Versions
		}

		if _, err := malStmt.ExecContext(ctx,
			m.ID, m.Ecosystem, m.Name, versions,
			m.ReferenceURLs, m.RiskType, m.Severity, m.Summary,
		); err != nil {
			return fmt.Errorf("sync: upsert malicious %s: %w", m.ID, err)
		}
	}

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
		return fmt.Errorf("sync: prepare reputation upsert: %w", err)
	}
	defer closeSilently(repStmt)

	repDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM reputation_findings_local WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("sync: prepare reputation delete: %w", err)
	}
	defer closeSilently(repDelStmt)

	for _, rep := range resp.Reputation {
		if rep.Withdrawn {
			if _, err := repDelStmt.ExecContext(ctx, rep.ID); err != nil {
				return fmt.Errorf("sync: delete withdrawn reputation %s: %w", rep.ID, err)
			}
			continue
		}

		if _, err := repStmt.ExecContext(ctx,
			rep.ID, rep.Ecosystem, rep.Name, rep.Version,
			rep.Type, rep.RiskType, rep.Severity, rep.Summary,
		); err != nil {
			return fmt.Errorf("sync: upsert reputation %s: %w", rep.ID, err)
		}
	}

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
		return fmt.Errorf("sync: prepare lifecycle upsert: %w", err)
	}
	defer closeSilently(lifecycleStmt)

	lifecycleDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM lifecycle_releases_local WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("sync: prepare lifecycle delete: %w", err)
	}
	defer closeSilently(lifecycleDelStmt)

	for _, lifecycle := range resp.Lifecycle {
		if lifecycle.Withdrawn {
			if _, err := lifecycleDelStmt.ExecContext(ctx, lifecycle.ID); err != nil {
				return fmt.Errorf("sync: delete withdrawn lifecycle %s: %w", lifecycle.ID, err)
			}
			continue
		}

		if _, err := lifecycleStmt.ExecContext(ctx,
			lifecycle.ID,
			lifecycle.Ecosystem,
			lifecycle.Name,
			lifecycle.ProductSlug,
			lifecycle.ProductLabel,
			lifecycle.Cycle,
			lifecycle.Latest,
			syncDateValue(lifecycle.ReleaseDate),
			boolInt(lifecycle.IsLTS),
			syncDateValue(lifecycle.LTSFrom),
			boolInt(lifecycle.IsEOAS),
			syncDateValue(lifecycle.EOASFrom),
			boolInt(lifecycle.IsEOL),
			syncDateValue(lifecycle.EOLFrom),
			boolInt(lifecycle.IsDiscontinued),
			syncDateValue(lifecycle.DiscontinuedFrom),
			nullableBoolInt(lifecycle.IsEOES),
			syncDateValue(lifecycle.EOESFrom),
			boolInt(lifecycle.IsMaintained),
		); err != nil {
			return fmt.Errorf("sync: upsert lifecycle %s: %w", lifecycle.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sync: commit transaction: %w", err)
	}

	return nil
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

func syncDateValue(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.DateOnly)
}
