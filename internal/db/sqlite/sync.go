package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// syncMetaKeyLastSync is the sync_meta key storing the ISO 8601 timestamp
// of the last successful sync.
const syncMetaKeyLastSync = "last_sync_at"

// SyncConfig holds parameters for a client-to-server sync operation.
type SyncConfig struct {
	ServerURL  string
	APIKey     string
	Ecosystems []string
	Full       bool
	Timeout    time.Duration
}

// syncVulnerability is the wire format for a single vulnerability
// delivered by the server's GET /api/v1/sync endpoint.
type syncVulnerability struct {
	ID            string   `json:"id"`
	Ecosystem     string   `json:"ecosystem"`
	Name          string   `json:"name"`
	VersionRanges string   `json:"version_ranges"` // JSON string
	Severity      string   `json:"severity"`
	CVSSScore     *float64 `json:"cvss_score"`
	EPSSScore     *float64 `json:"epss_score"`
	CISAKEV       bool     `json:"cisa_kev"`
	Summary       string   `json:"summary"`
	Withdrawn     bool     `json:"withdrawn"`
}

// syncMalicious is the wire format for a single malicious finding
// delivered by the server's GET /api/v1/sync endpoint.
type syncMalicious struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Versions  string `json:"versions"` // JSON string, empty = all
	RiskType  string `json:"risk_type"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Withdrawn bool   `json:"withdrawn"`
}

// syncResponse is the JSON envelope returned by the server sync endpoint.
type syncResponse struct {
	SyncedAt        string              `json:"synced_at"`
	Vulnerabilities []syncVulnerability `json:"vulnerabilities"`
	Malicious       []syncMalicious     `json:"malicious"`
	// Truncated is true when more data is available and the client
	// should call again with the updated since parameter.
	Truncated bool `json:"truncated"`
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

	client := &http.Client{Timeout: cfg.Timeout}

	// Determine the since timestamp for delta sync.
	var since string
	if !cfg.Full {
		var err error
		since, err = store.GetSyncMeta(ctx, syncMetaKeyLastSync)
		if err != nil {
			return fmt.Errorf("sync: read last sync timestamp: %w", err)
		}
	}

	// Loop to handle paginated responses.
	for {
		resp, err := fetchSyncPage(ctx, client, cfg, since)
		if err != nil {
			return err
		}

		if err := applySync(ctx, store, cfg.Full, resp); err != nil {
			return err
		}

		// Store the new sync timestamp.
		if resp.SyncedAt != "" {
			if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, resp.SyncedAt); err != nil {
				return fmt.Errorf("sync: store sync timestamp: %w", err)
			}
			since = resp.SyncedAt
		}

		if !resp.Truncated {
			break
		}

		// After the first page of a full sync, switch to delta mode
		// so subsequent pages use the since parameter.
		cfg.Full = false
	}

	return nil
}

// fetchSyncPage makes a single HTTP request to the server sync endpoint.
func fetchSyncPage(ctx context.Context, client *http.Client, cfg SyncConfig, since string) (*syncResponse, error) {
	u, err := url.Parse(strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/sync")
	if err != nil {
		return nil, fmt.Errorf("sync: parse server URL: %w", err)
	}

	q := u.Query()
	if since != "" {
		q.Set("since", since)
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
	defer resp.Body.Close()

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
	}

	// Upsert vulnerabilities.
	vulnStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities_local(id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, cisa_kev, summary)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ecosystem      = excluded.ecosystem,
			name           = excluded.name,
			version_ranges = excluded.version_ranges,
			severity       = excluded.severity,
			cvss_score     = excluded.cvss_score,
			epss_score     = excluded.epss_score,
			cisa_kev       = excluded.cisa_kev,
			summary        = excluded.summary`)
	if err != nil {
		return fmt.Errorf("sync: prepare vuln upsert: %w", err)
	}
	defer vulnStmt.Close()

	vulnDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM vulnerabilities_local WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("sync: prepare vuln delete: %w", err)
	}
	defer vulnDelStmt.Close()

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
			v.ID, v.Ecosystem, v.Name, v.VersionRanges,
			v.Severity, cvss, epss, cisaKEV, v.Summary,
		); err != nil {
			return fmt.Errorf("sync: upsert vuln %s: %w", v.ID, err)
		}
	}

	// Upsert malicious findings.
	malStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ecosystem = excluded.ecosystem,
			name      = excluded.name,
			versions  = excluded.versions,
			risk_type = excluded.risk_type,
			severity  = excluded.severity,
			summary   = excluded.summary`)
	if err != nil {
		return fmt.Errorf("sync: prepare malicious upsert: %w", err)
	}
	defer malStmt.Close()

	malDelStmt, err := tx.PrepareContext(ctx, `DELETE FROM malicious_local WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("sync: prepare malicious delete: %w", err)
	}
	defer malDelStmt.Close()

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
			m.RiskType, m.Severity, m.Summary,
		); err != nil {
			return fmt.Errorf("sync: upsert malicious %s: %w", m.ID, err)
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
