package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

const (
	PrivacySelectorClientIP      = "client-ip"
	PrivacySelectorRepoName      = "repo-name"
	PrivacySelectorAPIKeyID      = "api-key-id"
	PrivacySelectorAPIKeyName    = "api-key-name"
	PrivacySelectorCorrelationID = "correlation-id"
)

// PrivacyExportSelector identifies the exact server metadata selector used for
// an operator privacy export. Value is intentionally omitted from audit details
// and may only appear in the emitted export document.
type PrivacyExportSelector struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Digest returns a stable non-reversible selector digest for audit details.
func (s PrivacyExportSelector) Digest() string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s.Type) + "\x00" + strings.TrimSpace(s.Value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type PrivacyExport struct {
	GeneratedAt     time.Time                 `json:"generated_at"`
	Selector        PrivacyExportSelector     `json:"selector"`
	ScanLogs        []PrivacyExportScanLog    `json:"scan_logs"`
	AdminAuditLogs  []PrivacyExportAdminAudit `json:"admin_audit_logs"`
	ScanLogCount    int                       `json:"scan_log_count"`
	AdminAuditCount int                       `json:"admin_audit_count"`
}

type PrivacyExportScanLog struct {
	ScanID                string            `json:"scan_id"`
	RepoName              string            `json:"repo_name,omitempty"`
	ScannedAt             time.Time         `json:"scanned_at"`
	PackagesCount         int               `json:"packages_count"`
	FindingsCount         int               `json:"findings_count"`
	DurationMs            int               `json:"duration_ms"`
	ClientIP              string            `json:"client_ip,omitempty"`
	ClientVersion         string            `json:"client_version,omitempty"`
	APIKeyID              int               `json:"api_key_id,omitempty"`
	APIKeyName            string            `json:"api_key_name,omitempty"`
	CorrelationID         string            `json:"correlation_id,omitempty"`
	IdempotencyKey        string            `json:"idempotency_key,omitempty"`
	RequestDigest         string            `json:"request_digest,omitempty"`
	ResultDigest          string            `json:"result_digest,omitempty"`
	FindingsBlocking      bool              `json:"findings_blocking"`
	BlockThreshold        string            `json:"block_threshold,omitempty"`
	FeedStatus            string            `json:"feed_status,omitempty"`
	FeedVersions          map[string]string `json:"feed_versions,omitempty"`
	FindingIDs            []string          `json:"finding_ids,omitempty"`
	FindingSeverities     []string          `json:"finding_severities,omitempty"`
	ManualAdvisoriesCount int               `json:"manual_advisories_count"`
}

type PrivacyExportAdminAudit struct {
	ID              int             `json:"id"`
	Action          string          `json:"action"`
	Details         json.RawMessage `json:"details,omitempty"`
	IP              string          `json:"ip,omitempty"`
	CorrelationID   string          `json:"correlation_id,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	PreviousDigest  string          `json:"previous_digest,omitempty"`
	RowDigest       string          `json:"row_digest,omitempty"`
	IntegrityStatus string          `json:"integrity_status,omitempty"`
}
