package db

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
)

const (
	adminAuditSHA256Prefix     = "sha256:"
	adminAuditHMACSHA256Prefix = "hmac-sha256:"

	// AdminAuditIntegrityVerified means the row digest matches the row's canonical payload
	// and, when the adjacent prior row is loaded, the local digest-chain link is intact.
	AdminAuditIntegrityVerified = "verified"
	// AdminAuditIntegrityBroken means the row digest does not match its canonical
	// payload or the row's previous-digest link does not match the next loaded row.
	AdminAuditIntegrityBroken = "broken"
	// AdminAuditIntegrityLegacy means the row was written before row digests were
	// recorded, so Packmon cannot validate its canonical payload or chain link.
	AdminAuditIntegrityLegacy = "legacy"
)

var adminAuditDigestHMACKey struct {
	sync.RWMutex
	key []byte
}

type adminAuditDigestPayload struct {
	Version        int    `json:"version"`
	ID             int    `json:"id"`
	Action         string `json:"action"`
	Details        string `json:"details"`
	IP             string `json:"ip"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	CreatedAt      string `json:"created_at"`
	PreviousDigest string `json:"previous_digest"`
}

// SetAdminAuditDigestHMACKey configures the process-local key used for new
// admin audit row digests. The key is copied so callers can clear their input
// buffer after configuration.
func SetAdminAuditDigestHMACKey(key []byte) {
	adminAuditDigestHMACKey.Lock()
	defer adminAuditDigestHMACKey.Unlock()
	clear(adminAuditDigestHMACKey.key)
	adminAuditDigestHMACKey.key = append([]byte(nil), key...)
}

// ClearAdminAuditDigestHMACKey disables keyed admin audit digests for the
// current process. It is intended for development startup and tests.
func ClearAdminAuditDigestHMACKey() {
	adminAuditDigestHMACKey.Lock()
	defer adminAuditDigestHMACKey.Unlock()
	clear(adminAuditDigestHMACKey.key)
	adminAuditDigestHMACKey.key = nil
}

func currentAdminAuditDigestHMACKey() []byte {
	adminAuditDigestHMACKey.RLock()
	defer adminAuditDigestHMACKey.RUnlock()
	if len(adminAuditDigestHMACKey.key) == 0 {
		return nil
	}
	return append([]byte(nil), adminAuditDigestHMACKey.key...)
}

// ComputeAdminAuditDigest returns the digest for the canonical admin audit row
// payload. When a process-local HMAC key is configured, new rows use
// HMAC-SHA256 with the hmac-sha256: prefix. Without that key, Packmon writes the
// legacy sha256: digest used by older rows and development stores. The payload
// includes the row ID, action, raw JSON details, client IP, UTC creation
// timestamp with microsecond precision, and the previous row digest so each row
// commits to the loaded digest chain. Rows with a request correlation ID use
// payload version 2 and commit that ID; older rows without one keep version 1 so
// existing digest chains remain verifiable.
func ComputeAdminAuditDigest(entry AdminAuditLogEntry) string {
	data := adminAuditDigestPayloadBytes(entry)
	if key := currentAdminAuditDigestHMACKey(); len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(data)
		return adminAuditHMACSHA256Prefix + hex.EncodeToString(mac.Sum(nil))
	}
	return adminAuditLegacySHA256Digest(data)
}

func adminAuditDigestPayloadBytes(entry AdminAuditLogEntry) []byte {
	payload := adminAuditDigestPayload{
		Version:        1,
		ID:             entry.ID,
		Action:         entry.Action,
		Details:        string(entry.Details),
		IP:             entry.IP,
		CreatedAt:      entry.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00"),
		PreviousDigest: entry.PreviousDigest,
	}
	if entry.CorrelationID != "" {
		payload.Version = 2
		payload.CorrelationID = entry.CorrelationID
	}
	data, _ := json.Marshal(payload)
	return data
}

func adminAuditLegacySHA256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return adminAuditSHA256Prefix + hex.EncodeToString(sum[:])
}

func computeAdminAuditHMACSHA256Digest(data []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return adminAuditHMACSHA256Prefix + hex.EncodeToString(mac.Sum(nil))
}

// AdminAuditIntegrityStatus validates a single admin audit row digest without
// looking at neighboring rows. Rows without a digest are reported as legacy;
// rows whose stored digest no longer matches their canonical payload are broken.
func AdminAuditIntegrityStatus(entry AdminAuditLogEntry) string {
	if entry.RowDigest == "" {
		return AdminAuditIntegrityLegacy
	}
	data := adminAuditDigestPayloadBytes(entry)
	var expected string
	switch {
	case strings.HasPrefix(entry.RowDigest, adminAuditSHA256Prefix):
		expected = adminAuditLegacySHA256Digest(data)
	case strings.HasPrefix(entry.RowDigest, adminAuditHMACSHA256Prefix):
		key := currentAdminAuditDigestHMACKey()
		if len(key) == 0 {
			return AdminAuditIntegrityBroken
		}
		expected = computeAdminAuditHMACSHA256Digest(data, key)
	default:
		return AdminAuditIntegrityBroken
	}
	if !hmac.Equal([]byte(entry.RowDigest), []byte(expected)) {
		return AdminAuditIntegrityBroken
	}
	return AdminAuditIntegrityVerified
}

// AnnotateAdminAuditIntegrity populates IntegrityStatus for an already-loaded
// newest-to-oldest page of admin audit rows. Chain validation is local to that
// page: a verified row becomes broken when its PreviousDigest does not match the
// next loaded row's RowDigest.
func AnnotateAdminAuditIntegrity(entries []AdminAuditLogEntry) {
	for i := range entries {
		entries[i].IntegrityStatus = AdminAuditIntegrityStatus(entries[i])
	}
	for i := 0; i+1 < len(entries); i++ {
		if entries[i].IntegrityStatus != AdminAuditIntegrityVerified {
			continue
		}
		if entries[i].PreviousDigest == "" || entries[i+1].RowDigest == "" {
			continue
		}
		if entries[i].PreviousDigest != entries[i+1].RowDigest {
			entries[i].IntegrityStatus = AdminAuditIntegrityBroken
		}
	}
}
