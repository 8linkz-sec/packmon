package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const (
	AdminAuditIntegrityVerified = "verified"
	AdminAuditIntegrityBroken   = "broken"
	AdminAuditIntegrityLegacy   = "legacy"
)

type adminAuditDigestPayload struct {
	Version        int    `json:"version"`
	ID             int    `json:"id"`
	Action         string `json:"action"`
	Details        string `json:"details"`
	IP             string `json:"ip"`
	CreatedAt      string `json:"created_at"`
	PreviousDigest string `json:"previous_digest"`
}

func ComputeAdminAuditDigest(entry AdminAuditLogEntry) string {
	payload := adminAuditDigestPayload{
		Version:        1,
		ID:             entry.ID,
		Action:         entry.Action,
		Details:        string(entry.Details),
		IP:             entry.IP,
		CreatedAt:      entry.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00"),
		PreviousDigest: entry.PreviousDigest,
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func AdminAuditIntegrityStatus(entry AdminAuditLogEntry) string {
	if entry.RowDigest == "" {
		return AdminAuditIntegrityLegacy
	}
	if entry.RowDigest != ComputeAdminAuditDigest(entry) {
		return AdminAuditIntegrityBroken
	}
	return AdminAuditIntegrityVerified
}

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
