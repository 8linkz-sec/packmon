package devstore

import (
	"encoding/json"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func cloneVulnerability(vuln db.Vulnerability) db.Vulnerability {
	copyValue := vuln
	copyValue.Aliases = append([]db.VulnerabilityAlias(nil), vuln.Aliases...)
	copyValue.Sources = append([]db.VulnerabilitySource(nil), vuln.Sources...)
	copyValue.References = append([]db.VulnerabilityReference(nil), vuln.References...)
	copyValue.AffectedPackages = append([]db.AffectedPackage(nil), vuln.AffectedPackages...)
	for i := range copyValue.Sources {
		if copyValue.Sources[i].RawJSON != nil {
			copyValue.Sources[i].RawJSON = append(json.RawMessage(nil), copyValue.Sources[i].RawJSON...)
		}
	}
	for i := range copyValue.AffectedPackages {
		if copyValue.AffectedPackages[i].VersionRanges != nil {
			copyValue.AffectedPackages[i].VersionRanges = append(json.RawMessage(nil), copyValue.AffectedPackages[i].VersionRanges...)
		}
		if copyValue.AffectedPackages[i].VersionsAffected != nil {
			copyValue.AffectedPackages[i].VersionsAffected = append(json.RawMessage(nil), copyValue.AffectedPackages[i].VersionsAffected...)
		}
	}
	return copyValue
}

func cloneMaliciousFinding(finding db.MaliciousFinding) db.MaliciousFinding {
	copyValue := finding
	copyValue.VersionRanges = cloneRawMessage(finding.VersionRanges)
	copyValue.Versions = cloneRawMessage(finding.Versions)
	copyValue.ReferenceURLs = cloneRawMessage(finding.ReferenceURLs)
	copyValue.Published = cloneTimePtr(finding.Published)
	return copyValue
}

func cloneFeedSyncStatus(status db.FeedSyncStatus) db.FeedSyncStatus {
	copyValue := status
	copyValue.LastSyncAt = cloneTimePtr(status.LastSyncAt)
	copyValue.LastSyncDuration = cloneDurationPtr(status.LastSyncDuration)
	copyValue.Metadata = cloneRawMessage(status.Metadata)
	return copyValue
}

func cloneAdminAuditLogEntry(entry db.AdminAuditLogEntry) db.AdminAuditLogEntry {
	copyValue := entry
	copyValue.Details = cloneRawMessage(entry.Details)
	return copyValue
}

func cloneRefreshJob(job db.RefreshJob) db.RefreshJob {
	copyValue := job
	copyValue.ProcessedAt = cloneTimePtr(job.ProcessedAt)
	return copyValue
}

func cloneScanLogEntry(entry db.ScanLogEntry) db.ScanLogEntry {
	copyValue := entry
	copyValue.FeedVersions = cloneStringMap(entry.FeedVersions)
	copyValue.FindingIDs = append([]string(nil), entry.FindingIDs...)
	copyValue.FindingSeverities = append([]string(nil), entry.FindingSeverities...)
	return copyValue
}

func cloneAPIKey(apiKey db.APIKey) db.APIKey {
	copyValue := apiKey
	copyValue.RevokedAt = cloneTimePtr(apiKey.RevokedAt)
	copyValue.LastUsedAt = cloneTimePtr(apiKey.LastUsedAt)
	copyValue.ExpiresAt = cloneTimePtr(apiKey.ExpiresAt)
	copyValue.DeletedAt = cloneTimePtr(apiKey.DeletedAt)
	return copyValue
}

func clonePackageCheckStatus(status db.PackageCheckStatus) db.PackageCheckStatus {
	copyValue := status
	copyValue.LastCheckedAt = cloneTimePtr(status.LastCheckedAt)
	copyValue.NextCheckAt = cloneTimePtr(status.NextCheckAt)
	copyValue.LastResult = cloneRawMessage(status.LastResult)
	return copyValue
}

func cloneRawMessage(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	return append(json.RawMessage(nil), value...)
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	copyValue := make(map[string]string, len(value))
	for k, v := range value {
		copyValue[k] = v
	}
	return copyValue
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDurationPtr(value *time.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
