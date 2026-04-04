package db

import "time"

// SyncExportOptions controls the dataset returned by a server-side sync export.
type SyncExportOptions struct {
	Since      *time.Time
	SnapshotAt time.Time
	Ecosystems []string
}

// SyncExport is the server-side payload consumed by local SQLite sync.
type SyncExport struct {
	SyncedAt        time.Time
	Vulnerabilities []SyncVulnerability
	Malicious       []SyncMalicious
	Truncated       bool
}

// SyncVulnerability is the flattened vulnerability row exported to local SQLite.
type SyncVulnerability struct {
	ID            string
	Ecosystem     string
	Name          string
	VersionRanges string
	Severity      string
	CVSSScore     *float64
	EPSSScore     *float64
	CISAKEV       bool
	Summary       string
	Withdrawn     bool
}

// SyncMalicious is the flattened malicious finding row exported to local SQLite.
type SyncMalicious struct {
	ID        string
	Ecosystem string
	Name      string
	Versions  string
	RiskType  string
	Severity  string
	Summary   string
	Withdrawn bool
}
