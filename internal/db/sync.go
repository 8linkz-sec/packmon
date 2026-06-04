package db

import "time"

// SyncExportOptions controls the dataset returned by a server-side sync export.
type SyncExportOptions struct {
	Since      *time.Time
	SnapshotAt time.Time
	Ecosystems []string
	Limit      int
	Offset     int
	Cursor     SyncCursor
}

// SyncExport is the server-side payload consumed by local SQLite sync.
type SyncExport struct {
	SyncedAt        time.Time
	Vulnerabilities []SyncVulnerability
	Malicious       []SyncMalicious
	Reputation      []SyncReputationFinding
	Lifecycle       []SyncLifecycleRelease
	Truncated       bool
	NextCursor      *SyncCursor
}

type SyncCursor struct {
	Vulnerabilities int `json:"vulnerabilities"`
	Malicious       int `json:"malicious"`
	Reputation      int `json:"reputation"`
	Lifecycle       int `json:"lifecycle"`
}

func (c SyncCursor) IsZero() bool {
	return c.Vulnerabilities == 0 && c.Malicious == 0 && c.Reputation == 0 && c.Lifecycle == 0
}

func (opts SyncExportOptions) EffectiveCursor() SyncCursor {
	if !opts.Cursor.IsZero() {
		return opts.Cursor
	}
	if opts.Offset <= 0 {
		return SyncCursor{}
	}
	return SyncCursor{
		Vulnerabilities: opts.Offset,
		Malicious:       opts.Offset,
		Reputation:      opts.Offset,
		Lifecycle:       opts.Offset,
	}
}

// SyncVulnerability is the flattened vulnerability row exported to local SQLite.
type SyncVulnerability struct {
	ID               string
	Ecosystem        string
	Name             string
	VersionRanges    string
	VersionsAffected string
	References       string
	Severity         string
	CVSSScore        *float64
	EPSSScore        *float64
	CISAKEV          bool
	Summary          string
	Withdrawn        bool
}

// SyncMalicious is the flattened malicious finding row exported to local SQLite.
type SyncMalicious struct {
	ID            string
	Ecosystem     string
	Name          string
	Versions      string
	ReferenceURLs string
	RiskType      string
	Severity      string
	Summary       string
	Withdrawn     bool
}

// SyncReputationFinding is a flattened cached reputation row exported to local
// SQLite. Withdrawn rows are tombstones keyed by ID.
type SyncReputationFinding struct {
	ID        string
	Ecosystem string
	Name      string
	Version   string
	Type      string
	RiskType  string
	Severity  string
	Summary   string
	Withdrawn bool
}

// SyncLifecycleRelease is a flattened lifecycle package-map x release-cycle
// row exported to local SQLite. Local scans compute current lifecycle findings
// from these raw status booleans and dates.
type SyncLifecycleRelease struct {
	ID               string
	Ecosystem        string
	Name             string
	ProductSlug      string
	ProductLabel     string
	Cycle            string
	Latest           string
	ReleaseDate      *time.Time
	IsLTS            bool
	LTSFrom          *time.Time
	IsEOAS           bool
	EOASFrom         *time.Time
	IsEOL            bool
	EOLFrom          *time.Time
	IsDiscontinued   bool
	DiscontinuedFrom *time.Time
	IsEOES           *bool
	EOESFrom         *time.Time
	IsMaintained     bool
	Withdrawn        bool
}
