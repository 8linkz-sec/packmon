package db

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// SyncExportOptions controls the dataset returned by a server-side sync export.
type SyncExportOptions struct {
	Since       *time.Time
	SinceXID    uint64
	SnapshotAt  time.Time
	SnapshotXID uint64
	Ecosystems  []string
	Limit       int
	Offset      int
	Cursor      SyncCursor
	// ExcludeReputation omits the package reputation dataset. The API sets it
	// when /api/v1/check would not read reputation rows either (ReversingLabs
	// not enabled in self mode), so local sync never exports findings that a
	// remote check would ignore. EffectiveCursor reports the dataset as done.
	ExcludeReputation bool
}

// SyncExport is the server-side payload consumed by local SQLite sync.
type SyncExport struct {
	SyncedAt        time.Time
	SyncedXID       uint64
	Vulnerabilities []SyncVulnerability
	Malicious       []SyncMalicious
	Reputation      []SyncReputationFinding
	Lifecycle       []SyncLifecycleRelease
	Truncated       bool
	NextCursor      *SyncCursor
	// VulnerabilityAffectedComplete reports that this export is a delta page
	// (since window) that sends every vulnerability it includes with all of its
	// current affected packages (within the requested ecosystems), so a delta
	// client can drop local affected rows of those vulnerabilities the page did
	// not send. It holds per page: a delta paged by whole advisories never
	// splits a vulnerability across pages, and each page is one statement.
	VulnerabilityAffectedComplete bool
	// VulnerabilitiesWithoutAffected lists, on a page that carries
	// VulnerabilityAffectedComplete, the IDs of changed vulnerabilities on
	// that page that have no affected package left (within the requested
	// ecosystems). They have no row to export, so the delta client drops their
	// local affected rows (within the requested ecosystems) instead. It is
	// empty on every unflagged page.
	VulnerabilitiesWithoutAffected []string
}

// syncAdvisoryCursorTag versions the vulnerabilities_cursor of a delta that
// pages by whole advisories. Its payload is the last advisory ID of the page;
// the legacy row cursor carries three untagged parts (ecosystem, name, id).
const syncAdvisoryCursorTag = "advisory-v2"

// EncodeSyncAdvisoryCursor returns the vulnerabilities_cursor that continues
// an advisory-paged delta after the advisory with the given ID. It uses the
// same base64url JSON-array encoding as the other keyset cursors.
func EncodeSyncAdvisoryCursor(id string) string {
	payload, _ := json.Marshal([]string{syncAdvisoryCursorTag, id})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeSyncAdvisoryCursor returns the advisory ID of an advisory cursor. It
// reports false for any other value, including the legacy row cursor, so
// callers can fall back to legacy row paging for cursors older servers issued.
func DecodeSyncAdvisoryCursor(raw string) (string, bool) {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", false
	}
	var values []string
	if err := json.Unmarshal(payload, &values); err != nil {
		return "", false
	}
	if len(values) != 2 || values[0] != syncAdvisoryCursorTag || values[1] == "" {
		return "", false
	}
	return values[1], true
}

// SyncCursor carries per-dataset pagination state for /api/v1/sync exports.
//
// The zero value means "start at the beginning" for vulnerabilities, malicious
// findings, reputation rows, and lifecycle rows. Pagination state is split by
// dataset because each exported dataset can exhaust at a different page while
// the sync stays within one stable snapshot.
type SyncCursor struct {
	// Legacy offsets are retained for older clients and for the top-level
	// SyncExportOptions.Offset fallback. A dataset offset is used only when the
	// matching opaque keyset cursor string is empty.
	Vulnerabilities int `json:"vulnerabilities"`
	Malicious       int `json:"malicious"`
	Reputation      int `json:"reputation"`
	Lifecycle       int `json:"lifecycle"`

	// Opaque keyset cursor strings are returned by the server in next_cursor
	// and echoed by modern clients on the next page request. Callers must treat
	// these strings as server-owned tokens, not as a stable public encoding.
	VulnerabilitiesCursor string `json:"vulnerabilities_cursor,omitempty"`
	MaliciousCursor       string `json:"malicious_cursor,omitempty"`
	ReputationCursor      string `json:"reputation_cursor,omitempty"`
	LifecycleCursor       string `json:"lifecycle_cursor,omitempty"`

	// Done flags mark datasets that were exhausted in the current paginated
	// sync sequence. The exporter skips a done dataset on later pages so other
	// datasets can continue advancing independently.
	VulnerabilitiesDone bool `json:"vulnerabilities_done,omitempty"`
	MaliciousDone       bool `json:"malicious_done,omitempty"`
	ReputationDone      bool `json:"reputation_done,omitempty"`
	LifecycleDone       bool `json:"lifecycle_done,omitempty"`
}

// IsZero reports whether the cursor carries no offsets, keyset cursor strings,
// or done flags. A zero cursor requests the first page for every dataset.
func (c SyncCursor) IsZero() bool {
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

// EffectiveCursor returns the explicit cursor when one was provided. If only a
// legacy top-level Offset was provided, it expands that offset to all datasets
// so older offset-only clients keep paginating through the same export path.
// Non-positive offsets leave the cursor at its zero-value first-page state.
// With ExcludeReputation the reputation dataset is reported as done and its
// keyset cursor is dropped, so exporters skip it and every next_cursor keeps
// reputation_done=true.
func (opts SyncExportOptions) EffectiveCursor() SyncCursor {
	cursor := opts.Cursor
	if cursor.IsZero() && opts.Offset > 0 {
		cursor = SyncCursor{
			Vulnerabilities: opts.Offset,
			Malicious:       opts.Offset,
			Reputation:      opts.Offset,
			Lifecycle:       opts.Offset,
		}
	}
	if opts.ExcludeReputation {
		cursor.ReputationCursor = ""
		cursor.ReputationDone = true
	}
	return cursor
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
	EPSSPercentile   *float64
	CISAKEV          bool
	Summary          string
	Source           string
	Withdrawn        bool
}

// SyncMalicious is the flattened malicious finding row exported to local SQLite.
type SyncMalicious struct {
	ID            string
	Ecosystem     string
	Name          string
	VersionRanges string
	Versions      string
	ReferenceURLs string
	RiskType      string
	Severity      string
	Summary       string
	Source        string
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
