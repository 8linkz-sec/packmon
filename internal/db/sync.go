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
	// splits a vulnerability across flagged pages, and each page is one
	// statement. The pages of an advisory split because its rows exceed
	// SyncVulnerabilityPageByteBudget never carry it.
	VulnerabilityAffectedComplete bool
	// VulnerabilitiesWithoutAffected lists, on a page that carries
	// VulnerabilityAffectedComplete, the IDs of changed vulnerabilities on
	// that page that have no affected package left (within the requested
	// ecosystems). They have no row to export, so the delta client drops their
	// local affected rows (within the requested ecosystems) instead. It is
	// empty on every unflagged page.
	VulnerabilitiesWithoutAffected []string
	// VulnerabilitySplitAdvisory names, on every page that holds rows of an
	// advisory split because its rows exceed SyncVulnerabilityPageByteBudget
	// (the page that starts the split and every page that continues it), that
	// advisory. It is empty on every other page.
	VulnerabilitySplitAdvisory string
	// VulnerabilitySplitComplete reports, on the last page of such a split,
	// that the split pages of this request sequence together delivered every
	// current affected row of the advisory (within the requested ecosystems):
	// neither the advisory nor any of its affected rows changed after the
	// pinned snapshot. A delta client that received every split page of the
	// advisory in this sequence can then drop its local affected rows (within
	// the requested ecosystems) that no split page delivered.
	VulnerabilitySplitComplete bool
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

// syncAdvisoryRowCursorTag versions the vulnerabilities_cursor that continues
// an advisory too large for one page inside that advisory. Its payload is the
// advisory ID and the last delivered (ecosystem, name) row. It has four parts,
// so a server that does not know it rejects it instead of reading it as a
// three-part legacy row cursor.
const syncAdvisoryRowCursorTag = "advisory-rows-v2"

// The sync page byte budgets bound the estimated JSON bytes of each dataset on
// one /api/v1/sync page, in addition to the row limit. Each page of a dataset
// takes rows while they fit its budget and always its first row, so every
// dataset that has rows left advances on every page. Together they take 28 MiB
// of the response size a client accepts (32 MiB, see
// synccontract.MaxResponseBytes): the vulnerability dataset, which repeats an
// advisory's summary and references on every affected row, keeps the largest
// share, the other datasets share the remaining headroom, and 4 MiB stay free
// for the envelope and for a first row that alone exceeds its budget.
const (
	// SyncVulnerabilityPageByteBudget bounds the vulnerability dataset. An
	// advisory whose rows alone exceed it is split over several pages that do
	// not carry VulnerabilityAffectedComplete.
	SyncVulnerabilityPageByteBudget = 12 << 20
	// SyncMaliciousPageByteBudget bounds the malicious dataset, whose rows can
	// carry long version lists and references.
	SyncMaliciousPageByteBudget = 8 << 20
	// SyncReputationPageByteBudget bounds the reputation dataset.
	SyncReputationPageByteBudget = 4 << 20
	// SyncLifecyclePageByteBudget bounds the lifecycle dataset.
	SyncLifecyclePageByteBudget = 4 << 20
)

// EncodeSyncAdvisoryRowCursor returns the vulnerabilities_cursor that
// continues the advisory with the given ID after its affected row (ecosystem,
// name), for an advisory split across pages because its rows exceed
// SyncVulnerabilityPageByteBudget.
func EncodeSyncAdvisoryRowCursor(id, ecosystem, name string) string {
	payload, _ := json.Marshal([]string{syncAdvisoryRowCursorTag, id, ecosystem, name})
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeSyncAdvisoryRowCursor returns the advisory ID and the last delivered
// (ecosystem, name) row of an advisory row cursor. It reports false for any
// other value, including advisory cursors and legacy row cursors.
func DecodeSyncAdvisoryRowCursor(raw string) (id, ecosystem, name string, ok bool) {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", "", "", false
	}
	var values []string
	if err := json.Unmarshal(payload, &values); err != nil {
		return "", "", "", false
	}
	if len(values) != 4 || values[0] != syncAdvisoryRowCursorTag || values[1] == "" || values[2] == "" || values[3] == "" {
		return "", "", "", false
	}
	return values[1], values[2], values[3], true
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
