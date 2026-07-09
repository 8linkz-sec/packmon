// Package synccontract defines the shared /api/v1/sync wire contract.
package synccontract

import (
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

const (
	// DefaultLimit is the server default number of rows per source category.
	DefaultLimit = 1000

	// MaxLimit is the maximum accepted rows per source category. The SQLite
	// client requests this value to minimize pagination roundtrips while staying
	// inside the server contract.
	MaxLimit = 10000
)

// Response is the JSON envelope returned by the server sync endpoint.
type Response struct {
	SyncedAt        string            `json:"synced_at"`
	SyncedXID       uint64            `json:"synced_xid,omitempty"`
	FeedStatus      string            `json:"feed_status"`
	FeedVersions    map[string]string `json:"feed_versions"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	Malicious       []Malicious       `json:"malicious"`
	Reputation      []Reputation      `json:"reputation"`
	Lifecycle       []Lifecycle       `json:"lifecycle"`
	Truncated       bool              `json:"truncated"`
	HasMore         bool              `json:"has_more"`
	NextCursor      *Cursor           `json:"next_cursor,omitempty"`
}

// Cursor is the opaque paginated-sync cursor returned by the server and echoed
// by clients on subsequent sync pages.
type Cursor struct {
	Vulnerabilities int `json:"vulnerabilities"`
	Malicious       int `json:"malicious"`
	Reputation      int `json:"reputation"`
	Lifecycle       int `json:"lifecycle"`

	VulnerabilitiesCursor string `json:"vulnerabilities_cursor,omitempty"`
	MaliciousCursor       string `json:"malicious_cursor,omitempty"`
	ReputationCursor      string `json:"reputation_cursor,omitempty"`
	LifecycleCursor       string `json:"lifecycle_cursor,omitempty"`

	VulnerabilitiesDone bool `json:"vulnerabilities_done,omitempty"`
	MaliciousDone       bool `json:"malicious_done,omitempty"`
	ReputationDone      bool `json:"reputation_done,omitempty"`
	LifecycleDone       bool `json:"lifecycle_done,omitempty"`
}

// IsZero reports whether the cursor carries no pagination state.
func (c Cursor) IsZero() bool {
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

// Vulnerability is the wire format for one vulnerability row.
type Vulnerability struct {
	ID               string   `json:"id"`
	Ecosystem        string   `json:"ecosystem"`
	Name             string   `json:"name"`
	VersionRanges    string   `json:"version_ranges"`
	VersionsAffected string   `json:"versions_affected"`
	References       string   `json:"references"`
	Severity         string   `json:"severity"`
	CVSSScore        *float64 `json:"cvss_score"`
	EPSSScore        *float64 `json:"epss_score"`
	EPSSPercentile   *float64 `json:"epss_percentile"`
	CISAKEV          bool     `json:"cisa_kev"`
	Summary          string   `json:"summary"`
	Source           string   `json:"source"`
	Withdrawn        bool     `json:"withdrawn"`
}

// Malicious is the wire format for one malicious-package row.
type Malicious struct {
	ID            string `json:"id"`
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	VersionRanges string `json:"version_ranges"`
	Versions      string `json:"versions"`
	ReferenceURLs string `json:"reference_urls"`
	RiskType      string `json:"risk_type"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
	Source        string `json:"source"`
	Withdrawn     bool   `json:"withdrawn"`
}

// Reputation is the wire format for one cached reputation row or tombstone.
type Reputation struct {
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

// Lifecycle is the wire format for one lifecycle cache row or tombstone.
type Lifecycle struct {
	ID               string  `json:"id"`
	Ecosystem        string  `json:"ecosystem"`
	Name             string  `json:"name"`
	ProductSlug      string  `json:"product_slug"`
	ProductLabel     string  `json:"product_label"`
	Cycle            string  `json:"cycle"`
	Latest           string  `json:"latest"`
	ReleaseDate      *string `json:"release_date"`
	IsLTS            bool    `json:"is_lts"`
	LTSFrom          *string `json:"lts_from"`
	IsEOAS           bool    `json:"is_eoas"`
	EOASFrom         *string `json:"eoas_from"`
	IsEOL            bool    `json:"is_eol"`
	EOLFrom          *string `json:"eol_from"`
	IsDiscontinued   bool    `json:"is_discontinued"`
	DiscontinuedFrom *string `json:"discontinued_from"`
	IsEOES           *bool   `json:"is_eoes"`
	EOESFrom         *string `json:"eoes_from"`
	IsMaintained     bool    `json:"is_maintained"`
	Withdrawn        bool    `json:"withdrawn"`
}

// ResponseFromExport converts the server-side DB export shape to the shared
// sync wire shape used by API handlers and SQLite clients.
func ResponseFromExport(exported *db.SyncExport, feedStatus string, feedVersions map[string]string) Response {
	if exported == nil {
		return Response{
			FeedStatus:      feedStatus,
			FeedVersions:    feedVersions,
			Vulnerabilities: []Vulnerability{},
			Malicious:       []Malicious{},
			Reputation:      []Reputation{},
			Lifecycle:       []Lifecycle{},
		}
	}

	resp := Response{
		SyncedAt:        formatDateTime(exported.SyncedAt),
		SyncedXID:       exported.SyncedXID,
		FeedStatus:      feedStatus,
		FeedVersions:    feedVersions,
		Vulnerabilities: make([]Vulnerability, 0, len(exported.Vulnerabilities)),
		Malicious:       make([]Malicious, 0, len(exported.Malicious)),
		Reputation:      make([]Reputation, 0, len(exported.Reputation)),
		Lifecycle:       make([]Lifecycle, 0, len(exported.Lifecycle)),
		Truncated:       exported.Truncated,
		HasMore:         exported.Truncated,
		NextCursor:      cursorFromDB(exported.NextCursor),
	}

	for _, vuln := range exported.Vulnerabilities {
		resp.Vulnerabilities = append(resp.Vulnerabilities, Vulnerability{
			ID:               vuln.ID,
			Ecosystem:        vuln.Ecosystem,
			Name:             vuln.Name,
			VersionRanges:    vuln.VersionRanges,
			VersionsAffected: vuln.VersionsAffected,
			References:       vuln.References,
			Severity:         vuln.Severity,
			CVSSScore:        vuln.CVSSScore,
			EPSSScore:        vuln.EPSSScore,
			EPSSPercentile:   vuln.EPSSPercentile,
			CISAKEV:          vuln.CISAKEV,
			Summary:          vuln.Summary,
			Source:           vuln.Source,
			Withdrawn:        vuln.Withdrawn,
		})
	}

	for _, finding := range exported.Malicious {
		resp.Malicious = append(resp.Malicious, Malicious{
			ID:            finding.ID,
			Ecosystem:     finding.Ecosystem,
			Name:          finding.Name,
			VersionRanges: finding.VersionRanges,
			Versions:      finding.Versions,
			ReferenceURLs: finding.ReferenceURLs,
			RiskType:      finding.RiskType,
			Severity:      finding.Severity,
			Summary:       finding.Summary,
			Source:        finding.Source,
			Withdrawn:     finding.Withdrawn,
		})
	}

	for _, finding := range exported.Reputation {
		resp.Reputation = append(resp.Reputation, Reputation{
			ID:        finding.ID,
			Ecosystem: finding.Ecosystem,
			Name:      finding.Name,
			Version:   finding.Version,
			Type:      finding.Type,
			RiskType:  finding.RiskType,
			Severity:  finding.Severity,
			Summary:   finding.Summary,
			Withdrawn: finding.Withdrawn,
		})
	}

	for _, release := range exported.Lifecycle {
		resp.Lifecycle = append(resp.Lifecycle, Lifecycle{
			ID:               release.ID,
			Ecosystem:        release.Ecosystem,
			Name:             release.Name,
			ProductSlug:      release.ProductSlug,
			ProductLabel:     release.ProductLabel,
			Cycle:            release.Cycle,
			Latest:           release.Latest,
			ReleaseDate:      dateOnly(release.ReleaseDate),
			IsLTS:            release.IsLTS,
			LTSFrom:          dateOnly(release.LTSFrom),
			IsEOAS:           release.IsEOAS,
			EOASFrom:         dateOnly(release.EOASFrom),
			IsEOL:            release.IsEOL,
			EOLFrom:          dateOnly(release.EOLFrom),
			IsDiscontinued:   release.IsDiscontinued,
			DiscontinuedFrom: dateOnly(release.DiscontinuedFrom),
			IsEOES:           release.IsEOES,
			EOESFrom:         dateOnly(release.EOESFrom),
			IsMaintained:     release.IsMaintained,
			Withdrawn:        release.Withdrawn,
		})
	}

	return resp
}

func cursorFromDB(cursor *db.SyncCursor) *Cursor {
	if cursor == nil {
		return nil
	}
	return &Cursor{
		Vulnerabilities:       cursor.Vulnerabilities,
		Malicious:             cursor.Malicious,
		Reputation:            cursor.Reputation,
		Lifecycle:             cursor.Lifecycle,
		VulnerabilitiesCursor: cursor.VulnerabilitiesCursor,
		MaliciousCursor:       cursor.MaliciousCursor,
		ReputationCursor:      cursor.ReputationCursor,
		LifecycleCursor:       cursor.LifecycleCursor,
		VulnerabilitiesDone:   cursor.VulnerabilitiesDone,
		MaliciousDone:         cursor.MaliciousDone,
		ReputationDone:        cursor.ReputationDone,
		LifecycleDone:         cursor.LifecycleDone,
	}
}

func formatDateTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func dateOnly(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.DateOnly)
	return &formatted
}
