package postgres

import (
	"math"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/db"
)

// syncVulnerabilityRowWireOverhead bounds the JSON bytes of one exported
// vulnerability row outside its string values: the field names and
// punctuation, the three float scores (at most 24 bytes each), the booleans,
// and the comma that separates the row from the next one.
const syncVulnerabilityRowWireOverhead = 320

// syncVulnerabilityWireBytes returns an upper bound of the JSON bytes one
// vulnerability row takes in a sync response.
func syncVulnerabilityWireBytes(row db.SyncVulnerability) int {
	return syncVulnerabilityRowWireOverhead +
		jsonStringWireBytes(row.ID) +
		jsonStringWireBytes(row.Ecosystem) +
		jsonStringWireBytes(row.Name) +
		jsonStringWireBytes(row.VersionRanges) +
		jsonStringWireBytes(row.VersionsAffected) +
		jsonStringWireBytes(row.References) +
		jsonStringWireBytes(row.Severity) +
		jsonStringWireBytes(row.Summary) +
		jsonStringWireBytes(row.Source)
}

// syncAdvisoryIDWireBytes returns an upper bound of the JSON bytes one ID in
// vulnerabilities_without_affected takes, including its separating comma.
func syncAdvisoryIDWireBytes(id string) int {
	return jsonStringWireBytes(id) + 1
}

// syncMaliciousRowWireOverhead, syncReputationRowWireOverhead, and
// syncLifecycleRowWireOverhead bound the JSON bytes of one exported row of
// their dataset outside its string values: the field names and punctuation,
// the booleans, the comma that separates the row from the next one, and for
// lifecycle rows the six dates (at most 16 bytes each, quoted, for any year
// PostgreSQL stores).
const (
	syncMaliciousRowWireOverhead  = 192
	syncReputationRowWireOverhead = 160
	syncLifecycleRowWireOverhead  = 448
)

// syncMaliciousWireBytes returns an upper bound of the JSON bytes one
// malicious row takes in a sync response.
func syncMaliciousWireBytes(row db.SyncMalicious) int {
	return syncMaliciousRowWireOverhead +
		jsonStringWireBytes(row.ID) +
		jsonStringWireBytes(row.Ecosystem) +
		jsonStringWireBytes(row.Name) +
		jsonStringWireBytes(row.VersionRanges) +
		jsonStringWireBytes(row.Versions) +
		jsonStringWireBytes(row.ReferenceURLs) +
		jsonStringWireBytes(row.RiskType) +
		jsonStringWireBytes(row.Severity) +
		jsonStringWireBytes(row.Summary) +
		jsonStringWireBytes(row.Source)
}

// syncReputationWireBytes returns an upper bound of the JSON bytes one
// reputation row takes in a sync response.
func syncReputationWireBytes(row db.SyncReputationFinding) int {
	return syncReputationRowWireOverhead +
		jsonStringWireBytes(row.ID) +
		jsonStringWireBytes(row.Ecosystem) +
		jsonStringWireBytes(row.Name) +
		jsonStringWireBytes(row.Version) +
		jsonStringWireBytes(row.Type) +
		jsonStringWireBytes(row.RiskType) +
		jsonStringWireBytes(row.Severity) +
		jsonStringWireBytes(row.Summary)
}

// syncLifecycleWireBytes returns an upper bound of the JSON bytes one
// lifecycle row takes in a sync response.
func syncLifecycleWireBytes(row db.SyncLifecycleRelease) int {
	return syncLifecycleRowWireOverhead +
		jsonStringWireBytes(row.ID) +
		jsonStringWireBytes(row.Ecosystem) +
		jsonStringWireBytes(row.Name) +
		jsonStringWireBytes(row.ProductSlug) +
		jsonStringWireBytes(row.ProductLabel) +
		jsonStringWireBytes(row.Cycle) +
		jsonStringWireBytes(row.Latest)
}

// jsonStringWireBytes returns an upper bound of the bytes encoding/json writes
// for s as a JSON string with HTML escaping, as the sync handler encodes it:
// the quotes, two bytes for an escaped quote or backslash, six for a control
// character, <, >, &, U+2028, U+2029 or an invalid UTF-8 byte (\uXXXX), and
// the UTF-8 bytes of every other rune.
func jsonStringWireBytes(s string) int {
	n := 2
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				n += 2
			case c < 0x20 || c == '<' || c == '>' || c == '&':
				n += 6
			default:
				n++
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1, r == ' ', r == ' ':
			n += 6
		default:
			n += size
		}
		i += size
	}
	return n
}

// syncVulnerabilityPageBuilder assembles one page of the vulnerability
// dataset from the rows its query returns, in order, and bounds the page by
// the estimated wire bytes of its rows (syncVulnerabilityWireBytes) as well
// as by rows, so a sync response always stays below the size a client
// accepts and the sync makes progress:
//
//   - An advisory page (syncVulnerabilityAdvisoryPages) keeps advisories
//     whole. When the next advisory no longer fits the budget, the page ends
//     after the last whole advisory, still promises complete affected sets,
//     and continues with an advisory cursor after it. When the first advisory
//     of the page alone exceeds the budget, the page carries as many of its
//     rows as fit (at least one), is marked split -- it must not carry
//     vulnerability_affected_complete -- and continues inside the advisory
//     with an advisory row cursor.
//   - A split page (syncVulnerabilityAdvisorySplit) carries the next rows of
//     that advisory up to the row limit and the budget and continues with a
//     row cursor while rows remain, or else with an advisory cursor after the
//     advisory; that page is the last of the split (splitLast), on which the
//     exporter checks whether the split is complete. It is always split and
//     always continues.
//   - Every page of a split, including the one that starts it, names the
//     split advisory (splitAdvisoryID).
//   - Row pages (full exports and legacy deltas) end before the row that no
//     longer fits, never before the first one; their row cursor or offset
//     continues after the last delivered row.
type syncVulnerabilityPageBuilder struct {
	paging  syncVulnerabilityPaging
	limit   int
	splitID string
	budget  int

	page       syncVulnerabilityPage
	used       int
	sqlHasMore bool
	stopped    bool

	// currentID is the advisory the last accepted row belongs to, and
	// currentRows/currentMarkers are the lengths of page.rows and
	// page.withoutAffected before its first row. lastWholeID is the advisory
	// before it, which the page holds whole.
	currentID      string
	currentRows    int
	currentMarkers int
	lastWholeID    string
}

// newSyncVulnerabilityPageBuilder returns the builder of one page. An export
// without a limit is not paginated and has no next page to continue on, so it
// is not bounded by the byte budget either.
func newSyncVulnerabilityPageBuilder(paging syncVulnerabilityPaging, limit int, splitID string, budget int) *syncVulnerabilityPageBuilder {
	if limit <= 0 {
		budget = math.MaxInt
	}
	return &syncVulnerabilityPageBuilder{paging: paging, limit: limit, splitID: splitID, budget: budget, page: newSyncAdvisoryPage()}
}

// add offers the next row of the query result; withoutAffected marks the
// marker row of an advisory without in-scope affected rows, and hasMore is
// the advisory page query's verdict on whether advisories follow. add reports
// false once the page is full; the row it rejects and every later row belong
// to a later page.
func (b *syncVulnerabilityPageBuilder) add(item db.SyncVulnerability, withoutAffected, hasMore bool) bool {
	if b.stopped {
		return false
	}
	size := syncVulnerabilityWireBytes(item)
	if withoutAffected {
		size = syncAdvisoryIDWireBytes(item.ID)
	}
	fits := b.used+size <= b.budget || (len(b.page.rows) == 0 && len(b.page.withoutAffected) == 0)

	switch b.paging {
	case syncVulnerabilityAdvisoryPages:
		b.sqlHasMore = hasMore
		if item.ID != b.currentID {
			b.lastWholeID = b.currentID
			b.currentID = item.ID
			b.currentRows, b.currentMarkers = len(b.page.rows), len(b.page.withoutAffected)
		}
		if !fits {
			b.stopAdvisoryPage()
			return false
		}
	case syncVulnerabilityAdvisorySplit:
		if !fits || (b.limit > 0 && len(b.page.rows) == b.limit) {
			b.stopped = true
			return false
		}
	default:
		if !fits {
			b.stopped = true
			return false
		}
	}
	b.used += size
	b.page.add(item, withoutAffected)
	return true
}

// stopAdvisoryPage ends an advisory page at the row that no longer fits the
// budget: after the last whole advisory, or, when the advisory of that row is
// the first of the page, inside it (a split).
func (b *syncVulnerabilityPageBuilder) stopAdvisoryPage() {
	b.stopped = true
	b.page.hasMore = true
	if b.lastWholeID != "" {
		b.page.rows = b.page.rows[:b.currentRows]
		b.page.withoutAffected = b.page.withoutAffected[:b.currentMarkers]
		b.page.lastAdvisoryID = b.lastWholeID
		b.page.nextCursor = db.EncodeSyncAdvisoryCursor(b.lastWholeID)
		return
	}
	// A marker row always fits as the first row of a page, so the accepted
	// rows of the first advisory are package rows.
	last := b.page.rows[len(b.page.rows)-1]
	b.page.split = true
	b.page.splitAdvisoryID = last.ID
	b.page.nextCursor = db.EncodeSyncAdvisoryRowCursor(last.ID, last.Ecosystem, last.Name)
}

// finish returns the page with whether and where the dataset continues.
func (b *syncVulnerabilityPageBuilder) finish() syncVulnerabilityPage {
	switch b.paging {
	case syncVulnerabilityAdvisoryPages:
		if !b.stopped {
			b.page.hasMore = b.sqlHasMore
		}
	case syncVulnerabilityAdvisorySplit:
		b.page.split = true
		b.page.splitAdvisoryID = b.splitID
		b.page.hasMore = true
		if b.stopped && len(b.page.rows) > 0 {
			last := b.page.rows[len(b.page.rows)-1]
			b.page.nextCursor = db.EncodeSyncAdvisoryRowCursor(last.ID, last.Ecosystem, last.Name)
		} else {
			b.page.splitLast = true
			b.page.lastAdvisoryID = b.splitID
			b.page.nextCursor = db.EncodeSyncAdvisoryCursor(b.splitID)
		}
	default:
		b.page.hasMore = b.stopped || (b.limit > 0 && len(b.page.rows) == b.limit)
	}
	return b.page
}

// syncRowPage is one exported page of a dataset paged by rows only
// (malicious, reputation, and lifecycle). hasMore reports that the dataset may
// continue on the next page, after the last row of this one.
type syncRowPage[T any] struct {
	rows    []T
	hasMore bool
}

// syncRowPageBuilder assembles one page of a row-paged dataset from the rows
// its query returns, in order, and bounds it by the estimated wire bytes of
// its rows (wireBytes) as well as by the row limit the query applies: the page
// ends before the row that no longer fits the budget, never before the first
// one, so a sync response stays below the size a client accepts and every
// dataset advances on every page. A page cut by bytes, or one that filled the
// row limit, reports more data; its keyset cursor or offset continues after
// its last row.
type syncRowPageBuilder[T any] struct {
	limit     int
	budget    int
	wireBytes func(T) int

	page    syncRowPage[T]
	used    int
	stopped bool
}

// newSyncRowPageBuilder returns the builder of one page. An export without a
// limit is not paginated and has no next page to continue on, so it is not
// bounded by the byte budget either.
func newSyncRowPageBuilder[T any](limit, budget int, wireBytes func(T) int) *syncRowPageBuilder[T] {
	if limit <= 0 {
		budget = math.MaxInt
	}
	return &syncRowPageBuilder[T]{limit: limit, budget: budget, wireBytes: wireBytes, page: syncRowPage[T]{rows: make([]T, 0)}}
}

// add offers the next row of the query result. It reports false once the
// page is full; the row it rejects and every later row belong to a later
// page.
func (b *syncRowPageBuilder[T]) add(item T) bool {
	if b.stopped {
		return false
	}
	size := b.wireBytes(item)
	if len(b.page.rows) > 0 && b.used+size > b.budget {
		b.stopped = true
		return false
	}
	b.used += size
	b.page.rows = append(b.page.rows, item)
	return true
}

// finish returns the page with whether the dataset continues.
func (b *syncRowPageBuilder[T]) finish() syncRowPage[T] {
	b.page.hasMore = b.stopped || (b.limit > 0 && len(b.page.rows) == b.limit)
	return b.page
}
