package version

import (
	"encoding/json"
	"strconv"
	"strings"
)

// rangeBoundaryKeys are the OSV range event keys that carry a version
// boundary. Matching is exact, like the jsonb lookups in the PostgreSQL
// packmon_jsonb_version_ranges_valid function (migration 050); encoding/json
// struct decoding would also accept "Introduced" or "FIXED", which the
// database CHECK constraint refuses.
var rangeBoundaryKeys = [...]string{"introduced", "fixed", "last_affected", "limit"}

// RangeShapeError describes the first place where OSV version range JSON
// breaks the stored-range rule. Path is relative to the ranges value ("" for
// the value itself, then "[1]", "[1].events", "[1].events[0]",
// "[1].events[0].fixed"); Reason completes the sentence, for example "must not
// be empty".
type RangeShapeError struct {
	Path   string
	Reason string
}

func (e *RangeShapeError) Error() string {
	if e.Path == "" {
		return e.Reason
	}
	return e.Path + " " + e.Reason
}

// CheckRangesShape applies the rule every stored version_ranges value must
// satisfy, shared by the feed import handler, the PostgreSQL store pre-check
// and (as SQL) the database CHECK constraint: a JSON array of range objects,
// each with a nonempty "events" array of event objects; in each event the
// boundary keys introduced/fixed/last_affected/limit hold a string or null
// when present, and at least one holds a nonblank string. A range "type", when
// present, must be a string or null. Other keys (repo, database_specific, ...)
// are ignored, and [] is valid.
//
// raw must be a JSON value; callers decide beforehand whether an absent or
// null value is acceptable. The SQL function trims only ASCII whitespace and
// does not check "type", so it may accept what this check rejects, never the
// reverse.
func CheckRangesShape(raw []byte) *RangeShapeError {
	var ranges []json.RawMessage
	if err := json.Unmarshal(raw, &ranges); err != nil {
		return &RangeShapeError{Reason: "must be an array of range objects"}
	}
	for i, rawRange := range ranges {
		rangePath := "[" + strconv.Itoa(i) + "]"
		var versionRange map[string]json.RawMessage
		if err := json.Unmarshal(rawRange, &versionRange); err != nil || versionRange == nil {
			return &RangeShapeError{Path: rangePath, Reason: "must be a range object"}
		}
		// The range matcher decodes type into a string (parseRanges); any other
		// JSON type there makes the whole ranges value fail to parse.
		if rawType, ok := versionRange["type"]; ok {
			var rangeType *string
			if err := json.Unmarshal(rawType, &rangeType); err != nil {
				return &RangeShapeError{Path: rangePath + ".type", Reason: "must be a string"}
			}
		}
		var events []json.RawMessage
		if rawEvents, ok := versionRange["events"]; ok {
			if err := json.Unmarshal(rawEvents, &events); err != nil {
				return &RangeShapeError{Path: rangePath + ".events", Reason: "must be an array of event objects"}
			}
		}
		if len(events) == 0 {
			return &RangeShapeError{Path: rangePath + ".events", Reason: "must not be empty"}
		}
		for j, rawEvent := range events {
			if shapeErr := checkRangeEventShape(rawEvent, rangePath+".events["+strconv.Itoa(j)+"]"); shapeErr != nil {
				return shapeErr
			}
		}
	}
	return nil
}

func checkRangeEventShape(raw json.RawMessage, eventPath string) *RangeShapeError {
	var event map[string]json.RawMessage
	if err := json.Unmarshal(raw, &event); err != nil || event == nil {
		return &RangeShapeError{Path: eventPath, Reason: "must be an event object"}
	}
	hasBoundary := false
	for _, key := range rangeBoundaryKeys {
		rawValue, ok := event[key]
		if !ok {
			continue
		}
		var value *string
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return &RangeShapeError{Path: eventPath + "." + key, Reason: "must be a string"}
		}
		if value != nil && strings.TrimSpace(*value) != "" {
			hasBoundary = true
		}
	}
	if !hasBoundary {
		return &RangeShapeError{Path: eventPath, Reason: "must set introduced, fixed, last_affected, or limit"}
	}
	return nil
}
