package domain

import "strings"

// FeedMode controls whether Packmon manages a feed itself or expects an
// authenticated external importer to provide the feed data.
type FeedMode string

const (
	// FeedModeSelf means Packmon runs the feed syncer on its own schedule.
	FeedModeSelf FeedMode = "self"
	// FeedModeExternal means feed data is supplied through an external import
	// path and Packmon does not schedule self-sync for the feed.
	FeedModeExternal FeedMode = "external"
)

// FeedModeValues returns the stable public feed mode enum values.
func FeedModeValues() []FeedMode {
	return []FeedMode{FeedModeSelf, FeedModeExternal}
}

// ParseFeedMode validates and normalizes a feed mode.
func ParseFeedMode(raw string) (FeedMode, bool) {
	switch mode := FeedMode(strings.ToLower(strings.TrimSpace(raw))); mode {
	case FeedModeSelf, FeedModeExternal:
		return mode, true
	default:
		return "", false
	}
}
