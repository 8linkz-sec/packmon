package postgres

import (
	"reflect"
	"testing"
)

func TestSummarizeAffectedVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		versionRanges string
		versions      string
		want          string
	}{
		{
			name:          "range with fixed version only",
			versionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.1.0"}]}]`,
			want:          "< 2.1.0",
		},
		{
			name:          "range with introduced and fixed",
			versionRanges: `[{"type":"SEMVER","events":[{"introduced":"1.4.0"},{"fixed":"1.8.2"}]}]`,
			want:          ">= 1.4.0, < 1.8.2",
		},
		{
			name:          "range with last affected",
			versionRanges: `[{"type":"SEMVER","events":[{"introduced":"3.0.0"},{"last_affected":"3.2.5"}]}]`,
			want:          ">= 3.0.0, <= 3.2.5",
		},
		{
			name:     "fallback to explicit versions",
			versions: `["1.0.0","1.1.0","1.2.0","1.3.0"]`,
			want:     "1.0.0, 1.1.0, 1.2.0 (+1 more)",
		},
		{
			name:          "flat shorthand range",
			versionRanges: `[{"introduced":"0","fixed":"5.0.0"}]`,
			want:          "< 5.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeAffectedVersions(tt.versionRanges, tt.versions)
			if got != tt.want {
				t.Fatalf("summarizeAffectedVersions() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecentRangeEventsPreservesExplicitEvents(t *testing.T) {
	t.Parallel()

	events := []recentRangeEvent{
		{Introduced: "1.0.0"},
		{Fixed: "2.0.0"},
	}

	got := recentRangeEvents(recentRange{
		Introduced: "0",
		Fixed:      "9.9.9",
		Events:     events,
	})
	if !reflect.DeepEqual(got, events) {
		t.Fatalf("recentRangeEvents() = %#v, want explicit events %#v", got, events)
	}
}

func TestRecentRangeEventsConvertsLegacyFields(t *testing.T) {
	t.Parallel()

	got := recentRangeEvents(recentRange{
		Introduced:   "1.0.0",
		Fixed:        "2.0.0",
		LastAffected: "2.1.0",
	})
	want := []recentRangeEvent{
		{Introduced: "1.0.0"},
		{Fixed: "2.0.0"},
		{LastAffected: "2.1.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recentRangeEvents() = %#v, want legacy events %#v", got, want)
	}
}

func TestSummarizeRecentRangeEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		events []recentRangeEvent
		want   []string
	}{
		{
			name: "event list emits multiple bounded clauses",
			events: []recentRangeEvent{
				{Introduced: "1.0.0"},
				{Fixed: "2.0.0"},
				{Introduced: "3.0.0"},
				{LastAffected: "3.5.0"},
			},
			want: []string{">= 1.0.0, < 2.0.0", ">= 3.0.0, <= 3.5.0"},
		},
		{
			name:   "open range",
			events: []recentRangeEvent{{Introduced: "4.0.0"}},
			want:   []string{">= 4.0.0"},
		},
		{
			name:   "introduced zero means beginning of time",
			events: []recentRangeEvent{{Introduced: "0"}, {Fixed: "1.0.0"}},
			want:   []string{"< 1.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeRecentRangeEvents(tt.events)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("summarizeRecentRangeEvents() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestSummarizeRangeClausesJoinsMultipleClauses(t *testing.T) {
	t.Parallel()

	raw := `[
		{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"},{"introduced":"3.0.0"},{"last_affected":"3.5.0"}]},
		{"type":"ECOSYSTEM","introduced":"4.0.0"}
	]`
	want := ">= 1.0.0, < 2.0.0 or >= 3.0.0, <= 3.5.0 or >= 4.0.0"

	got := summarizeRangeClauses(raw)
	if got != want {
		t.Fatalf("summarizeRangeClauses() = %q, want %q", got, want)
	}
}
