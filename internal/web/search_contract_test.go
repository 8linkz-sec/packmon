package web

import (
	"strconv"
	"strings"
	"testing"
)

func TestValidateSearchReturnToAcceptsCanonicalSearchState(t *testing.T) {
	t.Parallel()

	const raw = " /search?finding=Malicious&q=%20example%20&severity=high&page=2 "
	if got, want := validateSearchReturnTo(raw), "/search?finding=malicious&page=2&q=example&severity=HIGH"; got != want {
		t.Fatalf("validateSearchReturnTo(%q) = %q, want %q", raw, got, want)
	}
}

func TestValidateSearchReturnToRejectsUnsafeOrInvalidSearchState(t *testing.T) {
	t.Parallel()

	tooLongQuery := strings.Repeat("x", maxSearchQueryLength+1)
	tests := []struct {
		name string
		raw  string
	}{
		{name: "external absolute URL", raw: "https://example.test/search?q=package"},
		{name: "protocol relative URL", raw: "//example.test/search?q=package"},
		{name: "absolute URL with userinfo", raw: "https://user@example.test/search?q=package"},
		{name: "fragment", raw: "/search?q=package#section"},
		{name: "other path", raw: "/packages?q=package"},
		{name: "query too short", raw: "/search?q=x"},
		{name: "query too long", raw: "/search?q=" + tooLongQuery},
		{name: "invalid severity", raw: "/search?severity=urgent"},
		{name: "invalid finding", raw: "/search?finding=unknown"},
		{name: "zero page", raw: "/search?page=0"},
		{name: "non numeric page", raw: "/search?page=two"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validateSearchReturnTo(tt.raw); got != "" {
				t.Fatalf("validateSearchReturnTo(%q) = %q, want empty", tt.raw, got)
			}
		})
	}
}

func TestParseSearchReturnToPageBounds(t *testing.T) {
	t.Parallel()

	maxPage := int(^uint(0)>>1) / searchResultLimit
	tests := []struct {
		raw  string
		want int
		ok   bool
	}{
		{raw: "", want: 1, ok: true},
		{raw: " 2 ", want: 2, ok: true},
		{raw: "0", ok: false},
		{raw: "-1", ok: false},
		{raw: "not-a-page", ok: false},
		{raw: "999999999999999999999999", ok: false},
		{raw: strconv.Itoa(maxPage + 1), ok: false},
	}

	for _, tt := range tests {
		got, ok := parseSearchReturnToPage(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseSearchReturnToPage(%q) = (%d, %t), want (%d, %t)", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}
