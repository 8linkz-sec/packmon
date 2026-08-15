package main

import (
	"context"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestVersionPrecisionIgnoresPrefixPrereleaseAndBuild(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]int{
		"":              0,
		"  ":            0,
		"v":             0,
		"v4":            1,
		"4":             1,
		"v4.2":          2,
		"v4.2.2":        3,
		"4.2.2":         3,
		"v4.2.2-rc.1":   3,
		"v4.2.2+build7": 3,
		"1.2.3.4":       4,
	} {
		if got := versionPrecision(input); got != want {
			t.Errorf("versionPrecision(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestResolveListAllLatestGitHubActionSHADeclaredVersionMixedVPrefixes(t *testing.T) {
	// Declared "4.2.2" against latest "v4.2.2" (and vice versa) is the same
	// release; a differing prefix must not be misread as an update or hide one.
	resolver := actionsSHAPinResolver(t, "v4.2.2", nil)
	if got := resolveActionsSHAPin(t, resolver, actionsSHAPinBehindLatest, "4.2.2"); got.Update != "-" || got.Unknown {
		t.Fatalf("declared 4.2.2 vs latest v4.2.2 = %+v, want current", got)
	}
	resolver = actionsSHAPinResolver(t, "4.2.3", nil)
	if got := resolveActionsSHAPin(t, resolver, actionsSHAPinBehindLatest, "v4.2.2"); got.Update != "yes" || got.Unknown {
		t.Fatalf("declared v4.2.2 vs latest 4.2.3 = %+v, want update", got)
	}
	resolver = actionsSHAPinResolver(t, "v4.2.2", nil)
	if got := resolveActionsSHAPin(t, resolver, actionsSHAPinBehindLatest, "v4.2.2-rc.1"); got.Update != "yes" || got.Unknown {
		t.Fatalf("declared prerelease vs final latest = %+v, want update", got)
	}
}

func TestResolveListAllLatestGitHubActionSHAWithoutLatestIsUnknownAndSkipsGit(t *testing.T) {
	resolver := actionsSHAPinResolver(t, "", nil)
	got := resolveActionsSHAPin(t, resolver, actionsSHAPinBehindLatest, "v4.2.2")
	if got.Latest != "unknown" || got.Update != "-" || !got.Unknown {
		t.Fatalf("resolveListAllLatest() without latest = %+v, want unknown without git traffic", got)
	}
}

func TestResolveOutdatedLatestGitHubActionSHAMatchesListAllPath(t *testing.T) {
	// --outdated and --list-all must agree on every SHA-pin branch.
	otherCommit := "ffffffffffffffffffffffffffffffffffffffff"
	cases := []struct {
		name       string
		latest     string
		declared   string
		tagCommit  func(remote, tag string) (string, bool)
		wantUpdate string
		wantUnk    bool
	}{
		{name: "hint current", latest: "v7.0.1", declared: "v7.0.1", wantUpdate: "-"},
		{name: "hint behind", latest: "v7.0.1", declared: "v4.2.2", wantUpdate: "yes"},
		{name: "no hint tag matches", latest: "v7.0.1", tagCommit: func(_, _ string) (string, bool) { return actionsSHAPinBehindLatest, true }, wantUpdate: "-"},
		{name: "no hint tag differs", latest: "v7.0.1", tagCommit: func(_, _ string) (string, bool) { return otherCommit, true }, wantUpdate: "yes"},
		{name: "no hint unresolvable", latest: "v7.0.1", tagCommit: func(_, _ string) (string, bool) { return "", false }, wantUpdate: "unknown", wantUnk: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := actionsSHAPinResolver(t, tc.latest, tc.tagCommit)
			lookup := directPackageUpdateLookupWithResolver(resolver)
			outdated := resolveOutdatedLatestWithLookup(context.Background(), outdatedPackage{
				Name: "actions/checkout", Version: actionsSHAPinBehindLatest, DeclaredVersion: tc.declared, Ecosystem: domain.EcosystemGitHubActions,
			}, lookup)
			listAll := resolveListAllLatestWithLookup(context.Background(), listAllPackage{
				Name: "actions/checkout", Version: actionsSHAPinBehindLatest, DeclaredVersion: tc.declared, Ecosystem: domain.EcosystemGitHubActions,
			}, lookup, nil)
			if outdated.Update != tc.wantUpdate || outdated.Unknown != tc.wantUnk {
				t.Fatalf("outdated = %+v, want update %q unknown %v", outdated, tc.wantUpdate, tc.wantUnk)
			}
			if listAll != outdated {
				t.Fatalf("list-all = %+v differs from outdated = %+v", listAll, outdated)
			}
		})
	}
}
