package ghsa

import (
	"log/slog"
	"testing"
)

// TestNewSyncerWithOptionsAppliesEveryOption covers the option constructor used
// when an operator points the feed at an internal mirror. Dropping the override
// would silently send the syncer to the public GitHub repository instead.
func TestNewSyncerWithOptionsAppliesEveryOption(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	dataDir := t.TempDir()

	base := NewSyncer(logger, dataDir)
	mirrored := NewSyncerWithOptions(logger, dataDir, WithRepoURL("https://git.internal/advisory-db.git"))

	if mirrored.repoURL != "https://git.internal/advisory-db.git" {
		t.Fatalf("repoURL = %q, want the mirror", mirrored.repoURL)
	}
	if base.repoURL == mirrored.repoURL {
		t.Fatal("the mirror override matched the default; the test proves nothing")
	}
	// Without options the result must equal the plain constructor.
	if plain := NewSyncerWithOptions(logger, dataDir); plain.repoURL != base.repoURL {
		t.Fatalf("repoURL = %q, want the default %q", plain.repoURL, base.repoURL)
	}
}

// TestWithRepoURLIgnoresBlankOverrides keeps an unset environment variable from
// wiping the default repository URL, which would leave the syncer with nothing
// to clone.
func TestWithRepoURLIgnoresBlankOverrides(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	dataDir := t.TempDir()
	defaultURL := NewSyncer(logger, dataDir).repoURL

	for _, blank := range []string{"", "   ", "\t\n"} {
		syncer := NewSyncerWithOptions(logger, dataDir, WithRepoURL(blank))
		if syncer.repoURL != defaultURL {
			t.Errorf("WithRepoURL(%q) changed the URL to %q, want the default kept", blank, syncer.repoURL)
		}
	}

	// A padded but real URL is trimmed rather than rejected.
	syncer := NewSyncerWithOptions(logger, dataDir, WithRepoURL("  https://git.internal/db.git  "))
	if syncer.repoURL != "https://git.internal/db.git" {
		t.Fatalf("repoURL = %q, want the trimmed override", syncer.repoURL)
	}
}

// TestNewSyncerWithOptionsAppliesOptionsInOrder pins that a later option wins,
// which is what makes a per-feed override beat a global default.
func TestNewSyncerWithOptionsAppliesOptionsInOrder(t *testing.T) {
	t.Parallel()

	syncer := NewSyncerWithOptions(slog.New(slog.DiscardHandler), t.TempDir(),
		WithRepoURL("https://git.internal/first.git"),
		WithRepoURL("https://git.internal/second.git"),
	)
	if syncer.repoURL != "https://git.internal/second.git" {
		t.Fatalf("repoURL = %q, want the last option to win", syncer.repoURL)
	}
}
