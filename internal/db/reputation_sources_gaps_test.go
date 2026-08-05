package db

import "testing"

func TestReputationReadSourcesReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	sources := ReputationReadSources()
	if len(sources) == 0 {
		t.Fatal("ReputationReadSources() = empty, want configured sources")
	}
	if sources[0].Source != ReputationSourceReversingLabs || sources[0].Label != "ReversingLabs" {
		t.Fatalf("ReputationReadSources()[0] = %+v, want ReversingLabs descriptor", sources[0])
	}

	sources[0].Label = "mutated"
	if again := ReputationReadSources(); again[0].Label != "ReversingLabs" {
		t.Fatalf("ReputationReadSources() after caller mutation = %+v, want unchanged copy", again[0])
	}
}

func TestReputationReadSourceLabelNormalizesLookup(t *testing.T) {
	t.Parallel()

	label, ok := ReputationReadSourceLabel("  ReversingLabs  ")
	if !ok || label != "ReversingLabs" {
		t.Fatalf("ReputationReadSourceLabel(padded mixed case) = %q, %t; want ReversingLabs, true", label, ok)
	}
	if label, ok := ReputationReadSourceLabel("unknown-source"); ok || label != "" {
		t.Fatalf("ReputationReadSourceLabel(unknown) = %q, %t; want empty, false", label, ok)
	}
}
