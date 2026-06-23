package postgres

import "testing"

func TestVersionAffectedWithEcosystemDelegatesToSharedVersionLogic(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]`
	got, err := versionAffectedWithEcosystem("1.0.0-beta", ranges, `[]`, "nuget")
	if err != nil {
		t.Fatalf("versionAffectedWithEcosystem() error = %v", err)
	}
	if !got {
		t.Fatal("versionAffectedWithEcosystem() = false, want true for NuGet pre-release before fixed release")
	}

	got, err = versionAffectedWithEcosystem("1.0.0", ranges, `[]`, "nuget")
	if err != nil {
		t.Fatalf("versionAffectedWithEcosystem(fixed) error = %v", err)
	}
	if got {
		t.Fatal("versionAffectedWithEcosystem() = true, want false at fixed NuGet release")
	}
}

func TestExtractFixedVersionFormatsConstraint(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`
	if got := extractFixedVersion(ranges); got != ">= 2.0.0" {
		t.Fatalf("extractFixedVersion() = %q, want >= 2.0.0", got)
	}
}

func TestNormalizeIntroduced(t *testing.T) {
	t.Parallel()

	if got := normalizeIntroduced("0"); got != "" {
		t.Fatalf("normalizeIntroduced(0) = %q, want empty", got)
	}
	if got := normalizeIntroduced("1.2.3"); got != "1.2.3" {
		t.Fatalf("normalizeIntroduced(1.2.3) = %q, want original", got)
	}
}
