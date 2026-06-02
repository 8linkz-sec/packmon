package domain

import "testing"

func TestEcosystemValid(t *testing.T) {
	t.Parallel()

	for _, eco := range []Ecosystem{
		EcosystemNPM,
		EcosystemPyPI,
		EcosystemGo,
		EcosystemMaven,
		EcosystemCargo,
		EcosystemNuGet,
		EcosystemComposer,
		EcosystemGem,
		EcosystemPub,
		EcosystemGitHubActions,
		EcosystemCocoaPods,
		EcosystemSwiftPM,
		EcosystemHex,
		EcosystemCRAN,
		EcosystemDocker,
	} {
		if !eco.Valid() {
			t.Fatalf("%q should be valid", eco)
		}
	}
	if Ecosystem("unknown").Valid() {
		t.Fatal("unknown ecosystem should be invalid")
	}
}

func TestDockerEcosystemIsValid(t *testing.T) {
	if !EcosystemDocker.Valid() {
		t.Fatalf("EcosystemDocker.Valid() = false, want true")
	}
}
