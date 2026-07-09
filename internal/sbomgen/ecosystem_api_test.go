package sbomgen

import (
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestAutoSBOMAPIsUseDomainEcosystems(t *testing.T) {
	var detectionEcosystem domain.Ecosystem = Detection{Ecosystem: domain.EcosystemNPM}.Ecosystem
	if detectionEcosystem != domain.EcosystemNPM {
		t.Fatalf("Detection.Ecosystem = %q, want %q", detectionEcosystem, domain.EcosystemNPM)
	}

	registry := DefaultRegistry()
	generator, ok := registry[domain.EcosystemNPM]
	if !ok {
		t.Fatalf("DefaultRegistry missing %q", domain.EcosystemNPM)
	}
	var generatorEcosystem domain.Ecosystem = generator.Ecosystem()
	if generatorEcosystem != domain.EcosystemNPM {
		t.Fatalf("Generator.Ecosystem() = %q, want %q", generatorEcosystem, domain.EcosystemNPM)
	}

	cfg := Config{
		Ecosystems: []domain.Ecosystem{domain.EcosystemNPM},
		Registry:   map[domain.Ecosystem]Generator{domain.EcosystemNPM: generator},
	}
	if len(cfg.Ecosystems) != 1 || cfg.Ecosystems[0] != domain.EcosystemNPM {
		t.Fatalf("Config.Ecosystems = %v, want [%s]", cfg.Ecosystems, domain.EcosystemNPM)
	}
}
