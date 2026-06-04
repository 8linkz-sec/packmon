package sbom

import (
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestParseDispatchesSupportedSBOMFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		source string
		eco    domain.Ecosystem
	}{
		{
			name:   "cyclonedx json",
			input:  `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"left-pad","purl":"pkg:npm/left-pad@1.0.0"}]}`,
			source: "cyclonedx",
			eco:    domain.EcosystemNPM,
		},
		{
			name:   "spdx json",
			input:  `{"spdxVersion":"SPDX-2.3","packages":[{"name":"requests","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/requests@2.32.0"}]}]}`,
			source: "spdx",
			eco:    domain.EcosystemPyPI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(got.Packages) != 1 || got.Packages[0].Source != tt.source || got.Packages[0].Package.Ecosystem != tt.eco {
				t.Fatalf("Parse() = %+v, want one %s package", got, tt.source)
			}
		})
	}
}
