package sbom

import (
	"errors"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type sbomFailingReader struct{}

func (sbomFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

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

func TestParseRejectsUnsupportedSBOMFormat(t *testing.T) {
	t.Parallel()

	got, err := Parse(strings.NewReader(`{"not":"an sbom"}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported SBOM format") {
		t.Fatalf("Parse() error = %v, want unsupported-format error", err)
	}
	if got != nil {
		t.Fatalf("Parse() result = %+v, want nil", got)
	}
}

func TestParsePropagatesInputReadErrors(t *testing.T) {
	t.Parallel()

	got, err := Parse(sbomFailingReader{})
	if err == nil || !strings.Contains(err.Error(), "read SBOM: read failed") {
		t.Fatalf("Parse() error = %v, want wrapped read error", err)
	}
	if got != nil {
		t.Fatalf("Parse() result = %+v, want nil", got)
	}
}
