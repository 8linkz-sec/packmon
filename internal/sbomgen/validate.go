package sbomgen

import (
	"bytes"
	"fmt"
	"os"

	"github.com/8linkz/packmon/internal/sbom"
)

func validateGeneratedSBOM(path string) (int, int, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the generator output reserved by this package.
	if err != nil {
		return 0, 0, fmt.Errorf("read generated SBOM %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return 0, 0, fmt.Errorf("generated SBOM %s is empty", path)
	}
	if !sbom.IsCycloneDXJSON(data) {
		return 0, 0, fmt.Errorf("generated SBOM %s is not CycloneDX JSON", path)
	}
	parsed, err := sbom.Parse(bytes.NewReader(data))
	if err != nil {
		return 0, 0, fmt.Errorf("parse generated SBOM %s: %w", path, err)
	}
	return len(parsed.Packages), len(parsed.Skipped), nil
}
