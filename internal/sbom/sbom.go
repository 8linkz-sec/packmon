package sbom

import (
	"bytes"
	"fmt"
	"io"

	"github.com/8linkz/packmon/internal/domain"
)

// Package is one dependency extracted from an SBOM.
type Package struct {
	Package domain.Package
	PURL    string
	Source  string
}

// ParseResult contains successfully imported packages and skipped components.
type ParseResult struct {
	Packages []Package
	Skipped  []SkippedComponent
}

// SkippedComponent records why an SBOM component could not be imported.
type SkippedComponent struct {
	Name   string
	Reason string
}

// Parse detects a supported SBOM format and parses package inventory from it.
func Parse(r io.Reader) (*ParseResult, error) {
	data, err := readSBOM(r)
	if err != nil {
		return nil, err
	}
	switch {
	case IsCycloneDXJSON(data), IsCycloneDXXML(data):
		return ParseCycloneDX(bytes.NewReader(data))
	case IsSPDXJSON(data):
		return ParseSPDXJSON(bytes.NewReader(data))
	default:
		return nil, fmt.Errorf("unsupported SBOM format")
	}
}
