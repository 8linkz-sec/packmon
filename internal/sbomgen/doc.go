// Package sbomgen detects supported project manifests and generates temporary
// or operator-kept CycloneDX SBOM files through pinned ecosystem generators.
//
// The package may invoke local toolchains, may install pinned generator tools
// when explicitly allowed, and returns cleanup ownership to callers when output
// is temporary. RunnerFunc and LookPath seams are intended for tests and for
// callers that need controlled command execution.
package sbomgen
