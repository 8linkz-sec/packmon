# Docker Image Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `packmon scan --list-all` include Docker images from Dockerfiles and Compose files, and show whether a locally present image digest is behind the current registry digest without using paid APIs or external vulnerability-scanning services.

**Architecture:** Keep Docker image inventory out of the normal vulnerability scan path for now: `scan` continues to send lockfile/SBOM packages to Packmon, while `--list-all` adds a second inventory source for Docker image declarations. A new `internal/dockerimage` package parses image references, Dockerfiles, and Compose files, resolves public registry manifest digests with the Docker Registry HTTP API, and optionally enriches rows from the local Docker CLI if it is available. The terminal and HTML list-all reports render Docker rows with the same provenance columns planned in `2026-06-02-package-scope-provenance-reporting.md`.

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3`, existing Cobra CLI/reporting code, Docker Registry HTTP API v2, optional local `docker` CLI JSON output.

---

## Prerequisites And Non-Goals

- Execute `docs/superpowers/plans/2026-06-02-package-scope-provenance-reporting.md` first, or include its Task 1 metadata fields before starting this plan. This plan uses `domain.Package.Direct`, `domain.Package.Indirect`, `domain.Package.Optional`, `domain.Package.Peer`, and `domain.Package.Via`.
- Docker rows are inventory/update rows only. This plan does not add vulnerability findings for container image layers, base OS packages, or image SBOMs.
- The implementation must not pull images, read Docker registry credentials, or require Docker Desktop to be running. Docker CLI enrichment is best-effort and must degrade to `UPDATE unknown`.
- Registry freshness checks use anonymous/public registry manifest `HEAD` requests and bearer-token challenges. Private registries may show `LATEST unknown` unless they allow anonymous metadata reads.
- `--list-all` must include Docker images. A plain `scan` without `--list-all` must not send Docker rows to `/api/v1/check` yet.

External contracts to verify while implementing:

- Docker Registry HTTP API v2 manifest endpoints return the canonical digest in the `Docker-Content-Digest` response header.
- Registry authentication uses the `WWW-Authenticate: Bearer realm=...,service=...,scope=...` challenge flow.

---

## File Structure

- Modify `internal/domain/models.go`: add `EcosystemDocker` and include it in `Ecosystem.Valid`.
- Create `internal/dockerimage/ref.go`: parse and normalize Docker image references.
- Create `internal/dockerimage/ref_test.go`: table tests for Docker Hub, custom registries, tags, and digest references.
- Create `internal/dockerimage/models.go`: shared Docker image inventory structs and row conversion helpers.
- Create `internal/dockerimage/dockerfile.go`: parse Dockerfile `ARG` and `FROM` lines.
- Create `internal/dockerimage/dockerfile_test.go`: Dockerfile parser tests for multi-stage builds and ARG substitution.
- Create `internal/dockerimage/compose.go`: parse Compose `services.*.image` and build-only services.
- Create `internal/dockerimage/compose_test.go`: Compose parser tests for image services and build services.
- Create `internal/dockerimage/discover.go`: discover Dockerfiles and Compose files under the scan root with the existing max-depth semantics.
- Create `internal/dockerimage/discover_test.go`: discovery tests.
- Create `internal/dockerimage/registry.go`: resolve remote manifest digests with the Docker Registry HTTP API.
- Create `internal/dockerimage/registry_test.go`: `httptest` coverage for digest headers, bearer challenges, and rate-limit/error degradation.
- Create `internal/dockerimage/local.go`: optional local Docker CLI image inspection.
- Create `internal/dockerimage/local_test.go`: fake-runner tests for local digest extraction and Docker-unavailable degradation.
- Modify `cmd/packmon/list_all.go`: append Docker inventory rows, use Docker-specific latest/update resolution, render Docker rows in terminal and HTML.
- Modify `cmd/packmon/list_all_test.go`: regression tests that `--list-all` and `--list-all --html` include Docker images.
- Modify `DESIGN.md`: document Docker image inventory in `--list-all` and the current non-goal for image-layer vulnerability scanning.
- Modify `SECURITY.md`: document local Docker CLI and registry metadata trust boundaries.

---

### Task 1: Add Docker As A Canonical Inventory Ecosystem

**Files:**
- Modify: `internal/domain/models.go`
- Test: `internal/domain/models_test.go`

- [ ] **Step 1: Write the failing ecosystem test**

Append this test to `internal/domain/models_test.go`:

```go
func TestDockerEcosystemIsValid(t *testing.T) {
	if !EcosystemDocker.Valid() {
		t.Fatalf("EcosystemDocker.Valid() = false, want true")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
$env:GOTMPDIR = Join-Path $PWD '.gotmp'
New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null
go test -count=1 .\internal\domain -run TestDockerEcosystemIsValid
```

Expected: FAIL with `undefined: EcosystemDocker`.

- [ ] **Step 3: Add the Docker ecosystem constant**

In `internal/domain/models.go`, add the constant after `EcosystemCRAN`:

```go
	EcosystemDocker        Ecosystem = "docker"
```

Then update the `Valid` switch to include Docker:

```go
	case EcosystemCocoaPods, EcosystemSwiftPM, EcosystemHex, EcosystemCRAN, EcosystemDocker:
		return true
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```powershell
go test -count=1 .\internal\domain -run TestDockerEcosystemIsValid
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/domain/models.go internal/domain/models_test.go
git commit -m "feat: add docker inventory ecosystem"
```

---

### Task 2: Parse And Normalize Docker Image References

**Files:**
- Create: `internal/dockerimage/ref.go`
- Test: `internal/dockerimage/ref_test.go`

- [ ] **Step 1: Write the failing reference parser tests**

Create `internal/dockerimage/ref_test.go`:

```go
package dockerimage

import "testing"

func TestParseRefNormalizesDockerHubReferences(t *testing.T) {
	tests := []struct {
		raw       string
		name      string
		reference string
		registry  string
		repo      string
		digest    bool
	}{
		{"alpine:3.23", "docker.io/library/alpine", "3.23", "registry-1.docker.io", "library/alpine", false},
		{"postgres:18-alpine", "docker.io/library/postgres", "18-alpine", "registry-1.docker.io", "library/postgres", false},
		{"library/postgres:18-alpine", "docker.io/library/postgres", "18-alpine", "registry-1.docker.io", "library/postgres", false},
		{"docker.io/library/alpine:3.23", "docker.io/library/alpine", "3.23", "registry-1.docker.io", "library/alpine", false},
		{"ghcr.io/acme/app:v1.2.3", "ghcr.io/acme/app", "v1.2.3", "ghcr.io", "acme/app", false},
		{"postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "docker.io/library/postgres", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "registry-1.docker.io", "library/postgres", true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ref, ok := ParseRef(tt.raw)
			if !ok {
				t.Fatalf("ParseRef(%q) returned ok=false", tt.raw)
			}
			if ref.Name != tt.name || ref.Reference != tt.reference || ref.Registry != tt.registry || ref.Repository != tt.repo || ref.Digest != tt.digest {
				t.Fatalf("ParseRef(%q) = %#v", tt.raw, ref)
			}
		})
	}
}

func TestParseRefRejectsInvalidReferences(t *testing.T) {
	for _, raw := range []string{"", "scratch", "http://example.com/image:tag", "$EMPTY"} {
		if ref, ok := ParseRef(raw); ok {
			t.Fatalf("ParseRef(%q) = %#v, true; want false", raw, ref)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestParseRef
```

Expected: FAIL because `internal/dockerimage` and `ParseRef` do not exist.

- [ ] **Step 3: Add the parser implementation**

Create `internal/dockerimage/ref.go`:

```go
package dockerimage

import "strings"

// Ref is a normalized Docker image reference. Name is the Packmon display
// identity; Registry/Repository/Reference are the values used for registry API
// calls.
type Ref struct {
	Original   string
	Name       string
	Registry   string
	Repository string
	Reference  string
	Digest     bool
}

func ParseRef(raw string) (Ref, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "scratch" || strings.Contains(raw, "://") || strings.HasPrefix(raw, "$") {
		return Ref{}, false
	}

	namePart := raw
	reference := "latest"
	digest := false
	if at := strings.Index(namePart, "@"); at >= 0 {
		reference = namePart[at+1:]
		namePart = namePart[:at]
		digest = true
	} else if colon := strings.LastIndex(namePart, ":"); colon > strings.LastIndex(namePart, "/") {
		reference = namePart[colon+1:]
		namePart = namePart[:colon]
	}
	if namePart == "" || reference == "" {
		return Ref{}, false
	}

	registry := "registry-1.docker.io"
	displayRegistry := "docker.io"
	repository := namePart
	first := namePart
	if slash := strings.Index(namePart, "/"); slash >= 0 {
		first = namePart[:slash]
	}
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		registry = first
		displayRegistry = first
		repository = strings.TrimPrefix(namePart[len(first):], "/")
		if first == "docker.io" {
			registry = "registry-1.docker.io"
			displayRegistry = "docker.io"
		}
	}
	if repository == "" {
		return Ref{}, false
	}
	if registry == "registry-1.docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	return Ref{
		Original:   raw,
		Name:       displayRegistry + "/" + repository,
		Registry:   registry,
		Repository: repository,
		Reference:  reference,
		Digest:     digest,
	}, true
}
```

- [ ] **Step 4: Run the parser tests**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestParseRef
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/ref.go internal/dockerimage/ref_test.go
git commit -m "feat: parse docker image references"
```

---

### Task 3: Add Shared Docker Inventory Models

**Files:**
- Create: `internal/dockerimage/models.go`
- Test: `internal/dockerimage/models_test.go`

- [ ] **Step 1: Write the failing conversion test**

Create `internal/dockerimage/models_test.go`:

```go
package dockerimage

import (
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestImagePackageConvertsToDockerDomainPackage(t *testing.T) {
	ref, ok := ParseRef("postgres:18-alpine")
	if !ok {
		t.Fatal("ParseRef(postgres:18-alpine) failed")
	}
	img := Image{
		Ref:        ref,
		SourceFile: "docker-compose.yml",
		SourceType: SourceCompose,
		Scope:      "runtime",
		Relation:   "compose",
		Direct:     true,
		Flags:      []string{"service=postgres"},
	}

	pkg := img.Package()
	if pkg.Name != "docker.io/library/postgres" || pkg.Version != "18-alpine" || pkg.Ecosystem != domain.EcosystemDocker {
		t.Fatalf("Package() = %#v", pkg)
	}
	if !pkg.Direct || pkg.Indirect || len(pkg.Via) != 0 {
		t.Fatalf("Package provenance = %#v, want direct docker row", pkg)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestImagePackageConvertsToDockerDomainPackage
```

Expected: FAIL because `Image`, `SourceCompose`, and `Image.Package` do not exist.

- [ ] **Step 3: Add the inventory model**

Create `internal/dockerimage/models.go`:

```go
package dockerimage

import "github.com/8linkz/packmon/internal/domain"

type SourceType string

const (
	SourceDockerfile SourceType = "dockerfile"
	SourceCompose    SourceType = "compose"
)

type Image struct {
	Ref        Ref
	SourceFile string
	SourceType SourceType
	Scope      string
	Relation   string
	Direct     bool
	Indirect   bool
	LocalBuild bool
	Flags      []string
}

func (i Image) Package() domain.Package {
	return domain.Package{
		Name:      i.Ref.Name,
		Version:   i.Ref.Reference,
		Ecosystem: domain.EcosystemDocker,
		Direct:    i.Direct,
		Indirect:  i.Indirect,
	}
}
```

If the package-scope plan has not yet added `Direct` and `Indirect` to `domain.Package`, stop here and execute that plan first.

- [ ] **Step 4: Run the model tests**

Run:

```powershell
go test -count=1 .\internal\domain .\internal\dockerimage -run "TestDockerEcosystemIsValid|TestImagePackageConvertsToDockerDomainPackage"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/models.go internal/dockerimage/models_test.go
git commit -m "feat: model docker image inventory rows"
```

---

### Task 4: Parse Dockerfile Base Images

**Files:**
- Create: `internal/dockerimage/dockerfile.go`
- Test: `internal/dockerimage/dockerfile_test.go`

- [ ] **Step 1: Write the failing Dockerfile parser tests**

Create `internal/dockerimage/dockerfile_test.go`:

```go
package dockerimage

import (
	"strings"
	"testing"
)

func TestParseDockerfileImagesHandlesArgsAndStages(t *testing.T) {
	input := `
ARG GO_VERSION=1.26
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
RUN go build ./...
FROM alpine:3.23 AS server
FROM server AS final
FROM scratch AS empty
`
	images, err := ParseDockerfileImages(strings.NewReader(input), "Dockerfile")
	if err != nil {
		t.Fatalf("ParseDockerfileImages: %v", err)
	}
	if len(images) != 2 {
		t.Fatalf("images = %#v, want 2 external non-scratch images; stage aliases must not become image rows", images)
	}
	if images[0].Ref.Name != "docker.io/library/golang" || images[0].Ref.Reference != "1.26-alpine" {
		t.Fatalf("first image = %#v", images[0])
	}
	if images[0].Scope != "build" || images[0].Relation != "base" || !images[0].Direct {
		t.Fatalf("first provenance = %#v", images[0])
	}
	if images[1].Ref.Name != "docker.io/library/alpine" || images[1].Ref.Reference != "3.23" {
		t.Fatalf("second image = %#v", images[1])
	}
	if images[1].Scope != "runtime" || images[1].Relation != "base" || !images[1].Direct {
		t.Fatalf("second provenance = %#v", images[1])
	}
}

func TestParseDockerfileImagesReturnsParseErrorForBadFrom(t *testing.T) {
	_, err := ParseDockerfileImages(strings.NewReader("FROM :bad\n"), "Dockerfile")
	if err == nil {
		t.Fatal("ParseDockerfileImages returned nil error for invalid FROM")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestParseDockerfileImages
```

Expected: FAIL because `ParseDockerfileImages` does not exist.

- [ ] **Step 3: Add Dockerfile parsing**

Create `internal/dockerimage/dockerfile.go`:

```go
package dockerimage

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func ParseDockerfileImages(r io.Reader, sourceFile string) ([]Image, error) {
	scanner := bufio.NewScanner(r)
	args := make(map[string]string)
	stages := make(map[string]struct{})
	var images []Image
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := stripDockerfileComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			name, value, ok := parseDockerArg(strings.TrimSpace(strings.TrimPrefix(line, fields[0])))
			if ok && value != "" {
				args[name] = value
			}
		case "FROM":
			fromFields := dockerfileFromFields(fields[1:])
			if len(fromFields) == 0 {
				return nil, fmt.Errorf("%s:%d: FROM without image", sourceFile, lineNo)
			}
			raw := substituteDockerArgs(fromFields[0], args)
			alias := dockerfileStageAlias(fromFields)
			if _, ok := stages[strings.ToLower(raw)]; ok {
				if alias != "" {
					stages[strings.ToLower(alias)] = struct{}{}
				}
				continue
			}
			ref, ok := ParseRef(raw)
			if !ok {
				if strings.EqualFold(raw, "scratch") {
					if alias != "" {
						stages[strings.ToLower(alias)] = struct{}{}
					}
					continue
				}
				return nil, fmt.Errorf("%s:%d: invalid FROM image %q", sourceFile, lineNo, raw)
			}
			if alias != "" {
				stages[strings.ToLower(alias)] = struct{}{}
			}
			images = append(images, Image{
				Ref:        ref,
				SourceFile: sourceFile,
				SourceType: SourceDockerfile,
				Scope:      "runtime",
				Relation:   "base",
				Direct:     true,
				Flags:      dockerfileFlags(fromFields),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: read Dockerfile: %w", sourceFile, err)
	}
	for i := range images {
		if i == 0 && len(images) > 1 {
			images[i].Scope = "build"
		}
	}
	return images, nil
}

func stripDockerfileComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return strings.TrimSpace(line[:idx])
	}
	return line
}

func parseDockerArg(raw string) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	parts := strings.SplitN(raw, "=", 2)
	name := strings.TrimSpace(parts[0])
	if name == "" {
		return "", "", false
	}
	if len(parts) == 1 {
		return name, "", true
	}
	return name, strings.TrimSpace(parts[1]), true
}

func substituteDockerArgs(raw string, args map[string]string) string {
	for name, value := range args {
		raw = strings.ReplaceAll(raw, "${"+name+"}", value)
		raw = strings.ReplaceAll(raw, "$"+name, value)
	}
	return raw
}

func dockerfileFlags(fields []string) []string {
	alias := dockerfileStageAlias(fields)
	if alias != "" {
		return []string{"stage=" + alias}
	}
	return nil
}

func dockerfileStageAlias(fields []string) string {
	for i := 1; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], "AS") {
			return fields[i+1]
		}
	}
	return ""
}

func dockerfileFromFields(fields []string) []string {
	for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
		fields = fields[1:]
	}
	return fields
}
```

- [ ] **Step 4: Run the Dockerfile parser tests**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestParseDockerfileImages
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/dockerfile.go internal/dockerimage/dockerfile_test.go
git commit -m "feat: parse dockerfile image inventory"
```

---

### Task 5: Parse Compose Image Services And Local Build Services

**Files:**
- Create: `internal/dockerimage/compose.go`
- Test: `internal/dockerimage/compose_test.go`

- [ ] **Step 1: Write the failing Compose parser tests**

Create `internal/dockerimage/compose_test.go`:

```go
package dockerimage

import (
	"strings"
	"testing"
)

func TestParseComposeImagesFindsImageAndBuildServices(t *testing.T) {
	input := `
services:
  postgres:
    image: postgres:18-alpine
  packmon-server:
    build:
      context: .
      dockerfile: Dockerfile
      target: server
  worker:
    image: ghcr.io/acme/worker:v1
    build: .
`
	images, err := ParseComposeImages(strings.NewReader(input), "docker-compose.yml")
	if err != nil {
		t.Fatalf("ParseComposeImages: %v", err)
	}
	if len(images) != 3 {
		t.Fatalf("images = %#v, want 3 rows", images)
	}
	if images[0].Ref.Name != "docker.io/library/postgres" || images[0].Ref.Reference != "18-alpine" {
		t.Fatalf("postgres image = %#v", images[0])
	}
	if images[0].Scope != "runtime" || images[0].Relation != "compose" || !images[0].Direct {
		t.Fatalf("postgres provenance = %#v", images[0])
	}
	if !containsString(images[0].Flags, "service=postgres") {
		t.Fatalf("postgres flags = %#v, want service flag", images[0].Flags)
	}
	if !images[1].LocalBuild || images[1].Ref.Name != "local/packmon-server" || images[1].Ref.Reference != "server" {
		t.Fatalf("build-only row = %#v", images[1])
	}
	for _, want := range []string{"service=packmon-server", "local-build", "context=.", "dockerfile=Dockerfile", "target=server"} {
		if !containsString(images[1].Flags, want) {
			t.Fatalf("build-only flags = %#v, want %q", images[1].Flags, want)
		}
	}
	if !images[2].LocalBuild || images[2].Ref.Name != "ghcr.io/acme/worker" {
		t.Fatalf("image+build row = %#v", images[2])
	}
	if !containsString(images[2].Flags, "context=.") {
		t.Fatalf("image+build flags = %#v, want scalar build context", images[2].Flags)
	}
}

func TestParseComposeImagesRejectsMalformedYAML(t *testing.T) {
	_, err := ParseComposeImages(strings.NewReader("services:\n  bad: ["), "compose.yml")
	if err == nil {
		t.Fatal("ParseComposeImages returned nil error for malformed YAML")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestParseComposeImages
```

Expected: FAIL because `ParseComposeImages` does not exist.

- [ ] **Step 3: Add Compose parsing**

Create `internal/dockerimage/compose.go`:

```go
package dockerimage

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Image string       `yaml:"image"`
	Build composeBuild `yaml:"build"`
}

type composeBuild struct {
	Present    bool
	Context    string
	Dockerfile string
	Target     string
}

func (b *composeBuild) UnmarshalYAML(value *yaml.Node) error {
	b.Present = true
	if value.Kind == yaml.ScalarNode {
		b.Context = strings.TrimSpace(value.Value)
		return nil
	}
	var raw struct {
		Context    string `yaml:"context"`
		Dockerfile string `yaml:"dockerfile"`
		Target     string `yaml:"target"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	b.Context = strings.TrimSpace(raw.Context)
	b.Dockerfile = strings.TrimSpace(raw.Dockerfile)
	b.Target = strings.TrimSpace(raw.Target)
	return nil
}

func ParseComposeImages(r io.Reader, sourceFile string) ([]Image, error) {
	var doc composeFile
	if err := yaml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: parse compose YAML: %w", sourceFile, err)
	}
	names := make([]string, 0, len(doc.Services))
	for name := range doc.Services {
		names = append(names, name)
	}
	sort.Strings(names)

	var images []Image
	for _, serviceName := range names {
		service := doc.Services[serviceName]
		hasBuild := service.Build.Present
		if strings.TrimSpace(service.Image) == "" {
			if hasBuild {
				images = append(images, localBuildImage(sourceFile, serviceName, service.Build))
			}
			continue
		}
		ref, ok := ParseRef(service.Image)
		if !ok {
			return nil, fmt.Errorf("%s: invalid image for service %s: %q", sourceFile, serviceName, service.Image)
		}
		flags := []string{"service=" + serviceName}
		if hasBuild {
			flags = composeBuildFlags(serviceName, service.Build)
		}
		images = append(images, Image{
			Ref:        ref,
			SourceFile: sourceFile,
			SourceType: SourceCompose,
			Scope:      "runtime",
			Relation:   "compose",
			Direct:     true,
			LocalBuild: hasBuild,
			Flags:      flags,
		})
	}
	return images, nil
}

func localBuildImage(sourceFile, serviceName string, build composeBuild) Image {
	reference := serviceName
	if build.Target != "" {
		reference = build.Target
	}
	return Image{
		Ref: Ref{
			Original:   serviceName,
			Name:       "local/" + serviceName,
			Registry:   "",
			Repository: serviceName,
			Reference:  reference,
		},
		SourceFile: sourceFile,
		SourceType: SourceCompose,
		Scope:      "runtime",
		Relation:   "compose-build",
		Direct:     true,
		LocalBuild: true,
		Flags:      composeBuildFlags(serviceName, build),
	}
}

func composeBuildFlags(serviceName string, build composeBuild) []string {
	flags := []string{"service=" + serviceName, "local-build"}
	if build.Context != "" {
		flags = append(flags, "context="+build.Context)
	}
	if build.Dockerfile != "" {
		flags = append(flags, "dockerfile="+build.Dockerfile)
	}
	if build.Target != "" {
		flags = append(flags, "target="+build.Target)
	}
	return flags
}
```

- [ ] **Step 4: Run the Compose parser tests**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestParseComposeImages
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/compose.go internal/dockerimage/compose_test.go
git commit -m "feat: parse compose image inventory"
```

---

### Task 6: Discover Docker Inventory Files Under The Scan Root

**Files:**
- Create: `internal/dockerimage/discover.go`
- Test: `internal/dockerimage/discover_test.go`

- [ ] **Step 1: Write the failing discovery test**

Create `internal/dockerimage/discover_test.go`:

```go
package dockerimage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFilesFindsDockerfilesAndComposeFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeTestFile(t, filepath.Join(root, "Dockerfile.cli"), "FROM alpine:3.23\n")
	writeTestFile(t, filepath.Join(root, "docker-compose.yml"), "services:\n  db:\n    image: postgres:18-alpine\n")
	writeTestFile(t, filepath.Join(root, "node_modules", "pkg", "Dockerfile"), "FROM ignored:latest\n")
	writeTestFile(t, filepath.Join(root, "deep", "too", "far", "Dockerfile"), "FROM ignored:latest\n")

	files, err := DiscoverFiles(root, 2)
	if err != nil {
		t.Fatalf("DiscoverFiles: %v", err)
	}
	got := make(map[string]Kind)
	for _, file := range files {
		got[file.RelPath] = file.Kind
	}
	want := map[string]Kind{
		"Dockerfile":          KindDockerfile,
		"Dockerfile.cli":      KindDockerfile,
		"docker-compose.yml":  KindCompose,
	}
	if len(got) != len(want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Fatalf("files[%q] = %q, want %q; all files %#v", path, got[path], kind, got)
		}
	}
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestDiscoverFilesFindsDockerfilesAndComposeFiles
```

Expected: FAIL because `DiscoverFiles`, `Kind`, and file kinds do not exist.

- [ ] **Step 3: Add discovery**

Create `internal/dockerimage/discover.go`:

```go
package dockerimage

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Kind string

const (
	KindDockerfile Kind = "dockerfile"
	KindCompose    Kind = "compose"
)

type File struct {
	Path    string
	RelPath string
	Kind    Kind
}

func DiscoverFiles(root string, maxDepth int) ([]File, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "walk", Path: absRoot, Err: fs.ErrInvalid}
	}

	rootDepth := strings.Count(filepath.ToSlash(absRoot), "/")
	var files []File
	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name != "." && name != ".github" && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			if name == "node_modules" || name == "vendor" || name == "__pycache__" {
				return fs.SkipDir
			}
			depth := strings.Count(filepath.ToSlash(path), "/") - rootDepth
			if depth > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		kind, ok := classifyFile(filepath.Base(path))
		if !ok {
			return nil
		}
		rel, relErr := filepath.Rel(absRoot, path)
		if relErr != nil {
			rel = path
		}
		files = append(files, File{Path: path, RelPath: filepath.ToSlash(rel), Kind: kind})
		return nil
	})
	return files, err
}

func classifyFile(base string) (Kind, bool) {
	lower := strings.ToLower(base)
	switch lower {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return KindCompose, true
	}
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return KindDockerfile, true
	}
	return "", false
}
```

- [ ] **Step 4: Run discovery tests**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestDiscoverFilesFindsDockerfilesAndComposeFiles
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/discover.go internal/dockerimage/discover_test.go
git commit -m "feat: discover docker inventory files"
```

---

### Task 7: Resolve Remote Registry Digests

**Files:**
- Create: `internal/dockerimage/registry.go`
- Test: `internal/dockerimage/registry_test.go`

- [ ] **Step 1: Write failing registry client tests**

Create `internal/dockerimage/registry_test.go`:

```go
package dockerimage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryClientResolvesDigestHeader(t *testing.T) {
	const digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Fatalf("method = %s, want HEAD", r.Method)
		}
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.docker.distribution.manifest.v2+json") {
			t.Fatalf("Accept header = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/alpine", Reference: "3.23"}
	client := NewRegistryClient(srv.Client())
	client.InsecureHTTP = true

	got, err := client.ResolveDigest(context.Background(), ref)
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if got != digest {
		t.Fatalf("digest = %q, want %q", got, digest)
	}
}

func TestRegistryClientHandlesBearerChallenge(t *testing.T) {
	const digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	var tokenSeen bool
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.URL.Query().Get("service") != "registry.example" || r.URL.Query().Get("scope") != "repository:library/alpine:pull" {
				t.Fatalf("token query = %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"abc123"}`))
		case "/v2/library/alpine/manifests/3.23":
			if r.Header.Get("Authorization") == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.example",scope="repository:library/alpine:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			tokenSeen = true
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/alpine", Reference: "3.23"}
	client := NewRegistryClient(srv.Client())
	client.InsecureHTTP = true

	got, err := client.ResolveDigest(context.Background(), ref)
	if err != nil {
		t.Fatalf("ResolveDigest: %v", err)
	}
	if got != digest || !tokenSeen {
		t.Fatalf("digest=%q tokenSeen=%v", got, tokenSeen)
	}
}

func TestRegistryClientReturnsEmptyDigestOnRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ref := Ref{Registry: strings.TrimPrefix(srv.URL, "http://"), Repository: "library/alpine", Reference: "3.23"}
	client := NewRegistryClient(srv.Client())
	client.InsecureHTTP = true

	got, err := client.ResolveDigest(context.Background(), ref)
	if err == nil {
		t.Fatal("ResolveDigest returned nil error for 429")
	}
	if got != "" {
		t.Fatalf("digest = %q, want empty on 429", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestRegistryClient
```

Expected: FAIL because `NewRegistryClient` and `ResolveDigest` do not exist.

- [ ] **Step 3: Add registry client implementation**

Create `internal/dockerimage/registry.go`:

```go
package dockerimage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

var ErrDigestUnavailable = errors.New("docker registry digest unavailable")

type RegistryClient struct {
	HTTP         *http.Client
	InsecureHTTP bool
}

func NewRegistryClient(client *http.Client) *RegistryClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &RegistryClient{HTTP: client}
}

func (c *RegistryClient) ResolveDigest(ctx context.Context, ref Ref) (string, error) {
	if ref.Registry == "" || ref.Repository == "" || ref.Reference == "" || strings.HasPrefix(ref.Name, "local/") {
		return "", ErrDigestUnavailable
	}
	digest, challenge, err := c.resolveDigestOnce(ctx, ref, "")
	if err == nil || challenge == "" {
		return digest, err
	}
	token, tokenErr := c.fetchBearerToken(ctx, challenge)
	if tokenErr != nil {
		return "", tokenErr
	}
	return c.resolveDigestOnceNoChallenge(ctx, ref, token)
}

func (c *RegistryClient) resolveDigestOnce(ctx context.Context, ref Ref, token string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.manifestURL(ref), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", manifestAccept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return "", resp.Header.Get("WWW-Authenticate"), ErrDigestUnavailable
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("%w: status %d", ErrDigestUnavailable, resp.StatusCode)
	}
	digest := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	if digest == "" {
		return "", "", ErrDigestUnavailable
	}
	return digest, "", nil
}

func (c *RegistryClient) resolveDigestOnceNoChallenge(ctx context.Context, ref Ref, token string) (string, error) {
	digest, _, err := c.resolveDigestOnce(ctx, ref, token)
	return digest, err
}

func (c *RegistryClient) manifestURL(ref Ref) string {
	scheme := "https"
	if c.InsecureHTTP {
		scheme = "http"
	}
	return scheme + "://" + ref.Registry + "/v2/" + ref.Repository + "/manifests/" + url.PathEscape(ref.Reference)
}

func (c *RegistryClient) fetchBearerToken(ctx context.Context, challenge string) (string, error) {
	params, ok := parseBearerChallenge(challenge)
	if !ok {
		return "", ErrDigestUnavailable
	}
	realm := params["realm"]
	if realm == "" {
		return "", ErrDigestUnavailable
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for _, key := range []string{"service", "scope"} {
		if value := params[key]; value != "" {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: token status %d", ErrDigestUnavailable, resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", ErrDigestUnavailable
}

func parseBearerChallenge(raw string) (map[string]string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		return nil, false
	}
	raw = strings.TrimSpace(raw[len("Bearer "):])
	out := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.ToLower(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out, len(out) > 0
}
```

- [ ] **Step 4: Run registry tests**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestRegistryClient
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/registry.go internal/dockerimage/registry_test.go
git commit -m "feat: resolve docker registry digests"
```

---

### Task 8: Inspect Local Docker Image Digests Best-Effort

**Files:**
- Create: `internal/dockerimage/local.go`
- Test: `internal/dockerimage/local_test.go`

- [ ] **Step 1: Write failing local Docker inspection tests**

Create `internal/dockerimage/local_test.go`:

```go
package dockerimage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLocalInspectorExtractsRepoDigest(t *testing.T) {
	runner := &fakeRunner{out: `[{
		"RepoTags":["postgres:18-alpine"],
		"RepoDigests":["postgres@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
		"Id":"sha256:local"
	}]`}
	inspector := LocalInspector{Runner: runner}
	ref, _ := ParseRef("postgres:18-alpine")

	got := inspector.Digests(context.Background(), []Ref{ref})
	if got[ref.Name] != "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" {
		t.Fatalf("digests = %#v", got)
	}
	if !strings.Contains(strings.Join(runner.args, " "), "image inspect") {
		t.Fatalf("runner args = %#v, want docker image inspect", runner.args)
	}
}

func TestLocalInspectorDegradesWhenDockerUnavailable(t *testing.T) {
	ref, _ := ParseRef("alpine:3.23")
	inspector := LocalInspector{Runner: &fakeRunner{err: errors.New("docker not found")}}

	got := inspector.Digests(context.Background(), []Ref{ref})
	if len(got) != 0 {
		t.Fatalf("digests = %#v, want empty when docker is unavailable", got)
	}
}

type fakeRunner struct {
	out  string
	err  error
	args []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.args = append([]string{name}, args...)
	return []byte(f.out), f.err
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestLocalInspector
```

Expected: FAIL because `LocalInspector` does not exist.

- [ ] **Step 3: Add local Docker inspection**

Create `internal/dockerimage/local.go`:

```go
package dockerimage

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

type LocalInspector struct {
	Runner CommandRunner
}

func (i LocalInspector) Digests(ctx context.Context, refs []Ref) map[string]string {
	if len(refs) == 0 {
		return nil
	}
	runner := i.Runner
	if runner == nil {
		runner = execRunner{}
	}
	args := []string{"image", "inspect"}
	refByTag := make(map[string]Ref, len(refs))
	for _, ref := range refs {
		if ref.Registry == "" || strings.HasPrefix(ref.Name, "local/") {
			continue
		}
		displayRef := ref.Name + ":" + ref.Reference
		refByTag[displayRef] = ref
		args = append(args, displayRef)
	}
	if len(args) == 2 {
		return nil
	}
	out, err := runner.Run(ctx, "docker", args...)
	if err != nil {
		return nil
	}
	var inspected []struct {
		RepoTags    []string `json:"RepoTags"`
		RepoDigests []string `json:"RepoDigests"`
		ID          string   `json:"Id"`
	}
	if err := json.Unmarshal(out, &inspected); err != nil {
		return nil
	}
	digests := make(map[string]string)
	for _, image := range inspected {
		var matched Ref
		for _, tag := range image.RepoTags {
			if ref, ok := refByTag[normalizeLocalRepoTag(tag)]; ok {
				matched = ref
				break
			}
		}
		if matched.Name == "" {
			continue
		}
		for _, repoDigest := range image.RepoDigests {
			name, digest, ok := strings.Cut(repoDigest, "@")
			if ok && normalizeLocalRepoName(name) == matched.Name {
				digests[matched.Name] = digest
				break
			}
		}
	}
	return digests
}

func normalizeLocalRepoTag(raw string) string {
	ref, ok := ParseRef(raw)
	if !ok {
		return raw
	}
	return ref.Name + ":" + ref.Reference
}

func normalizeLocalRepoName(raw string) string {
	ref, ok := ParseRef(raw + ":latest")
	if !ok {
		return raw
	}
	return ref.Name
}
```

- [ ] **Step 4: Run local inspector tests**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestLocalInspector
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/local.go internal/dockerimage/local_test.go
git commit -m "feat: inspect local docker image digests"
```

---

### Task 9: Build A Docker Image Collector

**Files:**
- Create: `internal/dockerimage/collector.go`
- Test: `internal/dockerimage/collector_test.go`

- [ ] **Step 1: Write the failing collector test**

Create `internal/dockerimage/collector_test.go`:

```go
package dockerimage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectFindsDockerfileAndComposeImages(t *testing.T) {
	root := t.TempDir()
	writeDockerImageTestFile(t, filepath.Join(root, "Dockerfile"), "FROM golang:1.26-alpine AS build\nFROM alpine:3.23 AS server\n")
	writeDockerImageTestFile(t, filepath.Join(root, "docker-compose.yml"), "services:\n  db:\n    image: postgres:18-alpine\n  app:\n    build:\n      context: .\n      target: server\n")

	collection, err := Collect(root, 5)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := make(map[string]Image)
	for _, img := range collection.Images {
		got[img.Ref.Name+"@"+img.Ref.Reference+"|"+img.SourceFile] = img
	}
	for _, key := range []string{
		"docker.io/library/golang@1.26-alpine|Dockerfile",
		"docker.io/library/alpine@3.23|Dockerfile",
		"docker.io/library/postgres@18-alpine|docker-compose.yml",
		"local/app@app|docker-compose.yml",
	} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing %s in %#v", key, got)
		}
	}
	if collection.Files != 2 {
		t.Fatalf("Files = %d, want 2", collection.Files)
	}
}

func TestCollectRecordsParseErrorsAndContinues(t *testing.T) {
	root := t.TempDir()
	writeDockerImageTestFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeDockerImageTestFile(t, filepath.Join(root, "compose.yml"), "services:\n  broken: [")

	collection, err := Collect(root, 5)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(collection.Images) != 1 {
		t.Fatalf("Images = %#v, want one Dockerfile image", collection.Images)
	}
	if len(collection.ParseErrors) != 1 {
		t.Fatalf("ParseErrors = %#v, want one compose parse error", collection.ParseErrors)
	}
}

func writeDockerImageTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestCollect
```

Expected: FAIL because `Collect` does not exist.

- [ ] **Step 3: Add the collector**

Create `internal/dockerimage/collector.go`:

```go
package dockerimage

import (
	"fmt"
	"os"
)

type Collection struct {
	Images      []Image
	ParseErrors []string
	Files       int
}

func Collect(root string, maxDepth int) (*Collection, error) {
	files, err := DiscoverFiles(root, maxDepth)
	if err != nil {
		return nil, err
	}
	result := &Collection{Files: len(files)}
	for _, file := range files {
		images, parseErr := parseFile(file)
		if parseErr != nil {
			result.ParseErrors = append(result.ParseErrors, parseErr.Error())
			continue
		}
		result.Images = append(result.Images, images...)
	}
	result.Images = dedupImages(result.Images)
	return result, nil
}

func parseFile(file File) ([]Image, error) {
	f, err := os.Open(file.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	switch file.Kind {
	case KindDockerfile:
		return ParseDockerfileImages(f, file.RelPath)
	case KindCompose:
		return ParseComposeImages(f, file.RelPath)
	default:
		return nil, fmt.Errorf("%s: unsupported docker inventory file kind %q", file.RelPath, file.Kind)
	}
}

func dedupImages(images []Image) []Image {
	seen := make(map[string]int, len(images))
	out := make([]Image, 0, len(images))
	for _, image := range images {
		key := image.Ref.Name + "@" + image.Ref.Reference + "|" + image.SourceFile + "|" + image.Relation
		if idx, ok := seen[key]; ok {
			out[idx].Flags = mergeStrings(out[idx].Flags, image.Flags)
			out[idx].LocalBuild = out[idx].LocalBuild || image.LocalBuild
			continue
		}
		seen[key] = len(out)
		out = append(out, image)
	}
	return out
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}
```

- [ ] **Step 4: Run collector tests**

Run:

```powershell
go test -count=1 .\internal\dockerimage -run TestCollect
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal/dockerimage/collector.go internal/dockerimage/collector_test.go
git commit -m "feat: collect docker image inventory"
```

---

### Task 10: Resolve Docker Latest/Update Status For List-All Rows

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Test: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Write the failing Docker update status test**

Append to `cmd/packmon/list_all_test.go`:

```go
func TestBuildListAllPackageReportDockerUpdateStatus(t *testing.T) {
	old := resolveDockerImageStatusFn
	t.Cleanup(func() { resolveDockerImageStatusFn = old })
	resolveDockerImageStatusFn = func(_ context.Context, p listAllPackage) listAllLatest {
		if p.Name != "docker.io/library/postgres" || p.Version != "18-alpine" {
			t.Fatalf("docker status package = %#v", p)
		}
		return listAllLatest{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	report := buildListAllPackageReport([]listAllPackage{{
		Name:      "docker.io/library/postgres",
		Version:   "18-alpine",
		Ecosystem: domain.EcosystemDocker,
		LockFile:  "docker-compose.yml",
	}}, &domain.ScanResult{}, ".")

	if len(report.Rows) != 1 {
		t.Fatalf("Rows = %#v", report.Rows)
	}
	row := report.Rows[0]
	if row.Latest != "sha256:remote" || row.Update != "unknown" || report.Unknown != 1 {
		t.Fatalf("row=%#v report=%#v", row, report)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestBuildListAllPackageReportDockerUpdateStatus
```

Expected: FAIL because `resolveDockerImageStatusFn` and `listAllLatest` do not exist.

- [ ] **Step 3: Add list-all latest status plumbing**

In `cmd/packmon/list_all.go`, add imports:

```go
	"net/http"

	"github.com/8linkz/packmon/internal/dockerimage"
```

Add this type and variables near the report structs:

```go
type listAllLatest struct {
	Latest  string
	Update  string
	Unknown bool
}

var resolveDockerImageStatusFn = resolveDockerImageStatus
```

In `buildListAllPackageReport`, replace the `latest := make([]string, len(packages))` flow with:

```go
latest := make([]listAllLatest, len(packages))
var wg sync.WaitGroup
sem := make(chan struct{}, maxConcurrentRegistryRequests)
for i, pkg := range packages {
	wg.Add(1)
	go func(idx int, p listAllPackage) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		latest[idx] = resolveListAllLatest(ctx, p)
	}(i, pkg)
}
wg.Wait()
```

Then change the per-row update logic to:

```go
lat := latest[i]
latestCol := lat.Latest
update := lat.Update
if latestCol == "" {
	latestCol = "unknown"
}
if update == "" {
	update = "-"
}
if lat.Unknown {
	report.Unknown++
}
if update == "yes" {
	report.WithUpdates++
}
```

Add these helpers below `buildListAllPackageReport`:

```go
func resolveListAllLatest(ctx context.Context, p listAllPackage) listAllLatest {
	if p.Ecosystem == domain.EcosystemDocker {
		return resolveDockerImageStatusFn(ctx, p)
	}
	lat := fetchLatestVersionFn(ctx, p.Ecosystem, p.Name)
	if lat == "" {
		return listAllLatest{Latest: "unknown", Update: "-", Unknown: true}
	}
	if updateAvailable(p.Version, lat, p.Ecosystem) {
		return listAllLatest{Latest: lat, Update: "yes"}
	}
	return listAllLatest{Latest: lat, Update: "-"}
}

func resolveDockerImageStatus(ctx context.Context, p listAllPackage) listAllLatest {
	ref, ok := dockerRefFromListAllPackage(p)
	if !ok || strings.HasPrefix(p.Name, "local/") {
		return listAllLatest{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	registryClient := dockerimage.NewRegistryClient(http.DefaultClient)
	remoteDigest, err := registryClient.ResolveDigest(ctx, ref)
	if err != nil || remoteDigest == "" {
		return listAllLatest{Latest: "unknown", Update: "unknown", Unknown: true}
	}
	localDigests := dockerimage.LocalInspector{}.Digests(ctx, []dockerimage.Ref{ref})
	localDigest := localDigests[ref.Name]
	if localDigest == "" {
		return listAllLatest{Latest: shortDigest(remoteDigest), Update: "unknown", Unknown: true}
	}
	if localDigest != remoteDigest {
		return listAllLatest{Latest: shortDigest(remoteDigest), Update: "yes"}
	}
	return listAllLatest{Latest: shortDigest(remoteDigest), Update: "-"}
}

func dockerRefFromListAllPackage(p listAllPackage) (dockerimage.Ref, bool) {
	raw := p.Name + ":" + p.Version
	if strings.Contains(p.Version, ":") {
		raw = p.Name + "@" + p.Version
	}
	return dockerimage.ParseRef(raw)
}

func shortDigest(digest string) string {
	algo, value, ok := strings.Cut(digest, ":")
	if !ok || len(value) <= 12 {
		return digest
	}
	return algo + ":" + value[:12]
}
```

- [ ] **Step 4: Run the Docker update status test**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestBuildListAllPackageReportDockerUpdateStatus
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add cmd/packmon/list_all.go cmd/packmon/list_all_test.go
git commit -m "feat: resolve docker image update status"
```

---

### Task 11: Append Docker Inventory To `--list-all`

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Test: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Write failing list-all Docker inventory tests**

Append to `cmd/packmon/list_all_test.go`:

```go
func TestRunListAllIncludesDockerImages(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM golang:1.26-alpine AS build\nFROM alpine:3.23 AS server\n"), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n  db:\n    image: postgres:18-alpine\n"), 0o600); err != nil {
		t.Fatalf("write compose: %v", err)
	}

	oldLatest := fetchLatestVersionFn
	oldDocker := resolveDockerImageStatusFn
	t.Cleanup(func() {
		fetchLatestVersionFn = oldLatest
		resolveDockerImageStatusFn = oldDocker
	})
	fetchLatestVersionFn = func(context.Context, domain.Ecosystem, string) string { return "" }
	resolveDockerImageStatusFn = func(context.Context, listAllPackage) listAllLatest {
		return listAllLatest{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	output := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	for _, want := range []string{
		"docker.io/library/golang",
		"docker.io/library/alpine",
		"docker.io/library/postgres",
		"docker",
		"Dockerfile",
		"docker-compose.yml",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("list-all output missing %q:\n%s", want, output)
		}
	}
}

func TestRunListAllHTMLIncludesDockerImages(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.23\n"), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	oldDocker := resolveDockerImageStatusFn
	t.Cleanup(func() { resolveDockerImageStatusFn = oldDocker })
	resolveDockerImageStatusFn = func(context.Context, listAllPackage) listAllLatest {
		return listAllLatest{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	settings := listAllSettings(dir, false)
	settings.OutputHTML = htmlPath
	if _, err := runListAll(context.Background(), settings); err != nil {
		t.Fatalf("runListAll: %v", err)
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"docker.io/library/alpine", "docker", "Dockerfile", "sha256:remote"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing %q:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestRunListAllIncludesDockerImages|TestRunListAllHTMLIncludesDockerImages"
```

Expected: FAIL because Docker images are not collected by `collectAllPackages`.

- [ ] **Step 3: Add Docker image collection to list-all only**

In `cmd/packmon/list_all.go`, add Docker collection at the end of `collectAllPackages` before `return packages, nil`:

```go
	dockerRows, dockerErr := collectDockerPackages(absPath, settings)
	if dockerErr != nil {
		fmt.Fprintf(os.Stderr, "warning: docker inventory error: %v\n", dockerErr)
	} else {
		packages = append(packages, dockerRows...)
	}
```

Add this helper near `collectAllPackages`:

```go
func collectDockerPackages(absPath string, settings scanSettings) ([]listAllPackage, error) {
	if !listAllAllowsEcosystem(settings.Ecosystems, domain.EcosystemDocker) {
		return nil, nil
	}
	collection, err := dockerimage.Collect(absPath, settings.MaxDepth)
	if err != nil {
		return nil, err
	}
	for _, parseErr := range collection.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: docker parse error in %s\n", parseErr)
	}
	rows := make([]listAllPackage, 0, len(collection.Images))
	for _, image := range collection.Images {
		pkg := image.Package()
		rows = append(rows, listAllPackage{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			LockFile:  image.SourceFile,
			Scope:     image.Scope,
			Relation:  image.Relation,
			Flags:     strings.Join(image.Flags, ", "),
		})
	}
	return rows, nil
}

func listAllAllowsEcosystem(ecosystems []string, eco domain.Ecosystem) bool {
	if len(ecosystems) == 0 {
		return true
	}
	for _, raw := range ecosystems {
		if strings.EqualFold(strings.TrimSpace(raw), string(eco)) {
			return true
		}
	}
	return false
}
```

This helper assumes the package-scope plan has already added `Scope`, `Relation`, and `Flags` fields to `listAllPackage`. If those fields are not present yet, execute that plan first and then continue this task.

- [ ] **Step 4: Run list-all Docker tests**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestRunListAllIncludesDockerImages|TestRunListAllHTMLIncludesDockerImages"
```

Expected: PASS.

- [ ] **Step 5: Verify plain scan still does not send Docker packages**

Append to `cmd/packmon/list_all_test.go` or the existing scan command test file:

```go
func TestPlainScanDoesNotSendDockerInventoryPackages(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.23\n"), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	var requestSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		requestSeen = true
		var req struct {
			Packages []domain.Package `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		var sawNPM bool
		for _, pkg := range req.Packages {
			if pkg.Ecosystem == domain.EcosystemNPM && pkg.Name == "left-pad" && pkg.Version == "1.3.0" {
				sawNPM = true
			}
			if pkg.Ecosystem == domain.EcosystemDocker {
				t.Fatalf("plain scan request included docker package: %#v", pkg)
			}
		}
		if !sawNPM {
			t.Fatalf("plain scan request packages = %#v, want npm left-pad and no docker packages", req.Packages)
		}
		writeJSONForTest(t, w, domain.ScanResult{ScanID: "scan", Mode: "remote"})
	}))
	defer server.Close()

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--mode", "remote", "--server", server.URL, "--api-key", "test", "--insecure-allow-http", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !requestSeen {
		t.Fatal("plain scan did not call remote check; test would not prove docker exclusion")
	}
}
```

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestPlainScanDoesNotSendDockerInventoryPackages
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add cmd/packmon/list_all.go cmd/packmon/list_all_test.go
git commit -m "feat: include docker images in list-all"
```

---

### Task 12: Render Docker Provenance Cleanly In Terminal And HTML

**Files:**
- Modify: `cmd/packmon/list_all.go`
- Test: `cmd/packmon/list_all_test.go`

- [ ] **Step 1: Write failing output-column tests**

Append to `cmd/packmon/list_all_test.go`:

```go
func TestListAllDockerRowsRenderScopeRelationAndFlags(t *testing.T) {
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "docker.io/library/postgres",
			Installed: "18-alpine",
			Latest:    "sha256:remote",
			Update:    "unknown",
			Ecosystem: "docker",
			Vuln:      "-",
			Scope:     "runtime",
			Relation:  "compose",
			Flags:     "service=postgres",
			LockFile:  "docker-compose.yml",
		}},
		Unknown: 1,
	}
	output := captureStdout(t, func() {
		printListAllPackageReport(report)
	})
	for _, want := range []string{"SCOPE", "RELATION", "VIA", "FLAGS", "runtime", "compose", "service=postgres"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
go test -count=1 .\cmd\packmon -run TestListAllDockerRowsRenderScopeRelationAndFlags
```

Expected: FAIL if the package-scope plan has not yet added the columns, or PASS if that plan is already implemented.

- [ ] **Step 3: Ensure list-all row structs include Docker provenance columns**

If the package-scope plan already added these fields, inspect the code and only adjust Docker-specific values. If not, add these fields to `listAllRow`:

```go
	Scope    string
	Relation string
	Via      string
	Flags    string
```

Then update `printListAllPackageReport` and the HTML table to include the columns in this order:

```text
PACKAGE  INSTALLED  LATEST  UPDATE  ECOSYSTEM  SCOPE  RELATION  VIA  FLAGS  VULN  LOCK FILE
```

Use the same CSS sizing rule as the package-scope plan: version/digest columns must be `white-space: nowrap`, table `min-width` must be at least `1600px`, and the scroll wrapper must allow horizontal scroll instead of wrapping digests.

- [ ] **Step 4: Run output tests**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestListAllDockerRowsRenderScopeRelationAndFlags|TestRunListAllIncludesDockerImages|TestRunListAllHTMLIncludesDockerImages"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add cmd/packmon/list_all.go cmd/packmon/list_all_test.go
git commit -m "feat: render docker provenance in list-all"
```

---

### Task 13: Document Docker Image Inventory Boundaries

**Files:**
- Modify: `DESIGN.md`
- Modify: `SECURITY.md`
- Test: none

- [ ] **Step 1: Update `DESIGN.md`**

Add a concise CLI behavior note near the `--list-all`/outdated reporting section:

```markdown
`scan --list-all` also inventories Docker image declarations from `Dockerfile`,
`Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, and
`compose.yaml`. Docker rows use ecosystem `docker`, show declared tags/digests,
and resolve public registry manifest digests best-effort. If the local Docker
CLI can inspect the declared image, Packmon compares the local repo digest with
the current registry digest and marks `UPDATE yes`, `-`, or `unknown`.

Docker image inventory is not a container-layer vulnerability scan. Packmon does
not pull images, scan OS packages inside images, or read private registry
credentials as part of `--list-all`.
```

- [ ] **Step 2: Update `SECURITY.md`**

Add a trust-boundary note near dependency handling or local tooling:

```markdown
Docker image freshness checks are metadata-only. The CLI may execute
`docker image inspect` with fixed argv to read local image metadata when Docker
is installed, but it must not execute compose files, build images, pull images,
or log full local Docker errors. Registry checks use public manifest metadata
requests and bearer-token challenges; private registry credentials are not read.
Failures degrade to `unknown` in reports.
```

- [ ] **Step 3: Review docs for drift**

Run:

```powershell
Select-String -Path DESIGN.md,SECURITY.md -Pattern "Docker image inventory","docker image inspect","container-layer vulnerability" -CaseSensitive
```

Expected: The new text appears once in each document, with no contradictory statement saying Docker images are scanned for vulnerabilities.

- [ ] **Step 4: Commit**

```powershell
git add DESIGN.md SECURITY.md
git commit -m "docs: document docker image inventory"
```

---

### Task 14: Final Verification And Build

**Files:**
- No file edits expected.

- [ ] **Step 1: Format changed Go files**

Run:

```powershell
gofumpt -extra -w internal/domain/models.go internal/domain/models_test.go internal/dockerimage cmd/packmon/list_all.go cmd/packmon/list_all_test.go
```

Expected: command exits 0. If `gofumpt` is not installed, run `gofmt -w` on the same files and state that `gofumpt` was unavailable.

- [ ] **Step 2: Run targeted tests**

Run:

```powershell
$env:GOTMPDIR = Join-Path $PWD '.gotmp'
New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null
go test -count=1 .\internal\domain .\internal\dockerimage .\cmd\packmon
```

Expected: PASS.

- [ ] **Step 3: Run scanner/parser regression tests**

Run:

```powershell
go test -count=1 .\internal\scanner .\internal\parser
```

Expected: PASS. This confirms normal package collection and parser behavior did not regress.

- [ ] **Step 4: Run full test suite**

Run:

```powershell
go test -count=1 ./...
```

Expected: PASS. If any pre-existing GOTMPDIR path-separator failures reappear in `cmd/packmon`, keep the output and verify whether they reproduce on a clean branch before changing Docker code.

- [ ] **Step 5: Vet and build both binaries**

Run:

```powershell
go vet ./...
go build -o packmon.exe .\cmd\packmon
go build -o packmon-server.exe .\cmd\packmon-server
```

Expected: all commands exit 0. Binaries are intentionally built in the repo root because the user asked for that workflow earlier.

- [ ] **Step 6: Manual smoke test with this repo**

Run:

```powershell
.\packmon.exe scan . --mode remote --server http://127.0.0.1:8080 --api-key <redacted> --insecure-allow-http --list-all --html 1.html
```

Expected in terminal and `1.html`:

```text
docker.io/library/golang
docker.io/library/alpine
docker.io/library/postgres
```

Expected Docker row semantics:

```text
ECOSYSTEM docker
UPDATE unknown
```

`UPDATE yes` or `UPDATE -` is also valid when the local Docker CLI can inspect a pulled image and a public registry digest is available.

- [ ] **Step 7: Final commit**

If Task commits were skipped during execution, create one combined commit:

```powershell
git status --short
git add internal/domain internal/dockerimage cmd/packmon/list_all.go cmd/packmon/list_all_test.go DESIGN.md SECURITY.md
git commit -m "feat: include docker images in list-all inventory"
```

Expected: commit succeeds and `git status --short` contains no tracked implementation changes except intentionally ignored/generated files.

---

## Self-Review Checklist

- Docker images are included only in `--list-all`; normal scan requests do not send Docker packages to the server.
- Static repo sources are covered: `Dockerfile`, `Dockerfile.*`, `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, and `compose.yaml`.
- Dockerfile stage aliases such as `FROM build AS final` are not reported as external Docker Hub images.
- Compose build metadata preserves `context`, `dockerfile`, and `target` in Docker row flags.
- Current repo rows are represented: `golang:1.26-alpine`, `alpine:3.23`, `postgres:18-alpine`, plus local build services from Compose.
- No paid API or container vulnerability service is introduced.
- Docker CLI use is optional, fixed-argv, JSON-decoded, and non-fatal.
- Registry errors, 401, 404, 429, and Docker-unavailable states degrade to `unknown`, not scan failure.
- Terminal and HTML reports show Docker rows with `SCOPE`, `RELATION`, `VIA`, and `FLAGS` when the package-scope plan has landed.
- Documentation states the boundary clearly: Docker image freshness is metadata-only, not a layer/package vulnerability scan.
