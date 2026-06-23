# Auto-SBOM Orchestration (`--auto-sbom`) - Design

**Date:** 2026-06-06
**Status:** Revised design + review fixes applied, ready for implementation plan
**Author:** Packmon

**Review fixes (this pass):** zero-package handling uses a required manifest
cross-check (declares deps + 0 imported = hard abort; empty manifest + 0 = exit
0), so dependency-free projects pass while soft failures never read as clean;
`--keep-sbom` `Cleanup` is
a no-op; injectable `Runner`/`LookPath` seams added so the 90% coverage target is
reachable tool-less; multiple positional targets rejected; `--include-dev`
honored at generation in both modes with a warning for no-dev-marker ecosystems;
workspace/aggregator suppression mechanism and `requirements.txt` boundary made
explicit. All CLI flag names verified against `cmd/packmon/scan.go`.

## Goal

Make `packmon scan` an all-in-one entry point that can **generate** an SBOM with
the appropriate CycloneDX tool and **analyse** it in a single command. Today the
chain is two manual steps: run a CycloneDX generator, then run
`packmon scan --sbom <file>`.

This feature adds `--auto-sbom`: Packmon detects the project's supported
manifest(s), invokes matching CycloneDX generator(s), feeds the resulting
SBOM(s) into the existing analysis pipeline, and emits the report in any
existing output format.

```text
packmon scan --auto-sbom ./myproject
-> detect manifests -> run CycloneDX generator(s) -> analyse -> report
```

## Non-Goals

- **Not** part of the server (`cmd/packmon-server`). This is a CLI-only feature
  (`cmd/packmon`). The server has no source trees or toolchains.
- No new generators beyond the v1 set: npm, PyPI, Go, Maven. Others are added
  later as one new file each behind the `Generator` interface.
- No best-effort partial scan in v1. See Error Handling.
- No change to the canonical `domain.ScanResult` schema, output renderers, or
  server behavior.
- No scanner behavior change after generated SBOM files are appended to
  `CollectConfig.SBOMFiles`. The existing SBOM parse, merge, dedup, ecosystem
  filter, analysis, and output paths remain the downstream source of truth.
- Packmon does not auto-install Maven (`mvn`), Python, Node, Go, or any base
  toolchain. It may install CycloneDX generator packages only when
  `--install-tools` is explicitly set.

## Approach

Chosen approach: a thin generator layer before the existing scanner.

`CollectPackages` (`internal/scanner/package_collector.go`) already accepts a
list of SBOM file paths (`CollectConfig.SBOMFiles`), parses them via
`sbom.Parse`, and merges plus de-duplicates them with lock-file packages. This
is the integration seam: `--auto-sbom` generates temporary CycloneDX JSON files
and appends their paths to `SBOMFiles`.

Important nuance: generated SBOMs must not rely on the existing SBOM importer to
recover ecosystem-specific dev/test metadata. The current importer primarily
uses Package URLs as inventory identities. Therefore the generator layer must
honor `--include-dev` at generation time. Two supported shapes:

- **Resolved-graph generators that separate dev/test from runtime** (npm, Go,
  Maven, Poetry): the adapter toggles that separation from `--include-dev`.
- **Flat, author-curated manifests with no dev/runtime distinction** (a plain
  `requirements.txt`): the listed entries are accepted as the stated inventory;
  `--include-dev` cannot change them and a warning is emitted.

An ecosystem whose generator co-mingles dev/test into the resolved graph with no
way to exclude them is not supported for auto-SBOM v1.

Rejected alternatives:

- **In-memory SBOMs:** Maven writes files, not stdout, and other generators also
  support file output. A file-based handoff is the uniform path.
- **Separate `generate-sbom` subcommand:** useful later, but v1 keeps one user
  command. A constrained form is provided by `--sbom-only`.
- **Best-effort generation:** partial inventory can produce a false-clean scan.
  v1 fails hard when a detected supported ecosystem cannot be generated.

## CLI Behavior

New flags on the existing `scan` command:

| Flag | Type | Effect |
|---|---|---|
| `--auto-sbom` | bool | Detect supported manifests, generate SBOM(s), then analyse them |
| `--install-tools` | bool | Allow auto-install of missing generators; otherwise print hint only |
| `--keep-sbom <dir>` | string | Write generated SBOMs there and keep them |
| `--sbom-only` | bool | Generate SBOM(s) only; no analysis, feed/server contact, history, webhook, or report outputs |

Reused unchanged:

- `--ecosystems` filters which ecosystems are generated and remains the scanner
  ecosystem filter.
- Existing output flags are `--html`, `--output-json`, `--output-sarif`, and
  `--output-junit`.
- Table output, `--fail-on`, `--quiet`, and `--no-color` keep their current
  meanings in normal scan mode.

Rules:

- `--auto-sbom` operates on exactly one target path. The target can come from a
  single positional path or `--repo`. More than one positional target, or
  `--all`, is rejected in v1 with an operational error.
- `--auto-sbom` is rejected with early-exit scan modes in v1:
  `--list-packages`, `--outdated`, and `--list-all`.
- `--install-tools`, `--keep-sbom`, and `--sbom-only` require `--auto-sbom`;
  otherwise they are operational errors.
- `--sbom-only` writes generated SBOMs to `--keep-sbom <dir>` if set, otherwise
  to the current working directory. It prints generated paths to stdout unless
  `--quiet` is set.
- `--sbom-only` rejects `--sbom`, result output flags (`--html`,
  `--output-json`, `--output-sarif`, `--output-junit`), webhook flags, and
  configured output files because no scan result is produced. `--fail-on` is
  ignored in this mode (no findings are evaluated).
- In normal scan mode, generated SBOMs combine with user-supplied `--sbom`
  inputs and normal lock files found in the same run.
- `--ecosystems` is applied before tool checks and generation. If the filtered
  target has no supported auto-SBOM detections, the command fails with a clear
  message listing what was searched for.
- `--include-dev` is honored at SBOM **generation** time in both normal and
  `--sbom-only` modes, because it changes generator flags (see the Generator
  table), not scanner behavior. For an ecosystem with no deterministic dev/test
  marker (for example a plain `requirements.txt`), `--include-dev` cannot change
  the inventory; Packmon emits a visible warning naming the detection so the user
  is not silently misled into thinking dev dependencies were toggled.

## Transparency Requirements

### Missing tool messaging

When a generator or base toolchain is absent, Packmon must name the ecosystem,
the missing executable, and the available remedies.

```text
$ packmon scan --auto-sbom ./myproject
-> detected: go (services/api/go.mod), npm (web/package.json)
x npm: generator "cyclonedx-npm" not found in PATH.
    Install manually:  npm install --global @cyclonedx/cyclonedx-npm@4.2.1
    Or automatically:  packmon scan --auto-sbom --install-tools ./myproject
```

Maven special case: `mvn` itself is the required base toolchain. Packmon cannot
auto-install it.

```text
x maven: "mvn" not found. Maven must be installed manually.
    Packmon cannot auto-install Maven.
```

### Install disclosure

Even when `--install-tools` is set, Packmon prints the package, source, and exact
command before installing. It never installs floating versions.

Initial design pins are npm `4.2.1`, Python `7.3.0`, Go `v1.10.0`, and Maven
plugin `2.9.1`. The implementation may revise these pins only by updating this
table, the code constants, and tests in the same change. Commands using
`@latest`, an unversioned Maven plugin, or an unqualified `pip install` are not
accepted.

| Ecosystem | Package/tool | Source | Install/invocation requirement |
|---|---|---|---|
| npm | `@cyclonedx/cyclonedx-npm` | npm registry | `npm install --global @cyclonedx/cyclonedx-npm@4.2.1` |
| pypi | `cyclonedx-bom` | PyPI | `python -m pip install --user cyclonedx-bom==7.3.0` |
| go | `cyclonedx-gomod` | Go module proxy | `go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0` |
| maven | CycloneDX Maven plugin | Maven Central | invoke `org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom` |

## Components

A new, isolated package: **`internal/sbomgen`**.

### Detector

The detector returns concrete generation targets, not just ecosystem names.
This is required for monorepos and nested projects.

```go
type Detection struct {
    Ecosystem    string // "go", "npm", "pypi", "maven"
    ProjectDir   string // directory where the generator must run
    ManifestPath string // exact manifest or lock file that caused detection
    InputKind    string // "go.mod", "npm-package", "requirements", "poetry", ...
    DisplayPath  string // sanitized relative path for messages
}
```

Detection uses a bounded walk with the same broad skip policy as the scanner:
skip `.git`, hidden directories except intentional scanner exceptions, vendor
directories, `node_modules`, and `__pycache__`.

| Ecosystem | Detected by | Project directory | Notes |
|---|---|---|---|
| go | `go.mod` | containing directory | one SBOM per module |
| npm | `package.json` | containing directory | workspace roots suppress child package manifests covered by that workspace |
| pypi | `requirements.txt` | containing directory | treated as runtime inventory because requirements files do not encode a universal dev marker |
| pypi | Poetry project (`pyproject.toml` with Poetry metadata, preferably with `poetry.lock`) | containing directory | use `cyclonedx-py poetry` |
| pypi | Pipenv project (`Pipfile`/`Pipfile.lock`) | containing directory | `cyclonedx-py pipenv`; deferred unless the implementation plan verifies the mode, like PDM/uv |
| maven | `pom.xml` | containing directory | aggregator/root poms suppress child module poms covered by the aggregate |

Bare `pyproject.toml` without a supported Python project mode is not an
auto-SBOM detection in v1. PDM and uv are explicitly deferred unless the
implementation plan adds a verified generator mode. Only `requirements.txt` is
detected for the requirements mode in v1; alternate names such as
`requirements-dev.txt` or `dev-requirements.txt` are intentionally out of scope
and recorded here as a known boundary.

Coverage suppression is computed from manifest contents, never guessed:

- npm workspace roots are identified by the `workspaces` field and suppress only
  the child `package.json` files matched by those globs. A child package outside
  the workspace globs remains its own detection.
- Maven aggregator/root poms are identified by `<modules>` and suppress only the
  child module poms they reach (recursively). A pom not reachable from any
  aggregator remains its own detection.

### Generator Interface

```go
type GenerateOptions struct {
    IncludeDev bool
    Timeout    time.Duration
}

type Generator interface {
    Ecosystem() string
    Tool() string
    InstallSpec() InstallSpec
    Generate(ctx context.Context, d Detection, outPath string, opts GenerateOptions) error
    // DeclaresDependencies reports whether the detection's manifest lists any
    // dependencies. Used by the required zero-package cross-check to tell a
    // genuinely empty project from a soft generator failure.
    DeclaresDependencies(d Detection) (bool, error)
}
```

One small adapter file per ecosystem (`go.go`, `npm.go`, `pypi.go`,
`maven.go`). A `Registry` maps ecosystem to generator. A new ecosystem is a new
adapter, not a rewrite.

Invocations are pinned and verified against real tool help during
implementation. The shape is:

| Eco | Tool | Invocation shape | Dev/test behavior |
|---|---|---|---|
| go | `cyclonedx-gomod` | `cyclonedx-gomod mod -json -output <out> <projectDir>` | add `-test` only when `--include-dev` is set |
| npm | `cyclonedx-npm` | `cyclonedx-npm --output-format JSON --output-file <out> <manifest>` | add `--omit dev` when `--include-dev` is false |
| pypi requirements | `cyclonedx-py` | `cyclonedx-py requirements --output-format JSON --output-file <out> <requirements.txt>` | requirements are treated as the selected inventory |
| pypi poetry | `cyclonedx-py` | `cyclonedx-py poetry --output-format JSON --output-file <out>` in `ProjectDir` | adapter must use a verified option set for main vs dev groups |
| maven | `mvn` | `mvn ... org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DoutputFormat=json -DoutputDirectory=<dir> -DoutputName=<name>` | set `-DincludeTestScope=true` only when `--include-dev` is set |

Maven output must be directed with `outputDirectory` and `outputName` instead of
assuming `target/bom.json`. The adapter then verifies the expected JSON file and
renames or copies it to `outPath` if needed.

### Generated SBOM Validation

Generated output is validated before being appended to `SBOMFiles`.
`sbom.IsCycloneDXJSON` alone is not sufficient because it only identifies the
format header.

Structural validation -- any failure is a hard abort (exit 2):

1. The generator process exited 0.
2. File exists and is non-empty.
3. `sbom.IsCycloneDXJSON(data)` is true.
4. `sbom.Parse` succeeds without error.

Package count is **not** a structural failure, but a zero-package result is
resolved by a **required** manifest cross-check (below), never by count alone --
a correct empty SBOM is otherwise indistinguishable from a soft failure (e.g. a
missing `npm install`).

Zero-package cross-check (v1, required):

- Each adapter reports whether its manifest declares any dependencies via
  `Generator.DeclaresDependencies(d)`: npm = non-empty
  `dependencies`/`devDependencies`/`optionalDependencies`/`peerDependencies`;
  Go = any `require`; Maven = any `<dependencies>` in the root or a covered
  module pom; requirements = any non-comment requirement line; Poetry = any
  dependency beyond `python`, or a non-empty `poetry.lock`.
- **Manifest declares dependencies, zero packages imported** -> hard abort
  (exit 2), naming the detection. This is the signature of a soft failure (a
  missing install or unresolved modules) and must never pass as "clean".
- **Manifest declares no dependencies, zero packages imported** -> genuinely
  dependency-free (or stdlib-only) project; that detection contributes zero
  packages and the run continues (exit 0). Failing this case would make
  legitimate projects unscannable -- itself a false negative on availability.
- In both cases the `sbom.Parse` skipped-component diagnostics are surfaced (as
  the existing `--sbom` path already does) so dropped/ versionless-PURL
  components remain visible.

### Orchestrator

The orchestrator must not delete temporary files before the scanner reads them.
It returns SBOM paths plus a cleanup callback owned by the CLI caller.

```go
type Result struct {
    SBOMPaths []string
    Cleanup   func() error
}

func Run(ctx context.Context, cfg Config) (Result, error)
```

Cleanup semantics: in temp mode `Cleanup` removes the entire temp directory. In
`--keep-sbom` mode `Cleanup` is a **no-op** -- kept SBOMs are an explicit
persistence opt-in and must never be deleted by the caller's `defer cleanup()`.
The caller always defers `Cleanup`; the mode, not the caller, decides whether
anything is removed.

Workflow:

1. Detect concrete `Detection` entries and apply `--ecosystems`.
2. For each detection, resolve the required tool via the `LookPath` seam
   (default `exec.LookPath`).
3. If missing, either install the pinned generator package when
   `--install-tools` is set, or fail with a hint.
4. Generate one SBOM per detection.
5. Validate each generated SBOM.
6. Return all paths and a cleanup callback. If generation fails, cleanup is run
   before returning the error.

File naming:

- Temp mode writes into one securely created temp directory (`os.MkdirTemp`);
  files are mode `0600`.
- `--keep-sbom` writes into the requested directory, creating it with mode
  `0700` when absent.
- Names are unique and non-overwriting:
  `sbom-<ecosystem>-<safe-relative-project-dir>-<short-hash>.cdx.json`.
- Existing files in `--keep-sbom` are never overwritten. Use `O_EXCL` or fail
  with a clear collision error.

The `exec` pattern mirrors `internal/feed/gitutil.go`: fixed binary names,
`exec.CommandContext`, `WaitDelay`, context cancellation, captured stderr,
`#nosec G204` with justification, and no shell (`sh -c`, `cmd /c`, or
PowerShell command strings).

Test seams: the orchestrator must not call `exec.LookPath` or build commands
directly against the OS, or the unit tests promised below (tool-missing,
install-uses-pinned-version, generator-fails) cannot run deterministically
without the real tools. The orchestrator takes two injectable seams on `Config`,
defaulting to the real implementations:

```go
type Config struct {
    // ... target, ecosystems, install/keep options ...
    LookPath func(name string) (string, error)         // default: exec.LookPath
    Runner   func(ctx context.Context, name string, args ...string) ([]byte, error) // default: real exec
}
```

The per-ecosystem adapters and the install path build argument arrays and run
them through `Runner`; tests inject a fake `Runner`/`LookPath` to assert exact
argv (pinned version, `--omit dev`, etc.) and to simulate missing tools and
non-zero exits with no real process.

Each generator invocation gets a context timeout. The implementation plan should
choose a default that is realistic for first-run Go/Maven dependency resolution
and expose it through config only if needed. Two minutes is a lower bound, not a
hard requirement.

## Data Flow

```text
packmon scan --auto-sbom [--install-tools] [--ecosystems ...] ./target
  -> cmd/packmon/scan.go resolves a single scan target
  -> sbomgen.Run(ctx, cfg)
       -> Detector.Detect(target)
       -> [go services/api/go.mod, npm web/package.json]
       -> per detection: resolve/install/generate/validate
     returns Result{SBOMPaths: [...], Cleanup: cleanup}
  -> defer cleanup() in cmd/packmon after scan/listing work is done
  -> settings.SBOMFiles = append(userSBOMs, generated...)
  -> scanner.CollectPackages(cfg)   [existing parse + merge + dedup + filters]
  -> scanner.Analyze(...)            [existing feeds, findings, block logic]
  -> output: table / --html / JSON / SARIF / JUnit
```

In `--sbom-only`, the flow stops after generation and validation. It prints the
generated SBOM paths and never opens the local advisory DB, contacts the server,
writes scan history, posts webhooks, or renders scan-result outputs.

Cross-platform behavior:

- One Go codebase cross-compiled for Windows/Linux/macOS.
- `exec.LookPath` resolves `.cmd`/`.exe` wrappers on Windows via `PATHEXT`.
- Paths go through `filepath`, `os.MkdirTemp`, and `os.OpenFile`; no hard-coded
  `/tmp`, shell quoting, or platform-specific command strings.

## Error Handling

Guiding principle: **a security scanner must never falsely report "clean."** A
hard failure is preferred over a silent partial scan.

| Situation | Behavior | Exit |
|---|---|---|
| `--auto-sbom` used with unsupported scan mode (`--all`, `--list-packages`, `--outdated`, `--list-all`) | Operational error naming the incompatible flags | 2 |
| `--auto-sbom` with more than one positional target | Operational error: auto-SBOM needs exactly one target | 2 |
| `--install-tools`, `--keep-sbom`, or `--sbom-only` without `--auto-sbom` | Operational error | 2 |
| No supported detection after filtering | Error listing searched manifest types | 2 |
| Tool missing, no `--install-tools` | Hint with manual and auto-install command | 2 |
| Tool missing, Maven base toolchain | Honest hint: Maven must be installed manually | 2 |
| Install fails | stderr captured, wrapped, names ecosystem and package | 2 |
| Generator fails | stderr captured, names detection, hard abort and no scan | 2 |
| Generated SBOM structurally invalid (non-zero exit, empty file, unparseable) | validation error, hard abort and no scan | 2 |
| Generator exits 0, manifest declares deps, zero packages imported | hard abort: likely soft failure (e.g. missing install), names the detection | 2 |
| Generator exits 0, manifest declares no deps, zero packages | genuinely dependency-free; detection contributes 0, scan continues | 0 |
| Multiple detections, one fails | whole run fails; no partial scan | 2 |
| `--sbom-only` succeeds | print generated paths unless quiet | 0 |

Optional `--best-effort` could be added later. It is not in v1.

Logging discipline:

- Persistent logs must not contain full local paths. User-facing CLI stderr may
  show sanitized relative paths and basenames.
- Generator stderr is captured for diagnostics and wrapped; it is not dumped raw
  into structured logs.
- `WaitDelay` plus context cancellation prevents hanging subprocesses.

## Testing

Follows the existing repo pattern: pure unit tests by default; tool-dependent
tests skip when unavailable.

Coverage target: package `internal/sbomgen` must reach **>= 90% line coverage**
with `go test -coverprofile`, measured in a tool-less environment (CI without the
real generators installed). This is only reachable because the orchestrator,
detector, registry, `InstallSpec`, and adapters all run their command building
through the injectable `Runner`/`LookPath` seams -- so a fake `Runner` exercises
the adapter argv-construction and error handling without the real binaries. The
only lines legitimately uncovered in a tool-less run are the trivial default
seam bodies (`return exec.LookPath(name)` and the real `exec.CommandContext`
wrapper); these are kept to a handful of lines so the package still clears 90%,
and they are exercised by the skipped-when-missing integration tests when the
tools are present. If keeping them in-package threatens the threshold, move the
default seam wrappers into a tiny separate file/package excluded from the target.
Adapters with post-run file handling (Maven's verify-and-copy from
`outputDirectory`) are unit-tested by staging the expected generator output file
before invoking the adapter with a fake `Runner`, so that path is covered without
a real `mvn`.

Unit tests:

- `Detector`
  - single manifests for each supported ecosystem
  - monorepo with multiple independent project dirs
  - npm workspace root suppresses covered child package manifests
  - Maven aggregate root suppresses covered child module poms
  - unsupported bare `pyproject.toml` is not detected
  - skip `node_modules`, `vendor`, `.git`, hidden dirs, and `__pycache__`
  - depth limiting and ecosystem filter behavior
- `Orchestrator` (via fake `Runner`/`LookPath`)
  - tool missing with and without `--install-tools`
  - install command uses the pinned version and a fixed argv (no shell)
  - generator exits non-zero -> hard abort and cleanup
  - structural validation rejects malformed, empty, and unparseable output
  - zero-package cross-check: manifest declares deps + 0 imported -> hard abort
    (exit 2); manifest declares no deps + 0 imported -> exit 0, scan continues
  - `DeclaresDependencies` is correct per ecosystem for empty vs non-empty
    manifests
  - temp dir deleted only after caller invokes cleanup
  - `--keep-sbom` keeps files, uses unique names, never overwrites, and its
    `Cleanup` is a no-op (kept files survive `defer cleanup()`)
  - `--sbom-only` returns generated paths and performs no scan callback
  - `--include-dev` changes generator argv in both normal and `--sbom-only`
    modes; for a no-dev-marker ecosystem it emits the visible warning
- CLI wiring in `cmd/packmon`
  - new flags parse and incompatible combinations fail
  - rejects more than one positional target, `--all`, and the early-exit modes
    (`--list-packages`, `--outdated`, `--list-all`) with `--auto-sbom`
  - `--install-tools`, `--keep-sbom`, `--sbom-only` without `--auto-sbom` error
  - `--auto-sbom` appends generated paths before `runScanPipeline`
  - cleanup happens after the scanner has consumed the generated files
  - `--sbom-only` does not open the local DB, contact remote mode, write history,
    post webhooks, or write scan-result outputs
- `InstallSpec`/Registry
  - package names, sources, command strings, and pinned-version requirements are
    correct
- Logging
  - no full paths in structured logs

Integration tests:

- One skipped-when-missing test per real generator against a minimal fixture.
  Fixtures intentionally declare dependencies so the cross-check expects >= 1
  imported package; a separate fixture with an empty manifest asserts the
  dependency-free exit-0 path.
- Assert generated CycloneDX JSON is valid and Packmon imports at least one
  supported package.
- Primary CI E2E path can use `cyclonedx-gomod` because it is a Go tool and is
  easiest to install in CI.

E2E smoke:

- `packmon scan --auto-sbom ./fixture --html report.html` produces an HTML
  report containing packages from the generated SBOM.
- `packmon scan --auto-sbom --sbom-only --keep-sbom out ./fixture` produces
  files and performs no server/local advisory DB contact.

Cross-platform:

- Exercise `LookPath` with `.cmd`/`.exe` wrappers on Windows where possible.
- Verify path-safe filenames on Windows and Linux.

## Security Notes

- Default is no install and no extra network from Packmon itself. Generating an
  SBOM may cause the project's own toolchain to contact package registries
  (`go`, `npm`, `mvn`, Python tooling). This must be documented because the CLI
  otherwise deliberately speaks only to the Packmon server for advisory data.
- `--install-tools` runs third-party package installation commands that may run
  install scripts. It is off by default and disclosed before execution.
- Install commands are fixed argument arrays, never shell strings.
- Generated SBOM files may contain package inventory and project metadata. Temp
  files are private (`0600` inside a `0700` temp directory) and deleted after the
  scan. `--keep-sbom` is the explicit persistence opt-in.
- CLI-only; the server gains no endpoint, storage, or execution path.

## Blast Radius

- New package `internal/sbomgen`.
- Scoped wiring in `cmd/packmon/scan.go` for flags, compatibility checks,
  calling the orchestrator, appending `SBOMFiles`, `--sbom-only`, and cleanup.
- No `domain.ScanResult` or server changes.
- No output renderer changes.
- Documentation updates are required in `DESIGN.md`, `SECURITY.md`, and
  `README.md` because this changes CLI behavior, toolchain network behavior, and
  persistent generated SBOM handling.
