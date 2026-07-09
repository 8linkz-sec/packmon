# Packmon Requirements

Packmon keeps source-checkout runtime, SBOM, server, and developer
prerequisites in `requirements/packmon-tools.tsv`. The helper scripts read that
file and support the same profiles on Windows, Linux, and macOS.

Release-binary users do not need this file or the helper scripts. A normal
Windows user can run `.\packmon.exe scan --list-all --html packmon-report.html
--output-json packmon-report.json .` directly from the target project
directory.

## Profiles

| Profile | Use it for | Includes |
|---|---|---|
| `full` | Normal Packmon use with native lockfile and existing-SBOM scanning. | The Packmon binary only: Windows EXE, Linux ELF, or macOS Mach-O |
| `agent` | Build Packmon from source. | Go |
| `sbom` | Optional `--auto-sbom` generation for targets that need external CycloneDX generators. | Only tools required by the detected target manifests when `--target` / `-Target` is used |
| `web` | Refresh embedded Tailwind and htmx assets. | Node.js and npm |
| `server` | Run the local Docker/PostgreSQL server stack. | Docker with Compose v2 |
| `dev` | Develop Packmon and run the release-facing verification gate. | `agent`, `web`, `server`, SBOM generators, `gofumpt`, `golangci-lint`, `govulncheck`, and `gosec` |

When you are working from a source checkout, use `full` only to verify that a
Packmon runtime binary is available. The `full` profile intentionally does not
require Go, Node.js, Python, JDK/Maven, Docker, or Go lint/security tools.
Packmon's released binaries contain the native parsers and report writers that
Packmon itself owns.

Use `sbom` only when you want Packmon to generate CycloneDX SBOMs with
`--auto-sbom`. Even then, pass a target path so the scripts check only the
ecosystem tools used by that repository.

## Normal User Full Scan

Install or build a Packmon runtime binary for your platform:

- Windows: `packmon.exe`
- Linux: Packmon ELF binary
- macOS: Packmon Mach-O binary

In a source checkout, check the runtime:

Windows:

```powershell
.\scripts\check-requirements.ps1 -Profile full
```

Linux/macOS:

```bash
bash scripts/check-requirements.sh --profile full
```

Run a native full report without installing language toolchains:

```bash
./packmon scan --list-all --html packmon-report.html --output-json packmon-report.json .
```

```powershell
.\packmon.exe scan --list-all --html packmon-report.html --output-json packmon-report.json .
```

That scan reads Packmon-supported lockfiles and existing SBOMs directly. It
does not require Maven, Node.js, Python, Go, or Docker unless the target
workflow specifically asks Packmon to generate new SBOMs or run the server
stack.

## Optional Auto-SBOM Requirements

When `--auto-sbom` is needed, check only the selected target:

Windows:

```powershell
.\scripts\check-requirements.ps1 -Profile sbom -Target .
.\scripts\bootstrap.ps1 -Profile sbom -Target .
```

Linux/macOS:

```bash
bash scripts/check-requirements.sh --profile sbom --target .
bash scripts/bootstrap.sh --profile sbom --target .
```

Target-aware SBOM checks currently map:

| Detected files | Checked tools |
|---|---|
| `go.mod` | Go toolchain (`go list`) |
| `package.json` | Node.js, npm, and `cyclonedx-npm` |
| `requirements.txt`, `pyproject.toml` | Python and `cyclonedx-py` |
| `pom.xml` | Maven 3.9.9 or newer through `mvn`, running on JDK 17 or newer |

Existing npm and Poetry lockfiles are used by their matching generators when a
supported project manifest is present. Gradle, Yarn, pnpm, and Pipenv lockfiles
are scanned natively by Packmon. They are not currently `--auto-sbom` generator
targets.

After the needed SBOM tools are present:

```bash
packmon scan --auto-sbom --install-tools --list-all --html packmon-report.html --output-json packmon-report.json .
```

```powershell
packmon scan --auto-sbom --install-tools --list-all --html packmon-report.html --output-json packmon-report.json .
```

Maven remains a base requirement for Maven SBOM generation: `--install-tools`
can use the pinned CycloneDX Maven plugin, but it cannot install the JDK or
`mvn` itself. The requirements preflight parses `mvn --version` and requires
Maven 3.9.9 or newer plus the Maven runtime's JDK 17 or newer.

Go auto-SBOM generation uses the Go toolchain directly through `go list`.
`cyclonedx-gomod` is retained only for release SBOM generation, where the
release workflow publishes the repository-level Go SBOM artifact.

## Build From Source

Use `agent` only when you want to build Packmon yourself.

Windows:

```powershell
.\scripts\check-requirements.ps1 -Profile agent
.\scripts\install.ps1
```

Linux/macOS:

```bash
bash scripts/check-requirements.sh --profile agent
./scripts/install.sh
```

For direct builds without installing to `~/.packmon/bin`:

```bash
mkdir -p .build
go build -o .build/packmon ./cmd/packmon
go build -o .build/packmon-server ./cmd/packmon-server
```

```powershell
New-Item -ItemType Directory -Force .build | Out-Null
go build -o .build\packmon.exe .\cmd\packmon
go build -o .build\packmon-server.exe .\cmd\packmon-server
```

## Server And Developer Setup

Use `server` for the local Docker stack:

```powershell
.\scripts\check-requirements.ps1 -Profile server
```

```bash
bash scripts/check-requirements.sh --profile server
```

Use `dev` before running the full local verification gate from `README.md`:

```powershell
.\scripts\bootstrap.ps1 -Profile dev
```

```bash
bash scripts/bootstrap.sh --profile dev
```

Bootstrap installs these managed developer/SBOM tools when their base runtime
is already available:

| Tool | Install source |
|---|---|
| `cyclonedx-gomod` | `go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0` |
| `cyclonedx-npm` | `npm install --global --ignore-scripts @cyclonedx/cyclonedx-npm@5.0.0` |
| `cyclonedx-py` | `python -m pip install --user cyclonedx-bom==7.3.0` |
| `go-licenses` | `go install github.com/google/go-licenses@v1.6.0` |
| `gofumpt` | `go install mvdan.cc/gofumpt@v0.9.2` |
| `golangci-lint` | `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.0` |
| `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@v1.4.0` |
| `gosec` | `go install github.com/securego/gosec/v2/cmd/gosec@v2.27.1` |

For managed tools, the versions in `requirements/packmon-tools.tsv` are
authoritative pins: check-requirements rejects stale managed tool versions, and
bootstrap upgrades stale managed tools to the pinned versions before running the
final requirement check.

The bootstrap scripts do not install OS-level runtimes such as Go, Node.js,
Python, JDK/Maven, or Docker. Those installs are platform-specific and often
need admin permissions.
