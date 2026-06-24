# List-All Technology Tags Design

## Scope

Add report-only technology tags to `packmon scan --list-all` so operators can
see selected frameworks/platforms derived from already parsed package
coordinates.

This first increment covers only:

- `angular` for npm packages named `@angular/*`, `angular`, or `angular-*`.
- `java` for packages whose ecosystem is `maven`.

The feature does not add SAST, source-code scanning, runtime host inventory, new
security findings, or new scan-blocking behavior.

## User-Facing Behavior

`--list-all` terminal output and list-all HTML gain a `Technology` column.

Rows without a recognized technology show `-`.
Rows with one or more recognized technologies show a comma-separated list using
stable lowercase tags, for example:

- `java`
- `angular`

For this first increment, npm packages that are not Angular packages do not get
a generic `js` tag. The user explicitly limited the quick win to Angular and
Java only.

## Detection Rules

Technology detection is deterministic and uses only package metadata already in
the scan inventory.

Angular:

- Applies only to `ecosystem == npm`.
- Match package names exactly equal to `angular`.
- Match package names with prefix `angular-`.
- Match package names with prefix `@angular/`.

Java:

- Applies to `ecosystem == maven`.
- This includes dependencies parsed from both Maven `pom.xml` and Gradle
  lockfiles, because Gradle dependencies are normalized to the Maven ecosystem
  in Packmon.

Detection is case-insensitive for matching but emits canonical lowercase tags.
Duplicate tags on one package row are removed and sorted in a stable order.

## Architecture

Keep technology detection inside the list-all reporting layer. Do not add a
`Technology` field to `domain.Package`, `ScanResult`, API contracts, SBOM
parsing, SARIF, JUnit, or webhook payloads in this increment.

Suggested implementation shape:

- Add a small helper in `cmd/packmon/list_all.go`, such as
  `listAllPackageTechnologies`.
- Extend `listAllRow` and `listAllHTMLPackageRow` with a `Technology` string.
- Populate the field while building the list-all package report.
- Render the column in terminal and HTML package tables.
- Include technology in the rows used by `Packages Needing Attention` and
  `All Packages`.

## Error Handling

Technology detection must never fail a scan. Unknown ecosystems or package
names simply produce no tag.

Malformed input handling remains owned by the existing parsers and scanner
pipeline.

## Tests

Add focused tests for:

- npm `@angular/core` produces `angular`.
- npm `angular` and `angular-*` produce `angular`.
- non-Angular npm packages do not produce a technology tag in this increment.
- Maven and Gradle-derived Maven rows produce `java`.
- terminal list-all output includes the `TECHNOLOGY` column.
- list-all HTML includes the `Technology` column and renders expected tags.

Existing scan-result JSON, SARIF, and JUnit tests should remain unchanged
unless they depend on generated list-all HTML structure.

## Non-Goals

- No `.java`, `.js`, `.ts`, Angular template, or source-code vulnerability
  scanning.
- No JDK, application-server, or host-runtime inventory.
- No `tomcat`, `gpt`, or generic `js` detection in this first increment.
- No new ecosystem identifiers such as `java`, `angular`, or `tomcat`.
- No security severity, blocking, or policy changes.
