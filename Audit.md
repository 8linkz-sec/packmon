# Packmon Audit Report (Closure Update)

**Date:** 2026-04-06
**Scope:** Independent re-check of all findings documented in the previous `Audit.md`
**Result:** All actionable security, bug, consistency, Helm, and CI findings from this audit pass were addressed in code. Remaining gaps are informational test-depth items only.

---

## Executive Summary

The findings from the previous audit document were re-validated against the current repository and then worked off directly in the codebase, CI, and Helm chart.

There are no open `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` findings left from that list.

The only remaining open point is `TEST-INFO`: overall automated test depth is still below the long-term target, and E2E / golden / CI integration coverage can still be expanded. That is a quality follow-up, not a product bug or release blocker.

---

## Status Summary

| Severity | Open | Closed in this pass | Notes |
|----------|------|---------------------|-------|
| CRITICAL | 0 | 0 | No critical findings in this audit pass |
| HIGH | 0 | 0 | No high findings in this audit pass |
| MEDIUM | 0 | 6 | All medium findings below were fixed |
| LOW | 0 | 8 | All low findings below were fixed or operationally mitigated |
| INFO | 1 | 0 | Test-depth and coverage follow-up remains |

---

## Closed Security Findings

- `SEC-M1` fixed in `internal/feed/nvd/syncer.go`.
  NVD CVE requests now build the query string via `net/url` instead of string concatenation.
  Verified by `TestFetchCVSS_EncodesCVEQuery` in `internal/feed/nvd/syncer_test.go`.

- `SEC-M2` fixed in `internal/feed/nvd/syncer.go`.
  Typed rate-limit handling was added for HTTP `429` / `403`, including `Retry-After` parsing and bounded retry logic.
  Verified by `TestSync_RetriesRateLimitedCVE` in `internal/feed/nvd/syncer_test.go`.

- `SEC-M3` fixed in `internal/server/middleware/securityheaders.go`.
  The middleware now sets a restrictive `Content-Security-Policy` in addition to the existing browser hardening headers.
  Verified by `internal/server/middleware/securityheaders_test.go`.

- `SEC-L1` fixed in `internal/server/middleware/securityheaders.go`, `internal/server/server.go`, `internal/config/config.go`, `cmd/packmon-server/main.go`, and the Helm chart.
  HTTPS redirects no longer trust arbitrary request hosts. Production deployments can set `PACKMON_SERVER_PUBLIC_HOST`; otherwise redirects fall back to loopback-only behavior.
  This closes the Host-header injection issue while keeping local development usable.

- `SEC-L2` operationally mitigated and documented in `cmd/packmon-server/main.go` and `deploy/helm/packmon/values.yaml`.
  The metrics endpoint remains intentionally unauthenticated for Prometheus-style scraping, but the runtime now warns when metrics bind to a non-localhost address and the Helm values explicitly document that the metrics port must not be exposed to untrusted networks.
  The original risk of accidental exposure is addressed.

---

## Closed Bugs and Code Quality Findings

- `BUG-M1` fixed in `internal/version/compare.go`.
  Open-ended OSV ranges with `introduced: "0"` no longer produce false negatives.
  Verified by `TestVersionAffected_FullOSV_OpenEndedZeroIntroduced` in `internal/version/compare_test.go`.

- `CQ-L1` fixed in `internal/feed/nvd/syncer.go`.
  The unused `cveEntry` dead-code struct was removed.

- `CQ-L2` fixed in `internal/feed/nvd/syncer.go`.
  The old retry comment no longer contradicted the actual behavior because the real retry logic now exists.

- `CQ-L3` fixed in `internal/db/sqlite/web.go`.
  SQLite dashboard severity counts now match PostgreSQL behavior and count only vulnerability severities.
  Verified by `internal/db/sqlite/web_test.go`.

- `TEST-L1` fixed in `internal/scanner/scanner_test.go`.
  `t.Fatalf` was removed from the `httptest` handler goroutine and replaced with a safe error-channel assertion pattern.

---

## Closed Infrastructure and CI Findings

- `INFRA-M1` fixed in `deploy/helm/packmon/templates/postgres-statefulset.yaml`.
  PostgreSQL now has readiness and liveness probes using `pg_isready`.

- `INFRA-M2` fixed in `.github/workflows/ci.yml`.
  `golangci-lint` now uses a pinned tool version instead of `latest`.

- `INFRA-L1` fixed in `deploy/helm/packmon/templates/postgres-statefulset.yaml`.
  `PGDATA` now points to a subdirectory, which avoids `lost+found` / volume-root initialization issues on CSI-backed storage.

- `INFRA-L2` fixed in `.github/workflows/nightly.yml`.
  The nightly fuzz job no longer hides crashes behind `continue-on-error: true`.

---

## Remaining Informational Follow-Up

- `TEST-INFO` remains open as an information-level quality item.
  Current automated coverage is still well below the long-term `80%` target, E2E tests are still a placeholder, golden tests are still missing, and integration tests are not yet part of CI.

This is intentionally tracked as follow-up work, not as an open correctness or security defect.

---

## Verification Performed

The fixes above were independently re-checked against the repository and validated with:

- `go test ./...`
- `go vet ./...`
- `go test ./... -race`
- `helm template packmon deploy/helm/packmon --set postgresql.password=test-password --set admin.initialPassword=test-admin --set server.publicHost=packmon.example.com`

In addition, the NVD syncer, version matching, SQLite dashboard stats, scanner test safety, and security-header behavior were covered by targeted unit tests in the touched packages.

---

## Conclusion

The previous audit file is now closed from a code-fix perspective.

What remains is test-depth expansion, not an unresolved product bug from the audited findings.
