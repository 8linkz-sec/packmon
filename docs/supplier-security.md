# Supplier Security Assessment

This assessment tracks Packmon's direct external feed, enrichment, and tooling
providers. Review cadence is quarterly and whenever a provider, data exchange,
or deployment mode changes.

| Provider | Data exchanged | Security dependency | Current controls |
|---|---|---|---|
| OSV | Vulnerability archives and advisory metadata downloaded by ecosystem. | Missing or poisoned OSV data can affect vulnerability coverage. | Source attribution, parser validation, feed health, and local server-mediated sync. |
| GHSA | Git advisory data and aliases. | Git source integrity and availability affect advisory coverage. | Fixed-argv git use, repository confinement, source attribution, and health status. |
| OpenSSF | Malicious package advisories from a git feed. | Feed compromise can affect malware blocking decisions. | Path confinement, source-scoped import, tombstone pruning, and fail-closed malware semantics. |
| CISA KEV | Known-exploited CVE catalog. | Stale KEV enrichment can understate exploitation priority. | Conditional HTTP validators, bounded parser, and feed health reporting. |
| EPSS | CVE probability CSV. | Stale EPSS enrichment can affect prioritization. | Conditional HTTP validators, bounded streaming parser, and full replacement semantics. |
| NVD | CVSS enrichment lookups. | NVD outage or missing scores can delay severity enrichment. | Bounded HTTP client, rate limiting, retry handling, and non-fatal enrichment behavior. |
| endoflife.date | Lifecycle product and release metadata. | Incorrect lifecycle data can affect supply-chain risk findings. | Self-mode only, cached data preservation on upstream failure, and source attribution. |
| VulnCheck | Optional backup/enrichment data. | Provider availability and API key handling affect enrichment freshness. | Disabled by default, API keys kept in secrets, permanent auth failures, digest verification, and feed health. |
| Socket.dev | Optional package reputation lookups. | Provider responses can create supply-chain-risk findings. | Disabled by default, async queueing, rate limits, and no direct local client calls. |
| ReversingLabs | Optional package reputation lookups. | Provider responses can create malware or supply-chain-risk findings. | Disabled by default, self-mode only, strict PURL predicate, API-key handling, batch caps, and terminal unsupported rows. |
| CycloneDX tooling | Optional third-party generators installed only when requested. | Generator compromise could affect local SBOM generation. | Operator opt-in, documented tooling requirements, and no implicit public-service dependency. |

## Review cadence

- Quarterly: confirm provider list, data exchanged, and security dependency.
- Provider changes: update this file and `DESIGN.md`/`SECURITY.md` in the same
  change when a new feed, mirror, or external tooling path is added.
- Incident follow-up: record any provider outage, compromise, or trust-boundary
  change that affects Packmon scan decisions.
