# ADR-0032: Logging Rules

## Status

Accepted

## Decision

Persistent server logs must avoid filesystem paths, file contents, secrets, API keys, and passwords.

## Rationale

- path leakage is unnecessary for normal operations
- secrets and raw file data are high-risk in centralized logs

## Consequences

- feed parsers log file names instead of full paths where practical
- sensitive debugging belongs in local-only workflows, not production logs
