# ADR-0037: Web UI Stack

## Status

Accepted

## Decision

Packmon's web UI uses Go `html/template`, htmx, Tailwind CSS v4, local static
assets, and embedded templates/assets served from the binary.

## Rationale

- The UI is an internal operational interface, so server-rendered pages and
  progressive enhancement are sufficient.
- Local assets support internal/offline deployments and a restrictive CSP.
- Avoiding runtime CDN dependencies keeps deployment and security review small.
- Tailwind and htmx provide enough UI velocity without a full SPA runtime.

## Consequences

- Admin interactivity belongs in local JavaScript and CSS assets.
- Template and Tailwind source changes must refresh generated web assets.
- Adding a SPA framework, runtime CDN dependency, or inline script/style model
  is an architecture and security change.
