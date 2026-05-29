# Agent Guide -- Web UI (templates, htmx, Tailwind)

Scope: `internal/web/` -- dashboard/search/package/scans/feeds handlers, the
embedded Go HTML templates under `templates/` (incl. `admin/`), and static
assets under `static/`. Primary owner agent: **frontend-engineer**; pair with
**ui-ux-designer** for IA/flows and backend-engineer for the handler data shape.

Read `AGENTS.md` (root) first.

## Invariants (do not break)

- Tech stack is Go templates + htmx + Tailwind, all embedded via `embed` into the
  binary. There is no separate frontend build step.
- Web UI assets are served LOCALLY from the repo/binary. Do not add CDN runtime
  dependencies (a recent change vendored Tailwind/htmx locally and added a CSP
  scoped to self-hosted assets -- keep it that way).
- The admin login form must stay Bitwarden/Vaultwarden compatible: clean HTML
  semantics, `autocomplete="username"` / `autocomplete="current-password"`, no
  JS tricks that block autofill, and a stable `/admin/login` URL.
- Every admin form posts a `_csrf` hidden field that the handler validates.
- Templates must reflect backend reality: the option sets they render (e.g.
  advisory `finding_type` vulnerability|malicious, severity values) must match
  what the handler accepts and validates.

## Notes

- New admin pages added recently: `queue.html`, `settings.html`, expanded
  `advisories.html`. Keep the handler/template contract in sync when editing.
- The HTML `<select>` only constrains the browser; the server must validate too
  (see Audit.md M4). Do not rely on the template as the validation boundary.

## Tests

```bash
go test ./internal/web/...
```
Render tests should assert that template-offered values match the handler's
accepted set.
