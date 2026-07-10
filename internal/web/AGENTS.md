# Agent Guide -- Web UI (templates, htmx, Tailwind)

Scope: `internal/web/` -- dashboard/search/package/scans/feeds handlers, the
embedded Go HTML templates under `templates/` (incl. `admin/`), and static
assets under `static/`. Primary owner agent: **frontend-engineer**; pair with
**ui-ux-designer** for IA/flows and backend-engineer for the handler data shape.

Read `AGENTS.md` (root) first.

## Invariants (do not break)

- Tech stack is Go templates + htmx + Tailwind, all embedded via `embed` into the
  binary. Runtime serving has no external frontend service, but generated assets
  are refreshed through the root npm build.
- Web UI assets are served LOCALLY from the repo/binary. Do not add CDN runtime
  dependencies (a recent change vendored Tailwind/htmx locally and added a CSP
  scoped to self-hosted assets -- keep it that way).
- After changing templates, Tailwind class strings, `tailwind.input.css`,
  `package.json`, `package-lock.json`, or htmx assets, run
  `npm ci --ignore-scripts && npm run build:web` from the repository root with
  Node.js 20+ and commit the resulting files under `internal/web/static`.
- There is no `tailwind.config.js`. Design tokens and layout tokens live in the
  `@theme` block of `tailwind.input.css`; dark mode overrides those variables
  under `[data-pm-theme="dark"]`. Never write a raw palette class such as
  `bg-gray-50` in a template or in Go -- `design_tokens_test.go` fails on it,
  and it would stay light in dark mode.
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
- The HTML `<select>` only constrains the browser; the server must validate too.
  Do not rely on the template as the validation boundary.

## Tests

```bash
go test -count=1 ./internal/web/...
```
Render tests should assert that template-offered values match the handler's
accepted set.
