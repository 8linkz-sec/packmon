# n8n Workflows

The example workflows in this directory are disabled by default and expect environment variables to be injected by n8n.

Recommended variables:

- `PACKMON_SERVER`
- `PACKMON_API_KEY`
- `PACKMON_SCAN_PATH`

The workflows are templates, not fully opinionated production flows. Adjust commands, credentials, and notification nodes for your environment.

The on-demand scan template intentionally ignores request-body path values. Set
`PACKMON_SCAN_PATH` in the n8n runtime environment or add your own allowlisted
path-selection node before re-enabling the workflow.
