# n8n Workflows

The example workflows in this directory are disabled by default and expect environment variables to be injected by n8n.

Recommended variables:

- `PACKMON_SERVER`
- `PACKMON_API_KEY`
- `PACKMON_SCAN_PATH`
- `PACKMON_METRICS_URL` for the weekly maintenance metrics request
- `PACKMON_FEED_IMPORT_SECRET` when a workflow calls Packmon feed import endpoints

The templates pass Packmon credentials through process environment variables.
Do not add `--api-key` to Execute Command nodes; command-line arguments can be
visible to process listings and workflow execution logs.
Keep command inputs as quoted runtime environment variables, not raw n8n
`{{$env...}}` shell substitutions.
Feed import HTTP calls must send both `Authorization: Bearer <PACKMON_API_KEY>`
and `X-Packmon-Feed-Import-Secret: <PACKMON_FEED_IMPORT_SECRET>` in production.

The on-demand scan workflow requires n8n Header Auth on the webhook before the
Execute Command node can run. Create a Header Auth credential for the Webhook
node, for example with header name `X-Packmon-N8N-Secret`, and keep the secret in
n8n credentials or an external secret store. The scan command runs with
`--mode remote --require-remote --server "$PACKMON_SERVER"` and uses
`PACKMON_API_KEY` from the process environment, so a missing server or API key
fails the workflow instead of falling back to local mode.

The weekly maintenance workflow reads metrics from `PACKMON_METRICS_URL`. Set it
to an endpoint reachable from the n8n runtime, such as a node-local listener,
sidecar, tunnel, or private service. Packmon metrics still bind to localhost by
default; do not expose the metrics listener to untrusted networks just to satisfy
this workflow.

The workflows are templates, not fully opinionated production flows. Adjust commands, credentials, and notification nodes for your environment.

The on-demand scan template intentionally ignores request-body path values. Set
`PACKMON_SCAN_PATH` in the n8n runtime environment or add your own allowlisted
path-selection node before re-enabling the workflow.
The shipped workflows do not write scan or export artifacts to `/tmp`. Do not
add fixed `/tmp/packmon-*.json` filenames or echo `PACKMON_SCAN_PATH` back to
webhook callers.
