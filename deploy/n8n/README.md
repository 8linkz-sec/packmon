# n8n Workflows

The example workflows in this directory are disabled by default. They are
operator-supplied starting points, not a Packmon-managed n8n service.

## Supported command runtime

`daily-sync.json` and `on-demand-scan.json` use Execute Command because they
run the local Packmon CLI. n8n 2.x disables that node by default. The supported
self-hosted runtime contract is stored in `command-runtime.json` and currently
pins:

```text
docker.io/n8nio/n8n:2.46.6@sha256:8602f5dfacbe2c931eeafd010de0e68182310e9f309921e780ab69182e92b3ae
NODES_EXCLUDE=["n8n-nodes-base.localFileTrigger"]
N8N_BLOCK_ENV_ACCESS_IN_NODE=true
```

Apply both environment settings to every n8n main, worker, and webhook process
that loads or executes these workflows. The exclusion list deliberately removes
only Execute Command from n8n 2.x's two default exclusions; Local File Trigger
stays disabled. `NODES_EXCLUDE=[]` is not supported. n8n Cloud does not provide
Execute Command. When upgrading n8n, update the reviewed image in
`command-runtime.json` and rerun the static and Docker runtime contract tests
before activation.

Enabling Execute Command gives a workflow author arbitrary shell execution as
the n8n operating-system user. Use a dedicated non-root n8n instance and workers
whose editors and workflow importers are fully trusted. Do not mount the Docker
socket, host root, or unrelated secrets. Mount the Packmon binary, helper, and
scan inputs read-only; provide only a dedicated writable n8n state/database area;
and restrict egress to required internal destinations. Keep the templates
disabled until the runtime, mounts, credentials, and network policy have been
reviewed.

`N8N_BLOCK_ENV_ACCESS_IN_NODE=true` blocks environment access from n8n
expressions and Code nodes. It does not remove variables inherited by a child
process launched through Execute Command. Anyone allowed to edit or import a
command workflow must therefore be trusted with every environment value and
file visible to its executor.

## Workflow variables

The command templates expect their required environment variables to be
injected by n8n. The weekly metrics template does not read process environment
variables.

Recommended variables:

- `PACKMON_SERVER`
- `PACKMON_API_KEY`
- `PACKMON_SCAN_PATH`
- `PACKMON_FEED_IMPORT_SECRET` when a workflow calls Packmon feed import endpoints

The command templates pass Packmon credentials through process environment
variables.
Do not add `--api-key` to Execute Command nodes; command-line arguments can be
visible to process listings and workflow execution logs.
Keep command inputs as quoted runtime environment variables, not raw n8n
`{{$env...}}` shell substitutions.
Feed import HTTP calls must send both `Authorization: Bearer <PACKMON_API_KEY>`
and `X-Packmon-Feed-Import-Secret: <PACKMON_FEED_IMPORT_SECRET>` in production.

Mount or install `deploy/n8n/on-demand-scan.sh` into the n8n runtime at
`/opt/packmon/n8n/on-demand-scan.sh`. The workflow runs it with
`sh /opt/packmon/n8n/on-demand-scan.sh`, so the file must be readable by the
n8n process and the `packmon` binary must be on `PATH`.

The on-demand scan workflow requires n8n Header Auth on the webhook before the
Execute Command node can run. Create a Header Auth credential for the Webhook
node, for example with header name `X-Packmon-N8N-Secret`, and keep the secret in
n8n credentials or an external secret store. The helper runs `packmon scan` with
`--mode remote --require-remote --server "$PACKMON_SERVER"` and uses
`PACKMON_API_KEY` from the process environment, so a missing server or API key
fails the workflow instead of falling back to local mode.

Before enabling the weekly maintenance workflow, edit its
`Configure Metrics URL` node and replace the empty `metricsUrl` string with an
endpoint reachable from the n8n runtime, such as a node-local listener, sidecar,
tunnel, or private service. The HTTP Request node reads only that workflow-local
field; it does not require environment access, and an empty value fails the
execution. Keep `N8N_BLOCK_ENV_ACCESS_IN_NODE=true`. Packmon metrics still bind
to localhost by default; do not expose the metrics listener to untrusted
networks just to satisfy this workflow.

The workflows are templates, not fully opinionated production flows. Adjust commands, credentials, and notification nodes for your environment.

The on-demand scan template intentionally ignores request-body path values. Set
`PACKMON_SCAN_PATH` in the n8n runtime environment or add your own allowlisted
path-selection node before re-enabling the workflow.
The shipped workflows do not write scan or export artifacts to `/tmp`. Do not
add fixed `/tmp/packmon-*.json` filenames or echo `PACKMON_SCAN_PATH` back to
webhook callers.
