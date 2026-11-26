package web

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAdminAPIKeyCopyExecutesClipboardOutcomes runs the real form-actions.js in
// Node against a minimal fake DOM and clicks the API-key copy button once per
// clipboard outcome. It pins the observable copy contract: writeText is called
// synchronously inside the click (user activation), success and every failure
// form (rejected Promise, synchronous throw) end in the right status text, a
// failure selects the key for manual copying, and no Promise rejection is left
// unhandled.
func TestAdminAPIKeyCopyExecutesClipboardOutcomes(t *testing.T) {
	t.Parallel()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute form-actions.js")
	}
	script, err := filepath.Abs(filepath.Join("static", "form-actions.js"))
	if err != nil {
		t.Fatalf("resolve form-actions.js: %v", err)
	}

	const nodeTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), nodeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", formActionsCopyNodeHarness, script) // #nosec G204 -- node resolved via LookPath; fixed harness script.
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("execute form-actions.js with Node timed out after %s\n%s", nodeTimeout, output)
		}
		t.Fatalf("execute form-actions.js with Node: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != "ok" {
		t.Fatalf("form-actions.js copy harness output = %q, want ok", got)
	}
}

// TestAdminAPIKeyCopyKeepsClipboardPromiseOutOfTryBlocks pins SonarQube
// javascript:S4822: a try/catch around the clipboard Promise suggests the catch
// clause handles its rejection, which it never does. The copy handler turns a
// synchronous writeText error into a rejection instead, so one .catch handles
// both failure forms and setupCopyButton needs no try statement.
func TestAdminAPIKeyCopyKeepsClipboardPromiseOutOfTryBlocks(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	start := strings.Index(script, "function setupCopyButton(button) {")
	end := strings.Index(script, "function copyStatusElement(button) {")
	if start < 0 || end <= start {
		t.Fatalf("form-actions.js is missing setupCopyButton followed by copyStatusElement:\n%s", script)
	}
	block := script[start:end]
	if !strings.Contains(block, "navigator.clipboard.writeText(") {
		t.Fatalf("setupCopyButton no longer calls navigator.clipboard.writeText:\n%s", block)
	}
	if strings.Contains(block, "try {") {
		t.Fatalf("setupCopyButton wraps the clipboard Promise in a try statement (SonarQube S4822):\n%s", block)
	}
}

const formActionsCopyNodeHarness = `
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(process.argv[1], 'utf8');

const unhandled = [];
process.on('unhandledRejection', (reason) => { unhandled.push(String(reason)); });

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function makeElement(dataset) {
  return {
    dataset: Object.assign({}, dataset),
    listeners: {},
    addEventListener(type, handler) { (this.listeners[type] = this.listeners[type] || []).push(handler); },
  };
}

// Waits past the microtask queue and the process-level unhandledRejection check.
function settle() {
  return new Promise((resolve) => setTimeout(resolve, 20));
}

async function runScenario(name, clipboard, want) {
  const button = makeElement({ copyTarget: '#new-api-key', copyStatus: '#new-api-key-copy-status' });
  const target = {
    value: 'pm_live_secret',
    selected: false,
    focus() {},
    select() { this.selected = true; },
  };
  const status = { textContent: '' };
  const document = {
    readyState: 'complete',
    body: makeElement({}),
    addEventListener() {},
    querySelectorAll(selector) { return selector === '[data-copy-target]' ? [button] : []; },
    querySelector(selector) {
      if (selector === '#new-api-key') return target;
      if (selector === '#new-api-key-copy-status') return status;
      return null;
    },
  };
  const window = { addEventListener() {}, confirm() { return true; }, location: { href: 'https://packmon.test/admin/keys' } };
  const navigator = clipboard ? { clipboard } : {};
  vm.runInNewContext(source, { document, window, navigator, URL });

  const clicks = button.listeners.click || [];
  assert(clicks.length === 1, name + ': copy button click listeners = ' + clicks.length + ', want 1');
  clicks[0]();
  if (clipboard) {
    assert(clipboard.calls.length === 1, name + ': writeText calls during the click = ' + clipboard.calls.length + ', want 1');
    assert(clipboard.calls[0] === 'pm_live_secret', name + ': writeText argument = ' + JSON.stringify(clipboard.calls[0]));
    // A synchronous failure may be reported at once or one microtask later.
    const during = status.textContent;
    assert(during === 'Copying API key.' || during === want.status, name + ': status during the write = ' + JSON.stringify(during));
  }
  await settle();
  assert(unhandled.length === 0, name + ': unhandled Promise rejection: ' + unhandled.join('; '));
  assert(status.textContent === want.status, name + ': final status = ' + JSON.stringify(status.textContent) + ', want ' + JSON.stringify(want.status));
  assert(target.selected === want.selected, name + ': key selected = ' + target.selected + ', want ' + want.selected);
}

function fakeClipboard(write) {
  const clipboard = {
    calls: [],
    writeText(text) { clipboard.calls.push(text); return write(); },
  };
  return clipboard;
}

const copied = { status: 'API key copied to clipboard.', selected: false };
const failed = { status: 'Copy failed. API key selected for manual copying.', selected: true };

(async () => {
  await runScenario('resolved write', fakeClipboard(() => Promise.resolve()), copied);
  await runScenario('non-Promise return', fakeClipboard(() => undefined), copied);
  await runScenario('rejected write', fakeClipboard(() => Promise.reject(new Error('NotAllowedError'))), failed);
  await runScenario('synchronous throw', fakeClipboard(() => { throw new Error('SecurityError'); }), failed);
  await runScenario('clipboard unavailable', null, { status: 'Clipboard unavailable. API key selected for manual copying.', selected: true });
  console.log('ok');
})().catch((error) => {
  console.log(error && error.stack ? error.stack : String(error));
  process.exitCode = 1;
});
`
