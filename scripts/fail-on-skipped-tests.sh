#!/usr/bin/env bash
# Fails when a `go test -v` log reports a skipped test or subtest. go-test-e2e runs it on the e2e output: the
# browser test skips when it finds no browser, and a skip must not pass as coverage. tests/ci checks its
# behaviour (TestFailOnSkippedTestsScriptRejectsSkippedTests).
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 GO_TEST_VERBOSE_LOG" >&2
  exit 2
fi
if [[ ! -r $1 ]]; then
  echo "$0: cannot read $1" >&2
  exit 2
fi
if grep -n -E -- '^[[:space:]]*--- SKIP: ' "$1"; then
  echo "tests were skipped (missing browser or tool); every test of this job must run in CI" >&2
  exit 1
fi
