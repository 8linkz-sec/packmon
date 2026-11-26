#!/usr/bin/env bash
# Prints the go test -skip pattern ^(Name|...)$ of the tests listed in .gitlab/integration-docker-only.txt (one
# "TestName  # reason" per line), which go-test-integration skips because they need a Docker daemon. Fails on a
# malformed or empty list. tests/ci checks the output against the list
# (TestIntegrationSkipPatternScriptMatchesDockerOnlyList).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
list=.gitlab/integration-docker-only.txt
names=()
while IFS= read -r line || [[ -n $line ]]; do
  if [[ $line =~ ^[[:space:]]*(#|$) ]]; then
    continue
  fi
  if [[ ! $line =~ ^(Test[A-Za-z0-9_]+)[[:space:]]+#[[:space:]]*[^[:space:]] ]]; then
    echo "$0: malformed entry in $list: $line" >&2
    exit 1
  fi
  names+=("${BASH_REMATCH[1]}")
done <"$list"
if [[ ${#names[@]} -eq 0 ]]; then
  echo "$0: $list lists no tests" >&2
  exit 1
fi
joined=$(IFS='|'; echo "${names[*]}")
printf '^(%s)$\n' "$joined"
