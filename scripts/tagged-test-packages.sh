#!/usr/bin/env bash
# Prints, one per line and sorted, the packages (./dir) that hold a tracked *_test.go file whose //go:build line
# requires one of the given build tags: the tag-gated suites the GitLab jobs run. tests/ci pins the output to the
# inventory the Makefile targets are checked against. Fails when no package matches, so a job can never pass
# without running anything.
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 TAG..." >&2
  exit 2
fi
for tag in "$@"; do
  if [[ ! $tag =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "$0: invalid build tag: $tag" >&2
    exit 2
  fi
done

cd "$(dirname "${BASH_SOURCE[0]}")/.."
tags=$(IFS='|'; echo "$*")
# The tag must stand alone in the constraint and must not be negated (!tag excludes the file from the suite).
pattern="^//go:build(.*[^[:alnum:]_!])?(${tags})([^[:alnum:]_].*)?\$"
status=0
files=$(git grep -l -E -e "$pattern" -- '*_test.go') || status=$?
# git grep exits 1 when nothing matches; anything else is an error.
if [[ $status -gt 1 ]]; then
  echo "$0: git grep failed with status $status" >&2
  exit 1
fi
packages=""
if [[ -n $files ]]; then
  packages=$(xargs -r -n1 dirname <<<"$files" | sort -u)
fi
if [[ -z $packages ]]; then
  echo "$0: no tracked test file is built with: $*" >&2
  exit 1
fi
mapfile -t dirs <<<"$packages"
printf './%s\n' "${dirs[@]}"
