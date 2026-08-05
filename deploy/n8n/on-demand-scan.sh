#!/bin/sh

case "${PACKMON_API_KEY:-}" in
  "")
    echo "PACKMON_API_KEY must be set in the n8n environment" >&2
    exit 1
    ;;
esac

case "${PACKMON_SERVER:-}" in
  "")
    echo "PACKMON_SERVER must be set in the n8n environment" >&2
    exit 1
    ;;
esac

case "${PACKMON_SCAN_PATH:-}" in
  ""|/*|-*|*..*)
    echo "PACKMON_SCAN_PATH must be a non-empty relative path without parent traversal or leading dash" >&2
    exit 1
    ;;
esac

packmon scan "$PACKMON_SCAN_PATH" --mode remote --require-remote --server "$PACKMON_SERVER"
