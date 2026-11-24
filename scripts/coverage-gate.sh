#!/usr/bin/env bash
# Fails if total statement coverage in a Go coverage profile is below a
# minimum percentage.
#
#   scripts/coverage-gate.sh coverage.out 90
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <coverage.out> <minimum-percent>" >&2
  exit 2
fi
profile="$1"
minimum="$2"

total="$(go tool cover -func="$profile" | awk '/^total:/ {sub("%", "", $3); print $3}')"
if [[ -z "$total" ]]; then
  echo "could not read total coverage from $profile" >&2
  exit 2
fi

if awk -v t="$total" -v m="$minimum" 'BEGIN { exit !(t + 0 < m + 0) }'; then
  echo "coverage ${total}% is below the ${minimum}% minimum" >&2
  exit 1
fi
echo "coverage ${total}% (minimum ${minimum}%)"
