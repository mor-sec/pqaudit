#!/usr/bin/env bash
# Run Vale on the project text. Skip the paths that do not exist yet.
# Set VALE to the Vale program. Set COMMITS to a Git range.
set -euo pipefail

VALE="${VALE:-vale}"
paths=()
for path in README.md docs/ target/ste/ \
  crates/pqaudit-report/src/templates/ crates/pqaudit-cli/src/templates/ \
  .github/release-notes-template.md; do
  if [ -e "$path" ]; then
    paths+=("$path")
  fi
done
exec "$VALE" "${paths[@]}"
