#!/usr/bin/env bash
# Run linters on all source files.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# --- Python ---
ruff check src/ tests/
echo "ruff: all checks passed."

# --- Bazel ---
bzl_files=$(find . -name '*.bazel' -o -name '*.bzl' -o -name 'BUILD' |
  grep -v -e '.git/' -e './site/')
echo "$bzl_files" | xargs --no-run-if-empty buildifier -lint=warn
echo "buildifier: all checks passed."

# --- Shell ---
sh_files=$(find . -name '*.sh' -not -path './.git/*' -not -path './site/*')
echo "$sh_files" | xargs --no-run-if-empty shellcheck
echo "shellcheck: all checks passed."
