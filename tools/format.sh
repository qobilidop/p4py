#!/usr/bin/env bash
# Auto-format all source files, or check formatting with --check.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

py_files=$(find src tests -name '*.py' 2>/dev/null || true)
bzl_files=$(find . -name '*.bazel' -o -name '*.bzl' -o -name 'BUILD' |
  grep -v -e '.git/' -e './site/')
sh_files=$(find . -name '*.sh' -not -path './.git/*' -not -path './site/*')

if [[ "${1:-}" == "--check" ]]; then
  fail=0

  # --- Python ---
  if [[ -n "$py_files" ]]; then
    if ! echo "$py_files" | xargs --no-run-if-empty ruff format --check 2>&1; then
      fail=1
    fi
  fi

  # --- Bazel ---
  if ! echo "$bzl_files" | xargs --no-run-if-empty buildifier -mode=check 2>&1; then
    fail=1
  fi

  # --- Shell ---
  if ! echo "$sh_files" | xargs --no-run-if-empty shfmt -d 2>&1; then
    fail=1
  fi

  # --- Markdown, JSON, YAML, TOML (dprint) ---
  if ! dprint check 2>&1; then
    fail=1
  fi

  if [[ $fail -ne 0 ]]; then
    echo ""
    echo "Formatting errors found. Run ./tools/format.sh to fix."
    exit 1
  fi
  echo "All files are properly formatted."
else
  if [[ -n "$py_files" ]]; then
    echo "$py_files" | xargs --no-run-if-empty ruff format
  fi
  echo "$bzl_files" | xargs --no-run-if-empty buildifier
  echo "$sh_files" | xargs --no-run-if-empty shfmt -w
  dprint fmt
  echo "Formatted all files."
fi
