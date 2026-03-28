#!/usr/bin/env bash
# Build or serve the Sphinx documentation site.
#
# Usage:
#   ./tools/docs.sh          # build the site to docs/_build/
#   ./tools/docs.sh serve    # serve locally with live reload
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [[ "${1:-}" == "serve" ]]; then
  sphinx-autobuild docs docs/_build/html --host 0.0.0.0 --port 8000
else
  sphinx-build -W docs docs/_build/html
  echo "Site built in docs/_build/"
fi
