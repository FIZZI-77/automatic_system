#!/usr/bin/env bash
set -euo pipefail
[[ "${LOAD_TEST_ALLOW_DESTRUCTIVE:-}" == true ]] || { echo 'fixture preparation requires LOAD_TEST_ALLOW_DESTRUCTIVE=true' >&2; exit 2; }
node load-tests/data/generators/generate.js "${1:-77}" "${2:-100}"
