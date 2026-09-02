#!/usr/bin/env bash
set -euo pipefail
scenario="${1:-gateway}"; rates="${K6_RATES:-10}"; base_url="${BASE_URL:-http://localhost:8081}"
case "$scenario" in gateway) script=gateway/baseline.js;; gateway-authenticated-read) script=gateway/authenticated-read.js;; auth-login) script=auth/login.js;; auth-refresh) script=auth/refresh.js;; ticket-read) script=ticket/read.js;; location) script=location/steady.js;; dispatch-preview) script=dispatch/preview.js;; analytics) script=analytics/queries.js;; full) script=full-system/mixed.js;; *) echo "unknown scenario: $scenario" >&2; exit 2;; esac
if [[ "$scenario" == location || "$scenario" == full ]]; then [[ "${LOAD_TEST_ALLOW_DESTRUCTIVE:-}" == true ]] || { echo 'set LOAD_TEST_ALLOW_DESTRUCTIVE=true' >&2; exit 2; }; [[ "$base_url" != *prod* ]] || { echo 'production target is forbidden' >&2; exit 2; }; fi
run_id="$(date -u +%Y%m%dT%H%M%SZ)-${scenario//\//-}"; raw="load-tests/results/raw/$run_id"; mkdir -p "$raw"
BASE_URL="$base_url" K6_RATES="$rates" K6_RUN_ID="$run_id" k6 run --summary-export "$raw/k6.json" "load-tests/k6/$script"
printf '{"run_id":"%s","scenario":"%s","git_sha":"%s","base_url":"%s","rates":"%s"}\n' "$run_id" "$scenario" "$(git rev-parse HEAD)" "$base_url" "$rates" > "$raw/config.json"
echo "Raw result: $raw"
