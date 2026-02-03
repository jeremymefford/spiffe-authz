#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"

require_env() {
  local name=$1
  if [[ -z "${!name:-}" ]]; then
    echo "Missing ${name}. Run: eval \"\$(./scripts/gen-jwt.sh)\"" >&2
    exit 1
  fi
}

require_env BASIC_AUTH_TOKEN
require_env ADMIN_AUTH_TOKEN

request() {
  local token=$1
  local body=$2
  curl -s -o /dev/null -w "%{http_code}" \
    -H 'content-type: application/json' \
    -H "authorization: Bearer ${token}" \
    -d "${body}" \
    "${BASE_URL}/v1/charge"
}

expect() {
  local name=$1
  local got=$2
  local want=$3
  if [[ "${got}" != "${want}" ]]; then
    echo "FAIL: ${name} expected ${want}, got ${got}" >&2
    exit 1
  fi
  echo "OK: ${name} -> ${got}"
}

code=$(request "${BASIC_AUTH_TOKEN}" '{"amount":99,"currency":"USD","card_country":"US","merchant_id":"m-123"}')
expect "basic under limit" "${code}" "200"

code=$(request "${BASIC_AUTH_TOKEN}" '{"amount":199,"currency":"USD","card_country":"US","merchant_id":"m-123"}')
expect "basic over limit" "${code}" "401"

code=$(request "${ADMIN_AUTH_TOKEN}" '{"amount":199,"currency":"USD","card_country":"US","merchant_id":"m-123"}')
expect "admin over basic limit" "${code}" "200"

code=$(request "${ADMIN_AUTH_TOKEN}" '{"amount":600,"currency":"USD","card_country":"US","merchant_id":"m-gambling"}')
expect "admin gambling threshold" "${code}" "401"

echo "Smoke test passed."
