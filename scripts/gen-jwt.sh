#!/usr/bin/env bash
set -euo pipefail

SECRET=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)

BASIC_TOKEN=$(JWT_SECRET="${SECRET}" python3 - <<'PY'
import base64, json, hmac, hashlib, time, os

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

secret = os.environ["JWT_SECRET"].encode()
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "usr-123",
    "roles": ["finance-data-entry"],
    "tenant": "acme",
    "merchant_tier": "silver",
    "mfa": True,
    "iat": int(time.time()),
    "exp": 1893456000,
}
segments = [b64url(json.dumps(header,separators=(',',':')).encode()), b64url(json.dumps(payload,separators=(',',':')).encode())]
msg = ".".join(segments).encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
print(".".join(segments + [b64url(sig)]))
PY
)

ADMIN_TOKEN=$(JWT_SECRET="${SECRET}" python3 - <<'PY'
import base64, json, hmac, hashlib, time, os

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

secret = os.environ["JWT_SECRET"].encode()
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "usr-456",
    "roles": ["finance-admin"],
    "tenant": "acme",
    "merchant_tier": "gold",
    "mfa": True,
    "iat": int(time.time()),
    "exp": 1893456000,
}
segments = [b64url(json.dumps(header,separators=(',',':')).encode()), b64url(json.dumps(payload,separators=(',',':')).encode())]
msg = ".".join(segments).encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
print(".".join(segments + [b64url(sig)]))
PY
)

kubectl -n lab create secret generic jwt-secret \
  --from-literal=secret="${SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

cat <<OUT
BASIC_AUTH_TOKEN=${BASIC_TOKEN}
ADMIN_AUTH_TOKEN=${ADMIN_TOKEN}
export BASIC_AUTH_TOKEN ADMIN_AUTH_TOKEN
OUT
