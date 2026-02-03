#!/usr/bin/env bash
set -euo pipefail

SECRET=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)

TOKEN=$(JWT_SECRET="${SECRET}" python3 - <<'PY'
import base64, json, hmac, hashlib, time, os

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

secret = os.environ["JWT_SECRET"].encode()
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "usr-123",
    "roles": ["finance-admin"],
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

kubectl -n lab create secret generic jwt-secret \
  --from-literal=secret="${SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f -

cat <<OUT
JWT secret stored in k8s secret jwt-secret (namespace lab).

Export for your shell:
  export AUTH_TOKEN="${TOKEN}"
OUT
