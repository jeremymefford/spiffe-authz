#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_cmd openssl
require_cmd python3
require_cmd kubectl

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

key_file="${tmpdir}/jwt-es256.key"
cert_file="${tmpdir}/jwt-es256.crt"

openssl ecparam -name prime256v1 -genkey -noout -out "${key_file}" >/dev/null 2>&1
openssl req -new -x509 -key "${key_file}" -out "${cert_file}" -subj "/CN=jwt-es256" -days 3650 >/dev/null 2>&1

sign_jwt() {
  python3 - <<'PY' "${key_file}" "$1"
import base64, json, subprocess, sys, tempfile

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

key_path = sys.argv[1]
payload_json = sys.argv[2]

header = {"alg": "ES256", "typ": "JWT"}
header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
payload_b64 = b64url(payload_json.encode())
signing_input = f"{header_b64}.{payload_b64}".encode()

with tempfile.NamedTemporaryFile() as msg, tempfile.NamedTemporaryFile() as sig:
    msg.write(signing_input)
    msg.flush()
    subprocess.check_call([
        "openssl", "dgst", "-sha256",
        "-sign", key_path,
        "-out", sig.name,
        msg.name,
    ])
    sig.seek(0)
    der = sig.read()

# Minimal DER parser for ECDSA signature (SEQUENCE of INTEGER r, s)
def read_int(data, idx):
    if data[idx] != 0x02:
        raise ValueError("bad DER integer")
    idx += 1
    length = data[idx]
    idx += 1
    val = data[idx:idx+length]
    idx += length
    return val, idx

if not der or der[0] != 0x30:
    raise ValueError("bad DER sequence")
idx = 1
seq_len = der[idx]
idx += 1
seq = der[idx:idx+seq_len]
idx = 0
r, idx = read_int(seq, idx)
s, idx = read_int(seq, idx)

# Strip leading zeros and pad to 32 bytes
r = r.lstrip(b"\x00").rjust(32, b"\x00")
s = s.lstrip(b"\x00").rjust(32, b"\x00")
sig_raw = r + s

print(f"{header_b64}.{payload_b64}.{b64url(sig_raw)}")
PY
}

BASIC_PAYLOAD=$(python3 - <<'PY'
import json, time
payload = {
    "sub": "usr-123",
    "roles": ["finance-data-entry"],
    "tenant": "acme",
    "merchant_tier": "silver",
    "mfa": True,
    "iat": int(time.time()),
    "exp": 1893456000,
}
print(json.dumps(payload, separators=(",", ":")))
PY
)
BASIC_TOKEN=$(sign_jwt "${BASIC_PAYLOAD}")

ADMIN_PAYLOAD=$(python3 - <<'PY'
import json, time
payload = {
    "sub": "usr-456",
    "roles": ["finance-admin"],
    "tenant": "acme",
    "merchant_tier": "gold",
    "mfa": True,
    "iat": int(time.time()),
    "exp": 1893456000,
}
print(json.dumps(payload, separators=(",", ":")))
PY
)
ADMIN_TOKEN=$(sign_jwt "${ADMIN_PAYLOAD}")

kubectl -n lab create secret generic jwt-cert \
  --from-file=cert.pem="${cert_file}" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

cat <<OUT
BASIC_AUTH_TOKEN=${BASIC_TOKEN}
ADMIN_AUTH_TOKEN=${ADMIN_TOKEN}
export BASIC_AUTH_TOKEN ADMIN_AUTH_TOKEN
OUT
