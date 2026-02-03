#!/usr/bin/env bash
set -euo pipefail

KIND_NAME=${KIND_NAME:-spiffe-authz}

docker build -t payment:local apps/payment
docker build -t fraud:local apps/fraud

kind load docker-image --name "${KIND_NAME}" payment:local fraud:local
