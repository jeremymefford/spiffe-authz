#!/usr/bin/env bash
set -euo pipefail

KIND_NAME=${KIND_NAME:-spiffe-authz}

if kind get clusters | grep -q "^${KIND_NAME}$"; then
  echo "kind cluster ${KIND_NAME} already exists"
  exit 0
fi

cat <<'CONFIG' | kind create cluster --name "${KIND_NAME}" --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
CONFIG
