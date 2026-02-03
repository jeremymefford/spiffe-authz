#!/usr/bin/env bash
set -euo pipefail

find_spire_server_pod() {
  local pod
  pod=$(kubectl get pod -n spire -l app.kubernetes.io/name=spire-server -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [[ -z "${pod}" ]]; then
    pod=$(kubectl get pod -n spire -l app=spire-server -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  fi
  if [[ -z "${pod}" ]]; then
    pod=$(kubectl get pod -n spire -l app.kubernetes.io/name=server -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  fi
  if [[ -z "${pod}" ]]; then
    pod=$(kubectl get pods -n spire --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | grep -m1 spire-server || true)
  fi
  echo "${pod}"
}

SERVER_POD=$(find_spire_server_pod)
if [[ -z "${SERVER_POD}" ]]; then
  echo "Could not find spire-server pod. Try: kubectl get pods -n spire --show-labels"
  exit 1
fi
SERVER_POD=${SERVER_POD//\"/}
SERVER_POD=$(echo "${SERVER_POD}" | tr -d '\r' | xargs)

exec_spire() {
  local cmd=("$@")
  if kubectl exec -n spire "${SERVER_POD}" -c spire-server -- spire-server "${cmd[@]}" >/dev/null 2>&1; then
    kubectl exec -n spire "${SERVER_POD}" -c spire-server -- spire-server "${cmd[@]}"
    return
  fi
  kubectl exec -n spire "${SERVER_POD}" -- spire-server "${cmd[@]}"
}

AGENT_ID=$(exec_spire agent list | awk '/^SPIFFE ID/ {print $4; exit}')

if [[ -z "${AGENT_ID}" ]]; then
  echo "Could not determine SPIRE agent ID"
  exit 1
fi

echo "Using agent: ${AGENT_ID}"

register_entry() {
  local spiffe_id=$1
  local ns=$2
  local sa=$3

  local output
  output=$(exec_spire entry create \
      -spiffeID "${spiffe_id}" \
      -parentID "${AGENT_ID}" \
      -selector "k8s:ns:${ns}" \
      -selector "k8s:sa:${sa}" 2>&1) || true

  if echo "${output}" | grep -q "AlreadyExists"; then
    echo "Entry already exists: ${spiffe_id}"
    return
  fi

  if echo "${output}" | grep -q "Failed to create"; then
    echo "${output}"
    exit 1
  fi
}

register_entry "spiffe://example.org/ns/lab/sa/payment" lab payment
register_entry "spiffe://example.org/ns/lab/sa/fraud" lab fraud
register_entry "spiffe://example.org/ns/lab/sa/client" lab client

echo "Entries registered."
