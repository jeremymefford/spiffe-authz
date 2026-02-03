#!/usr/bin/env bash
set -euo pipefail

helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm repo update

helm upgrade --install spire-crds spiffe/spire-crds -n spire --create-namespace
helm upgrade --install spire spiffe/spire -n spire

kubectl rollout status -n spire deploy -l app.kubernetes.io/name=spire-server
kubectl rollout status -n spire ds -l app.kubernetes.io/name=spire-agent
