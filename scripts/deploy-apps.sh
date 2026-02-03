#!/usr/bin/env bash
set -euo pipefail

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/serviceaccounts.yaml
kubectl apply -f k8s/payment-config.yaml
kubectl apply -f k8s/fraud-config.yaml
kubectl apply -f k8s/opa/opa-payment-config.yaml
kubectl apply -f k8s/opa/opa-fraud-config.yaml
kubectl apply -f k8s/entitlements/entitlements-config.yaml

kubectl create configmap opa-payment-policy -n lab \
  --from-file=policy.rego=policies/payment.rego \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap opa-fraud-policy -n lab \
  --from-file=policy.rego=policies/fraud.rego \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f k8s/payment-deploy.yaml
kubectl apply -f k8s/fraud-deploy.yaml
kubectl apply -f k8s/opa/opa-payment-deploy.yaml
kubectl apply -f k8s/opa/opa-fraud-deploy.yaml
kubectl apply -f k8s/entitlements/entitlements-deploy.yaml
kubectl apply -f k8s/payment-svc.yaml
kubectl apply -f k8s/fraud-svc.yaml
kubectl apply -f k8s/opa/opa-payment-svc.yaml
kubectl apply -f k8s/opa/opa-fraud-svc.yaml
kubectl apply -f k8s/entitlements/entitlements-svc.yaml

kubectl -n lab rollout restart deploy/payment deploy/fraud deploy/opa-payment deploy/opa-fraud deploy/entitlements

kubectl rollout status -n lab deploy/payment
kubectl rollout status -n lab deploy/fraud
kubectl rollout status -n lab deploy/opa-payment
kubectl rollout status -n lab deploy/opa-fraud
kubectl rollout status -n lab deploy/entitlements
