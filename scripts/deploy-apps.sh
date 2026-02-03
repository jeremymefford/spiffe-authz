#!/usr/bin/env bash
set -euo pipefail

kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/serviceaccounts.yaml
kubectl apply -f k8s/payment-config.yaml
kubectl apply -f k8s/fraud-config.yaml
kubectl apply -f k8s/payment-deploy.yaml
kubectl apply -f k8s/fraud-deploy.yaml
kubectl apply -f k8s/payment-svc.yaml
kubectl apply -f k8s/fraud-svc.yaml

kubectl rollout status -n lab deploy/payment
kubectl rollout status -n lab deploy/fraud
