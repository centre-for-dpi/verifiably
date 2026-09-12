#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Renders and deploys every Helm chart under deploy/vca/helm into a kind
# cluster, then waits for all deployments to become available
# (ADR-006 decision 7).
#
# Skips with exit 0 when deploy/vca/helm does not exist yet.
# Requires: helm, kubectl, and a reachable cluster (kind in CI).
# Environment:
#   VCA_SMOKE_NAMESPACE  namespace to install into (default: vca-smoke)
#   VCA_SMOKE_TIMEOUT    rollout timeout (default: 180s)
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
charts="$repo/deploy/vca/helm"
ns="${VCA_SMOKE_NAMESPACE:-vca-smoke}"
timeout="${VCA_SMOKE_TIMEOUT:-180s}"

if [[ ! -d "$charts" ]]; then
  echo "k8s-smoke: $charts does not exist; nothing to deploy"
  exit 0
fi

found=0
for chart in "$charts"/*/; do
  [[ -f "$chart/Chart.yaml" ]] || continue
  found=1
done
if [[ $found -eq 0 ]]; then
  echo "k8s-smoke: no Chart.yaml under $charts; nothing to deploy"
  exit 0
fi

for tool in helm kubectl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "k8s-smoke: FAIL: $tool is not installed"
    exit 1
  fi
done

kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -

fail=0
for chart in "$charts"/*/; do
  [[ -f "$chart/Chart.yaml" ]] || continue
  name="$(basename "$chart")"
  echo "k8s-smoke: lint $name"
  helm lint "$chart" || fail=1
  echo "k8s-smoke: render $name"
  helm template "$name" "$chart" --namespace "$ns" >/dev/null || fail=1
  echo "k8s-smoke: install $name"
  if ! helm upgrade --install "$name" "$chart" --namespace "$ns" --wait --timeout "$timeout"; then
    echo "k8s-smoke: FAIL: install $name"
    kubectl -n "$ns" get all || true
    kubectl -n "$ns" describe pods || true
    fail=1
  fi
done

echo "k8s-smoke: wait for deployments in $ns"
for dep in $(kubectl -n "$ns" get deployments -o name); do
  if ! kubectl -n "$ns" rollout status "$dep" --timeout="$timeout"; then
    echo "k8s-smoke: FAIL: $dep did not become available"
    fail=1
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "k8s-smoke: PASS"
fi
exit $fail
