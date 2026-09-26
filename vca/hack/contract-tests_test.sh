#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests the deployment guard of contract-tests.sh (ADR-050). The script
# runs against a test deployment only: the deploy root must hold
# contract.env with VCA_CONTRACT_DEPLOYMENT=test, and no file of the deploy
# root may name a sample data set or a mock identity system.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/contract-tests.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0

# run_case runs the script in its prepare only mode against one deploy
# root with a clean environment. It prints the output and returns the
# exit code of the script.
run_case() {
  local deploy="$1" dpgs="${2-inji}"
  env -i PATH="$PATH" HOME="$work" VCA_CONTRACT_DPGS="$dpgs" VCA_CONTRACT_PREPARE_ONLY=1 \
    VCA_CONTRACT_DEPLOY_DIR="$deploy" VCA_INJI_CONTRACT_HOLDER_USER=given \
    VCA_INJI_CONTRACT_HOLDER_PASSWORD=given VCA_INJI_CONTRACT_CLAIMS_DIR="$work/claims" \
    bash "$script" 2>&1
}

# expect checks the exit code and one text of the output of a case.
expect() {
  local name="$1" want_code="$2" want_text="$3" deploy="$4" dpgs="${5-inji}" out code=0
  out="$(run_case "$deploy" "$dpgs")" || code=$?
  if [[ "$code" != "$want_code" ]]; then
    echo "FAIL: $name: exit $code, want $want_code"
    echo "$out"
    fail=1
    return
  fi
  if [[ "$out" != *"$want_text"* ]]; then
    echo "FAIL: $name: the output has no \"$want_text\""
    echo "$out"
    fail=1
  fi
}

# refuses_without_marker: a deploy root without contract.env is not a
# test deployment.
mkdir -p "$work/none"
expect refuses_without_marker 2 "REFUSED" "$work/none"

# refuses_another_deployment: the marker must say test.
mkdir -p "$work/production"
printf 'VCA_CONTRACT_DEPLOYMENT=production\n' >"$work/production/contract.env"
expect refuses_another_deployment 2 "VCA_CONTRACT_DEPLOYMENT=test" "$work/production"

# refuses_sample_data: a test deployment of an old release that still
# holds the sample identities.
mkdir -p "$work/old/dpg/inji/certify"
printf 'VCA_CONTRACT_DEPLOYMENT=test\n' >"$work/old/contract.env"
printf 'id,name\n' >"$work/old/dpg/inji/certify/farmer_identity_data.csv"
expect refuses_sample_data 2 "farmer_identity_data.csv" "$work/old"

# refuses_mock_identity: a stack file that runs the mock identity system.
mkdir -p "$work/mock/dpg"
printf 'VCA_CONTRACT_DEPLOYMENT=test\n' >"$work/mock/contract.env"
printf 'services:\n  inji-mock-identity:\n    image: x\n' >"$work/mock/dpg/inji.yaml"
expect refuses_mock_identity 2 "mock identity system" "$work/mock"

# runs_on_a_test_deployment: the marker and a clean deploy root.
mkdir -p "$work/test/dpg"
printf 'VCA_CONTRACT_DEPLOYMENT=test\n' >"$work/test/contract.env"
printf 'services:\n  inji-certify:\n    image: x\n' >"$work/test/dpg/inji.yaml"
expect runs_on_a_test_deployment 0 "inji holder case" "$work/test"

# nothing_to_run: with no DPG the script touches no deployment, so it
# needs no marker.
expect nothing_to_run 0 "nothing to run" "$work/none" ""

if [[ "$fail" == 0 ]]; then
  echo "contract-tests_test: ok"
fi
exit "$fail"
