#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs contract tests against real DPG containers (ADR-006 decision 7).
#
# Set VCA_CONTRACT_DPGS to a space separated list of DPG names to test,
# for example "waltid inji". When the variable is empty, the script prints
# a message and exits 0. Each DPG name maps to a Go test tag "contract_<dpg>"
# under vca/services/dpg-adapter-<dpg>/.
set -euo pipefail
cd "$(dirname "$0")/.."

dpgs="${VCA_CONTRACT_DPGS:-}"
if [[ -z "$dpgs" ]]; then
  echo "contract-tests: no DPG containers configured (VCA_CONTRACT_DPGS is empty); nothing to run"
  exit 0
fi

fail=0
for dpg in $dpgs; do
  dir="services/dpg-adapter-${dpg}"
  if [[ ! -d "$dir" ]]; then
    echo "contract-tests: FAIL: $dir does not exist"
    fail=1
    continue
  fi
  echo "contract-tests: running $dpg"
  if ! go test -race -count=1 -tags "contract_${dpg}" "./${dir}/..."; then
    fail=1
  fi
done
exit $fail
