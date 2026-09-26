#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs contract tests against real DPG containers (ADR-006 decision 7).
#
# Set VCA_CONTRACT_DPGS to a space separated list of DPG names to test,
# for example "waltid inji". When the variable is empty, the script prints
# a message and exits 0. Each DPG name maps to a Go test tag "contract_<dpg>"
# under vca/services/dpg-adapter-<dpg>/.
#
# The Inji holder case signs a test holder in at the holder realm of the
# stack Keycloak: set VCA_INJI_CONTRACT_HOLDER_USER,
# VCA_INJI_CONTRACT_HOLDER_PASSWORD, and
# VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI (the redirect URI of the holder
# pair). VCA_INJI_CONTRACT_MIMOTO_URL defaults to the host port of Mimoto.
# VCA_INJI_CONTRACT_HOLDER_PIN is the wallet PIN of the test holder.
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
  if [[ "$dpg" == "inji" ]]; then
    # The holder case of Mimoto 0.21.0 (P6-I7d). A test holder of the
    # holder realm signs in, and the case opens the stack wallet on the
    # host port of Mimoto in deploy/vca/dpg/inji.yaml.
    if [[ -n "${VCA_INJI_CONTRACT_HOLDER_USER:-}${VCA_INJI_CONTRACT_ID_TOKEN:-}" ]]; then
      export VCA_INJI_CONTRACT_MIMOTO_URL="${VCA_INJI_CONTRACT_MIMOTO_URL:-http://127.0.0.1:17084}"
      echo "contract-tests: inji holder case against Mimoto at $VCA_INJI_CONTRACT_MIMOTO_URL"
    else
      echo "contract-tests: inji holder case skipped; set VCA_INJI_CONTRACT_HOLDER_USER and _PASSWORD"
    fi
  fi
  echo "contract-tests: running $dpg"
  if ! go test -race -count=1 -tags "contract_${dpg}" "./${dir}/..."; then
    fail=1
  fi
done
exit $fail
