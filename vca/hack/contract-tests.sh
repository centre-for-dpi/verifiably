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

# The nightly job needs a test holder in the holder realm of the stack
# Keycloak (P6-I7g). When the job gives no holder, the script makes one
# through the Keycloak admin API with the administrator of
# keycloak-inji/.env under the deploy root. The password, the wallet PIN,
# and the redirect URI of the holder pair stay in
# mimoto-inji/contract-holder.env with mode 0600, so a second run keeps
# the same holder and the same Mimoto wallet. Given values win.
# VCA_CONTRACT_DEPLOY_DIR is the deploy root (../deploy/vca by default).
# VCA_CONTRACT_KEYCLOAK_URL is the stack Keycloak (host port 17080).
# VCA_CONTRACT_PREPARE_ONLY=1 prepares the holder and runs no test.

# env_value prints the value of one variable of a .env file.
env_value() {
  local file="$1" key="$2" line
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "$key="* ]]; then
      line="${line#"$key="}"
      line="${line%\"}"
      printf '%s' "${line#\"}"
      return 0
    fi
  done <"$file"
}

# kc_call runs one admin API call. The token goes through a header file,
# so no secret shows in the process list.
kc_call() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -X "$method" -H @<(printf 'Authorization: Bearer %s\n' "$kc_token") \
    -H 'Content-Type: application/json' "$@" "$kc_url/admin/realms/vca-holder-realm$path"
}

prepare_inji_holder() {
  local deploy="${VCA_CONTRACT_DEPLOY_DIR:-../deploy/vca}"
  local kc_env="$deploy/keycloak-inji/.env" state="$deploy/mimoto-inji/contract-holder.env"
  if [[ -n "${VCA_INJI_CONTRACT_HOLDER_USER:-}${VCA_INJI_CONTRACT_ID_TOKEN:-}" ]]; then
    return 0
  fi
  if [[ ! -f "$kc_env" ]]; then
    echo "contract-tests: $kc_env does not exist; run vca setup for the Inji stack first"
    return 0
  fi
  local user password pin redirect
  user="$(env_value "$state" VCA_INJI_CONTRACT_HOLDER_USER)"
  password="$(env_value "$state" VCA_INJI_CONTRACT_HOLDER_PASSWORD)"
  pin="$(env_value "$state" VCA_INJI_CONTRACT_HOLDER_PIN)"
  redirect="$(env_value "$state" VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI)"
  if [[ -z "$user" || -z "$password" ]]; then
    user="contract-holder"
    password="$(head -c 48 /dev/urandom | base64 | tr -d '\n/+=')"
    password="${password:0:24}"
  fi
  if [[ -z "$pin" ]]; then
    pin="$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')"
    pin="$((pin % 900000 + 100000))"
  fi
  pin="${VCA_INJI_CONTRACT_HOLDER_PIN:-$pin}"
  if [[ -z "$redirect" ]]; then
    redirect="$(env_value "$deploy/holder-inji/.env" VCA_OIDC_REDIRECT_URI)"
  fi
  redirect="${VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI:-$redirect}"
  if [[ -z "$redirect" ]]; then
    echo "contract-tests: FAIL: no redirect URI; set up the Inji holder pair or set VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI"
    return 1
  fi

  kc_url="${VCA_CONTRACT_KEYCLOAK_URL:-http://127.0.0.1:17080}"
  local admin admin_password
  admin="$(env_value "$kc_env" KEYCLOAK_ADMIN)"
  admin_password="$(env_value "$kc_env" KEYCLOAK_ADMIN_PASSWORD)"
  kc_token="$(printf '%s' "$admin_password" | curl -fsS \
    --data-urlencode client_id=admin-cli --data-urlencode grant_type=password \
    --data-urlencode "username=${admin:-admin}" --data-urlencode password@- \
    "$kc_url/realms/master/protocol/openid-connect/token" | jq -er .access_token)"

  local id credential
  id="$(kc_call GET "/users?exact=true&username=$user" | jq -r '.[0].id // empty')"
  credential="$(HOLDER_PASSWORD="$password" jq -cn '{type: "password", value: env.HOLDER_PASSWORD, temporary: false}')"
  if [[ -n "$id" ]]; then
    printf '%s' "$credential" | kc_call PUT "/users/$id/reset-password" --data-binary @- >/dev/null
    echo "contract-tests: the test holder $user exists; its password is set again"
  else
    HOLDER_CREDENTIAL="$credential" jq -cn --arg user "$user" '{username: $user, enabled: true,
      email: ($user + "@example.org"), emailVerified: true, firstName: "Contract", lastName: "Holder",
      requiredActions: [], credentials: [env.HOLDER_CREDENTIAL | fromjson]}' |
      kc_call POST /users --data-binary @- >/dev/null
    echo "contract-tests: made the test holder $user in the holder realm"
  fi

  mkdir -p "$(dirname "$state")"
  [[ -f "$(dirname "$state")/.gitignore" ]] || printf '*\n' >"$(dirname "$state")/.gitignore"
  (
    umask 077
    printf 'VCA_INJI_CONTRACT_HOLDER_USER=%s\nVCA_INJI_CONTRACT_HOLDER_PASSWORD=%s\nVCA_INJI_CONTRACT_HOLDER_PIN=%s\nVCA_INJI_CONTRACT_HOLDER_REDIRECT_URI=%s\n' \
      "$user" "$password" "$pin" "$redirect" >"$state.tmp"
  )
  mv "$state.tmp" "$state"
  chmod 600 "$state"
  echo "contract-tests: the test holder is in $state"
  export VCA_INJI_CONTRACT_HOLDER_USER="$user" VCA_INJI_CONTRACT_HOLDER_PASSWORD="$password"
  export VCA_INJI_CONTRACT_HOLDER_PIN="$pin" VCA_INJI_CONTRACT_HOLDER_REDIRECT_URI="$redirect"
}

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
    # A failed preparation stops the script, as set -e says.
    prepare_inji_holder
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
  if [[ "${VCA_CONTRACT_PREPARE_ONLY:-}" == "1" ]]; then
    continue
  fi
  echo "contract-tests: running $dpg"
  if ! go test -race -count=1 -tags "contract_${dpg}" "./${dir}/..."; then
    fail=1
  fi
done
exit $fail
