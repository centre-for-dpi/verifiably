#!/usr/bin/env bash
# gen-demo-pki.sh — generate the demo stack's TLS and signing material locally
# instead of committing it.
#
# WHY THIS EXISTS
#
# Every one of these files used to be checked into a public repository. The TLS
# keys are self-signed with container hostnames, so the blast radius was small,
# but the wallet `tokenKey` is an RSA private key that signs wallet auth
# tokens -- and it shipped as a chart/config default, so every deployment that
# did not override it shared one key. Anyone with the repo could mint valid
# wallet tokens against any such deployment.
#
# Treat everything this script replaces as COMPROMISED. It is in the git
# history of a public repo and cannot be un-published; the only remedy is that
# no deployment uses it again, which is what generating locally achieves.
#
# CONTRACT
#
# Idempotent: a file that already exists is left alone, so re-running `up` on a
# live stack never rotates a key underneath it. Delete a file to force a fresh
# one. Everything written here is gitignored.
#
# Shapes are deliberately identical to what was committed -- same filenames,
# same subjects, same keystore alias and password -- so nothing downstream has
# to learn a new layout. The WSO2 keystore password stays `wso2carbon` because
# wso2-deployment.toml pins it; that is WSO2's documented default and is a
# separate (tracked) concern from shipping the private key itself.

set -euo pipefail

_pki_root() { printf '%s' "${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"; }

# ── self-signed TLS for the two Certify nginx front-ends ─────────────────────
_gen_nginx_cert() {
  local dir="$1" cn="$2"
  [[ -s "$dir/nginx.key" && -s "$dir/nginx.crt" ]] && return 0
  mkdir -p "$dir"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$dir/nginx.key" -out "$dir/nginx.crt" \
    -days 825 -subj "/CN=$cn" \
    -addext "subjectAltName=DNS:$cn" >/dev/null 2>&1
  chmod 600 "$dir/nginx.key"
  echo "  generated $cn TLS cert"
}

# ── WSO2 Identity Server primary keystore + truststore ───────────────────────
# WSO2 wants a JKS whose alias and store password both match deployment.toml.
# openssl builds the PKCS#12; keytool converts and builds the truststore.
_gen_wso2_certs() {
  local dir="$1" pass="wso2carbon" alias="wso2carbon"
  [[ -s "$dir/wso2carbon.jks" && -s "$dir/wso2.key" ]] && return 0
  command -v keytool >/dev/null || {
    echo "  keytool not found (install a JDK) — cannot generate the WSO2 keystore" >&2
    return 1
  }
  mkdir -p "$dir"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$dir/wso2.key" -out "$dir/wso2.pem" \
    -days 3650 -subj "/CN=localhost/O=vcplatform/C=TT" \
    -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
  openssl pkcs12 -export -in "$dir/wso2.pem" -inkey "$dir/wso2.key" \
    -name "$alias" -out "$dir/wso2.p12" -passout "pass:$pass" >/dev/null 2>&1
  rm -f "$dir/wso2carbon.jks" "$dir/client-truststore.jks"
  keytool -importkeystore -noprompt \
    -srckeystore "$dir/wso2.p12" -srcstoretype PKCS12 -srcstorepass "$pass" \
    -destkeystore "$dir/wso2carbon.jks" -deststoretype JKS -deststorepass "$pass" \
    >/dev/null 2>&1
  keytool -importcert -noprompt -alias "$alias" \
    -file "$dir/wso2.pem" -keystore "$dir/client-truststore.jks" \
    -storepass "$pass" >/dev/null 2>&1
  chmod 600 "$dir/wso2.key" "$dir/wso2.p12"
  echo "  generated WSO2 keystore + truststore"
}

# ── walt.id wallet auth.conf (the RSA JWK that signs wallet tokens) ───────────
# auth.conf is bind-mounted verbatim and parsed by walt.id, so this renders the
# committed template with a freshly generated key and changes nothing else
# about the file's shape.
_gen_wallet_authconf() {
  local tmpl="$1" out="$2"
  [[ -s "$out" ]] && return 0
  [[ -s "$tmpl" ]] || { echo "  missing template: $tmpl" >&2; return 1; }
  command -v python3 >/dev/null || {
    echo "  python3 not found — cannot generate the wallet signing key" >&2
    return 1
  }
  local jwk
  jwk="$(openssl genrsa 2048 2>/dev/null | python3 "$(_pki_root)/scripts/pem-to-jwk.py")"
  [[ -n "$jwk" ]] || { echo "  wallet JWK generation failed" >&2; return 1; }
  mkdir -p "$(dirname "$out")"
  # The JWK contains no '|', so it is a safe sed delimiter here.
  sed "s|__WALLET_TOKEN_JWK__|$jwk|" "$tmpl" > "$out"
  chmod 600 "$out"
  echo "  generated wallet signing key (auth.conf)"
}

ensure_demo_pki() {
  local root; root="$(_pki_root)"
  echo "▶ Demo PKI (generated locally, never committed)"
  _gen_nginx_cert "$root/deploy/compose/stack/inji/certify-nginx/certs"         "certify-nginx"
  _gen_nginx_cert "$root/deploy/compose/stack/inji/certify-preauth-nginx/certs" "certify-preauth-nginx"
  _gen_wso2_certs "$root/deploy/compose/stack/wso2-certs"
  _gen_wallet_authconf \
    "$root/deploy/k8s/config/wallet/auth.conf.template" \
    "$root/deploy/k8s/config/wallet/auth.conf"
}

# Allow running standalone: ./scripts/gen-demo-pki.sh
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  ensure_demo_pki
fi
