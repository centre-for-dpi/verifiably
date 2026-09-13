#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generates the OpenAPI 3.1 document from the proto files with
# protoc-gen-connect-openapi (ADR-003 decision 3).
#
# Usage:
#   hack/openapi.sh            write docs/openapi/vca.openapi.yaml
#   OPENAPI_OUT=<dir> hack/openapi.sh
#
# The plugin binary comes from github.com/sudorandom/protoc-gen-connect-openapi.
# Install it on a networked machine with:
#   go install github.com/sudorandom/protoc-gen-connect-openapi@v0.18.0
# When the binary is absent the script prints a skip message and exits 0,
# so make targets on a restricted network do not fail.
set -euo pipefail
cd "$(dirname "$0")/.."

out="${OPENAPI_OUT:-docs/openapi}"
plugin="protoc-gen-connect-openapi"

if ! command -v buf >/dev/null 2>&1; then
  echo "openapi: skip, buf is not on PATH (run make bootstrap)" >&2
  exit 0
fi

if ! command -v "$plugin" >/dev/null 2>&1; then
  echo "openapi: skip, $plugin is not on PATH" >&2
  echo "openapi: install it with: go install github.com/sudorandom/protoc-gen-connect-openapi@v0.18.0" >&2
  exit 0
fi

mkdir -p "$out"
template=$(cat <<EOF
{
  "version": "v2",
  "plugins": [
    {
      "local": "$plugin",
      "out": "$out",
      "opt": [
        "path=vca.openapi.yaml",
        "format=yaml",
        "base=hack/openapi-base.yaml",
        "with-streaming",
        "short-service-tags"
      ]
    }
  ]
}
EOF
)

# The base file adds the standard HTTP endpoints that stay outside the
# proto contract (ADR-003 decision 7). It is optional.
if [ ! -f hack/openapi-base.yaml ]; then
  template=$(printf '%s' "$template" | sed '/"base=hack\/openapi-base.yaml",/d')
fi

buf generate --template "$template"
echo "openapi: wrote $out/vca.openapi.yaml"
