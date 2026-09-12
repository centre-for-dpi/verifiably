#!/usr/bin/env bash
# Prepares a machine to build vca.
# Normal network: installs buf and the two protoc plugins with go install.
# Restricted network (no proxy.golang.org): clones GitHub mirrors of the
# vanity-hosted modules and writes a go.work file (git-ignored) that replaces
# them. go.sum stays authoritative for normal machines; run "make tidy" on a
# networked machine before you open a pull request.
set -euo pipefail
cd "$(dirname "$0")/.."
MIRRORS="${VCA_MIRRORS:-$HOME/.cache/vca-mirrors}"
BIN="$MIRRORS/bin"
mkdir -p "$MIRRORS" "$BIN"

clone() { # repo tag dir
  [ -d "$MIRRORS/$3" ] || git clone -q --depth 1 -b "$2" "https://github.com/$1.git" "$MIRRORS/$3"
}

if curl -fsS --max-time 5 https://proxy.golang.org >/dev/null 2>&1; then
  echo "network: normal"
  go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
  go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.21.0
  rm -f go.work go.work.sum
  exit 0
fi

echo "network: restricted, using GitHub mirrors in $MIRRORS"
clone protocolbuffers/protobuf-go v1.36.12 protobuf-go
clone connectrpc/connect-go v1.21.0 connect-go
clone google/go-cmp v0.7.0 go-cmp
clone golang/net v0.59.0 net
clone golang/crypto v0.57.0 crypto
clone golang/text v0.42.0 text
clone golang/sync v0.23.0 sync
clone golang/sys v0.48.0 sys

export GOPROXY=off GOSUMDB=off GOFLAGS=-mod=mod
( cd "$MIRRORS/protobuf-go" && go mod edit -replace github.com/google/go-cmp="$MIRRORS/go-cmp" && GOBIN="$BIN" go install ./cmd/protoc-gen-go )
( cd "$MIRRORS/connect-go" && go mod edit -replace google.golang.org/protobuf="$MIRRORS/protobuf-go" -replace github.com/google/go-cmp="$MIRRORS/go-cmp" && GOBIN="$BIN" go install ./cmd/protoc-gen-connect-go )

cat > go.work <<WORK
go 1.25.0

use .

replace (
	google.golang.org/protobuf => $MIRRORS/protobuf-go
	connectrpc.com/connect => $MIRRORS/connect-go
	github.com/google/go-cmp => $MIRRORS/go-cmp
	golang.org/x/net => $MIRRORS/net
	golang.org/x/crypto => $MIRRORS/crypto
	golang.org/x/text => $MIRRORS/text
	golang.org/x/sync => $MIRRORS/sync
	golang.org/x/sys => $MIRRORS/sys
)
WORK
echo "wrote go.work; add $BIN to PATH"
