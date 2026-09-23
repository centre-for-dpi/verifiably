#!/usr/bin/env bash
# Prepares a machine to build vca.
# Both networks: installs buf from its GitHub release and checks the
# SHA-256 of the binary before it runs.
# Normal network: installs the two protoc plugins with go install.
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

# buf comes from the GitHub release, because the Go module proxy is not
# reachable on a restricted network. The sums below come from the
# sha256.txt file of the release. The script also checks that file, so a
# changed release fails before the binary runs.
BUF_VERSION=1.47.2
buf_sum() { # asset name -> pinned SHA-256
  case "$1" in
    buf-Linux-x86_64) echo 3a0c4da8d46eea8136affa63db202c76a44f8112384160b73c3fffb1cf14b5d8 ;;
    buf-Linux-aarch64) echo 47ddd7ac0bb2a29f8c92aa420dd113bed3b6857190976402eec93ab9847270b4 ;;
    *) return 1 ;;
  esac
}

install_buf() {
  if [ -x "$BIN/buf" ] && [ "$("$BIN/buf" --version 2>/dev/null)" = "$BUF_VERSION" ]; then
    echo "buf $BUF_VERSION: present in $BIN"
    return 0
  fi
  local asset want url tmp listed got
  asset="buf-$(uname -s)-$(uname -m)"
  if ! want=$(buf_sum "$asset"); then
    echo "buf: no pinned release for $asset; install buf $BUF_VERSION by hand" >&2
    return 0
  fi
  url="https://github.com/bufbuild/buf/releases/download/v$BUF_VERSION"
  tmp=$(mktemp -d)
  curl -fsSL --retry 3 -o "$tmp/sha256.txt" "$url/sha256.txt"
  curl -fsSL --retry 3 -o "$tmp/$asset" "$url/$asset"
  listed=$(awk -v a="$asset" '$2 == a { print $1 }' "$tmp/sha256.txt")
  got=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
  if [ "$listed" != "$want" ] || [ "$got" != "$want" ]; then
    echo "buf: SHA-256 mismatch for $asset (pinned $want, sha256.txt ${listed:-none}, file $got)" >&2
    rm -rf "$tmp"
    return 1
  fi
  install -m 0755 "$tmp/$asset" "$BIN/buf"
  rm -rf "$tmp"
  echo "buf $BUF_VERSION: installed in $BIN"
}

install_buf

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
# x/text v0.42.0 needs Go 1.26. gozxing needs x/text, so the mirror stays
# on v0.30.0, which builds with Go 1.25.
clone golang/text v0.30.0 text-v0.30
clone golang/sync v0.23.0 sync
clone golang/sys v0.48.0 sys
# gozxing needs x/xerrors. The repository publishes no tags.
[ -d "$MIRRORS/xerrors" ] || git clone -q --depth 1 https://github.com/golang/xerrors.git "$MIRRORS/xerrors"
# cobra needs gopkg.in/yaml.v3, a vanity path. The GitHub mirror is
# github.com/go-yaml/yaml at tag v3.0.1 (ADR-007 decision 1).
clone go-yaml/yaml v3.0.1 yaml-v3
# The yaml mirror requires gopkg.in/check.v1 for its own tests only.
# Drop the requirement and the tests so no extra vanity path is needed.
( cd "$MIRRORS/yaml-v3" && rm -f ./*_test.go && GOWORK=off GOFLAGS=-mod=mod go mod edit -droprequire gopkg.in/check.v1 )

# GitHub-hosted modules used by core/ need no mirror: fetch them straight
# from GitHub into the module cache (proxy.golang.org is blocked). Run
# outside the module so go.sum is not touched; make tidy owns go.sum.
( cd "$MIRRORS" && GOWORK=off GOPROXY=direct GOSUMDB=off go mod download \
  github.com/go-jose/go-jose/v4@v4.1.5 \
  github.com/fxamacker/cbor/v2@v2.9.1 \
  github.com/makiuchi-d/gozxing@v0.1.1 \
  github.com/x448/float16@v0.8.4 \
  github.com/spf13/cobra@v1.10.1 \
  github.com/spf13/pflag@v1.0.9 \
  github.com/inconshreveable/mousetrap@v1.1.0 \
  github.com/cpuguy83/go-md2man/v2@v2.0.6 \
  github.com/russross/blackfriday/v2@v2.1.0 )

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
	golang.org/x/text => $MIRRORS/text-v0.30
	golang.org/x/xerrors => $MIRRORS/xerrors
	golang.org/x/sync => $MIRRORS/sync
	golang.org/x/sys => $MIRRORS/sys
	gopkg.in/yaml.v3 => $MIRRORS/yaml-v3
)
WORK
echo "wrote go.work; add $BIN to PATH"
