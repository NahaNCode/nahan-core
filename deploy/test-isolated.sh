#!/bin/sh
set -eu

# Run on the isolated lab host against an archived checkout, never the live runtime directory.
root=${NAHAN_BUILD_ROOT:-/opt/nahan-core-build}
mkdir -p "$root/go-cache" "$root/mod-cache"
test -f "$root/source/go.mod"
docker run --rm --name nahan-core-build-test \
  --cpus=1 --memory=2g --memory-swap=2g \
  -e GOMAXPROCS=2 -e GOCACHE=/cache \
  -v "$root/source:/src" -v "$root/go-cache:/cache" \
  -v "$root/mod-cache:/go/pkg/mod" -w /src golang:1.26-alpine \
  sh -c 'go mod download && go run ./tools/xray-patch > /tmp/modfile &&
    go test -p 1 -modfile="$(cat /tmp/modfile)" ./utility/outbox ./api/nahan ./service/controller'
