#!/usr/bin/env bash
# Static musl build of perch-collector with nDPI 5.0 linked in, for
# sideloading onto an x86_64 OpenWrt system that has no SDK at hand (an LXC
# gateway, a VM). Needs Docker; nothing is installed on the host. The result
# has no runtime dependencies at all: libpcap and libndpi are inside the binary.
#
#   scripts/build-static.sh [output]        # default: out/perch-collector-ndpi.static
#
# Environment: VERSION (baked into the start-up line, /healthz and the hello,
# default 1.0.0-rc.1-static), NDPI_TAG (git tag, default 5.0), GOARCH (default
# amd64), AGENTKIT (a local perch-agentkit checkout to build against instead
# of the published module; default ../perch-agentkit when it exists).
# Then, on the router: copy it to /usr/bin/perch-collector together with
# openwrt/perch-collector/files/* (see openwrt/README.md).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-out/perch-collector-ndpi.static}"
VERSION="${VERSION:-1.0.0-rc.1-static}"
NDPI_TAG="${NDPI_TAG:-5.0}"
GOARCH="${GOARCH:-amd64}"
AGENTKIT="${AGENTKIT:-}"
if [ -z "$AGENTKIT" ] && [ -f ../perch-agentkit/go.mod ]; then
  AGENTKIT="$(cd ../perch-agentkit && pwd)"
fi
mkdir -p "$(dirname "$OUT")"

# An unpublished kit is mounted and wired in with a container-side go.work;
# nothing is written into this checkout.
KIT_MOUNT=()
if [ -n "$AGENTKIT" ]; then
  KIT_MOUNT=(-v "$AGENTKIT":/agentkit:ro -e KIT=/agentkit)
  echo "building against the local kit in $AGENTKIT"
fi

docker run --rm -v "$PWD":/src -w /src "${KIT_MOUNT[@]}" -e CGO_ENABLED=1 -e GOARCH="$GOARCH" \
  -e GOFLAGS=-buildvcs=false -e VERSION="$VERSION" -e NDPI_TAG="$NDPI_TAG" -e OUT="$OUT" \
  golang:1.23-alpine sh -euc '
    apk add --no-cache gcc g++ musl-dev libpcap-dev git autoconf automake libtool make pkgconf linux-headers >/dev/null
    git clone -q --depth 1 --branch "$NDPI_TAG" https://github.com/ntop/nDPI /tmp/nDPI
    cd /tmp/nDPI && ./autogen.sh >/dev/null 2>&1 && ./configure --prefix=/usr/local --with-only-libndpi >/dev/null
    make -j"$(nproc)" >/dev/null && make install >/dev/null
    cd /src
    if [ -n "${KIT:-}" ]; then
      kit_version="$(sed -n "s|^[[:space:]]*github.com/capthndsme/perch-agentkit \(v[^ ]*\).*|\1|p" go.mod | head -n1)"
      printf "go 1.22.2\n\nuse (\n\t/src\n\t%s\n)\n\nreplace github.com/capthndsme/perch-agentkit %s => %s\n" "$KIT" "$kit_version" "$KIT" > /tmp/go.work
      export GOWORK=/tmp/go.work
    fi
    echo "libndpi $(pkg-config --modversion libndpi) (static)"
    go build -trimpath -tags ndpi -ldflags "-s -w -linkmode external -extldflags -static -X main.version=$VERSION" -o "$OUT" .
  '
file "$OUT" | grep -q "statically linked" && echo "built $OUT ($(stat -c %s "$OUT") bytes, static, version $VERSION)"
