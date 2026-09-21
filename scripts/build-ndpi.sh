#!/usr/bin/env bash
# Build nDPI 5.0 (library only) into a prefix, for machines whose distro
# libndpi is older than the 5.0 that perch-collector's cgo binding requires.
#
#   scripts/build-ndpi.sh [prefix]      # default: $HOME/.local/ndpi5
#
# Then: make build-ndpi NDPI_PREFIX=<prefix>   (or export the two
# variables printed at the end for plain `go build -tags ndpi`).
#
# Environment: NDPI_TAG (git tag, default 5.0), NDPI_SRC (checkout dir,
# default ${TMPDIR:-/tmp}/nDPI-<tag>), JOBS (make -j, default nproc).
set -euo pipefail

PREFIX="${1:-$HOME/.local/ndpi5}"
TAG="${NDPI_TAG:-5.0}"
REPO="${NDPI_REPO:-https://github.com/ntop/nDPI}"
SRC="${NDPI_SRC:-${TMPDIR:-/tmp}/nDPI-$TAG}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

for tool in git autoconf automake libtoolize make gcc pkg-config; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "build-ndpi: $tool not found (Debian/Ubuntu: apt install git autoconf automake libtool build-essential pkg-config)" >&2
    exit 1
  }
done

case "$PREFIX" in
  /*) ;;
  *) PREFIX="$PWD/$PREFIX" ;;
esac

if [ ! -d "$SRC/.git" ]; then
  echo "build-ndpi: cloning $REPO at tag $TAG into $SRC"
  git clone --depth 1 --branch "$TAG" "$REPO" "$SRC"
else
  echo "build-ndpi: reusing checkout $SRC ($(git -C "$SRC" describe --tags --always))"
fi

cd "$SRC"
./autogen.sh                    # generates ./configure only; nDPI 5 deliberately doesn't run it
./configure --prefix="$PREFIX" --with-only-libndpi
make -j"$JOBS"
make install

PC="$PREFIX/lib/pkgconfig"
VERSION="$(PKG_CONFIG_PATH="$PC" pkg-config --modversion libndpi)"

cat <<MSG

build-ndpi: nDPI $VERSION installed in $PREFIX

  make build-ndpi NDPI_PREFIX=$PREFIX
  make test-ndpi  NDPI_PREFIX=$PREFIX

or, for plain go commands (build and run):

  export PKG_CONFIG_PATH=$PC\${PKG_CONFIG_PATH:+:\$PKG_CONFIG_PATH}
  export LD_LIBRARY_PATH=$PREFIX/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}

A binary built this way loads libndpi.so.5 from $PREFIX/lib at run
time, so LD_LIBRARY_PATH (or an ld.so.conf entry) is needed there too.
MSG
