#!/usr/bin/env bash
# Build OpenSSL 4.1 into target/ and run the dimpl <-> OpenSSL DTLS 1.3 interop tests.
#
#   scripts/openssl-4.1-interop.sh                 # all interop tests
#   scripts/openssl-4.1-interop.sh key_update      # filtered by test name
#
# OPENSSL_41_VERSION picks another 4.1 pre-release or release tag.
set -euo pipefail

VERSION="${OPENSSL_41_VERSION:-4.1.0-beta2}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/target/openssl-$VERSION"
PREFIX="$WORK/prefix"
TARBALL="openssl-$VERSION.tar.gz"
URL="https://github.com/openssl/openssl/releases/download/openssl-$VERSION/$TARBALL"

# Keep the static libraries linkable by Rust's default macOS deployment target.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"

if [ ! -f "$PREFIX/lib/libssl.a" ]; then
    mkdir -p "$WORK"
    cd "$WORK"
    [ -f "$TARBALL" ] || curl -fsSL "$URL" -o "$TARBALL"
    curl -fsSL "$URL.sha256" -o "$TARBALL.sha256"
    expected="$(awk '{print $1}' "$TARBALL.sha256")"
    actual="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
        echo "SHA-256 mismatch for $TARBALL: expected $expected, got $actual" >&2
        exit 1
    fi
    rm -rf "openssl-$VERSION"
    tar xzf "$TARBALL"
    cd "openssl-$VERSION"
    ./Configure no-shared no-tests no-docs \
        --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib
    make -j"$(getconf _NPROCESSORS_ONLN)"
    make install_sw
fi

export OPENSSL_NO_VENDOR=1
export OPENSSL_DIR="$PREFIX"
export OPENSSL_STATIC=1
export DIMPL_REQUIRE_OPENSSL_DTLS13=1
# A separate target dir avoids rebuilding the vendored OpenSSL for normal runs.
export CARGO_TARGET_DIR="$ROOT/target/interop-openssl-$VERSION"

cd "$ROOT"
cargo test --test dtls13_ossl -- "$@"
