#!/usr/bin/env bash
# 02-build-openssl.sh — Build OpenSSL for one sanitizer tree.
#
# Usage: ./02-build-openssl.sh <tree>
#   tree ∈ { libfuzzer, tsan }
#
# OpenSSL is built as a static library (no-shared) with -fPIC so that
# SoftHSM2, libp11, and OpenSC (all shared libs) can link it in.
# enable-deprecated keeps the ENGINE API alive (required by libp11 0.4.12).
set -euo pipefail
source "$(dirname "$0")/common.sh"
USE_UPSTREAM="${USE_UPSTREAM_OPENSSL:-${USE_UPSTREAM:-0}}"
require_clang

TREE="${1:-}"
[[ -z "$TREE" ]] && { echo "Usage: $0 <libfuzzer|tsan>"; exit 1; }

PREFIX="$(get_tree_var "$TREE" PREFIX)"
CC="$(get_tree_var "$TREE" CC)"
CXX="$(get_tree_var "$TREE" CXX)"
CFLAGS="$(get_tree_var "$TREE" CFLAGS)"
CXXFLAGS="$(get_tree_var "$TREE" CXXFLAGS)"
LDFLAGS="$(get_tree_var "$TREE" LDFLAGS)"


banner "OpenSSL ${OPENSSL_TAG} [${TREE}]"
echo "  prefix:  $PREFIX"
echo "  CC:      $CC"
echo "  CFLAGS:  $CFLAGS"
echo "  LDFLAGS: $LDFLAGS"

# ---------------------------------------------------------------------------
# 1. Source (shared across all trees — builds happen in a per-tree build dir)
# ---------------------------------------------------------------------------
clone_if_needed "$OPENSSL_REPO" "$OPENSSL_TAG" "$SRC_DIR/openssl"

# Per-tree build directory so trees don't overwrite each other
BUILD_DIR="$SRC_DIR/openssl/build-${TREE}"
ensure_clean_build_dir "$BUILD_DIR" "$CC" "$CFLAGS"
cd "$BUILD_DIR"

# ---------------------------------------------------------------------------
# 2. Configure
# OpenSSL's Configure is a Perl script, not autoconf.  It accepts compiler
# and linker settings as named make-variable arguments (CC=, CFLAGS=, LDFLAGS=)
# OR as positional raw flags — but NOT both styles at the same time.
# We use the named-argument style throughout so all settings are explicit.
# -fPIC is merged into CFLAGS so downstream shared libs can link the static
# archive.
# ---------------------------------------------------------------------------
"$SRC_DIR/openssl/Configure" \
    "CC=$CC" \
    "CFLAGS=$CFLAGS -fPIC" \
    "LDFLAGS=$LDFLAGS" \
    linux-x86_64 \
    --prefix="$PREFIX" \
    --libdir=lib \
    --openssldir="$PREFIX/etc/ssl" \
    no-shared \
    no-fuzz-libfuzzer \
    enable-deprecated

# ---------------------------------------------------------------------------
# 3. Build + Install
# libfuzzer tree: build everything (libs + openssl binary for init-token.sh)
# tsan tree: build only the libraries to avoid TSan conflicts with OpenSSL's
#            test helper binaries.
# ---------------------------------------------------------------------------
if [[ "$TREE" == "libfuzzer" ]]; then
    make -j"$(nproc)"
    make install_sw
else
    # Build only static libs; skip apps, tests, and fuzz targets
    make -j"$(nproc)" build_libs
    make install_dev    # installs headers, static libs, pkgconfig
fi

# ---------------------------------------------------------------------------
# 4. Verify
# ---------------------------------------------------------------------------
banner "OpenSSL [${TREE}] verification"
if [[ -x "$PREFIX/bin/openssl" ]]; then
    UBSAN_OPTIONS=halt_on_error=0 ASAN_OPTIONS=halt_on_error=0 \
        "$PREFIX/bin/openssl" version 2>/dev/null || true
fi
echo "  static libs: $(ls "$PREFIX/lib"/libssl.a "$PREFIX/lib"/libcrypto.a)"
verify_sanitizer "$TREE" "$PREFIX/lib/libssl.a"
verify_sanitizer "$TREE" "$PREFIX/lib/libcrypto.a"
write_built_stamp "$PREFIX" "openssl" "$OPENSSL_TAG"
echo ""
echo "==> OpenSSL [${TREE}] complete."
