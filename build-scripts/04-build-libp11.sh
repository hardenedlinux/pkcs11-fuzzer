#!/usr/bin/env bash
# 04-build-libp11.sh — Build libp11 (OpenSSL PKCS#11 engine) for one tree.
#
# Usage: ./04-build-libp11.sh <tree>
#   tree ∈ { libfuzzer, tsan }
#
# libp11 provides pkcs11.so — the OpenSSL ENGINE that delegates crypto ops
# to a PKCS#11 module (SoftHSM2 in our case).  It must be built against
# our sanitized OpenSSL so engine callbacks are fully instrumented.
set -euo pipefail
source "$(dirname "$0")/common.sh"
USE_UPSTREAM="${USE_UPSTREAM_LIBP11:-${USE_UPSTREAM:-0}}"
require_clang

TREE="${1:-}"
[[ -z "$TREE" ]] && { echo "Usage: $0 <libfuzzer|tsan>"; exit 1; }

PREFIX="$(get_tree_var "$TREE" PREFIX)"
CC="$(get_tree_var "$TREE" CC)"
CXX="$(get_tree_var "$TREE" CXX)"
CFLAGS="$(get_tree_var "$TREE" CFLAGS)"
LDFLAGS="$(get_tree_var "$TREE" LDFLAGS)"

banner "libp11 ${LIBP11_TAG} [${TREE}]"
echo "  prefix:  $PREFIX"
echo "  CC:      $CC"
echo "  CFLAGS:  $CFLAGS"

# ---------------------------------------------------------------------------
# 1. Source
# ---------------------------------------------------------------------------
clone_if_needed "$LIBP11_REPO" "$LIBP11_TAG" "$SRC_DIR/libp11"

cd "$SRC_DIR/libp11"
autoreconf -fi 2>/dev/null || autoreconf -i

# ---------------------------------------------------------------------------
# 2. Configure (per-tree build dir)
# ---------------------------------------------------------------------------
BUILD_DIR="$SRC_DIR/libp11/build-${TREE}"
ensure_clean_build_dir "$BUILD_DIR" "$CC" "$CFLAGS"
cd "$BUILD_DIR"

CC="$CC" \
CFLAGS="$CFLAGS -fno-omit-frame-pointer -I$PREFIX/include" \
LDFLAGS="-L$PREFIX/lib $LDFLAGS" \
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" \
"$SRC_DIR/libp11/configure" \
    --prefix="$PREFIX" \
    --with-pkcs11-module="$PREFIX/lib/softhsm/libsofthsm2.so"

# ---------------------------------------------------------------------------
# 3. Build + Install
# ---------------------------------------------------------------------------
make -j"$(nproc)"
make install

# ---------------------------------------------------------------------------
# 4. Verify
# ---------------------------------------------------------------------------
banner "libp11 [${TREE}] verification"
ENGINE_SO="$(ls "$PREFIX/lib/engines-"*/pkcs11.so 2>/dev/null | head -1 || \
             ls "$PREFIX/lib/libp11.so" 2>/dev/null || echo '')"
echo "  engine so: ${ENGINE_SO:-NOT FOUND}"
if [[ -n "$ENGINE_SO" ]]; then
    verify_sanitizer "$TREE" "$ENGINE_SO"
fi
write_built_stamp "$PREFIX" "libp11" "$LIBP11_TAG"
echo ""
echo "==> libp11 [${TREE}] complete."
