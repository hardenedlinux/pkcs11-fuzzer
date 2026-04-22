#!/usr/bin/env bash
# 05-build-opensc.sh — Build OpenSC (pkcs11-tool + libopensc) for one tree.
#
# Usage: ./05-build-opensc.sh <tree>
#   tree ∈ { libfuzzer, tsan }
#
# OpenSC provides pkcs11-tool and libopensc.so
# which handles object/attribute parsing.  Both must be built with sanitizer
# flags so the full code path is instrumented end-to-end.
set -euo pipefail
source "$(dirname "$0")/common.sh"
USE_UPSTREAM="${USE_UPSTREAM_OPENSC:-${USE_UPSTREAM:-0}}"
require_clang

TREE="${1:-}"
[[ -z "$TREE" ]] && { echo "Usage: $0 <libfuzzer|tsan>"; exit 1; }

PREFIX="$(get_tree_var "$TREE" PREFIX)"
CC="$(get_tree_var "$TREE" CC)"
CXX="$(get_tree_var "$TREE" CXX)"
CFLAGS="$(get_tree_var "$TREE" CFLAGS)"
CXXFLAGS="$(get_tree_var "$TREE" CXXFLAGS)"
LDFLAGS="$(get_tree_var "$TREE" LDFLAGS)"

banner "OpenSC ${OPENSC_TAG} [${TREE}]"
echo "  prefix:  $PREFIX"
echo "  CC:      $CC"
echo "  CFLAGS:  $CFLAGS"

# ---------------------------------------------------------------------------
# 1. Source
# ---------------------------------------------------------------------------
clone_if_needed "$OPENSC_REPO" "$OPENSC_TAG" "$SRC_DIR/opensc"

# ---------------------------------------------------------------------------
# 1a. Mock PC/SC for fuzzing
# ---------------------------------------------------------------------------
PATCH_FILE="$SCRIPT_DIR/patches/opensc-mock-pcsc.patch"
if [[ -f "$PATCH_FILE" ]]; then
    echo "  [patch] applying opensc-mock-pcsc.patch"
    patch --forward --quiet -p1 -d "$SRC_DIR/opensc" < "$PATCH_FILE" \
        && echo "  [patch] applied" \
        || echo "  [patch] already applied (skipped)"
fi

# 1b. Fix for NULL deref in mechanism lookup
# ---------------------------------------------------------------------------
PATCH_FILE_FIX="$SCRIPT_DIR/patches/opensc-fix-null-deref.patch"
if [[ -f "$PATCH_FILE_FIX" ]]; then
    echo "  [patch] applying opensc-fix-null-deref.patch"
    patch --forward --quiet -p1 -d "$SRC_DIR/opensc" < "$PATCH_FILE_FIX" \
        && echo "  [patch] applied" \
        || echo "  [patch] already applied (skipped)"
fi

cd "$SRC_DIR/opensc"
autoreconf -fi 2>/dev/null || autoreconf -i

# ---------------------------------------------------------------------------
# 2. Configure (per-tree build dir)
# ---------------------------------------------------------------------------
BUILD_DIR="$SRC_DIR/opensc/build-${TREE}"
ensure_clean_build_dir "$BUILD_DIR" "$CC" "$CFLAGS"
cd "$BUILD_DIR"

CC="$CC" CXX="$CXX" \
CFLAGS="$CFLAGS -fno-omit-frame-pointer -I$PREFIX/include" \
CXXFLAGS="$CXXFLAGS -fno-omit-frame-pointer -I$PREFIX/include" \
LDFLAGS="-L$PREFIX/lib $LDFLAGS \
    -Wl,--whole-archive $PREFIX/lib/libcrypto.a $PREFIX/lib/libssl.a -Wl,--no-whole-archive" \
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" \
"$SRC_DIR/opensc/configure" \
    --prefix="$PREFIX" \
    --enable-pcsc \
    --disable-notify \
    --disable-doc \
    --enable-shared \
    --disable-static \
    --without-xsl-stylesheetsdir

# ---------------------------------------------------------------------------
# 3. Build + Install
# Skip the doc install step (xsl/man page generation fails without docs).
# Install only what we need: programs and libraries.
# ---------------------------------------------------------------------------
make -j"$(nproc)"
make install-pkgincludeHEADERS install-pkgconfigDATA 2>/dev/null || true  # headers + pkgconfig
# Redirect p11-kit module registration file to our prefix instead of the
# system-wide /usr/share/p11-kit/modules (which requires root).
# p11kitdir is the automake variable that controls the install destination.
mkdir -p "$PREFIX/share/p11-kit/modules"
make -C src install p11kitdir="$PREFIX/share/p11-kit/modules"
make -C etc install 2>/dev/null || true  # config files if any

# ---------------------------------------------------------------------------
# 4. Verify
# ---------------------------------------------------------------------------
banner "OpenSC [${TREE}] verification"
"$PREFIX/bin/pkcs11-tool" --help 2>&1 | head -1 || true
echo "  pkcs11-tool: $(ls "$PREFIX/bin/pkcs11-tool")"
OPENSC_SO="$(ls "$PREFIX/lib/libopensc.so"* 2>/dev/null | head -1)"
echo "  libopensc:   ${OPENSC_SO:-NOT FOUND}"
verify_sanitizer "$TREE" "$OPENSC_SO"
write_built_stamp "$PREFIX" "opensc" "$OPENSC_TAG"
echo ""
echo "==> OpenSC [${TREE}] complete."
