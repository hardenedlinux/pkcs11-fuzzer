#!/usr/bin/env bash
# 03-build-softhsm2.sh — Build SoftHSM2 for one sanitizer tree.
#
# Usage: ./03-build-softhsm2.sh <tree>
#   tree ∈ { libfuzzer, tsan }
#
# SoftHSM2 is our PKCS#11 backend. It must be built with the same sanitizer
# flags as everything else, because it's loaded via dlopen() at runtime —
# if it's uninstrumented, the fuzzer/sanitizer won't see bugs inside it.
#
# --with-crypto-backend=openssl uses the sanitized OpenSSL we built in step 2.
set -euo pipefail
source "$(dirname "$0")/common.sh"
USE_UPSTREAM="${USE_UPSTREAM_SOFTHSM2:-${USE_UPSTREAM:-0}}"
require_clang

TREE="${1:-}"
[[ -z "$TREE" ]] && { echo "Usage: $0 <libfuzzer|tsan>"; exit 1; }

PREFIX="$(get_tree_var "$TREE" PREFIX)"
CC="$(get_tree_var "$TREE" CC)"
CXX="$(get_tree_var "$TREE" CXX)"
CFLAGS="$(get_tree_var "$TREE" CFLAGS)"
CXXFLAGS="$(get_tree_var "$TREE" CXXFLAGS)"
LDFLAGS="$(get_tree_var "$TREE" LDFLAGS)"

banner "SoftHSM2 ${SOFTHSM2_TAG} [${TREE}]"
echo "  prefix:  $PREFIX"
echo "  CC:      $CC"
echo "  CFLAGS:  $CFLAGS"

# ---------------------------------------------------------------------------
# 1. Source
# ---------------------------------------------------------------------------
clone_if_needed "$SOFTHSM2_REPO" "$SOFTHSM2_TAG" "$SRC_DIR/softhsm2"

# ---------------------------------------------------------------------------
# 1a. Compatibility patch for OpenSSL 3.4+ / 4.x
#
# OpenSSL 3.4 moved asn1_string_st to internal headers, making the struct
# opaque.  SoftHSM2 2.6.1 accesses ->data directly in OSSLUtil.cpp.
# Replace with the public accessor ASN1_STRING_get0_data(), available since
# OpenSSL 1.1.0.  A null-check for the d2i result is also added.
#
# The patch is idempotent: `patch --forward` is a no-op if already applied.
# ---------------------------------------------------------------------------
PATCH_FILE="$SCRIPT_DIR/patches/softhsm2-asn1-opaque.patch"
if [[ -f "$PATCH_FILE" ]]; then
    echo "  [patch] applying softhsm2-asn1-opaque.patch"
    patch --forward --quiet -p1 -d "$SRC_DIR/softhsm2" < "$PATCH_FILE" \
        && echo "  [patch] applied" \
        || echo "  [patch] already applied (skipped)"
fi

cd "$SRC_DIR/softhsm2"

# autoreconf every time in case the clone is fresh
autoreconf -fi 2>/dev/null || autoreconf -i

# ---------------------------------------------------------------------------
# 2. Configure (per-tree build dir)
# ---------------------------------------------------------------------------
BUILD_DIR="$SRC_DIR/softhsm2/build-${TREE}"
ensure_clean_build_dir "$BUILD_DIR" "$CC" "$CFLAGS"
cd "$BUILD_DIR"

# ASan's LeakSanitizer fires during autoconf conftest runs that allocate
# OpenSSL EC key objects without freeing them (they're just feature probes).
# This makes autoconf think EC support is unavailable.  Suppress leaks
# during configure only; they're re-enabled for actual fuzzing runs via
# ASAN_OPTIONS in the fuzzing scripts.
export ASAN_OPTIONS="detect_leaks=0"
export UBSAN_OPTIONS="halt_on_error=0"

CC="$CC" CXX="$CXX" \
CFLAGS="$CFLAGS -fno-omit-frame-pointer -I$PREFIX/include" \
CXXFLAGS="$CXXFLAGS -fno-omit-frame-pointer -I$PREFIX/include" \
LDFLAGS="-L$PREFIX/lib $LDFLAGS" \
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" \
"$SRC_DIR/softhsm2/configure" \
    --prefix="$PREFIX" \
    --with-crypto-backend=openssl \
    --with-openssl="$PREFIX" \
    --enable-shared \
    --disable-static \
    --without-p11-kit   # prevent install to system /usr/share/p11-kit/modules/

# Reset ASan options for the actual build (leaks will be caught in harnesses)
unset ASAN_OPTIONS UBSAN_OPTIONS

# ---------------------------------------------------------------------------
# 3. Build + Install
# ---------------------------------------------------------------------------
make -j"$(nproc)"
make install

# ---------------------------------------------------------------------------
# 4. Write a default softhsm2.conf pointing at our token dir
# ---------------------------------------------------------------------------
CONF_DIR="$PREFIX/etc/softhsm2"
TOKEN_DIR="$PREFIX/var/lib/softhsm/tokens"
mkdir -p "$TOKEN_DIR"
cat > "$PREFIX/etc/softhsm2.conf" <<EOF
# SoftHSM2 configuration — ${TREE} tree
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

# ---------------------------------------------------------------------------
# 5. Verify
# ---------------------------------------------------------------------------
banner "SoftHSM2 [${TREE}] verification"
# detect_odr_violation=0: softhsm2-util links both libsofthsm2.so (which
# embeds static libcrypto.a) and libcrypto.a directly, so OpenSSL globals
# like ossl_sm2_asn1_meth appear in both.  ASan reports this as an ODR
# violation even though the two copies are byte-for-byte identical and cause
# no memory unsafety.  Suppress the false positive here; the sanitizer
# instrumentation in libsofthsm2.so itself is verified below by nm.
SOFTHSM2_CONF="$PREFIX/etc/softhsm2.conf" \
ASAN_OPTIONS="detect_odr_violation=0:halt_on_error=0:detect_leaks=0" \
UBSAN_OPTIONS="halt_on_error=0" \
    "$PREFIX/bin/softhsm2-util" --show-slots 2>&1 | head -5
echo "  module: $(ls "$PREFIX/lib/softhsm/libsofthsm2.so")"
verify_sanitizer "$TREE" "$PREFIX/lib/softhsm/libsofthsm2.so"
write_built_stamp "$PREFIX" "softhsm2" "$SOFTHSM2_TAG"
echo ""
echo "==> SoftHSM2 [${TREE}] complete."
