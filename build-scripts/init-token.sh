#!/usr/bin/env bash
# init-token.sh — Initialize a SoftHSM2 PKCS#11 token with test keys
#                 and snapshot it for reproducible fuzzing.
#
# Uses the libfuzzer tree's tools (same sanitizer flags as the harnesses).
# The snapshot in token-template/ is restored by each harness at startup
# via LLVMFuzzerInitialize(), giving every fuzzing run a clean, known state.
#
# Keys created:
#   id=01  RSA-2048 key pair   label=rsa-fuzz-key
#   id=02  EC P-256 key pair   label=ec-fuzz-key
#   id=03  AES-256 secret key  label=aes-fuzz-key
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_clang

PREFIX="$LIBFUZZER_PREFIX"
MODULE="$PREFIX/lib/softhsm/libsofthsm2.so"
SOFTHSM2_UTIL="$PREFIX/bin/softhsm2-util"
PKCS11_TOOL="$PREFIX/bin/pkcs11-tool"
TOKEN_TEMPLATE="$PROJECT_ROOT/token-template"

TOKEN_LABEL="fuzz-token"
PIN="1234"
SO_PIN="12345678"

banner "SoftHSM2 Token Initialization"
echo "  prefix:    $PREFIX"
echo "  module:    $MODULE"
echo "  template:  $TOKEN_TEMPLATE"
echo "  label:     $TOKEN_LABEL"
echo "  PIN:       $PIN"

[[ -x "$SOFTHSM2_UTIL" ]] || { echo "ERROR: softhsm2-util not found. Run build-all.sh first."; exit 1; }
[[ -x "$PKCS11_TOOL" ]]   || { echo "ERROR: pkcs11-tool not found. Run build-all.sh first."; exit 1; }

# ---------------------------------------------------------------------------
# 1. Fresh working token directory
# ---------------------------------------------------------------------------
WORK_TOKEN_DIR="$(mktemp -d)"
WORK_CONF="$(mktemp)"

cat > "$WORK_CONF" <<EOF
directories.tokendir = $WORK_TOKEN_DIR
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

export SOFTHSM2_CONF="$WORK_CONF"

# ---------------------------------------------------------------------------
# 2. Initialize token
# Set UBSAN_OPTIONS=halt_on_error=0 for setup steps only — SoftHSM2 has a
# known-benign function-pointer type mismatch in its factory pattern that
# UBSan's -fsanitize=function would flag.  We suppress halt_on_error here
# so initialization proceeds; the finding is noted but not critical for setup.
# ---------------------------------------------------------------------------
export ASAN_OPTIONS="halt_on_error=0:detect_leaks=0:detect_odr_violation=0"
export UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1"

echo ""
echo "--- Initializing token '$TOKEN_LABEL' ---"
"$SOFTHSM2_UTIL" --init-token --slot 0 \
    --label "$TOKEN_LABEL" \
    --pin "$PIN" \
    --so-pin "$SO_PIN"

# Resolve the slot the token was assigned to (SoftHSM2 re-numbers after init)
SLOT=$("$SOFTHSM2_UTIL" --show-slots 2>/dev/null \
        | awk '/Label:.*fuzz-token/{found=1} found && /Slot/{print $2; exit}' || true)
# Fallback: use label-based lookup via pkcs11-tool
P11_COMMON=(--module "$MODULE" --pin "$PIN" --token-label "$TOKEN_LABEL")

# ---------------------------------------------------------------------------
# 3. Generate key pairs
# ---------------------------------------------------------------------------
echo ""
echo "--- Generating RSA-2048 key pair (id=01) ---"
"$PKCS11_TOOL" "${P11_COMMON[@]}" \
    --keypairgen --key-type RSA:2048 \
    --id 01 --label rsa-fuzz-key

echo ""
echo "--- Generating EC P-256 key pair (id=02) ---"
"$PKCS11_TOOL" "${P11_COMMON[@]}" \
    --keypairgen --key-type EC:prime256v1 \
    --id 02 --label ec-fuzz-key

echo ""
echo "--- Generating AES-256 secret key (id=03) ---"
"$PKCS11_TOOL" "${P11_COMMON[@]}" \
    --keygen --key-type AES:32 \
    --id 03 --label aes-fuzz-key

# ---------------------------------------------------------------------------
# 4. Snapshot
# ---------------------------------------------------------------------------
echo ""
echo "--- Snapshotting token → $TOKEN_TEMPLATE ---"
rm -rf "$TOKEN_TEMPLATE"
mkdir -p "$TOKEN_TEMPLATE"

# Copy the token DB files
cp -a "$WORK_TOKEN_DIR/." "$TOKEN_TEMPLATE/"
# Store the conf template (paths will be rewritten by harnesses at runtime)
cp "$WORK_CONF" "$TOKEN_TEMPLATE/softhsm2.conf.template"

# Store PIN for harnesses to use
echo "$PIN"    > "$TOKEN_TEMPLATE/pin.txt"
echo "$SO_PIN" > "$TOKEN_TEMPLATE/so-pin.txt"
chmod 600 "$TOKEN_TEMPLATE/pin.txt" "$TOKEN_TEMPLATE/so-pin.txt"

# SHA-256 manifest for integrity checking
(cd "$TOKEN_TEMPLATE" && find . -type f | sort | xargs sha256sum) \
    > "$TOKEN_TEMPLATE/MANIFEST.sha256"

echo "  Snapshot checksum:"
sha256sum "$TOKEN_TEMPLATE/MANIFEST.sha256"

# ---------------------------------------------------------------------------
# 5. Verify: list objects from snapshot
# ---------------------------------------------------------------------------
echo ""
echo "--- Objects in token ---"
cp "$WORK_CONF" /tmp/verify-softhsm2.conf
"$PKCS11_TOOL" "${P11_COMMON[@]}" --list-objects

# ---------------------------------------------------------------------------
# 6. Cleanup temp files
# ---------------------------------------------------------------------------
rm -f "$WORK_CONF" /tmp/verify-softhsm2.conf
rm -rf "$WORK_TOKEN_DIR"

banner "Token init complete"
echo "  template: $TOKEN_TEMPLATE"
echo "  keys:     RSA-2048 (id=01), EC P-256 (id=02), AES-256 (id=03)"
echo ""
echo "  Harnesses restore this snapshot to a per-run tmpfs path in"
echo "  LLVMFuzzerInitialize() before any PKCS#11 calls."
