#!/usr/bin/env bash
# run-libfuzzer.sh — Run all libFuzzer harnesses in parallel.
#
# Each harness runs in its own background process.
# Crashes land in crashes/raw/<harness>-<hash>.
# Coverage corpus is evolved in corpus/<harness>/.
#
# Usage:
#   ./run-libfuzzer.sh              # run forever
#   ./run-libfuzzer.sh --time 3600  # run for 1 hour per harness
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HARNESSES_DIR="$PROJECT_ROOT/harnesses"
CORPUS_DIR="$PROJECT_ROOT/corpus"
CRASH_DIR="$PROJECT_ROOT/crashes/raw"
BUILDS="$PROJECT_ROOT/builds"

# System llvm-symbolizer for inline ASan/UBSan stack trace symbolization.
# Try versioned names first (clang-18 installs llvm-symbolizer-18 etc.),
# then fall back to the unversioned alias managed by update-alternatives.
_sym=""
for _v in 20 19 18 17 16 15 14; do
    command -v "llvm-symbolizer-${_v}" &>/dev/null && { _sym="llvm-symbolizer-${_v}"; break; }
done
[[ -z "$_sym" ]] && _sym="$(command -v llvm-symbolizer 2>/dev/null || echo '')"

MAX_TIME=0   # 0 = run forever
for arg in "$@"; do
    case "$arg" in
        --time) shift; MAX_TIME="${1:-3600}" ;;
        --time=*) MAX_TIME="${arg#--time=}" ;;
    esac
done

mkdir -p "$CRASH_DIR" "$PROJECT_ROOT/coverage"

# ---------------------------------------------------------------------------
# Sanitizer environment
# ---------------------------------------------------------------------------
# detect_odr_violation=0: libsofthsm2.so embeds static libcrypto (so it is
# instrumented end-to-end), and the TLS harness also statically links
# libcrypto.  ASan sees the same OpenSSL globals twice and reports an ODR
# violation even though both copies are identical.  This is a structural
# false positive of the static-in-shared architecture, not a real bug.
# Memory-safety bugs (heap overflow, UAF, etc.) are still fully detected.
export ASAN_OPTIONS="halt_on_error=1:detect_leaks=1:symbolize=1:log_path=/tmp/asan:detect_odr_violation=0"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:symbolize=1"
[[ -n "$_sym" ]] && export ASAN_SYMBOLIZER_PATH="$_sym"
# Suppress known-benign OpenSSL global-singleton leaks (ENGINE_rdrand etc.)
# that appear at process exit and are not real bugs.
export LSAN_OPTIONS="suppressions=$PROJECT_ROOT/fuzzing/lsan.suppressions"
export LD_LIBRARY_PATH="$BUILDS/libfuzzer/lib/softhsm:${LD_LIBRARY_PATH:-}"

# ---------------------------------------------------------------------------
# Launch each harness
# ---------------------------------------------------------------------------
HARNESSES=(
    pkcs11_sign_fuzz
    pkcs11_decrypt_fuzz
    pkcs11_findobj_fuzz
    pkcs11_wrap_fuzz
    pkcs11_attrs_fuzz
    pkcs11_digest_fuzz
    pkcs11_multipart_fuzz
    pkcs11_keygen_fuzz
    libp11_evp_fuzz
    opensc_pkcs11_fuzz
    tls_pkcs11_fuzz
)

PIDS=()

for h in "${HARNESSES[@]}"; do
    binary="$HARNESSES_DIR/$h"
    [[ -x "$binary" ]] || { echo "SKIP: $binary not built"; continue; }

    corpus="$CORPUS_DIR/$(echo "$h" | sed 's/_fuzz//;s/_/-/g')"
    mkdir -p "$corpus"

    flags=(-max_len=65536 -rss_limit_mb=2048)
    [[ $MAX_TIME -gt 0 ]] && flags+=(-max_total_time="$MAX_TIME")

    echo "[start] $h → corpus=$corpus"
    "$binary" "${flags[@]}" \
        -artifact_prefix="$CRASH_DIR/${h}-" \
        "$corpus" \
        2>&1 | tee "$PROJECT_ROOT/coverage/${h}.log" &

    PIDS+=($!)
done

echo ""
echo "Running ${#PIDS[@]} harnesses (PIDs: ${PIDS[*]})"
echo "Crashes: $CRASH_DIR"
echo "Press Ctrl-C to stop all."
echo ""

# Wait for all or exit on any crash
wait "${PIDS[@]}"
