#!/usr/bin/env bash
# build-all.sh — One-shot build of the entire fuzzing toolchain.
#
# Runs every step in the correct order:
#   02–05 × 2 trees → OpenSSL, SoftHSM2, libp11, OpenSC
#   init → SoftHSM2 token initialization + snapshot
#
# All components are compiled with system Clang using -fsanitize=fuzzer-no-link
# plus ASan+UBSan (libfuzzer tree) or TSan (tsan tree).
#
# Designed to be idempotent: already-cloned sources are skipped,
# already-installed components are not rebuilt (unless you rm -rf the
# corresponding builds/<tree>/ directory).
#
# Usage:
#   ./build-all.sh                # build everything at pinned versions
#   ./build-all.sh --upstream    # clone components from upstream HEAD instead
#                                 # of pinned tags (use when a component has
#                                 # not cut a release with the fix you need)
set -euo pipefail
source "$(dirname "$0")/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build the complete pkcs11-fuzzer toolchain from source using system Clang/LLVM.

Options:
  -h, --help                Show this help message and exit
  --upstream                Clone ALL components from upstream HEAD instead of
                            pinned tags.
  --upstream-openssl        Use upstream HEAD for OpenSSL only.
  --upstream-softhsm2       Use upstream HEAD for SoftHSM2 only.
  --upstream-libp11         Use upstream HEAD for libp11 only.
  --upstream-opensc         Use upstream HEAD for OpenSC only.
  --coverage-tree           Additionally build a coverage-instrumented tree at
                            builds/coverage/ using -fprofile-instr-generate +
                            -fcoverage-mapping.  Required for source-level
                            coverage of target libraries via gen-coverage.sh.
                            Can be combined with --upstream-* flags.

  Flags may be combined freely:
    $(basename "$0") --upstream-openssl --upstream-opensc

Prerequisites (install once):
  sudo apt-get install clang lld
  # or from https://apt.llvm.org for a specific version:
  sudo apt-get install clang-18 lld-18

Pinned versions (from build-scripts/common.sh):
  OpenSSL   $OPENSSL_TAG
  SoftHSM2  $SOFTHSM2_TAG
  libp11    $LIBP11_TAG
  OpenSC    $OPENSC_TAG

Compiler: $OUR_CC ($(${OUR_CC} --version 2>/dev/null | head -1 || echo 'not found'))
EOF
}

USE_UPSTREAM=0
USE_UPSTREAM_OPENSSL=0
USE_UPSTREAM_SOFTHSM2=0
USE_UPSTREAM_LIBP11=0
USE_UPSTREAM_OPENSC=0
BUILD_COVERAGE_TREE=0

for arg in "$@"; do
    case "$arg" in
        -h|--help)             usage; exit 0 ;;
        --upstream)            USE_UPSTREAM=1
                               USE_UPSTREAM_OPENSSL=1
                               USE_UPSTREAM_SOFTHSM2=1
                               USE_UPSTREAM_LIBP11=1
                               USE_UPSTREAM_OPENSC=1 ;;
        --upstream-openssl)    USE_UPSTREAM_OPENSSL=1 ;;
        --upstream-softhsm2)   USE_UPSTREAM_SOFTHSM2=1 ;;
        --upstream-libp11)     USE_UPSTREAM_LIBP11=1 ;;
        --upstream-opensc)     USE_UPSTREAM_OPENSC=1 ;;
        --coverage-tree)       BUILD_COVERAGE_TREE=1 ;;
        *) echo "Unknown option: $arg  (try --help)" >&2; exit 1 ;;
    esac
done
# Export all upstream flags so component scripts can read them.
# Each script overrides the global USE_UPSTREAM with its own component flag.
export USE_UPSTREAM
export USE_UPSTREAM_OPENSSL USE_UPSTREAM_SOFTHSM2 USE_UPSTREAM_LIBP11 USE_UPSTREAM_OPENSC

require_clang

START_TIME=$(date +%s)

banner "Fuzzing Toolchain — Full Build"
echo "  PROJECT_ROOT: $PROJECT_ROOT"
echo "  Compiler:     $("$OUR_CC" --version | head -1)"
_any_upstream=$(( USE_UPSTREAM_OPENSSL | USE_UPSTREAM_SOFTHSM2 | USE_UPSTREAM_LIBP11 | USE_UPSTREAM_OPENSC ))
if [[ $_any_upstream -eq 0 ]]; then
echo "  OpenSSL:      $OPENSSL_TAG"
echo "  SoftHSM2:     $SOFTHSM2_TAG"
echo "  libp11:       $LIBP11_TAG"
echo "  OpenSC:       $OPENSC_TAG"
else
echo "  OpenSSL:      $([[ $USE_UPSTREAM_OPENSSL  -eq 1 ]] && echo 'upstream HEAD' || echo "$OPENSSL_TAG")"
echo "  SoftHSM2:     $([[ $USE_UPSTREAM_SOFTHSM2 -eq 1 ]] && echo 'upstream HEAD' || echo "$SOFTHSM2_TAG")"
echo "  libp11:       $([[ $USE_UPSTREAM_LIBP11   -eq 1 ]] && echo 'upstream HEAD' || echo "$LIBP11_TAG")"
echo "  OpenSC:       $([[ $USE_UPSTREAM_OPENSC   -eq 1 ]] && echo 'upstream HEAD' || echo "$OPENSC_TAG")"
fi
echo "  CPU cores:    $(nproc)"
echo ""

SCRIPT_DIR_ABS="$(cd "$(dirname "$0")" && pwd)"

run_step() {
    local script="$1"; shift
    echo ""
    echo ">>> Running $script $*"
    bash "$SCRIPT_DIR_ABS/$script" "$@"
}

# ---------------------------------------------------------------------------
# Per-tree builds
# ---------------------------------------------------------------------------
for TREE in libfuzzer tsan; do
    PREFIX="$(get_tree_var "$TREE" PREFIX)"

    if built_stamp_ok "$PREFIX" "openssl" "$OPENSSL_TAG" "$USE_UPSTREAM_OPENSSL"; then
        echo "[skip] OpenSSL [$TREE] already at expected version"
    else
        run_step 02-build-openssl.sh "$TREE"
    fi

    if built_stamp_ok "$PREFIX" "softhsm2" "$SOFTHSM2_TAG" "$USE_UPSTREAM_SOFTHSM2"; then
        echo "[skip] SoftHSM2 [$TREE] already at expected version"
    else
        run_step 03-build-softhsm2.sh "$TREE"
    fi

    if built_stamp_ok "$PREFIX" "libp11" "$LIBP11_TAG" "$USE_UPSTREAM_LIBP11"; then
        echo "[skip] libp11 [$TREE] already at expected version"
    else
        run_step 04-build-libp11.sh "$TREE"
    fi

    if built_stamp_ok "$PREFIX" "opensc" "$OPENSC_TAG" "$USE_UPSTREAM_OPENSC"; then
        echo "[skip] OpenSC [$TREE] already at expected version"
    else
        run_step 05-build-opensc.sh "$TREE"
    fi
done

# ---------------------------------------------------------------------------
# Coverage tree (optional — only built with --coverage-tree)
# Builds all components with -fprofile-instr-generate -fcoverage-mapping so
# gen-coverage.sh can produce per-source-line coverage across target libraries.
# ---------------------------------------------------------------------------
if [[ $BUILD_COVERAGE_TREE -eq 1 ]]; then
    banner "Coverage Tree Build"
    echo "  Prefix: $(get_tree_var coverage PREFIX)"
    echo ""
    PREFIX_COV="$(get_tree_var coverage PREFIX)"
    for COMP_SCRIPT in 02-build-openssl.sh 03-build-softhsm2.sh \
                        04-build-libp11.sh  05-build-opensc.sh; do
        run_step "$COMP_SCRIPT" coverage
    done
fi

# ---------------------------------------------------------------------------
# Token init
# ---------------------------------------------------------------------------
if [[ -d "$PROJECT_ROOT/token-template" && \
      "$(ls -A "$PROJECT_ROOT/token-template")" ]]; then
    echo "[skip] token-template already populated"
else
    run_step init-token.sh
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
banner "Build complete in $(( ELAPSED / 60 ))m $(( ELAPSED % 60 ))s"
echo ""
echo "  Compiler: $("$OUR_CC" --version | head -1)"
echo ""
echo "  Sanitizer trees:"
for TREE in libfuzzer tsan; do
    echo "    [$TREE] $(get_tree_var "$TREE" PREFIX)"
done
if [[ $BUILD_COVERAGE_TREE -eq 1 ]]; then
    echo "  Coverage tree: $(get_tree_var coverage PREFIX)"
fi
echo ""
echo "  Token snapshot: $PROJECT_ROOT/token-template/"
echo ""
echo "Next steps:"
echo "  make -C harnesses/               # compile fuzz harnesses"
echo "  make -C harnesses/ smoke-test    # quick 10-second sanity check"
echo "  fuzzing/run-libfuzzer.sh         # start libFuzzer campaign"
echo "  screen -dmS fuzz bash fuzzing/continuous.sh   # run continuously"
echo ""
echo "  # Code coverage (seed corpus gives baseline; run after fuzzing for"
echo "  # meaningful numbers):"
if [[ $BUILD_COVERAGE_TREE -eq 1 ]]; then
echo "  make -C harnesses/ coverage      # FULL mode: OpenSSL+SoftHSM2+libp11+OpenSC"
echo "  bash tools/show-coverage         # print coverage trend table"
else
echo "  make -C harnesses/ seeds      # Generate seeds"
echo "  make -C harnesses/ coverage      # harness-only coverage (no coverage tree)"
echo "  # For full target-library coverage, rebuild with --coverage-tree:"
echo "  # bash build-scripts/build-all.sh --coverage-tree"
fi
echo "  tail -f coverage/<harness>.log | grep -E 'NEW|PULSE'  # real-time cov growth"
