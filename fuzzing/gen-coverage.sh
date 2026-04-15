#!/usr/bin/env bash
# gen-coverage.sh — Generate Clang source-based coverage reports.
#
# Two modes, selected automatically:
#
#   FULL mode (builds/coverage/ exists):
#     Uses the dedicated coverage-instrumented build tree to report per-source-
#     line coverage across ALL target libraries — OpenSSL, SoftHSM2, libp11,
#     OpenSC.  Build the coverage tree first:
#
#       bash build-scripts/build-all.sh --coverage-tree
#       bash fuzzing/gen-coverage.sh      # then run this
#
#     Output: coverage/<harness>/index.html  (full target-library breakdown)
#             coverage/coverage.log          (trending data)
#
#   HARNESS-ONLY mode (no coverage tree):
#     Falls back to the libfuzzer sanitizer tree.  Only the harness source
#     files (common.h + each .c) appear in the report.  This mode is retained
#     for quick smoke-checks without needing a separate build.
#
#     Output: coverage/<harness>/index.html  (harness code only, ~100-200 lines)
#
# In both modes the corpus must contain evolved inputs to show meaningful
# coverage growth over seed-only results.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILDS="$PROJECT_ROOT/builds"
HARNESSES_DIR="$PROJECT_ROOT/harnesses"
CORPUS_DIR="$PROJECT_ROOT/corpus"
COV_DIR="$PROJECT_ROOT/coverage"

COV_PREFIX="$BUILDS/coverage"
LF_PREFIX="$BUILDS/libfuzzer"

# ---------------------------------------------------------------------------
# Locate system Clang and LLVM coverage tools
# ---------------------------------------------------------------------------
_find_tool() {
    local name="$1"
    for ver in 20 19 18 17 16 15 14; do
        command -v "${name}-${ver}" &>/dev/null && { echo "${name}-${ver}"; return; }
    done
    command -v "$name" 2>/dev/null || echo ""
}

CC="$(_find_tool clang)"
LLVM_PROFDATA="$(_find_tool llvm-profdata)"
LLVM_COV="$(_find_tool llvm-cov)"

for _tool in "$CC" "$LLVM_PROFDATA" "$LLVM_COV"; do
    if [[ -z "$_tool" ]]; then
        echo "ERROR: clang, llvm-profdata, or llvm-cov not found." >&2
        echo "       Install: sudo apt-get install clang llvm" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Detect which mode to use
# ---------------------------------------------------------------------------
FULL_MODE=0
if [[ -d "$COV_PREFIX/lib/softhsm" && -f "$COV_PREFIX/lib/libcrypto.a" ]]; then
    FULL_MODE=1
fi

if [[ $FULL_MODE -eq 1 ]]; then
    echo "Coverage mode: FULL (target-library source coverage)"
    echo "  Coverage tree: $COV_PREFIX"
    COV_LIB="$COV_PREFIX"
else
    echo "Coverage mode: HARNESS-ONLY (harness source coverage)"
    echo "  No coverage tree found at $COV_PREFIX"
    echo "  To get full target-library coverage, run:"
    echo "    bash build-scripts/build-all.sh --coverage-tree"
    echo "    bash fuzzing/gen-coverage.sh"
    COV_LIB="$LF_PREFIX"
fi
echo ""

mkdir -p "$COV_DIR"

# TLS harness excluded: it links OpenSSL statically (complex object list).
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
)

for h in "${HARNESSES[@]}"; do
    echo "=== Coverage: $h ==="

    corpus="$CORPUS_DIR/$(echo "$h" | sed 's/_fuzz//;s/_/-/g')"
    if [[ ! -d "$corpus" ]] || [[ -z "$(ls -A "$corpus" 2>/dev/null)" ]]; then
        echo "  No corpus — skipping"
        continue
    fi

    build_dir="$COV_DIR/build-$h"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cov_bin="$build_dir/${h}.cov"

    # Harness-specific extra flags (arrays — safe for paths with spaces,
    # and avoids shell quoting pitfalls with embedded string-literal macros).
    declare -a extra_cflags=()
    declare -a extra_ldflags=()
    case "$h" in
        libp11_evp_fuzz)
            # Needs OpenSSL static libs (uses ENGINE_by_id, EVP_DigestSign etc.)
            # and the OpenSC PKCS#11 path macro (guard in common.h needs it).
            extra_cflags=("-DOPENSC_PKCS11_PATH=\"$COV_LIB/lib/opensc-pkcs11.so\"")
            extra_ldflags=(
                "-Wl,--whole-archive"
                "$COV_LIB/lib/libssl.a"
                "$COV_LIB/lib/libcrypto.a"
                "-Wl,--no-whole-archive"
            )
            ;;
        opensc_pkcs11_fuzz)
            # Needs -DOPENSC_PKCS11_PATH pointing at the coverage-tree module.
            extra_cflags=("-DOPENSC_PKCS11_PATH=\"$COV_LIB/lib/opensc-pkcs11.so\"")
            ;;
    esac

    # -fprofile-instr-generate + -fcoverage-mapping: Clang source-based coverage.
    # -fsanitize=address,fuzzer: ASan provides __sancov_lowest_stack (required
    #   by libsofthsm2.so which was built with -fsanitize=fuzzer-no-link).
    "$CC" \
        -fprofile-instr-generate \
        -fcoverage-mapping \
        -fsanitize=address,fuzzer \
        -fuse-ld=lld \
        -O0 -g \
        -I"$COV_LIB/include" \
        -I"$PROJECT_ROOT/src/libp11/src" \
        -I"$PROJECT_ROOT/src/softhsm2/src/lib/pkcs11" \
        -DHARNESS_PROJECT_ROOT='"'"$PROJECT_ROOT"'"' \
        -DSOFTHSM2_MODULE_PATH='"'"$COV_LIB/lib/softhsm/libsofthsm2.so"'"' \
        -DENGINE_PATH='"'"$COV_LIB/lib/engines-3/pkcs11.so"'"' \
        -Wno-unused-variable -Wno-deprecated-declarations \
        "${extra_cflags[@]}" \
        "$HARNESSES_DIR/${h}.c" \
        "${extra_ldflags[@]}" \
        -ldl -lpthread \
        -Wl,-rpath,"$COV_LIB/lib/softhsm" \
        -o "$cov_bin" 2>/dev/null \
    || { echo "  Build failed — skipping"; rm -rf "$build_dir"; continue; }

    # -runs=0: libFuzzer executes every corpus input once, then exits normally,
    # flushing all profiling counters (harness + every dlopen'd library).
    LLVM_PROFILE_FILE="$build_dir/${h}-%p.profraw" \
    SOFTHSM2_CONF="$COV_LIB/etc/softhsm2.conf" \
    LD_LIBRARY_PATH="$COV_LIB/lib/softhsm:${LD_LIBRARY_PATH:-}" \
    ASAN_OPTIONS="halt_on_error=0:detect_leaks=0:detect_odr_violation=0" \
    LSAN_OPTIONS="suppressions=$PROJECT_ROOT/fuzzing/lsan.suppressions" \
        "$cov_bin" "$corpus" -runs=0 2>/dev/null || true

    profdata="$build_dir/${h}.profdata"
    if ! "$LLVM_PROFDATA" merge \
            -o "$profdata" \
            "$build_dir/${h}"-*.profraw 2>/dev/null; then
        echo "  No profile data — possibly no corpus entries ran"
        continue
    fi
    rm -f "$build_dir/${h}"-*.profraw

    report_dir="$COV_DIR/$h"
    mkdir -p "$report_dir"

    # In FULL mode, pass the coverage-instrumented shared libraries that this
    # specific harness actually loads so llvm-cov attributes counters correctly.
    extra_objects=""
    if [[ $FULL_MODE -eq 1 ]]; then
        case "$h" in
            opensc_pkcs11_fuzz)
                # This harness loads opensc-pkcs11.so (which embeds libopensc.so
                # internally) — not libsofthsm2.so.
                for so in \
                    "$COV_PREFIX/lib/opensc-pkcs11.so" \
                    "$COV_PREFIX/lib/libopensc.so"; do
                    [[ -f "$so" ]] && extra_objects="$extra_objects -object=$so"
                done
                ;;
            libp11_evp_fuzz)
                # This harness statically links OpenSSL (in the binary itself) and
                # loads pkcs11.so (libp11 engine) + libsofthsm2.so at runtime.
                for so in \
                    "$COV_PREFIX/lib/engines-3/pkcs11.so" \
                    "$COV_PREFIX/lib/softhsm/libsofthsm2.so"; do
                    [[ -f "$so" ]] && extra_objects="$extra_objects -object=$so"
                done
                ;;
            *)
                # All other PKCS#11 harnesses load libsofthsm2.so (which embeds
                # OpenSSL) and the pkcs11 engine (libp11) via ENGINE_PATH.
                for so in \
                    "$COV_PREFIX/lib/softhsm/libsofthsm2.so" \
                    "$COV_PREFIX/lib/engines-3/pkcs11.so" \
                    "$COV_PREFIX/lib/libopensc.so"; do
                    [[ -f "$so" ]] && extra_objects="$extra_objects -object=$so"
                done
                ;;
        esac
    fi

    # shellcheck disable=SC2086
    "$LLVM_COV" show "$cov_bin" \
        $extra_objects \
        -instr-profile="$profdata" \
        -format=html \
        -output-dir="$report_dir" \
        -show-line-counts-or-regions \
        -Xdemangler=c++filt \
        2>/dev/null || true

    # Text summary for trending log
    # shellcheck disable=SC2086
    summary_text=$("$LLVM_COV" report "$cov_bin" \
        $extra_objects \
        -instr-profile="$profdata" 2>/dev/null | tail -3) || true
    echo "$summary_text" | sed 's/^/  /'

    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    lines_pct=$(echo "$summary_text" | grep -oE '[0-9]+\.[0-9]+%' | sed -n '1p' || echo "-")
    funcs_pct=$(echo "$summary_text" | grep -oE '[0-9]+\.[0-9]+%' | sed -n '2p' || echo "-")
    rgns_pct=$(echo "$summary_text"  | grep -oE '[0-9]+\.[0-9]+%' | sed -n '3p' || echo "-")
    printf '%s\t%s\tlines:%s\tfuncs:%s\tregions:%s\n' \
        "$ts" "$h" "$lines_pct" "$funcs_pct" "$rgns_pct" \
        >> "$COV_DIR/coverage.log"

    # Per-component breakdown (FULL mode only).
    # llvm-cov report accepts source-path filters as positional arguments;
    # passing a directory restricts the TOTAL line to files in that tree.
    # This gives us per-library line/function/region coverage independent of
    # the overall total, logged as comp:<name> entries for show-coverage.
    if [[ $FULL_MODE -eq 1 ]]; then
        declare -A _comp_dirs=(
            [softhsm2]="$PROJECT_ROOT/src/softhsm2"
            [openssl]="$PROJECT_ROOT/src/openssl"
            [libp11]="$PROJECT_ROOT/src/libp11"
            [opensc]="$PROJECT_ROOT/src/opensc"
        )
        for comp in softhsm2 openssl libp11 opensc; do
            src_dir="${_comp_dirs[$comp]}"
            [[ -d "$src_dir" ]] || continue

            # libp11_evp_fuzz embeds two copies of the LLVM profiling runtime
            # (one in the harness from --whole-archive OpenSSL, one in pkcs11.so).
            # When pkcs11.so is dlopen'd, its counters do not register with the
            # process-global runtime, so all libp11 functions appear at 0 % even
            # though they ARE called.  Skip the per-component report for libp11
            # in this harness and annotate it with the known reason instead.
            if [[ "$h" == "libp11_evp_fuzz" && "$comp" == "libp11" ]]; then
                printf '  %-12s [n/a — dual profiling-runtime conflict with statically-linked OpenSSL]\n' "[$comp]"
                printf '%s\t%s\tcomp:%s\tlines:%s\tfuncs:%s\tregions:%s\n' \
                    "$ts" "$h" "$comp" "n/a" "n/a" "n/a" \
                    >> "$COV_DIR/coverage.log"
                continue
            fi

            # shellcheck disable=SC2086
            comp_text=$("$LLVM_COV" report "$cov_bin" \
                $extra_objects \
                -instr-profile="$profdata" \
                -- "$src_dir" 2>/dev/null | tail -3) || true
            c_lines=$(echo "$comp_text" | grep -oE '[0-9]+\.[0-9]+%' | sed -n '1p' || echo "-")
            c_funcs=$(echo "$comp_text" | grep -oE '[0-9]+\.[0-9]+%' | sed -n '2p' || echo "-")
            c_rgns=$(echo "$comp_text"  | grep -oE '[0-9]+\.[0-9]+%' | sed -n '3p' || echo "-")
            printf '%s\t%s\tcomp:%s\tlines:%s\tfuncs:%s\tregions:%s\n' \
                "$ts" "$h" "$comp" "$c_lines" "$c_funcs" "$c_rgns" \
                >> "$COV_DIR/coverage.log"
            printf '  %-12s lines:%-8s funcs:%-8s regions:%s\n' \
                "[$comp]" "$c_lines" "$c_funcs" "$c_rgns"
        done
        unset _comp_dirs
    fi

    echo "  HTML report: $report_dir/index.html"
    echo ""
done

echo "Coverage generation complete."
echo "  Trending log:   $COV_DIR/coverage.log"
echo "  HTML reports:   $COV_DIR/<harness>/index.html"
if [[ $FULL_MODE -eq 1 ]]; then
    echo "  Coverage scope: OpenSSL + SoftHSM2 + libp11 + OpenSC (full target libraries)"
else
    echo "  Coverage scope: harness source only"
    echo "  Run --coverage-tree for full target-library coverage."
fi
echo ""
echo "NOTE: for real-time target coverage growth during fuzzing, watch:"
echo "  tail -f coverage/<harness>.log | grep -E 'NEW|PULSE'"
