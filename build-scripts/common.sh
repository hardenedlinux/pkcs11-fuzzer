#!/usr/bin/env bash
# common.sh — sourced by every build script.
# Defines all paths, pinned versions, and per-tree compiler flags.
# Never run directly; always sourced: source "$(dirname "$0")/common.sh"

# ---------------------------------------------------------------------------
# Project layout (everything relative to PROJECT_ROOT so the tree is portable)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC_DIR="$PROJECT_ROOT/src"
BUILDS_DIR="$PROJECT_ROOT/builds"

# Install roots inside builds/
LIBFUZZER_PREFIX="$BUILDS_DIR/libfuzzer"
TSAN_PREFIX="$BUILDS_DIR/tsan"

# ---------------------------------------------------------------------------
# System LLVM/Clang detection
#
# We use the system LLVM packages (apt-get install clang lld) rather than
# building LLVM from source.  This section detects the best available clang
# and the associated LLVM tools, preferring unversioned names (managed by
# update-alternatives) and falling back to versioned names (clang-18 etc.)
# when the unversioned alias is absent or too old.
#
# Exports: OUR_CC  OUR_CXX  OUR_LLVM_SYMBOLIZER  OUR_LLVM_COV  OUR_LLVM_PROFDATA
# ---------------------------------------------------------------------------
_LLVM_MIN_VER=14          # minimum LLVM version that has fuzzer-no-link support
_LLVM_SEARCH="20 19 18 17 16 15 14"

# _llvm_ver <binary>  →  prints the major version number, or empty string
_llvm_ver() {
    "$1" --version 2>/dev/null \
        | grep -oE '(clang|LLVM) version [0-9]+' \
        | grep -oE '[0-9]+' \
        | head -1 || true
}

# _find_llvm_tool <name> <ver>  →  prints the first working path for the tool
# Tries versioned (name-ver) before unversioned (name).
_find_llvm_tool() {
    local name="$1" ver="$2"
    command -v "${name}-${ver}" 2>/dev/null && return
    command -v "$name" 2>/dev/null || true
}

# Detect system clang and set OUR_CC / OUR_CXX / OUR_LLVM_* accordingly.
# Called once at source time; safe to re-call (idempotent).
_detect_system_clang() {
    local ver=""

    # --- try unversioned clang first ---
    if command -v clang &>/dev/null; then
        ver=$(_llvm_ver clang)
        if [[ -n "$ver" && "$ver" -ge "$_LLVM_MIN_VER" ]]; then
            OUR_CC="clang"
            OUR_CXX="clang++"
            OUR_LLVM_SYMBOLIZER="$(_find_llvm_tool llvm-symbolizer "$ver")"
            OUR_LLVM_COV="$(_find_llvm_tool llvm-cov "$ver")"
            OUR_LLVM_PROFDATA="$(_find_llvm_tool llvm-profdata "$ver")"
            _DETECTED_CLANG_VER="$ver"
            return 0
        fi
    fi

    # --- try versioned clang (newest first) ---
    for ver in $_LLVM_SEARCH; do
        [[ "$ver" -lt "$_LLVM_MIN_VER" ]] && break
        if command -v "clang-${ver}" &>/dev/null; then
            OUR_CC="clang-${ver}"
            OUR_CXX="clang++-${ver}"
            OUR_LLVM_SYMBOLIZER="$(_find_llvm_tool llvm-symbolizer "$ver")"
            OUR_LLVM_COV="$(_find_llvm_tool llvm-cov "$ver")"
            OUR_LLVM_PROFDATA="$(_find_llvm_tool llvm-profdata "$ver")"
            _DETECTED_CLANG_VER="$ver"
            return 0
        fi
    done

    # --- not found: set safe defaults so get_tree_var still returns strings ---
    OUR_CC="clang"
    OUR_CXX="clang++"
    OUR_LLVM_SYMBOLIZER="llvm-symbolizer"
    OUR_LLVM_COV="llvm-cov"
    OUR_LLVM_PROFDATA="llvm-profdata"
    _DETECTED_CLANG_VER=""
    return 1
}

_detect_system_clang || true   # errors handled at require_clang time

# ---------------------------------------------------------------------------
# Pinned source versions — bump here to upgrade, nothing else changes
# ---------------------------------------------------------------------------
OPENSSL_TAG="openssl-3.6.2"
OPENSSL_REPO="https://github.com/openssl/openssl"

SOFTHSM2_TAG="2.6.1"
SOFTHSM2_REPO="https://github.com/softhsm/SoftHSMv2"

LIBP11_TAG="libp11-0.4.18"
LIBP11_REPO="https://github.com/OpenSC/libp11"

OPENSC_TAG="0.27.1"
OPENSC_REPO="https://github.com/OpenSC/OpenSC"

# ---------------------------------------------------------------------------
# Per-tree compiler / flag tables
#
# Both sanitizer trees (libfuzzer, tsan) use the system Clang.
# The coverage tree (coverage) also uses Clang but with profile instrumentation
# instead of sanitizer flags.
#
#   libfuzzer — ASan + UBSan + fuzzer-no-link for the fuzzing harnesses.
#   tsan      — TSan only (cannot mix with ASan).
#   coverage  — Clang source-based coverage: -fprofile-instr-generate +
#               -fcoverage-mapping.  No sanitizers.  Used by gen-coverage.sh
#               to produce per-source-line coverage reports for every target
#               component (OpenSSL, SoftHSM2, libp11, OpenSC) via llvm-cov.
#
# -fno-sanitize=vptr: PKCS#11 modules use C-style void* function pointers
#   across dlopen boundaries; Clang's vptr check produces false positives.
#
# -fno-sanitize=function: OpenSSL and SoftHSM2 use intentional C-style
#   function pointer casts (ENGINE API, factory pattern) that trigger this
#   Clang-specific check benignly.
#
# -fuse-ld=lld: use LLVM's lld instead of the system GNU ld.
# ---------------------------------------------------------------------------
# Usage: get_tree_var <tree> <var>
#   tree ∈ { libfuzzer, tsan, coverage }
#   var  ∈ { CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS, PREFIX }
get_tree_var() {
    local tree="$1" var="$2"
    case "${tree}__${var}" in
        # --- libfuzzer tree: clang + ASan + UBSan + fuzzer-no-link ----------
        libfuzzer__CC)       echo "$OUR_CC" ;;
        libfuzzer__CXX)      echo "$OUR_CXX" ;;
        libfuzzer__CFLAGS)   echo "-fsanitize=fuzzer-no-link,address,undefined \
-fno-sanitize=vptr,function \
-fno-sanitize-recover=undefined \
-fno-omit-frame-pointer -g -O1" ;;
        libfuzzer__CXXFLAGS) echo "-fsanitize=fuzzer-no-link,address,undefined \
-fno-sanitize=vptr,function \
-fno-sanitize-recover=undefined \
-fno-omit-frame-pointer -g -O1" ;;
        libfuzzer__LDFLAGS)  echo "-fsanitize=fuzzer-no-link,address,undefined \
-fno-sanitize=vptr -fuse-ld=lld -rdynamic" ;;
        libfuzzer__PREFIX)   echo "$LIBFUZZER_PREFIX" ;;

        # --- tsan tree: clang + TSan only (cannot mix with ASan) ------------
        tsan__CC)       echo "$OUR_CC" ;;
        tsan__CXX)      echo "$OUR_CXX" ;;
        tsan__CFLAGS)   echo "-fsanitize=thread \
-fno-omit-frame-pointer -g -O1" ;;
        tsan__CXXFLAGS) echo "-fsanitize=thread \
-fno-omit-frame-pointer -g -O1" ;;
        tsan__LDFLAGS)  echo "-fsanitize=thread -fuse-ld=lld -rdynamic" ;;
        tsan__PREFIX)   echo "$TSAN_PREFIX" ;;

        # --- coverage tree: clang + source-based coverage instrumentation ----
        # No sanitizers: coverage data is cleaner without ASan overhead and
        # the profiling runtime (-fprofile-instr-generate) is incompatible
        # with ASAN_OPTIONS=halt_on_error that the sanitizer trees use.
        coverage__CC)       echo "$OUR_CC" ;;
        coverage__CXX)      echo "$OUR_CXX" ;;
        coverage__CFLAGS)   echo "-fprofile-instr-generate -fcoverage-mapping \
-fno-omit-frame-pointer -g -O0" ;;
        coverage__CXXFLAGS) echo "-fprofile-instr-generate -fcoverage-mapping \
-fno-omit-frame-pointer -g -O0" ;;
        coverage__LDFLAGS)  echo "-fprofile-instr-generate -fcoverage-mapping \
-fuse-ld=lld -rdynamic" ;;
        coverage__PREFIX)   echo "$BUILDS_DIR/coverage" ;;

        *) echo "common.sh: unknown tree/var: ${tree}/${var}" >&2; return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Helper: full clone for component repos (OpenSSL, SoftHSM2, libp11, OpenSC).
#
# Full history is preserved so that `git log`, `git bisect`, and patch
# context all work correctly against any commit.
#
# Respects USE_UPSTREAM (set by build-all.sh --upstream):
#   USE_UPSTREAM=0  →  clone at pinned tag (default, reproducible builds)
#   USE_UPSTREAM=1  →  clone default branch tip (latest upstream code)
#
# A .clone-stamp file inside the destination records the mode|tag so that
# switching from --upstream to pinned (or changing the pinned tag) triggers
# a fresh re-clone instead of silently reusing an incompatible source tree.
#
# Usage: clone_if_needed <repo> <tag> <dest>
# ---------------------------------------------------------------------------
clone_if_needed() {
    local repo="$1" tag="$2" dest="$3"
    local stamp="$dest/.clone-stamp"
    local expected="${USE_UPSTREAM:-0}|${tag}"

    if [[ -d "$dest/.git" ]]; then
        local stored=""
        [[ -f "$stamp" ]] && stored="$(cat "$stamp")"

        # Never wipe a source directory that has uncommitted local modifications
        # (e.g. a patch applied by patch_workflow.py).  The caller is responsible
        # for reverting changes before requesting a fresh clone.
        if ! git -C "$dest" diff --quiet 2>/dev/null || \
           ! git -C "$dest" diff --cached --quiet 2>/dev/null; then
            echo "  [skip] $dest has local modifications — skipping re-clone"
            return
        fi

        if [[ "$stored" == "$expected" ]]; then
            echo "  [skip] $dest already cloned"
            return
        fi
        echo "  [reclone] source mode/tag changed (${stored:-untracked} → $expected)"
        echo "            Wiping $dest and re-cloning…"
        rm -rf "$dest"
    fi

    if [[ "${USE_UPSTREAM:-0}" == "1" ]]; then
        echo "  [git] cloning $repo (upstream HEAD) → $dest"
        git clone "$repo" "$dest"
    else
        echo "  [git] cloning $repo @ $tag → $dest"
        git clone --branch "$tag" "$repo" "$dest"
    fi
    printf '%s' "$expected" > "$stamp"
}

# ---------------------------------------------------------------------------
# Helper: write a built-stamp into the install prefix after a successful
# component build.  The stamp encodes the upstream flag and the pinned tag
# so build-all.sh can skip a component only when the installed version
# actually matches what is currently requested.
#
# Usage: write_built_stamp <prefix> <component> <tag>
#   component: openssl | softhsm2 | libp11 | opensc
#   tag:       the pinned tag from common.sh (e.g. $OPENSSL_TAG)
#   USE_UPSTREAM must be set in the caller's environment.
# ---------------------------------------------------------------------------
write_built_stamp() {
    local prefix="$1" component="$2" tag="$3"
    printf '%s' "${USE_UPSTREAM:-0}|${tag}" > "$prefix/.${component}-built"
}

# ---------------------------------------------------------------------------
# Helper: check whether a built-stamp matches the current request.
# Returns 0 (true) if the stamp exists and matches, 1 otherwise.
#
# Usage: built_stamp_ok <prefix> <component> <tag> <upstream_flag>
# ---------------------------------------------------------------------------
built_stamp_ok() {
    local prefix="$1" component="$2" tag="$3" upstream="$4"
    local stamp="$prefix/.${component}-built"
    local expected="${upstream}|${tag}"
    [[ -f "$stamp" ]] && [[ "$(cat "$stamp")" == "$expected" ]]
}

# ---------------------------------------------------------------------------
# Helper: assert that a built artifact contains sanitizer instrumentation.
# Uses nm to scan for sanitizer callback symbols that the compiler injects
# into every instrumented translation unit.  Exits non-zero if absent.
#
# Usage: verify_sanitizer <tree> <path>
#   tree ∈ { libfuzzer, tsan }
#   path: .so, .a, or executable to inspect
# ---------------------------------------------------------------------------
verify_sanitizer() {
    local tree="$1" path="$2"
    local pattern label
    case "$tree" in
        libfuzzer) pattern="__asan_\|__ubsan_"; label="ASan/UBSan" ;;
        tsan)      pattern="__tsan_";            label="TSan"       ;;
        # Coverage tree: look for the LLVM profiling counter symbols that
        # -fprofile-instr-generate injects into every instrumented TU.
        coverage)  pattern="__llvm_prf_cnts\|__llvm_prf_data\|__profc_"; label="Coverage instrumentation" ;;
        *) echo "verify_sanitizer: unknown tree '$tree'" >&2; return 1 ;;
    esac
    # nm "$path" 2>/dev/null | grep -c "$pattern" >/dev/null
    #
    # grep -c reads ALL of nm's output before exiting (unlike grep -q, which
    # stops at the first match and causes nm to receive SIGPIPE).  With
    # set -euo pipefail in the build scripts, a SIGPIPE on nm would set the
    # pipeline exit status to 141 — making the condition look false even when
    # the pattern was found.  grep -c eliminates this race entirely.
    if nm "$path" 2>/dev/null | grep -c "$pattern" >/dev/null; then
        echo "  [sanitizer] $label instrumentation present in $(basename "$path") ✓"
    else
        echo "" >&2
        echo "  ERROR: $label instrumentation NOT found in $path" >&2
        echo "         Expected symbols matching: $pattern" >&2
        echo "         The component was built without sanitizer flags." >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Helper: prepare a per-tree build directory, wiping it if the compiler or
# key flags changed since the last build.
#
# Each build directory records the compiler path + CFLAGS in a hidden stamp
# file (.build-stamp).  If that stamp differs from the current values, the
# directory is wiped before Configure runs, preventing stale object files
# from a previous compiler (e.g. gcc → clang) from silently ending up in
# the installed libraries.
#
# Usage: ensure_clean_build_dir <build_dir> <cc> <cflags>
# ---------------------------------------------------------------------------
ensure_clean_build_dir() {
    local build_dir="$1" cc="$2" cflags="$3"
    local stamp="$build_dir/.build-stamp"
    local current="${cc}|${cflags}"

    mkdir -p "$build_dir"

    if [[ -f "$stamp" ]]; then
        local stored
        stored="$(cat "$stamp")"
        if [[ "$stored" != "$current" ]]; then
            echo "  [rebuild] compiler or flags changed — wiping $build_dir"
            rm -rf "$build_dir"
            mkdir -p "$build_dir"
        fi
    fi

    printf '%s' "$current" > "$stamp"
}

# ---------------------------------------------------------------------------
# Helper: print a section banner
# ---------------------------------------------------------------------------
banner() {
    echo ""
    echo "================================================================"
    echo "  $*"
    echo "================================================================"
}

# ---------------------------------------------------------------------------
# Ensure system Clang (>= _LLVM_MIN_VER) is present and lld is available.
# Called at the top of every build script.
# ---------------------------------------------------------------------------
require_clang() {
    if [[ -z "$_DETECTED_CLANG_VER" ]]; then
        echo "ERROR: clang >= ${_LLVM_MIN_VER} not found." >&2
        echo "       Install with:" >&2
        echo "         sudo apt-get install clang lld" >&2
        echo "       Or from the LLVM APT repo (https://apt.llvm.org):" >&2
        echo "         sudo apt-get install clang-18 lld-18" >&2
        exit 1
    fi
    if ! command -v lld &>/dev/null && ! command -v "lld-${_DETECTED_CLANG_VER}" &>/dev/null; then
        echo "ERROR: lld not found (needed for -fuse-ld=lld)." >&2
        echo "       Install with: sudo apt-get install lld" >&2
        exit 1
    fi
    echo "  [clang] $("$OUR_CC" --version | head -1)"
}

# Make all build-script/*.sh executable
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true
