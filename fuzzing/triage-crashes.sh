#!/usr/bin/env bash
# triage-crashes.sh — Deduplicate and summarize crash artifacts.
#
# Deduplication strategy (without CASR):
#   1. Group crashes by their last 3 unique ASan/UBSan stack frames.
#   2. Print a summary with crash type, first frame, and count.
#   3. Keep the smallest reproducer per unique stack.
#
# If `casr-libfuzzer` (from the CASR tool) is available, use it instead.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILDS="$PROJECT_ROOT/builds"
HARNESSES_DIR="$PROJECT_ROOT/harnesses"
CRASH_RAW="$PROJECT_ROOT/crashes/raw"
CRASH_DEDUP="$PROJECT_ROOT/crashes/deduplicated"

mkdir -p "$CRASH_DEDUP"

export ASAN_OPTIONS="halt_on_error=0:detect_leaks=0:detect_odr_violation=0:symbolize=1"
export UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1:symbolize=1"

crash_files=( "$CRASH_RAW"/* )
[[ -f "${crash_files[0]:-}" ]] || { echo "No crash files in $CRASH_RAW"; exit 0; }

echo "Triaging ${#crash_files[@]} crash files..."
echo ""

declare -A SEEN_STACKS

for crash in "${crash_files[@]}"; do
    [[ -f "$crash" ]] || continue

    # Find which harness this crash belongs to
    harness=""
    for binary in "$HARNESSES_DIR"/*_fuzz; do
        [[ -x "$binary" ]] || continue
        h="$(basename "$binary")"
        [[ "$crash" == *"${h}-"* ]] && { harness="$h"; break; }
    done
    [[ -z "$harness" ]] && continue

    binary="$HARNESSES_DIR/$harness"
    [[ -x "$binary" ]] || continue

    # Run harness with crash input, capture output
    output=$("$binary" "$crash" 2>&1 || true)

    # Extract stack key (first 3 unique non-libfuzzer frames)
    stack_key=$(echo "$output" | grep -E "^\s+#[0-9]+" | \
                grep -v "libFuzzer\|sanitizer\|intercept" | \
                head -3 | \
                sed 's/.*in \([^ ]*\).*/\1/' | \
                tr '\n' '|' || true)
    [[ -z "$stack_key" ]] && stack_key="NO_STACK:$(basename "$crash")"

    # Crash type — match SUMMARY line or runtime error line
    crash_type=$(echo "$output" | \
        grep -oE "SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer): [^\n]+" | \
        head -1 || true)
    [[ -z "$crash_type" ]] && crash_type=$(echo "$output" | \
        grep -oE "runtime error: [^\n]+" | head -1 || true)
    [[ -z "$crash_type" ]] && crash_type="UNKNOWN"

    if [[ -n "${SEEN_STACKS[$stack_key]:-}" ]]; then
        # Duplicate: keep smaller file
        existing="${SEEN_STACKS[$stack_key]}"
        if [[ $(stat -c%s "$crash") -lt $(stat -c%s "$existing") ]]; then
            cp "$crash" "$existing"
        fi
    else
        SEEN_STACKS[$stack_key]="$crash"
        dest="$CRASH_DEDUP/$(basename "$crash")"
        cp "$crash" "$dest"
        echo "  NEW [$harness] $crash_type"
        echo "      Stack key: $stack_key"
        echo "      Reproducer: $dest"
        echo ""
    fi
done

echo "Deduplicated: ${#SEEN_STACKS[@]} unique crash(es) → $CRASH_DEDUP/"
