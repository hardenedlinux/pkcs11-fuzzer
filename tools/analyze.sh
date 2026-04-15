#!/usr/bin/env bash
# tools/analyze.sh — Shell entry point for the crash analysis tool.
#
# Usage:
#   ./tools/analyze.sh crashes/raw/<crash_file>
#   ./tools/analyze.sh --all                      # analyze all raw crashes
#   ./tools/analyze.sh --apply-patches            # apply all generated patches
#
# Runs tools/analyze.py for each crash and prints a consolidated summary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="$(command -v python3)"

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
run_one() {
    local crash="$1"; shift
    local extra_args=("$@")
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $(basename "$crash")"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    "$PYTHON" "$SCRIPT_DIR/analyze.py" "$crash" "${extra_args[@]}" || true
}

apply_patches() {
    local applied=0
    for diff in crashes/analysis/*/patch.diff; do
        [[ -f "$diff" ]] || continue
        echo "Applying: $diff"
        if patch -p1 --dry-run < "$diff" &>/dev/null; then
            patch -p1 < "$diff" && (( applied++ )) || echo "  FAILED"
        else
            echo "  Dry-run failed — patch may already be applied or conflict"
        fi
    done
    echo ""
    echo "Applied $applied patch(es)."
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [CRASH_FILE]

Analyze a libFuzzer crash artifact, classify it, minimize the input,
and generate a maintainer-ready patch and report.

Arguments:
  CRASH_FILE                   Path to a crash file in crashes/raw/

Options:
  -h, --help                   Show this help message and exit
  --all                        Analyze every file in crashes/raw/ and print
                               a consolidated summary table at the end
  --apply-patches              Apply all patch.diff files under crashes/analysis/
                               using 'patch -p1' (dry-run checked first)
  --harness <name>             Override the harness name (default: auto-detected
                               from the crash filename prefix)
  --minimize-timeout <sec>     Time budget for crash minimization (default: 30)
  --output <dir>               Output directory for the analysis artifacts
                               (default: crashes/analysis/<crash_name>/)

Examples:
  $(basename "$0") crashes/raw/pkcs11_sign_fuzz-crash-abc123
  $(basename "$0") --all
  $(basename "$0") --apply-patches
  $(basename "$0") crashes/raw/some_crash --harness pkcs11_sign_fuzz --minimize-timeout 60
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ "${1:-}" == "--apply-patches" ]]; then
    apply_patches
    exit 0
fi

if [[ "${1:-}" == "--all" ]]; then
    crashes=( crashes/raw/* )
    [[ -f "${crashes[0]:-}" ]] || { echo "No crashes in crashes/raw/"; exit 0; }
    for crash in "${crashes[@]}"; do
        [[ -f "$crash" ]] && run_one "$crash"
    done
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  CONSOLIDATED SUMMARY"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    for json_file in crashes/analysis/*/analysis.json; do
        [[ -f "$json_file" ]] || continue
        python3 -c "
import json, sys
d = json.load(open('$json_file'))
status = 'FALSE POSITIVE' if d['is_false_positive'] else ('PATCHED' if d['has_patch'] else 'REAL BUG (manual fix)')
print(f\"  [{status}] {d['bug_subtype']:25s} {d['harness']}\")
if d['is_false_positive']:
    print(f\"     Reason: {d['fp_reason']}\")
"
    done
    exit 0
fi

# Single crash
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <crash_file> [--harness <name>] [--minimize-timeout <sec>]"
    echo "       $0 --all"
    echo "       $0 --apply-patches"
    echo "       $0 --help"
    exit 1
fi

run_one "$@"
