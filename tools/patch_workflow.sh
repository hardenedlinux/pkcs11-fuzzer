#!/usr/bin/env bash
# tools/patch_workflow.sh — Shell entry point for the patch workflow tool.
#
# Wraps tools/patch_workflow.py with convenience shortcuts and batch modes.
#
# Usage:
#   ./tools/patch_workflow.sh <crash_file>            # full pipeline
#   ./tools/patch_workflow.sh --interactive <crash>   # prompt at each stage
#   ./tools/patch_workflow.sh --revert <state.json>   # undo a patch
#   ./tools/patch_workflow.sh --batch                 # process all raw crashes
#   ./tools/patch_workflow.sh --status                # show all workflow states
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="$(command -v python3)"

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
print_header() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ---------------------------------------------------------------------------
# --status: print all workflow_state.json files in a table
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--status" ]]; then
    echo ""
    printf "  %-12s %-22s %-30s\n" "OUTCOME" "HARNESS" "CRASH"
    printf "  %-12s %-22s %-30s\n" "────────────" "──────────────────────" "──────────────────────────────"
    for f in crashes/analysis/*/workflow_state.json; do
        [[ -f "$f" ]] || continue
        python3 -c "
import json, sys
d = json.load(open('$f'))
outcome  = d.get('outcome', '?')
harness  = d.get('harness', '?')
crash    = d.get('crash_file', '?')
crash    = crash.rsplit('/', 1)[-1][:30]
print(f\"  {outcome:<12} {harness:<22} {crash:<30}\")
"
    done
    echo ""
    exit 0
fi

# ---------------------------------------------------------------------------
# --batch: run workflow on every crash in crashes/raw/ that hasn't been fixed
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--batch" ]]; then
    shift
    crashes=( crashes/raw/* )
    [[ -f "${crashes[0]:-}" ]] || { echo "No crashes in crashes/raw/"; exit 0; }
    failed=0
    for crash in "${crashes[@]}"; do
        [[ -f "$crash" ]] || continue
        print_header "$(basename "$crash")"
        "$PYTHON" "$SCRIPT_DIR/patch_workflow.py" "$crash" "$@" || (( failed++ )) || true
    done
    echo ""
    print_header "Batch complete — $failed crash(es) need attention"
    exit $failed
fi

# ---------------------------------------------------------------------------
# --revert: pass directly to Python script
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--revert" ]]; then
    "$PYTHON" "$SCRIPT_DIR/patch_workflow.py" "$@"
    exit $?
fi

# ---------------------------------------------------------------------------
# Single crash (default)
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <crash_file> [--interactive] [--minimize-timeout <sec>]"
    echo "       $0 --revert <state.json>"
    echo "       $0 --batch [extra args]"
    echo "       $0 --status"
    exit 1
fi

"$PYTHON" "$SCRIPT_DIR/patch_workflow.py" "$@"
