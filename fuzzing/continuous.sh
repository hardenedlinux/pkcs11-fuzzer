#!/usr/bin/env bash
# continuous.sh — Orchestrator for continuous libFuzzer fuzzing on bare metal.
#
# Runs all libFuzzer harnesses in background, monitors for crashes, minimizes
# corpus periodically, and generates coverage reports.
#
# Designed to run inside a screen/tmux session:
#   screen -dmS fuzz bash fuzzing/continuous.sh
#   screen -r fuzz   # to reattach
#
# Environment:
#   FUZZ_DURATION_H   — hours to run before auto-stopping (default: 0 = forever)
#   FUZZ_MIN_INTERVAL — corpus minimization interval in seconds (default: 21600 = 6h)
#   FUZZ_COV_INTERVAL — coverage report interval in seconds (default: 86400 = 24h)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DURATION_H="${FUZZ_DURATION_H:-0}"
MIN_INTERVAL="${FUZZ_MIN_INTERVAL:-21600}"   # 6 hours
COV_INTERVAL="${FUZZ_COV_INTERVAL:-86400}"   # 24 hours

LOG_DIR="$PROJECT_ROOT/coverage"
mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_DIR/continuous.log"; }

# ---------------------------------------------------------------------------
# Check for new crashes
# ---------------------------------------------------------------------------
last_crash_count=0
check_crashes() {
    local count
    count=$(ls "$PROJECT_ROOT/crashes/raw/" 2>/dev/null | wc -l)
    if [[ $count -gt $last_crash_count ]]; then
        local new=$(( count - last_crash_count ))
        log "NEW CRASHES: $new new crash(es) found!"
        log "  Running triage..."

        triage_out=$(bash "$SCRIPT_DIR/triage-crashes.sh" 2>&1)
        echo "$triage_out" >> "$LOG_DIR/triage.log"

        crash_type=$(echo "$triage_out" | \
            grep -E "SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer):" | \
            sed 's/SUMMARY: //;s/ in .*$//' | head -1 | tr -d '\n' || true)
        [[ -z "$crash_type" ]] && crash_type=$(echo "$triage_out" | \
            grep -oE "runtime error: [^$]+" | head -1 | cut -c1-60 || echo "crash detected")
        crash_detail=$(echo "$triage_out" | grep -E "(NEW|Stack|Reproducer)" | head -6 | sed 's/^/  /')

        bash "$SCRIPT_DIR/notify.sh" crash \
            "pkcs11-fuzzer: $new new crash(es) — $crash_type" \
            "Host: $(hostname)
Harnesses running: $(ls "$PROJECT_ROOT"/harnesses/*_fuzz 2>/dev/null | wc -l)
Crash dir: $PROJECT_ROOT/crashes/raw/
${crash_detail}"

        last_crash_count=$count
    fi
}

# ---------------------------------------------------------------------------
# Start libFuzzer harnesses
# ---------------------------------------------------------------------------
log "Starting continuous fuzzing. duration=${DURATION_H}h, minimize_every=${MIN_INTERVAL}s"
bash "$SCRIPT_DIR/notify.sh" info \
    "pkcs11-fuzzer started on $(hostname)" \
    "Duration: ${DURATION_H}h (0=forever)
Minimize every: ${MIN_INTERVAL}s | Coverage every: ${COV_INTERVAL}s
Project: $PROJECT_ROOT"

LIBFUZZER_ARGS=()
[[ $DURATION_H -gt 0 ]] && LIBFUZZER_ARGS+=(--time=$(( DURATION_H * 3600 )))
bash "$SCRIPT_DIR/run-libfuzzer.sh" "${LIBFUZZER_ARGS[@]}" \
    >> "$LOG_DIR/libfuzzer.log" 2>&1 &
LIBFUZZER_PID=$!
log "libFuzzer PID: $LIBFUZZER_PID"

# ---------------------------------------------------------------------------
# Monitor loop
# ---------------------------------------------------------------------------
START_TIME=$(date +%s)
LAST_MIN=$START_TIME
LAST_COV=$START_TIME

stop_all() {
    log "Stopping all fuzzers..."
    kill "$LIBFUZZER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    total_crashes=$(ls "$PROJECT_ROOT/crashes/raw/" 2>/dev/null | wc -l)
    bash "$SCRIPT_DIR/notify.sh" info \
        "pkcs11-fuzzer stopped on $(hostname)" \
        "Total crashes found: $total_crashes
Corpus: $PROJECT_ROOT/corpus/
Coverage report: $PROJECT_ROOT/coverage/"
    log "Stopped."
}
trap stop_all INT TERM

while true; do
    sleep 60

    NOW=$(date +%s)
    ELAPSED=$(( NOW - START_TIME ))

    if [[ $DURATION_H -gt 0 && $ELAPSED -ge $(( DURATION_H * 3600 )) ]]; then
        log "Duration reached (${DURATION_H}h). Stopping."
        stop_all
        break
    fi

    check_crashes

    if [[ $(( NOW - LAST_MIN )) -ge $MIN_INTERVAL ]]; then
        log "Running corpus minimization..."
        bash "$SCRIPT_DIR/minimize-corpus.sh" >> "$LOG_DIR/minimize.log" 2>&1
        LAST_MIN=$NOW
        log "Corpus minimization done."
    fi

    if [[ $(( NOW - LAST_COV )) -ge $COV_INTERVAL ]]; then
        log "Generating coverage report..."
        bash "$SCRIPT_DIR/gen-coverage.sh" >> "$LOG_DIR/coverage.log" 2>&1
        LAST_COV=$NOW
        log "Coverage report done."
    fi

    if ! kill -0 "$LIBFUZZER_PID" 2>/dev/null; then
        log "WARNING: libFuzzer process died. Restarting..."
        bash "$SCRIPT_DIR/run-libfuzzer.sh" "${LIBFUZZER_ARGS[@]}" \
            >> "$LOG_DIR/libfuzzer.log" 2>&1 &
        LIBFUZZER_PID=$!
        log "libFuzzer restarted with PID $LIBFUZZER_PID"
    fi
done
