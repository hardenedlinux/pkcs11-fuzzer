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
STOPPING=0

LOG_DIR="$PROJECT_ROOT/coverage"
mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG_DIR/continuous.log"; }

ANALYZE_LOG="$LOG_DIR/analyze.log"
declare -A SEEN_CRASHES=()

snapshot_crash_context() {
    local crash="$1"
    local base harness out_dir crash_size crash_sha git_rev

    base="$(basename "$crash")"
    harness="${base%%-crash-*}"
    out_dir="$PROJECT_ROOT/crashes/analysis/$base"
    mkdir -p "$out_dir"

    crash_size=$(stat -c%s "$crash" 2>/dev/null || printf '0')
    crash_sha=$(sha256sum "$crash" 2>/dev/null | cut -d' ' -f1 || printf 'unknown')
    git_rev=$(git rev-parse HEAD 2>/dev/null || printf 'unknown')

    printf '{\n' > "$out_dir/fuzzing-session.json"
    printf '  "captured_at": "%s",\n' "$(date --iso-8601=seconds)" >> "$out_dir/fuzzing-session.json"
    printf '  "host": "%s",\n' "$(hostname)" >> "$out_dir/fuzzing-session.json"
    printf '  "git_revision": "%s",\n' "$git_rev" >> "$out_dir/fuzzing-session.json"
    printf '  "harness": "%s",\n' "$harness" >> "$out_dir/fuzzing-session.json"
    printf '  "crash_file": "%s",\n' "$crash" >> "$out_dir/fuzzing-session.json"
    printf '  "crash_size": %s,\n' "$crash_size" >> "$out_dir/fuzzing-session.json"
    printf '  "crash_sha256": "%s"\n' "$crash_sha" >> "$out_dir/fuzzing-session.json"
    printf '}\n' >> "$out_dir/fuzzing-session.json"

    if [[ -f "$LOG_DIR/fuzzing-runtime.env" ]]; then
        cp "$LOG_DIR/fuzzing-runtime.env" "$out_dir/fuzzing-session.env"
    else
        printf 'ASAN_OPTIONS=%s\n' "${ASAN_OPTIONS:-}" > "$out_dir/fuzzing-session.env"
        printf 'UBSAN_OPTIONS=%s\n' "${UBSAN_OPTIONS:-}" >> "$out_dir/fuzzing-session.env"
        printf 'LSAN_OPTIONS=%s\n' "${LSAN_OPTIONS:-}" >> "$out_dir/fuzzing-session.env"
        printf 'LD_LIBRARY_PATH=%s\n' "${LD_LIBRARY_PATH:-}" >> "$out_dir/fuzzing-session.env"
        printf 'ASAN_SYMBOLIZER_PATH=%s\n' "${ASAN_SYMBOLIZER_PATH:-}" >> "$out_dir/fuzzing-session.env"
    fi
    printf 'SOFTHSM2_CONF=%s\n' "${SOFTHSM2_CONF:-}" >> "$out_dir/fuzzing-session.env"

    if [[ -f "$LOG_DIR/${harness}.log" ]]; then
        tail -n 200 "$LOG_DIR/${harness}.log" > "$out_dir/fuzzing-harness.log"
    fi
    if [[ -f "$LOG_DIR/libfuzzer.log" ]]; then
        tail -n 200 "$LOG_DIR/libfuzzer.log" > "$out_dir/fuzzing-libfuzzer.log"
    fi

    local asan_log idx=1
    while IFS= read -r asan_log; do
        [[ -f "$asan_log" ]] || continue
        cp "$asan_log" "$out_dir/asan-report-${idx}.log"
        idx=$(( idx + 1 ))
    done < <(grep -l "$harness" /tmp/asan.* 2>/dev/null | tail -n 3 || true)
}

analyze_new_crash() {
    local crash="$1"
    log "  Analyzing $(basename "$crash")"
    bash "$PROJECT_ROOT/tools/analyze.sh" "$crash" --repro-attempts 5 >> "$ANALYZE_LOG" 2>&1 || true
}

# ---------------------------------------------------------------------------
# Check for new crashes
# ---------------------------------------------------------------------------
check_crashes() {
    local crash base
    local new_crashes=()

    for crash in "$PROJECT_ROOT"/crashes/raw/*; do
        [[ -f "$crash" ]] || continue
        base="$(basename "$crash")"
        [[ -n "${SEEN_CRASHES[$base]:-}" ]] && continue
        SEEN_CRASHES[$base]=1
        new_crashes+=("$crash")
    done

    if [[ ${#new_crashes[@]} -gt 0 ]]; then
        local new=${#new_crashes[@]}
        log "NEW CRASHES: $new new crash(es) found!"

        for crash in "${new_crashes[@]}"; do
            snapshot_crash_context "$crash"
            analyze_new_crash "$crash"
        done

        log "  Running triage..."

        if triage_out=$(bash "$SCRIPT_DIR/triage-crashes.sh" 2>&1); then
            echo "$triage_out" >> "$LOG_DIR/triage.log"
        else
            echo "$triage_out" >> "$LOG_DIR/triage.log"
            log "  WARNING: triage failed; continuing fuzzing loop"
            triage_out=""
        fi

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
    fi
}

# ---------------------------------------------------------------------------
# Start libFuzzer harnesses
# ---------------------------------------------------------------------------
log "Starting continuous fuzzing. duration=${DURATION_H}h, minimize_every=${MIN_INTERVAL}s"
for crash in "$PROJECT_ROOT"/crashes/raw/*; do
    [[ -f "$crash" ]] || continue
    SEEN_CRASHES["$(basename "$crash")"]=1
done

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
    STOPPING=1
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

    [[ $STOPPING -eq 1 ]] && break

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

    if [[ $STOPPING -eq 0 ]] && ! kill -0 "$LIBFUZZER_PID" 2>/dev/null; then
        log "WARNING: libFuzzer process died. Restarting..."
        bash "$SCRIPT_DIR/run-libfuzzer.sh" "${LIBFUZZER_ARGS[@]}" \
            >> "$LOG_DIR/libfuzzer.log" 2>&1 &
        LIBFUZZER_PID=$!
        log "libFuzzer restarted with PID $LIBFUZZER_PID"
    fi
done
