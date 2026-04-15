#!/usr/bin/env bash
# notify.sh — Send a fuzzing notification through configured channels.
#
# Usage:
#   ./notify.sh <level> <title> <body>
#
#   level  = info | warn | crash   (affects icon/color/emoji)
#   title  = short one-line subject
#   body   = multi-line detail (optional)
#
# Examples:
#   ./notify.sh crash "New crash found" "pkcs11_sign_fuzz: heap-buffer-overflow in C_Sign"
#   ./notify.sh info  "Fuzzing started" "6 harnesses, 8 cores, corpus: 42 entries"
#
# Reads configuration from fuzzing/notify.conf (relative to PROJECT_ROOT).
# All channels with empty/unset values are silently skipped.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LEVEL="${1:-info}"
TITLE="${2:-Fuzzing notification}"
BODY="${3:-}"

# ---------------------------------------------------------------------------
# Load configuration (if present)
# ---------------------------------------------------------------------------
CONF="$SCRIPT_DIR/notify.conf"
# Defaults (can be overridden by conf file)
NOTIFY_DESKTOP=0
NOTIFY_SLACK_WEBHOOK=""
NOTIFY_DISCORD_WEBHOOK=""
NOTIFY_WEBHOOK_URL=""
NOTIFY_EMAIL=""
NOTIFY_EMAIL_FROM="fuzz-bot@localhost"
NOTIFY_EMAIL_SUBJECT_PREFIX="[FUZZ]"
NOTIFY_LOG="coverage/notifications.log"

[[ -f "$CONF" ]] && source "$CONF"

# Resolve log path
[[ "$NOTIFY_LOG" != /* ]] && NOTIFY_LOG="$PROJECT_ROOT/$NOTIFY_LOG"
mkdir -p "$(dirname "$NOTIFY_LOG")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
timestamp() { date '+%F %T'; }

level_emoji() {
    case "$LEVEL" in
        crash) echo "💥" ;;
        warn)  echo "⚠️ " ;;
        *)     echo "ℹ️ " ;;
    esac
}

level_color_slack() {
    # Slack attachment color
    case "$LEVEL" in
        crash) echo "danger" ;;
        warn)  echo "warning" ;;
        *)     echo "good" ;;
    esac
}

level_color_discord() {
    # Discord embed color (decimal)
    case "$LEVEL" in
        crash) echo "15158332" ;;  # red
        warn)  echo "16776960" ;;  # yellow
        *)     echo "3066993"  ;;  # green
    esac
}

EMOJI=$(level_emoji)
FULL_MSG="${EMOJI} [$(timestamp)] ${TITLE}"
[[ -n "$BODY" ]] && FULL_MSG+=$'\n'"${BODY}"

# ---------------------------------------------------------------------------
# 1. Always: write to log file
# ---------------------------------------------------------------------------
echo "[$LEVEL] $(timestamp) | $TITLE" >> "$NOTIFY_LOG"
[[ -n "$BODY" ]] && echo "  $BODY" >> "$NOTIFY_LOG"
echo "" >> "$NOTIFY_LOG"

# ---------------------------------------------------------------------------
# 2. Desktop notification (notify-send)
# ---------------------------------------------------------------------------
if [[ "${NOTIFY_DESKTOP:-0}" == "1" ]] && command -v notify-send &>/dev/null; then
    urgency="normal"
    [[ "$LEVEL" == "crash" ]] && urgency="critical"
    notify-send \
        --urgency="$urgency" \
        --app-name="pkcs11-fuzzer" \
        --icon="dialog-error" \
        "$TITLE" \
        "$BODY" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 3. Slack webhook
# ---------------------------------------------------------------------------
if [[ -n "${NOTIFY_SLACK_WEBHOOK:-}" ]] && command -v curl &>/dev/null; then
    # Escape body for JSON
    body_json=$(echo "$BODY" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || \
                echo '"'"$(echo "$BODY" | sed 's/"/\\"/g' | tr '\n' ' ')"'"')

    curl -s -X POST "$NOTIFY_SLACK_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d '{
            "attachments": [{
                "color": "'"$(level_color_slack)"'",
                "title": "'"${EMOJI} ${TITLE}"'",
                "text": '"${body_json}"',
                "footer": "pkcs11-fuzzer | '"$(hostname)"'",
                "ts": '"$(date +%s)"'
            }]
        }' >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 4. Discord webhook
# ---------------------------------------------------------------------------
if [[ -n "${NOTIFY_DISCORD_WEBHOOK:-}" ]] && command -v curl &>/dev/null; then
    body_json=$(echo "$BODY" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || \
                echo '"'"$(echo "$BODY" | sed 's/"/\\"/g' | tr '\n' ' ')"'"')

    curl -s -X POST "$NOTIFY_DISCORD_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d '{
            "embeds": [{
                "title": "'"${EMOJI} ${TITLE}"'",
                "description": '"${body_json}"',
                "color": '"$(level_color_discord)"',
                "footer": { "text": "pkcs11-fuzzer | '"$(hostname)"'" },
                "timestamp": "'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'"
            }]
        }' >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 5. Generic HTTP webhook
# ---------------------------------------------------------------------------
if [[ -n "${NOTIFY_WEBHOOK_URL:-}" ]] && command -v curl &>/dev/null; then
    text_json=$(echo "${FULL_MSG}" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || \
                echo '"'"$(echo "$FULL_MSG" | sed 's/"/\\"/g' | tr '\n' ' ')"'"')

    curl -s -X POST "$NOTIFY_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d '{"level":"'"$LEVEL"'","title":'"$(echo "$TITLE" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read().strip()))' 2>/dev/null)"',"text":'"$text_json"'}' \
        >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# 6. Email
# ---------------------------------------------------------------------------
if [[ -n "${NOTIFY_EMAIL:-}" ]] && command -v mail &>/dev/null; then
    subject="${NOTIFY_EMAIL_SUBJECT_PREFIX} ${EMOJI} ${TITLE}"
    printf '%s\n\n%s\n\n--\npkcs11-fuzzer @ %s\n%s\n' \
        "$TITLE" "$BODY" "$(hostname)" "$(timestamp)" \
        | mail -s "$subject" \
               -a "From: ${NOTIFY_EMAIL_FROM}" \
               "$NOTIFY_EMAIL" 2>/dev/null || true
fi
