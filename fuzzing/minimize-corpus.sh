#!/usr/bin/env bash
# minimize-corpus.sh — Minimize libFuzzer corpora using -merge=1 mode.
#
# Run this periodically (e.g., every 6 hours) to keep corpus sizes manageable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILDS="$PROJECT_ROOT/builds"
HARNESSES_DIR="$PROJECT_ROOT/harnesses"
CORPUS_DIR="$PROJECT_ROOT/corpus"

export ASAN_OPTIONS="halt_on_error=0:detect_leaks=0:symbolize=0"
export UBSAN_OPTIONS="halt_on_error=0"

echo "=== libFuzzer corpus minimization ==="
for h in pkcs11_sign_fuzz pkcs11_decrypt_fuzz pkcs11_findobj_fuzz \
          pkcs11_wrap_fuzz pkcs11_attrs_fuzz tls_pkcs11_fuzz; do
    binary="$HARNESSES_DIR/$h"
    [[ -x "$binary" ]] || continue

    corpus="$CORPUS_DIR/$(echo "$h" | sed 's/_fuzz//;s/_/-/g')"
    [[ -d "$corpus" ]] || continue

    count_before=$(ls "$corpus" | wc -l)
    tmp_corpus="${corpus}.tmp"
    rm -rf "$tmp_corpus"
    mkdir -p "$tmp_corpus"

    "$binary" -merge=1 "$tmp_corpus" "$corpus" 2>/dev/null || true

    if [[ -n "$(ls -A "$tmp_corpus" 2>/dev/null)" ]]; then
        count_after=$(ls "$tmp_corpus" | wc -l)
        rm -rf "$corpus"
        mv "$tmp_corpus" "$corpus"
        echo "  $h: $count_before → $count_after entries"
    else
        rm -rf "$tmp_corpus"
        echo "  $h: merge produced empty corpus, keeping original"
    fi
done

echo ""
echo "Minimization complete."
