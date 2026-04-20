#!/usr/bin/env bash
# tests/test_opensc_mock_pcsc.sh — Regression test for OpenSC mock PC/SC driver.
set -euo pipefail

# Find the built pkcs11-tool and opensc-pkcs11.so
PKCS11_TOOL="/home/john/pkcs11-fuzzer/builds/coverage/bin/pkcs11-tool"
OPENSC_MODULE="/home/john/pkcs11-fuzzer/builds/coverage/lib/opensc-pkcs11.so"

if [[ ! -f "$PKCS11_TOOL" || ! -f "$OPENSC_MODULE" ]]; then
    # Fallback to libfuzzer build if coverage build is missing
    PKCS11_TOOL="/home/john/pkcs11-fuzzer/builds/libfuzzer/bin/pkcs11-tool"
    OPENSC_MODULE="/home/john/pkcs11-fuzzer/builds/libfuzzer/lib/opensc-pkcs11.so"
fi

echo "Testing OpenSC mock PC/SC driver..."

# 1. Test that without the mock, no readers are found (assuming no real PCSC is running)
# We use a dummy OPENSC_CONF to avoid using system config
echo "app default { reader_driver pcsc { provider_library = /nonexistent; } }" > tmp-test.conf
OPENSC_CONF=tmp-test.conf "$PKCS11_TOOL" --module "$OPENSC_MODULE" --list-slots > out-no-mock.txt || true
if grep -q "Mock Reader" out-no-mock.txt; then
    echo "ERROR: Mock Reader found when it shouldn't be!"
    exit 1
fi
echo "  [PASS] No mock reader found without env var."

# 2. Test that with OPENSC_MOCK_PCSC=1, the Mock Reader is found
OPENSC_MOCK_PCSC=1 OPENSC_CONF=tmp-test.conf "$PKCS11_TOOL" --module "$OPENSC_MODULE" --list-slots > out-mock.txt
if ! grep -q "Mock Reader" out-mock.txt; then
    echo "ERROR: Mock Reader NOT found with OPENSC_MOCK_PCSC=1!"
    cat out-mock.txt
    exit 1
fi
echo "  [PASS] Mock Reader found with OPENSC_MOCK_PCSC=1."

rm tmp-test.conf out-no-mock.txt out-mock.txt
echo "OpenSC mock PC/SC regression test passed."
