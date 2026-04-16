/*
 * pkcs11_session_fuzz.c — Fuzz session/auth and operation-state APIs.
 *
 * The existing harnesses mostly hit happy-path cryptographic operations. This
 * one focuses on state transitions: open/close, login/logout, invalid-handle
 * reuse, and Get/SetOperationState around digest/sign contexts.
 *
 * Input layout:
 *   byte 0: selector (0-9)
 *   byte 1+: payload used for pin/state variation
 */
#include "common.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STATE_BUF_MAX 4096

static CK_SLOT_ID get_active_slot(void)
{
    CK_SESSION_INFO info;

    if (sess == CK_INVALID_HANDLE) return CK_INVALID_HANDLE;
    if (p11->C_GetSessionInfo(sess, &info) != CKR_OK) return CK_INVALID_HANDLE;
    return info.slotID;
}

static CK_SESSION_HANDLE open_local_session(CK_SLOT_ID slot, CK_FLAGS flags)
{
    CK_SESSION_HANDLE local = CK_INVALID_HANDLE;

    if (slot == CK_INVALID_HANDLE) return CK_INVALID_HANDLE;
    if (p11->C_OpenSession(slot, flags, NULL_PTR, NULL_PTR, &local) != CKR_OK) {
        return CK_INVALID_HANDLE;
    }
    return local;
}

static void restore_user_login(void)
{
    if (sess == CK_INVALID_HANDLE) return;
    p11->C_Login(sess, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    pkcs11_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE s1 = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE s2 = CK_INVALID_HANDLE;
    CK_BYTE state_buf[STATE_BUF_MAX];
    CK_ULONG state_len = sizeof(state_buf);
    CK_MECHANISM mech;
    CK_SESSION_INFO info;
    CK_RV rv;
    uint8_t sel;
    const uint8_t *pay;
    size_t plen;

    if (size < 1) return 0;

    sel = data[0] % 10;
    pay = payload_ptr(data, size);
    plen = payload_len(size);
    slot = get_active_slot();
    if (slot == CK_INVALID_HANDLE) return 0;

    switch (sel) {
    case 0:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION);
        if (s1 != CK_INVALID_HANDLE) {
            p11->C_GetSessionInfo(s1, &info);
            p11->C_CloseSession(s1);
        }
        break;

    case 1:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        if (s1 != CK_INVALID_HANDLE) {
            p11->C_GetSessionInfo(s1, &info);
            p11->C_CloseSession(s1);
            p11->C_CloseSession(s1);
        }
        break;

    case 2:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        if (s1 != CK_INVALID_HANDLE) {
            CK_UTF8CHAR fuzz_pin[16];
            CK_ULONG pin_len = (plen < sizeof(fuzz_pin)) ? (CK_ULONG)plen : (CK_ULONG)sizeof(fuzz_pin);

            memset(fuzz_pin, 0, sizeof(fuzz_pin));
            if (pin_len > 0) memcpy(fuzz_pin, pay, pin_len);

            p11->C_Logout(s1);
            p11->C_Login(s1, CKU_USER, fuzz_pin, pin_len);
            restore_user_login();
            p11->C_CloseSession(s1);
        }
        break;

    case 3:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        if (s1 != CK_INVALID_HANDLE) {
            p11->C_Logout(s1);
            p11->C_Login(s1, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
            p11->C_Login(s1, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
            p11->C_CloseSession(s1);
        }
        restore_user_login();
        break;

    case 4:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION);
        if (s1 != CK_INVALID_HANDLE) {
            p11->C_CloseSession(s1);
            p11->C_GetSessionInfo(s1, &info);
        }
        p11->C_CloseSession(CK_INVALID_HANDLE);
        break;

    case 5:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION);
        if (s1 != CK_INVALID_HANDLE) {
            mech.mechanism = CKM_SHA256;
            mech.pParameter = NULL_PTR;
            mech.ulParameterLen = 0;
            if (p11->C_DigestInit(s1, &mech) == CKR_OK) {
                state_len = 0;
                rv = p11->C_GetOperationState(s1, NULL_PTR, &state_len);
                if ((rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) && state_len <= STATE_BUF_MAX) {
                    p11->C_GetOperationState(s1, state_buf, &state_len);
                }
            }
            p11->C_CloseSession(s1);
        }
        break;

    case 6:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION);
        if (s1 != CK_INVALID_HANDLE && rsa_priv != CK_INVALID_HANDLE) {
            mech.mechanism = CKM_SHA256_RSA_PKCS;
            mech.pParameter = NULL_PTR;
            mech.ulParameterLen = 0;
            if (p11->C_SignInit(s1, &mech, rsa_priv) == CKR_OK) {
                state_len = 0;
                rv = p11->C_GetOperationState(s1, NULL_PTR, &state_len);
                if ((rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) && state_len <= STATE_BUF_MAX) {
                    p11->C_GetOperationState(s1, state_buf, &state_len);
                }
            }
            p11->C_CloseSession(s1);
        }
        break;

    case 7:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION);
        s2 = open_local_session(slot, CKF_SERIAL_SESSION);
        if (s1 != CK_INVALID_HANDLE && s2 != CK_INVALID_HANDLE) {
            mech.mechanism = CKM_SHA256;
            mech.pParameter = NULL_PTR;
            mech.ulParameterLen = 0;
            if (p11->C_DigestInit(s1, &mech) == CKR_OK) {
                state_len = sizeof(state_buf);
                if (p11->C_GetOperationState(s1, state_buf, &state_len) == CKR_OK && state_len <= STATE_BUF_MAX) {
                    CK_BYTE out[32];
                    CK_ULONG out_len = sizeof(out);
                    p11->C_SetOperationState(s2, state_buf, state_len,
                                             CK_INVALID_HANDLE, CK_INVALID_HANDLE);
                    if (plen > 0) p11->C_DigestUpdate(s2, (CK_BYTE_PTR)pay, (CK_ULONG)plen);
                    p11->C_DigestFinal(s2, out, &out_len);
                }
            }
        }
        if (s1 != CK_INVALID_HANDLE) p11->C_CloseSession(s1);
        if (s2 != CK_INVALID_HANDLE) p11->C_CloseSession(s2);
        break;

    case 8:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION);
        s2 = open_local_session(slot, CKF_SERIAL_SESSION);
        if (s1 != CK_INVALID_HANDLE && s2 != CK_INVALID_HANDLE && rsa_priv != CK_INVALID_HANDLE) {
            mech.mechanism = CKM_SHA256_RSA_PKCS;
            mech.pParameter = NULL_PTR;
            mech.ulParameterLen = 0;
            if (p11->C_SignInit(s1, &mech, rsa_priv) == CKR_OK) {
                state_len = sizeof(state_buf);
                if (p11->C_GetOperationState(s1, state_buf, &state_len) == CKR_OK && state_len <= STATE_BUF_MAX) {
                    CK_BYTE sig[512];
                    CK_ULONG sig_len = sizeof(sig);
                    CK_OBJECT_HANDLE auth_key = (plen > 0 && (pay[0] & 1)) ? rsa_priv : CK_INVALID_HANDLE;

                    p11->C_SetOperationState(s2, state_buf, state_len,
                                             CK_INVALID_HANDLE, auth_key);
                    if (plen > 1) p11->C_SignUpdate(s2, (CK_BYTE_PTR)(pay + 1), (CK_ULONG)(plen - 1));
                    p11->C_SignFinal(s2, sig, &sig_len);
                }
            }
        }
        if (s1 != CK_INVALID_HANDLE) p11->C_CloseSession(s1);
        if (s2 != CK_INVALID_HANDLE) p11->C_CloseSession(s2);
        break;

    case 9:
        s1 = open_local_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION);
        if (s1 != CK_INVALID_HANDLE) {
            CK_UTF8CHAR so_pin[16];
            CK_ULONG so_len = (plen < sizeof(so_pin)) ? (CK_ULONG)plen : (CK_ULONG)sizeof(so_pin);

            memset(so_pin, 0, sizeof(so_pin));
            if (so_len > 0) memcpy(so_pin, pay, so_len);

            p11->C_Login(s1, CKU_SO, so_pin, so_len);
            p11->C_GetOperationState(s1, state_buf, &state_len);
            p11->C_Logout(s1);
            p11->C_CloseSession(s1);
        }
        restore_user_login();
        break;
    }

    return 0;
}
