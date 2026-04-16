/*
 * pkcs11_state_machine_fuzz.c — Bytecode-style mixed PKCS#11 state fuzzer.
 *
 * Each input is interpreted as a short sequence of opcodes. This lets one
 * iteration explore invalid call ordering, cleanup edges, and state transfer
 * between operations instead of only single happy-path APIs.
 */
#include "common.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MAX_STEPS 32
#define MAX_STATE 4096

static uint8_t take_u8(const uint8_t *data, size_t size, size_t *off)
{
    if (*off >= size) return 0;
    return data[(*off)++];
}

static CK_SLOT_ID get_active_slot(void)
{
    CK_SESSION_INFO info;

    if (sess == CK_INVALID_HANDLE) return CK_INVALID_HANDLE;
    if (p11->C_GetSessionInfo(sess, &info) != CKR_OK) return CK_INVALID_HANDLE;
    return info.slotID;
}

static CK_SESSION_HANDLE open_rw_session(CK_SLOT_ID slot)
{
    CK_SESSION_HANDLE local = CK_INVALID_HANDLE;

    if (slot == CK_INVALID_HANDLE) return CK_INVALID_HANDLE;
    if (p11->C_OpenSession(slot,
                           CKF_SERIAL_SESSION | CKF_RW_SESSION,
                           NULL_PTR,
                           NULL_PTR,
                           &local) != CKR_OK) {
        return CK_INVALID_HANDLE;
    }
    return local;
}

static void restore_user_login(void)
{
    if (sess == CK_INVALID_HANDLE) return;
    p11->C_Login(sess, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
}

static CK_OBJECT_HANDLE pick_object(uint8_t sel,
                                    const CK_OBJECT_HANDLE *temps,
                                    size_t ntemps)
{
    switch (sel % 8) {
    case 0: return rsa_pub;
    case 1: return rsa_priv;
    case 2: return ec_pub;
    case 3: return ec_priv;
    case 4: return aes_key;
    case 5: return hmac_key;
    case 6: return (ntemps > 0) ? temps[0] : CK_INVALID_HANDLE;
    default: return (ntemps > 0) ? temps[ntemps - 1] : CK_INVALID_HANDLE;
    }
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
    static const CK_ATTRIBUTE_TYPE attr_types[] = {
        CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID,
        CKA_VALUE, CKA_VALUE_LEN, CKA_MODULUS, CKA_EC_POINT,
    };
    static const CK_MECHANISM_TYPE digest_mechs[] = {
        CKM_SHA_1, CKM_SHA224, CKM_SHA256, CKM_SHA512, CKM_MD5,
    };
    static const CK_BYTE label_prefix[] = "sm-obj-";

    CK_SLOT_ID slot;
    CK_SESSION_HANDLE local;
    CK_OBJECT_HANDLE temps[8];
    size_t ntemps = 0;
    CK_OBJECT_HANDLE found[4];
    CK_ULONG found_count = 0;
    CK_BYTE state_buf[MAX_STATE];
    CK_ULONG state_len = 0;
    size_t off = 0;

    if (size == 0) return 0;

    memset(temps, 0xff, sizeof(temps));
    slot = get_active_slot();
    if (slot == CK_INVALID_HANDLE) return 0;

    local = open_rw_session(slot);
    if (local == CK_INVALID_HANDLE) return 0;
    p11->C_Login(local, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);

    for (size_t step = 0; step < MAX_STEPS && off < size; step++) {
        CK_BYTE op = take_u8(data, size, &off) % 20;

        switch (op) {
        case 0: {
            CK_SESSION_INFO info;
            p11->C_GetSessionInfo(local, &info);
            break;
        }

        case 1: {
            CK_OBJECT_CLASS cls = (take_u8(data, size, &off) & 1) ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
            CK_BYTE id = (take_u8(data, size, &off) % 4) + 1;
            CK_ATTRIBUTE tmpl[] = {
                { CKA_CLASS, &cls, sizeof(cls) },
                { CKA_ID, &id, sizeof(id) },
            };
            p11->C_FindObjectsInit(local, tmpl, 2);
            break;
        }

        case 2:
            found_count = 0;
            p11->C_FindObjects(local, found, 4, &found_count);
            break;

        case 3:
            p11->C_FindObjectsFinal(local);
            break;

        case 4: {
            CK_OBJECT_HANDLE obj = pick_object(take_u8(data, size, &off), temps, ntemps);
            CK_ATTRIBUTE tmpl[2];

            tmpl[0].type = attr_types[take_u8(data, size, &off) % (sizeof(attr_types) / sizeof(attr_types[0]))];
            tmpl[0].pValue = NULL_PTR;
            tmpl[0].ulValueLen = 0;
            tmpl[1].type = attr_types[take_u8(data, size, &off) % (sizeof(attr_types) / sizeof(attr_types[0]))];
            tmpl[1].pValue = NULL_PTR;
            tmpl[1].ulValueLen = 0;
            p11->C_GetAttributeValue(local, obj, tmpl, 2);
            break;
        }

        case 5: {
            CK_OBJECT_CLASS cls = CKO_DATA;
            CK_BBOOL token = CK_FALSE;
            CK_BBOOL priv = (take_u8(data, size, &off) & 1) ? CK_TRUE : CK_FALSE;
            CK_BYTE value[32];
            CK_BYTE label[sizeof(label_prefix) + 1];
            CK_ULONG vlen = (CK_ULONG)(take_u8(data, size, &off) % sizeof(value));
            CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
            CK_ATTRIBUTE tmpl[5];

            memset(value, 0, sizeof(value));
            if (vlen > 0 && off + vlen <= size) {
                memcpy(value, data + off, vlen);
                off += vlen;
            }
            memcpy(label, label_prefix, sizeof(label_prefix) - 1);
            label[sizeof(label_prefix) - 1] = take_u8(data, size, &off);
            label[sizeof(label_prefix)] = '\0';

            tmpl[0] = (CK_ATTRIBUTE){ CKA_CLASS, &cls, sizeof(cls) };
            tmpl[1] = (CK_ATTRIBUTE){ CKA_TOKEN, &token, sizeof(token) };
            tmpl[2] = (CK_ATTRIBUTE){ CKA_PRIVATE, &priv, sizeof(priv) };
            tmpl[3] = (CK_ATTRIBUTE){ CKA_LABEL, label, sizeof(label) - 1 };
            tmpl[4] = (CK_ATTRIBUTE){ CKA_VALUE, value, vlen };

            if (p11->C_CreateObject(local, tmpl, 5, &obj) == CKR_OK &&
                obj != CK_INVALID_HANDLE && ntemps < sizeof(temps) / sizeof(temps[0])) {
                temps[ntemps++] = obj;
            }
            break;
        }

        case 6: {
            CK_OBJECT_HANDLE src = pick_object(take_u8(data, size, &off), temps, ntemps);
            CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
            CK_BBOOL token = CK_FALSE;
            CK_BYTE label[8] = { 'c', 'o', 'p', 'y', '-', take_u8(data, size, &off), 0 };
            CK_ATTRIBUTE tmpl[] = {
                { CKA_TOKEN, &token, sizeof(token) },
                { CKA_LABEL, label, 6 },
            };

            if (p11->C_CopyObject(local, src, tmpl, 2, &copy) == CKR_OK &&
                copy != CK_INVALID_HANDLE && ntemps < sizeof(temps) / sizeof(temps[0])) {
                temps[ntemps++] = copy;
            }
            break;
        }

        case 7: {
            uint8_t which = take_u8(data, size, &off);
            CK_OBJECT_HANDLE obj = pick_object(which, temps, ntemps);

            p11->C_DestroyObject(local, obj);
            for (size_t i = 0; i < ntemps; i++) {
                if (temps[i] == obj) {
                    temps[i] = temps[ntemps - 1];
                    temps[ntemps - 1] = CK_INVALID_HANDLE;
                    ntemps--;
                    break;
                }
            }
            break;
        }

        case 8: {
            CK_MECHANISM mech = {
                digest_mechs[take_u8(data, size, &off) % (sizeof(digest_mechs) / sizeof(digest_mechs[0]))],
                NULL_PTR,
                0,
            };
            p11->C_DigestInit(local, &mech);
            break;
        }

        case 9: {
            CK_ULONG chunk = (CK_ULONG)(take_u8(data, size, &off) % 32);

            if (off + chunk > size) chunk = (CK_ULONG)(size - off);
            p11->C_DigestUpdate(local, (CK_BYTE_PTR)(data + off), chunk);
            off += chunk;
            break;
        }

        case 10: {
            CK_BYTE out[64];
            CK_ULONG outlen = sizeof(out);
            p11->C_DigestFinal(local, out, &outlen);
            break;
        }

        case 11: {
            CK_BYTE which = take_u8(data, size, &off);
            CK_MECHANISM mech;
            CK_OBJECT_HANDLE key;

            switch (which % 3) {
            case 0:
                mech = (CK_MECHANISM){ CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
                key = rsa_priv;
                break;
            case 1:
                mech = (CK_MECHANISM){ CKM_ECDSA_SHA256, NULL_PTR, 0 };
                key = ec_priv;
                break;
            default:
                mech = (CK_MECHANISM){ CKM_SHA256_HMAC, NULL_PTR, 0 };
                key = hmac_key;
                break;
            }
            p11->C_SignInit(local, &mech, key);
            break;
        }

        case 12: {
            CK_ULONG chunk = (CK_ULONG)(take_u8(data, size, &off) % 32);

            if (off + chunk > size) chunk = (CK_ULONG)(size - off);
            p11->C_SignUpdate(local, (CK_BYTE_PTR)(data + off), chunk);
            off += chunk;
            break;
        }

        case 13: {
            CK_BYTE sig[512];
            CK_ULONG siglen = sizeof(sig);
            p11->C_SignFinal(local, sig, &siglen);
            break;
        }

        case 14:
            state_len = sizeof(state_buf);
            p11->C_GetOperationState(local, state_buf, &state_len);
            break;

        case 15: {
            CK_OBJECT_HANDLE enc_key = (take_u8(data, size, &off) & 1) ? aes_key : CK_INVALID_HANDLE;
            CK_OBJECT_HANDLE auth_key = (take_u8(data, size, &off) & 1) ? rsa_priv : CK_INVALID_HANDLE;
            p11->C_SetOperationState(local, state_buf, state_len, enc_key, auth_key);
            break;
        }

        case 16:
            p11->C_Logout(local);
            break;

        case 17: {
            CK_UTF8CHAR pin[16];
            CK_ULONG pin_len = (CK_ULONG)(take_u8(data, size, &off) % sizeof(pin));

            memset(pin, 0, sizeof(pin));
            if (pin_len > 0 && off + pin_len <= size) {
                memcpy(pin, data + off, pin_len);
                off += pin_len;
            }
            p11->C_Login(local, CKU_USER, pin, pin_len);
            break;
        }

        case 18:
            p11->C_CloseSession(local);
            local = CK_INVALID_HANDLE;
            break;

        case 19:
            if (local == CK_INVALID_HANDLE) {
                local = open_rw_session(slot);
            }
            break;
        }
    }

    if (local != CK_INVALID_HANDLE) {
        for (size_t i = 0; i < ntemps; i++) {
            if (temps[i] != CK_INVALID_HANDLE) {
                p11->C_DestroyObject(local, temps[i]);
            }
        }
        p11->C_FindObjectsFinal(local);
        p11->C_CloseSession(local);
    }
    restore_user_login();
    return 0;
}
