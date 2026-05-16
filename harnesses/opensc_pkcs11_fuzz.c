/*
 * opensc_pkcs11_fuzz.c — Fuzz OpenSC via its PKCS#11 module (opensc-pkcs11.so).
 *
 * OpenSC coverage stays low if each input drives only one PKCS#11 call. This
 * harness interprets one input as a short command stream so it can chain init,
 * slot enumeration, mechanism queries, session churn, and object operations.
 *
 * The harness must still work on systems with no PC/SC daemon or token, so it
 * deliberately mixes real slot IDs (when present) with fuzz-controlled invalid
 * ones to exercise both success and error paths.
 */
#include <assert.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* PKCS#11 header — prefer the build-tree install, but keep a source-tree
 * fallback so editor tooling can parse harnesses before the targets are built. */
#if __has_include(<pkcs11.h>)
#include <pkcs11.h>
#elif __has_include("../src/softhsm2/src/lib/pkcs11/pkcs11.h")
#include "../src/softhsm2/src/lib/pkcs11/pkcs11.h"
#else
#error "pkcs11.h not found"
#endif

#ifndef OPENSC_PKCS11_PATH
#  error "OPENSC_PKCS11_PATH must be defined via -DOPENSC_PKCS11_PATH=..."
#endif

#define MAX_STEPS 54
#define MAX_ATTRS 8
#define MAX_SESSIONS 4
#define MAX_SLOTS 64
#define MAX_MECHS 256
#define MAX_OBJECTS 16

static CK_FUNCTION_LIST_PTR p11 = NULL;
static void *dl = NULL;

/* Exported for libopensc mock driver to consume */
uint8_t fuzz_resp_buffer[8192];
size_t fuzz_resp_len = 0;

static const CK_ATTRIBUTE_TYPE KNOWN_ATTRS[] = {
    CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL,
    CKA_APPLICATION, CKA_VALUE, CKA_ID,
    CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_VERIFY,
    CKA_KEY_TYPE, CKA_MODULUS, CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT, CKA_EC_PARAMS, CKA_EC_POINT,
    CKA_CERTIFICATE_TYPE, CKA_ISSUER, CKA_SUBJECT,
};
#define N_KNOWN_ATTRS (sizeof(KNOWN_ATTRS) / sizeof(KNOWN_ATTRS[0]))

static uint8_t take_u8(const uint8_t *data, size_t size, size_t *off)
{
    if (*off >= size) return 0;
    return data[(*off)++];
}

static uint32_t take_u32(const uint8_t *data, size_t size, size_t *off)
{
    uint32_t out = 0;
    for (size_t i = 0; i < 4; i++) {
        out |= ((uint32_t)take_u8(data, size, off)) << (i * 8);
    }
    return out;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    dl = dlopen(OPENSC_PKCS11_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!dl) {
        fprintf(stderr, "[opensc_pkcs11] dlopen failed: %s\n", dlerror());
        return 0;
    }

    CK_C_GetFunctionList get_fl =
        (CK_C_GetFunctionList)dlsym(dl, "C_GetFunctionList");
    if (!get_fl || get_fl(&p11) != CKR_OK || !p11) {
        fprintf(stderr, "[opensc_pkcs11] C_GetFunctionList failed\n");
        return 0;
    }

    fprintf(stderr, "[opensc_pkcs11] Loaded %s\n", OPENSC_PKCS11_PATH);
    return 0;
}

static void build_template(CK_ATTRIBUTE *tmpl,
                           CK_ULONG *count_out,
                           CK_ULONG max_attrs,
                           const uint8_t *data,
                           size_t size,
                           size_t *off)
{
    static uint8_t attr_buf[MAX_ATTRS][32];
    CK_ULONG n = 0;
    CK_ULONG want = ((CK_ULONG)take_u8(data, size, off) % max_attrs) + 1;

    for (CK_ULONG i = 0; i < want && i < max_attrs; i++) {
        uint8_t type_idx = take_u8(data, size, off) % (N_KNOWN_ATTRS + 8);
        CK_ATTRIBUTE_TYPE atype = (type_idx < N_KNOWN_ATTRS)
            ? KNOWN_ATTRS[type_idx]
            : (CK_ATTRIBUTE_TYPE)(type_idx - N_KNOWN_ATTRS);
        CK_ULONG actual = (CK_ULONG)(take_u8(data, size, off) % sizeof(attr_buf[i]));

        if (*off + actual > size) actual = (CK_ULONG)(size - *off);
        if (actual > 0) memcpy(attr_buf[i], data + *off, actual);
        *off += actual;

        tmpl[n].type = atype;
        tmpl[n].pValue = (actual > 0) ? attr_buf[i] : NULL_PTR;
        tmpl[n].ulValueLen = actual;
        n++;
    }

    *count_out = n;
}

static CK_SLOT_ID choose_slot(const CK_SLOT_ID *slots,
                              CK_ULONG nslots,
                              CK_SLOT_ID fuzz_slot,
                              uint8_t mode)
{
    if (nslots > 0 && (mode & 1) == 0) {
        return slots[mode % nslots];
    }
    return fuzz_slot;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CK_RV rv;
    CK_SLOT_ID slots[MAX_SLOTS];
    CK_ULONG nslots = 0;
    CK_ULONG nslots_with_token = 0;
    CK_SESSION_HANDLE sessions[MAX_SESSIONS];
    CK_SESSION_HANDLE active = CK_INVALID_HANDLE;
    CK_SLOT_ID active_slot = CK_INVALID_HANDLE;
    CK_SLOT_ID fuzz_slot;
    CK_OBJECT_HANDLE objs[MAX_OBJECTS];
    CK_ULONG obj_count = 0;
    size_t off = 0;

    if (!p11 || size == 0) return 0;

    fuzz_slot = (CK_SLOT_ID)take_u32(data, size, &off);
    memset(slots, 0, sizeof(slots));
    for (size_t i = 0; i < MAX_SESSIONS; i++) sessions[i] = CK_INVALID_HANDLE;

    rv = p11->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        return 0;
    }

    p11->C_GetSlotList(CK_FALSE, NULL, &nslots);
    if (nslots > 0 && nslots <= MAX_SLOTS) {
        p11->C_GetSlotList(CK_FALSE, slots, &nslots);
    } else {
        nslots = 0;
    }
    static int once = 0;
    if (!once) {
        fprintf(stderr, "[opensc_pkcs11] Found %lu slots\n", nslots);
        once = 1;
    }
    p11->C_GetSlotList(CK_TRUE, NULL, &nslots_with_token);

    for (size_t step = 0; step < MAX_STEPS && off < size; step++) {
        CK_BYTE op = take_u8(data, size, &off) % 54;

        switch (op) {
        case 0: {
            CK_INFO info;
            p11->C_GetInfo(&info);
            break;
        }

        case 1: {
            CK_SLOT_ID slot = choose_slot(slots, nslots, fuzz_slot, take_u8(data, size, &off));
            CK_SLOT_INFO si;
            CK_TOKEN_INFO ti;
            active_slot = slot;
            p11->C_GetSlotInfo(slot, &si);
            p11->C_GetTokenInfo(slot, &ti);
            break;
        }

        case 2: {
            CK_SLOT_ID slot = choose_slot(slots, nslots, fuzz_slot, take_u8(data, size, &off));
            CK_ULONG nmechs = 0;
            CK_MECHANISM_TYPE mechs[MAX_MECHS];

            p11->C_GetMechanismList(slot, NULL, &nmechs);
            if (nmechs > 0 && nmechs <= MAX_MECHS) {
                p11->C_GetMechanismList(slot, mechs, &nmechs);
                for (CK_ULONG i = 0; i < nmechs && i < 8; i++) {
                    CK_MECHANISM_INFO mi;
                    p11->C_GetMechanismInfo(slot, mechs[i], &mi);
                }
            }
            break;
        }

        case 3: {
            CK_SLOT_ID slot = choose_slot(slots, nslots, fuzz_slot, take_u8(data, size, &off));
            CK_SESSION_HANDLE h = CK_INVALID_HANDLE;
            CK_FLAGS flags = CKF_SERIAL_SESSION;
            uint8_t which = take_u8(data, size, &off) % MAX_SESSIONS;

            if (take_u8(data, size, &off) & 1) flags |= CKF_RW_SESSION;
            if (p11->C_OpenSession(slot, flags, NULL_PTR, NULL_PTR, &h) == CKR_OK) {
                sessions[which] = h;
                active = h;
                active_slot = slot;
            }
            break;
        }

        case 4: {
            uint8_t which = take_u8(data, size, &off) % MAX_SESSIONS;
            if (sessions[which] != CK_INVALID_HANDLE) active = sessions[which];
            break;
        }

        case 5:
            if (active != CK_INVALID_HANDLE) {
                CK_SESSION_INFO info;
                p11->C_GetSessionInfo(active, &info);
            }
            break;

        case 6: {
            if (active != CK_INVALID_HANDLE) {
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                if (p11->C_FindObjectsInit(active, tmpl, nattr) == CKR_OK) {
                    obj_count = 0;
                    p11->C_FindObjects(active, objs, MAX_OBJECTS, &obj_count);
                    p11->C_FindObjectsFinal(active);
                }
            }
            break;
        }

        case 7: {
            if (active != CK_INVALID_HANDLE) {
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                if (obj_count > 0) {
                    p11->C_GetAttributeValue(active,
                                             objs[take_u8(data, size, &off) % obj_count],
                                             tmpl,
                                             nattr);
                } else {
                    p11->C_GetAttributeValue(active,
                                             (CK_OBJECT_HANDLE)take_u32(data, size, &off),
                                             tmpl,
                                             nattr);
                }
            }
            break;
        }

        case 8:
            if (active_slot != CK_INVALID_HANDLE) {
                p11->C_CloseAllSessions(active_slot);
                for (size_t i = 0; i < MAX_SESSIONS; i++) sessions[i] = CK_INVALID_HANDLE;
                active = CK_INVALID_HANDLE;
            }
            break;

        case 9: {
            uint8_t which = take_u8(data, size, &off) % MAX_SESSIONS;
            if (sessions[which] != CK_INVALID_HANDLE) {
                p11->C_CloseSession(sessions[which]);
                if (active == sessions[which]) active = CK_INVALID_HANDLE;
                sessions[which] = CK_INVALID_HANDLE;
            }
            break;
        }

        case 10: {
            CK_UTF8CHAR pin[16];
            CK_ULONG pin_len = (CK_ULONG)(take_u8(data, size, &off) % sizeof(pin));
            CK_USER_TYPE user = (take_u8(data, size, &off) & 1) ? CKU_SO : CKU_USER;

            if (pin_len > size - off) pin_len = (CK_ULONG)(size - off);
            memset(pin, 0, sizeof(pin));
            if (pin_len > 0) memcpy(pin, data + off, pin_len);
            off += pin_len;
            if (active != CK_INVALID_HANDLE) p11->C_Login(active, user, pin, pin_len);
            break;
        }

        case 11:
            if (active != CK_INVALID_HANDLE) p11->C_Logout(active);
            break;

        case 12:
            p11->C_Finalize(NULL_PTR);
            p11->C_Initialize(NULL_PTR);
            p11->C_GetSlotList(CK_FALSE, NULL, &nslots);
            if (nslots > 0 && nslots <= MAX_SLOTS) {
                p11->C_GetSlotList(CK_FALSE, slots, &nslots);
            } else {
                nslots = 0;
            }
            for (size_t i = 0; i < MAX_SESSIONS; i++) sessions[i] = CK_INVALID_HANDLE;
            active = CK_INVALID_HANDLE;
            active_slot = CK_INVALID_HANDLE;
            obj_count = 0;
            break;

        case 13:
            if (active_slot != CK_INVALID_HANDLE) {
                CK_MECHANISM_INFO mi;
                p11->C_GetMechanismInfo(active_slot,
                                        (CK_MECHANISM_TYPE)take_u32(data, size, &off),
                                        &mi);
            }
            break;

        case 14: {
            CK_ULONG count = 0;
            p11->C_GetSlotList((take_u8(data, size, &off) & 1) ? CK_TRUE : CK_FALSE,
                               NULL,
                               &count);
            break;
        }

        case 15:
            if (active != CK_INVALID_HANDLE) {
                p11->C_FindObjectsInit(active, NULL_PTR, 0);
                obj_count = 0;
                p11->C_FindObjects(active, objs, MAX_OBJECTS, &obj_count);
                p11->C_FindObjectsFinal(active);
            }
            break;

        case 16: {
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                p11->C_SetAttributeValue(active,
                                         objs[take_u8(data, size, &off) % obj_count],
                                         tmpl,
                                         nattr);
            }
            break;
        }

        case 17: {
            if (active != CK_INVALID_HANDLE) {
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                CK_OBJECT_HANDLE h;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                p11->C_CreateObject(active, tmpl, nattr, &h);
            }
            break;
        }

        case 18: {
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                CK_OBJECT_HANDLE h;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                p11->C_CopyObject(active, objs[take_u8(data, size, &off) % obj_count], tmpl, nattr, &h);
            }
            break;
        }

        case 19: {
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                p11->C_DestroyObject(active, objs[take_u8(data, size, &off) % obj_count]);
            }
            break;
        }

        case 20: {
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                if (p11->C_SignInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    CK_BYTE buf[256];
                    CK_ULONG len = sizeof(buf);
                    size_t remaining = (off < size) ? size - off : 0;
                    if (remaining == 0) remaining = 1;
                    if (remaining > sizeof(buf)) remaining = sizeof(buf);
                    p11->C_Sign(active, (CK_BYTE_PTR)(data + off), (CK_ULONG)remaining, buf, &len);
                    off += remaining;
                }
            }
            break;
        }

        case 21: {
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                if (p11->C_VerifyInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    size_t remaining = (off < size) ? size - off : 0;
                    size_t data_len = (remaining > 64) ? 64 : remaining;
                    size_t sig_len = (remaining > data_len) ? ((remaining - data_len) > 128 ? 128 : remaining - data_len) : 0;
                    p11->C_Verify(active, (CK_BYTE_PTR)(data + off), (CK_ULONG)data_len,
                                  (CK_BYTE_PTR)(data + off + data_len), (CK_ULONG)sig_len);
                    off += data_len + sig_len;
                }
            }
            break;
        }

        case 22: {
            uint32_t len = take_u8(data, size, &off) * 4;
            if (len > sizeof(fuzz_resp_buffer)) len = sizeof(fuzz_resp_buffer);
            if (len > size - off) len = size - off;
            memcpy(fuzz_resp_buffer, data + off, len);
            fuzz_resp_len = len;
            off += len;
            break;
        }
        case 23: { /* C_GenerateKey */
            if (active != CK_INVALID_HANDLE) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                CK_OBJECT_HANDLE h;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                p11->C_GenerateKey(active, &mech, tmpl, nattr, &h);
            }
            break;
        }
        case 24: { /* C_Encrypt */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_BYTE in[64], out[256]; CK_ULONG ilen=32, olen=sizeof(out);
                if (p11->C_EncryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Encrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        case 25: { /* C_Decrypt */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_BYTE in[64], out[256]; CK_ULONG ilen=32, olen=sizeof(out);
                if (p11->C_DecryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Decrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        case 26: { /* C_GenerateRandom */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE buf[128];
                CK_ULONG len = take_u8(data, size, &off) % sizeof(buf);
                p11->C_GenerateRandom(active, buf, len);
            }
            break;
        }
        case 27: { /* C_SetPIN */
            if (active != CK_INVALID_HANDLE) {
                CK_UTF8CHAR oldpin[16], newpin[16];
                CK_ULONG olen = (CK_ULONG)(take_u8(data, size, &off) % sizeof(oldpin));
                CK_ULONG nlen = (CK_ULONG)(take_u8(data, size, &off) % sizeof(newpin));
                if (olen > size-off) olen = size-off;
                memcpy(oldpin, data+off, olen); off += olen;
                if (nlen > size-off) nlen = size-off;
                memcpy(newpin, data+off, nlen); off += nlen;
                p11->C_SetPIN(active, oldpin, olen, newpin, nlen);
            }
            break;
        }
        case 28: { /* C_Initialize with params */
            CK_C_INITIALIZE_ARGS args = {0};
            args.flags = take_u8(data, size, &off) & 3;
            p11->C_Initialize(&args);
            break;
        }
        case 29: { /* C_Digest */
            if (active != CK_INVALID_HANDLE) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_BYTE buf[64]; CK_ULONG len = sizeof(buf);
                if (p11->C_DigestInit(active, &mech) == CKR_OK) {
                    size_t remaining = (off < size) ? size - off : 0;
                    if (remaining == 0) remaining = 1;
                    if (remaining > sizeof(buf)) remaining = sizeof(buf);
                    p11->C_Digest(active, (CK_BYTE_PTR)(data + off), (CK_ULONG)remaining, buf, &len);
                    off += remaining;
                }
            }
            break;
        }
        case 30: { /* C_WaitForSlotEvent stub */
            CK_SLOT_ID slot;
            p11->C_WaitForSlotEvent(0, &slot, NULL_PTR);
            break;
        }
        case 31: { /* C_SignUpdate */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE part[32];
                CK_ULONG len = take_u8(data, size, &off) % sizeof(part);
                if (len > size - off) len = size - off;
                memcpy(part, data + off, len);
                off += len;
                p11->C_SignUpdate(active, part, len);
            }
            break;
        }
        case 32: { /* C_SignFinal */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE sig[256];
                CK_ULONG len = sizeof(sig);
                p11->C_SignFinal(active, sig, &len);
            }
            break;
        }
        case 33: { /* C_VerifyUpdate */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE part[32];
                CK_ULONG len = take_u8(data, size, &off) % sizeof(part);
                if (len > size - off) len = size - off;
                memcpy(part, data + off, len);
                off += len;
                p11->C_VerifyUpdate(active, part, len);
            }
            break;
        }
        case 34: { /* C_VerifyFinal */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE sig[256];
                CK_ULONG len = take_u8(data, size, &off) % sizeof(sig);
                if (len > size - off) len = size - off;
                memcpy(sig, data + off, len);
                off += len;
                p11->C_VerifyFinal(active, sig, len);
            }
            break;
        }
        case 35: { /* C_EncryptUpdate */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_BYTE in[64], out[64];
                CK_ULONG ilen = take_u8(data, size, &off) % sizeof(in);
                if (ilen > size - off) ilen = size - off;
                memcpy(in, data + off, ilen);
                off += ilen;
                CK_ULONG olen = sizeof(out);
                p11->C_EncryptUpdate(active, in, ilen, out, &olen);
            }
            break;
        }
        case 36: { /* C_EncryptFinal */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE out[64];
                CK_ULONG olen = sizeof(out);
                p11->C_EncryptFinal(active, out, &olen);
            }
            break;
        }
        case 37: { /* C_DecryptUpdate */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_BYTE in[64], out[64];
                CK_ULONG ilen = take_u8(data, size, &off) % sizeof(in);
                if (ilen > size - off) ilen = size - off;
                memcpy(in, data + off, ilen);
                off += ilen;
                CK_ULONG olen = sizeof(out);
                p11->C_DecryptUpdate(active, in, ilen, out, &olen);
            }
            break;
        }
        case 38: { /* C_DecryptFinal */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE out[64];
                CK_ULONG olen = sizeof(out);
                p11->C_DecryptFinal(active, out, &olen);
            }
            break;
        }
        case 39: { /* C_DigestUpdate */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE part[32];
                CK_ULONG len = take_u8(data, size, &off) % sizeof(part);
                if (len > size - off) len = size - off;
                memcpy(part, data + off, len);
                off += len;
                p11->C_DigestUpdate(active, part, len);
            }
            break;
        }
        case 40: { /* C_DigestKey */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_OBJECT_HANDLE key = objs[take_u8(data, size, &off) % obj_count];
                p11->C_DigestKey(active, key);
            }
            break;
        }
        case 41: { /* C_DigestFinal */
            if (active != CK_INVALID_HANDLE) {
                CK_BYTE hash[64];
                CK_ULONG len = sizeof(hash);
                p11->C_DigestFinal(active, hash, &len);
            }
            break;
        }
        case 42: { /* C_GenerateKeyPair */
            if (active != CK_INVALID_HANDLE) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_ATTRIBUTE pub_tmpl[MAX_ATTRS], priv_tmpl[MAX_ATTRS];
                CK_ULONG npub = 0, npriv = 0;
                build_template(pub_tmpl, &npub, MAX_ATTRS, data, size, &off);
                build_template(priv_tmpl, &npriv, MAX_ATTRS, data, size, &off);
                CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;
                p11->C_GenerateKeyPair(active, &mech, pub_tmpl, npub,
                                        priv_tmpl, npriv, &pub_h, &priv_h);
            }
            break;
        }
        case 43: { /* C_WrapKey */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_OBJECT_HANDLE wrap_key = objs[take_u8(data, size, &off) % obj_count];
                CK_OBJECT_HANDLE key = objs[take_u8(data, size, &off) % obj_count];
                CK_BYTE wrapped[256];
                CK_ULONG len = sizeof(wrapped);
                p11->C_WrapKey(active, &mech, wrap_key, key, wrapped, &len);
            }
            break;
        }
        case 44: { /* C_UnwrapKey */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_OBJECT_HANDLE unwrap_key = objs[take_u8(data, size, &off) % obj_count];
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                CK_ULONG wrapped_len = take_u8(data, size, &off) % sizeof(fuzz_resp_buffer);
                CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
                p11->C_UnwrapKey(active, &mech, unwrap_key,
                                  fuzz_resp_buffer, wrapped_len, tmpl, nattr, &key);
            }
            break;
        }
        case 45: { /* C_DeriveKey */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)take_u32(data, size, &off), NULL_PTR, 0};
                CK_OBJECT_HANDLE base_key = objs[take_u8(data, size, &off) % obj_count];
                CK_ATTRIBUTE tmpl[MAX_ATTRS];
                CK_ULONG nattr = 0;
                build_template(tmpl, &nattr, MAX_ATTRS, data, size, &off);
                CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
                p11->C_DeriveKey(active, &mech, base_key, tmpl, nattr, &key);
            }
            break;
        }
        case 46: { /* C_GetObjectSize */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_ULONG size = 0;
                p11->C_GetObjectSize(active,
                    objs[take_u8(data, size, &off) % obj_count], &size);
            }
            break;
        }
        case 47: { /* C_InitToken */
            CK_UTF8CHAR pin[16];
            CK_ULONG pin_len = take_u8(data, size, &off) % sizeof(pin);
            if (pin_len > size - off) pin_len = size - off;
            memcpy(pin, data + off, pin_len);
            off += pin_len;
            CK_UTF8CHAR label[32];
            CK_ULONG label_len = take_u8(data, size, &off) % sizeof(label);
            if (label_len > size - off) label_len = size - off;
            memcpy(label, data + off, label_len);
            off += label_len;
            if (active_slot != CK_INVALID_HANDLE) {
                p11->C_InitToken(active_slot, pin, pin_len, label);
            }
            break;
        }
        case 48: { /* C_Encrypt with AES-CBC IV */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_ULONG mech_type = take_u32(data, size, &off);
                CK_BYTE iv[16] = {0};
                for (size_t i = 0; i < 16 && off < size; i++) {
                    iv[i] = take_u8(data, size, &off);
                }
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)mech_type, iv, sizeof(iv)};
                CK_BYTE in[64], out[256]; CK_ULONG ilen=32, olen=sizeof(out);
                if (p11->C_EncryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Encrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        case 49: { /* C_Decrypt with AES-CBC IV */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_ULONG mech_type = take_u32(data, size, &off);
                CK_BYTE iv[16] = {0};
                for (size_t i = 0; i < 16 && off < size; i++) {
                    iv[i] = take_u8(data, size, &off);
                }
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)mech_type, iv, sizeof(iv)};
                CK_BYTE in[64], out[256]; CK_ULONG ilen=32, olen=sizeof(out);
                if (p11->C_DecryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Decrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        case 50: { /* C_Encrypt with AES-CTR counter block */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_ULONG mech_type = take_u32(data, size, &off);
                CK_AES_CTR_PARAMS ctr_params;
                ctr_params.ulCounterBits = 128;
                for (size_t i = 0; i < 16 && off < size; i++) {
                    ctr_params.cb[i] = take_u8(data, size, &off);
                }
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)mech_type, &ctr_params, sizeof(ctr_params)};
                CK_BYTE in[64], out[256]; CK_ULONG ilen=32, olen=sizeof(out);
                if (p11->C_EncryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Encrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        case 51: { /* C_Decrypt with AES-CTR counter block */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_ULONG mech_type = take_u32(data, size, &off);
                CK_AES_CTR_PARAMS ctr_params;
                ctr_params.ulCounterBits = 128;
                for (size_t i = 0; i < 16 && off < size; i++) {
                    ctr_params.cb[i] = take_u8(data, size, &off);
                }
                CK_MECHANISM mech = {(CK_MECHANISM_TYPE)mech_type, &ctr_params, sizeof(ctr_params)};
                CK_BYTE in[64], out[256]; CK_ULONG ilen=32, olen=sizeof(out);
                if (p11->C_DecryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Decrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        case 52: { /* C_Encrypt with AES-GCM */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_BYTE iv[12] = {0};
                for (size_t i = 0; i < 12 && off < size; i++) {
                    iv[i] = take_u8(data, size, &off);
                }
                CK_BYTE aad[32] = {0};
                size_t aad_len = 0;
                for (size_t i = 0; i < 16 && off < size; i++) {
                    aad[i] = take_u8(data, size, &off);
                    aad_len++;
                }
                CK_GCM_PARAMS gcm_params;
                gcm_params.pIv = iv;
                gcm_params.ulIvLen = 12;
                gcm_params.ulIvBits = 96;
                gcm_params.pAAD = aad_len > 0 ? aad : NULL;
                gcm_params.ulAADLen = (CK_ULONG)aad_len;
                gcm_params.ulTagBits = 128;
                CK_MECHANISM mech = {CKM_AES_GCM, &gcm_params, sizeof(gcm_params)};
                CK_BYTE in[64], out[256]; CK_ULONG olen=sizeof(out);
                size_t ilen = 0;
                for (size_t i = 0; i < 64 && off < size; i++) {
                    in[i] = take_u8(data, size, &off);
                    ilen++;
                }
                if (ilen == 0) ilen = 1;
                if (p11->C_EncryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Encrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        case 53: { /* C_Decrypt with AES-GCM */
            if (active != CK_INVALID_HANDLE && obj_count > 0) {
                CK_BYTE iv[12] = {0};
                for (size_t i = 0; i < 12 && off < size; i++) {
                    iv[i] = take_u8(data, size, &off);
                }
                CK_BYTE aad[32] = {0};
                size_t aad_len = 0;
                for (size_t i = 0; i < 16 && off < size; i++) {
                    aad[i] = take_u8(data, size, &off);
                    aad_len++;
                }
                CK_GCM_PARAMS gcm_params;
                gcm_params.pIv = iv;
                gcm_params.ulIvLen = 12;
                gcm_params.ulIvBits = 96;
                gcm_params.pAAD = aad_len > 0 ? aad : NULL;
                gcm_params.ulAADLen = (CK_ULONG)aad_len;
                gcm_params.ulTagBits = 128;
                CK_MECHANISM mech = {CKM_AES_GCM, &gcm_params, sizeof(gcm_params)};
                CK_BYTE in[64], out[256]; CK_ULONG olen=sizeof(out);
                size_t ilen = 0;
                for (size_t i = 0; i < 64 && off < size; i++) {
                    in[i] = take_u8(data, size, &off);
                    ilen++;
                }
                if (ilen == 0) ilen = 1;
                if (p11->C_DecryptInit(active, &mech, objs[take_u8(data, size, &off) % obj_count]) == CKR_OK) {
                    p11->C_Decrypt(active, in, ilen, out, &olen);
                }
            }
            break;
        }
        }
    }

    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i] != CK_INVALID_HANDLE) p11->C_CloseSession(sessions[i]);
    }
    p11->C_Finalize(NULL_PTR);
    return 0;
}
