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

#define MAX_STEPS 48
#define MAX_ATTRS 8
#define MAX_SESSIONS 4
#define MAX_SLOTS 64
#define MAX_MECHS 256
#define MAX_OBJECTS 16

static CK_FUNCTION_LIST_PTR p11 = NULL;
static void *dl = NULL;

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
    p11->C_GetSlotList(CK_TRUE, NULL, &nslots_with_token);

    for (size_t step = 0; step < MAX_STEPS && off < size; step++) {
        CK_BYTE op = take_u8(data, size, &off) % 16;

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
        }
    }

    for (size_t i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i] != CK_INVALID_HANDLE) p11->C_CloseSession(sessions[i]);
    }
    p11->C_Finalize(NULL_PTR);
    return 0;
}
