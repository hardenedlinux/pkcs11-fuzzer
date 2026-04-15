/*
 * opensc_pkcs11_fuzz.c — Fuzz OpenSC via its PKCS#11 module (opensc-pkcs11.so).
 *
 * OpenSC provides opensc-pkcs11.so, a full PKCS#11 implementation that sits
 * on top of libopensc.so.  Unlike the other harnesses that use SoftHSM2,
 * this harness loads OpenSC's own PKCS#11 module, exercising:
 *
 *   - OpenSC context creation and PC/SC reader enumeration
 *   - Slot/token information retrieval
 *   - Mechanism list and info queries
 *   - C_FindObjectsInit with arbitrary attribute templates (attribute
 *     parsing and matching code even when the result set is empty)
 *   - Session lifecycle (open/close) and error handling
 *   - The C_Initialize / C_Finalize cycle (context setup/teardown)
 *
 * No smart card or card reader is required: OpenSC operates on virtual
 * slots.  The coverage focuses on initialization, slot enumeration, and
 * attribute-template processing which have historically been bug-prone.
 *
 * Input layout:
 *   byte 0: operation selector (0–7)
 *   byte 1: nattrs — number of CK_ATTRIBUTE entries to build from fuzz
 *            bytes (1–8)
 *   byte 2+: raw bytes used to fill attribute types, lengths, and values
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

/* PKCS#11 types — use the header installed by SoftHSM2 */
#ifndef SOFTHSM2_MODULE_PATH
#  error "SOFTHSM2_MODULE_PATH must be defined (needed for pkcs11.h path)"
#endif
#include <pkcs11.h>

#ifndef OPENSC_PKCS11_PATH
#  error "OPENSC_PKCS11_PATH must be defined via -DOPENSC_PKCS11_PATH=..."
#endif

/* ── Module globals ─────────────────────────────────────────────────────── */
static CK_FUNCTION_LIST_PTR p11 = NULL;   /* OpenSC PKCS#11 function table */
static void               *dl  = NULL;   /* dlopen handle                  */

/* ── Known attribute types to use as query candidates ──────────────────── */
static const CK_ATTRIBUTE_TYPE KNOWN_ATTRS[] = {
    CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL,
    CKA_APPLICATION, CKA_VALUE, CKA_ID,
    CKA_SENSITIVE, CKA_ENCRYPT, CKA_DECRYPT,
    CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_VERIFY,
    CKA_KEY_TYPE, CKA_MODULUS, CKA_MODULUS_BITS,
    CKA_PUBLIC_EXPONENT, CKA_EC_PARAMS, CKA_EC_POINT,
};
#define N_KNOWN_ATTRS (sizeof(KNOWN_ATTRS) / sizeof(KNOWN_ATTRS[0]))

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;

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

/* ── Build a CK_ATTRIBUTE template from raw fuzz bytes ─────────────────── */
static void build_template(CK_ATTRIBUTE  *tmpl,
                            CK_ULONG      *count_out,
                            CK_ULONG       max_attrs,
                            const uint8_t *data,
                            size_t         size,
                            uint8_t        nattrs)
{
    static uint8_t attr_buf[4096];
    CK_ULONG n = 0;
    size_t   off = 0;

    nattrs = ((CK_ULONG)nattrs < max_attrs) ? (CK_ULONG)nattrs : (CK_ULONG)max_attrs;

    for (CK_ULONG i = 0; i < nattrs && off < size; i++) {
        /* byte 0: pick attribute type from known list or raw */
        uint8_t type_idx = data[off++] % (N_KNOWN_ATTRS + 4);
        CK_ATTRIBUTE_TYPE atype = (type_idx < N_KNOWN_ATTRS)
            ? KNOWN_ATTRS[type_idx]
            : (CK_ATTRIBUTE_TYPE)(type_idx - N_KNOWN_ATTRS);  /* raw small value */

        /* byte 1: value length (0–31) */
        CK_ULONG vlen = 0;
        if (off < size) vlen = data[off++] % 32;

        /* bytes 2..vlen+1: value data */
        CK_ULONG actual = (off + vlen <= size) ? vlen : (CK_ULONG)(size - off);
        size_t buf_off = i * 32;
        if (actual > 0 && buf_off + actual <= sizeof(attr_buf))
            memcpy(attr_buf + buf_off, data + off, actual);
        off += actual;

        tmpl[n].type       = atype;
        tmpl[n].pValue     = (actual > 0) ? (attr_buf + buf_off) : NULL_PTR;
        tmpl[n].ulValueLen = actual;
        n++;
    }
    *count_out = n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!p11 || size < 2) return 0;

    uint8_t sel    = data[0] % 8;
    uint8_t nattrs = (data[1] % 8) + 1;
    const uint8_t *pay  = (size > 2) ? data + 2 : (const uint8_t *)"";
    size_t         plen = (size > 2) ? size - 2 : 0;

    /* ── Initialize OpenSC ─────────────────────────────────────────────── */
    CK_RV rv = p11->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
        return 0;

    /* ── Enumerate slots ────────────────────────────────────────────────── */
    CK_ULONG nslots = 0;
    p11->C_GetSlotList(CK_FALSE, NULL, &nslots);
    if (nslots == 0) { p11->C_Finalize(NULL_PTR); return 0; }

    CK_SLOT_ID *slots = (CK_SLOT_ID *)calloc(nslots, sizeof(CK_SLOT_ID));
    if (!slots) { p11->C_Finalize(NULL_PTR); return 0; }
    p11->C_GetSlotList(CK_FALSE, slots, &nslots);

    CK_SLOT_ID slot = slots[0];   /* always exercise at least the first slot */
    free(slots);

    switch (sel) {

    /* ── Slot and token information ──────────────────────────────────────── */
    case 0: {
        CK_SLOT_INFO  si; p11->C_GetSlotInfo(slot, &si);
        CK_TOKEN_INFO ti; p11->C_GetTokenInfo(slot, &ti);
        break;
    }

    /* ── Mechanism list and info ─────────────────────────────────────────── */
    case 1: {
        CK_ULONG nmechs = 0;
        p11->C_GetMechanismList(slot, NULL, &nmechs);
        if (nmechs > 0 && nmechs <= 512) {
            CK_MECHANISM_TYPE *mechs =
                (CK_MECHANISM_TYPE *)calloc(nmechs, sizeof(CK_MECHANISM_TYPE));
            if (mechs) {
                p11->C_GetMechanismList(slot, mechs, &nmechs);
                /* Query info for each mechanism — exercises type dispatch */
                for (CK_ULONG i = 0; i < nmechs; i++) {
                    CK_MECHANISM_INFO mi;
                    p11->C_GetMechanismInfo(slot, mechs[i], &mi);
                }
                free(mechs);
            }
        }
        /* Also query fuzzed mechanism types (exercises error handling) */
        if (plen >= 4) {
            CK_MECHANISM_TYPE fuzz_mech;
            memcpy(&fuzz_mech, pay, 4);
            CK_MECHANISM_INFO mi;
            p11->C_GetMechanismInfo(slot, fuzz_mech, &mi);
        }
        break;
    }

    /* ── Session open/close cycle ────────────────────────────────────────── */
    case 2: {
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
        rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
                                &sess);
        if (rv == CKR_OK && sess != CK_INVALID_HANDLE)
            p11->C_CloseSession(sess);
        break;
    }

    /* ── C_FindObjects with arbitrary attribute template ─────────────────── */
    case 3:
    case 4: {
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
        if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
                               NULL_PTR, NULL_PTR, &sess) != CKR_OK) break;

        CK_ATTRIBUTE tmpl[8]; CK_ULONG nattr = 0;
        build_template(tmpl, &nattr, 8, pay, plen, nattrs);

        rv = p11->C_FindObjectsInit(sess, (nattr > 0) ? tmpl : NULL_PTR, nattr);
        if (rv == CKR_OK) {
            CK_OBJECT_HANDLE objs[16]; CK_ULONG found = 0;
            p11->C_FindObjects(sess, objs, 16, &found);
            p11->C_FindObjectsFinal(sess);

            /* For any found objects, try GetAttributeValue with fuzzed types */
            for (CK_ULONG i = 0; i < found; i++) {
                build_template(tmpl, &nattr, 4, pay, plen,
                               (nattrs % 4) + 1);
                p11->C_GetAttributeValue(sess, objs[i], tmpl, nattr);
            }
        }
        p11->C_CloseSession(sess);
        break;
    }

    /* ── C_GetAttributeValue on slot-0 objects with fuzzed attr types ────── */
    case 5: {
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
        if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
                               NULL_PTR, NULL_PTR, &sess) != CKR_OK) break;

        /* Enumerate all objects first */
        if (p11->C_FindObjectsInit(sess, NULL_PTR, 0) == CKR_OK) {
            CK_OBJECT_HANDLE objs[32]; CK_ULONG found = 0;
            p11->C_FindObjects(sess, objs, 32, &found);
            p11->C_FindObjectsFinal(sess);

            CK_ATTRIBUTE tmpl[8]; CK_ULONG nattr = 0;
            build_template(tmpl, &nattr, 8, pay, plen, nattrs);

            for (CK_ULONG i = 0; i < found; i++)
                p11->C_GetAttributeValue(sess, objs[i], tmpl, nattr);
        }
        p11->C_CloseSession(sess);
        break;
    }

    /* ── C_GetInfo (library-level) + repeated init/finalize cycle ────────── */
    case 6: {
        CK_INFO info;
        p11->C_GetInfo(&info);
        /* Finalize and re-initialize — exercises cleanup + re-init paths */
        p11->C_Finalize(NULL_PTR);
        p11->C_Initialize(NULL_PTR);
        p11->C_GetInfo(&info);
        break;
    }

    /* ── Close all sessions on the slot ─────────────────────────────────── */
    case 7: {
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
        for (int i = 0; i < 3; i++) {
            if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
                                   NULL_PTR, NULL_PTR, &sess) == CKR_OK
                && sess != CK_INVALID_HANDLE)
                p11->C_CloseSession(sess);
        }
        p11->C_CloseAllSessions(slot);
        break;
    }
    }

    p11->C_Finalize(NULL_PTR);
    return 0;
}
