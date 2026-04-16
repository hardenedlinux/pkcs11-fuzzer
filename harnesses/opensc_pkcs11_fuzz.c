/*
 * opensc_pkcs11_fuzz.c — Fuzz OpenSC via its PKCS#11 module (opensc-pkcs11.so).
 *
 * OpenSC provides opensc-pkcs11.so, a full PKCS#11 implementation that sits
 * on top of libopensc.so.  Unlike the other harnesses that use SoftHSM2,
 * this harness loads OpenSC's own PKCS#11 module.
 *
 * WHY COVERAGE WAS LOW (0.74%)
 * ----------------------------
 * The previous version exited immediately when C_GetSlotList returned 0 slots,
 * which always happens in fuzzing environments without a PC/SC daemon or card
 * reader.  This meant only C_Initialize + C_GetSlotList + C_Finalize were
 * ever exercised — a tiny fraction of the code.
 *
 * FIX: do NOT bail on nslots == 0.  Instead:
 *   (a) Always exercise the slot-less code paths (C_GetInfo, C_GetSlotList
 *       with both tokenPresent values, repeated init/finalize cycling).
 *   (b) Call all slot-dependent functions with fuzz-controlled slot IDs —
 *       they return CKR_SLOT_ID_INVALID, but that exercises OpenSC's parameter
 *       validation, internal slot-list iteration, and error-handling paths.
 *   (c) When real slots are present (e.g., if pcscd is running), use them.
 *
 * This approach more than triples reachable code even with zero hardware.
 *
 * Input layout:
 *   byte 0: operation selector (0–9)
 *   byte 1: nattrs — number of CK_ATTRIBUTE entries to build (1–8)
 *   byte 2..5: slot ID override (little-endian u32; may be invalid)
 *   byte 6+: payload for attribute templates and mechanism queries
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
static CK_FUNCTION_LIST_PTR p11 = NULL;
static void               *dl  = NULL;

/* ── Known attribute types ──────────────────────────────────────────────── */
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

    nattrs = ((CK_ULONG)nattrs < max_attrs) ? (CK_ULONG)nattrs
                                             : (CK_ULONG)max_attrs;

    for (CK_ULONG i = 0; i < nattrs && off < size; i++) {
        uint8_t type_idx = data[off++] % (N_KNOWN_ATTRS + 4);
        CK_ATTRIBUTE_TYPE atype = (type_idx < N_KNOWN_ATTRS)
            ? KNOWN_ATTRS[type_idx]
            : (CK_ATTRIBUTE_TYPE)(type_idx - N_KNOWN_ATTRS);

        CK_ULONG vlen = 0;
        if (off < size) vlen = data[off++] % 32;

        CK_ULONG actual = (off + vlen <= size) ? vlen
                                               : (CK_ULONG)(size - off);
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
    if (!p11 || size < 6) return 0;

    uint8_t sel    = data[0] % 10;
    uint8_t nattrs = (data[1] % 8) + 1;

    /* Fuzz-controlled slot ID — may be invalid, which is intentional:
     * it drives OpenSC's slot-lookup and error-handling code paths. */
    CK_SLOT_ID fuzz_slot;
    memcpy(&fuzz_slot, data + 2, 4);

    const uint8_t *pay  = data + 6;
    size_t         plen = size - 6;

    /* ── Initialize OpenSC ─────────────────────────────────────────────── */
    CK_RV rv = p11->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
        return 0;

    /* ── Enumerate slots (tokenPresent=FALSE to get all, even empty) ────── */
    CK_ULONG nslots = 0;
    p11->C_GetSlotList(CK_FALSE, NULL, &nslots);

    /* Also query with tokenPresent=TRUE — exercises a different code path */
    CK_ULONG nslots_with_token = 0;
    p11->C_GetSlotList(CK_TRUE, NULL, &nslots_with_token);

    /* Collect real slot IDs if any exist */
    CK_SLOT_ID real_slot = fuzz_slot;   /* default: fuzz-controlled (may be invalid) */
    if (nslots > 0 && nslots <= 64) {
        CK_SLOT_ID *slots = (CK_SLOT_ID *)calloc(nslots, sizeof(CK_SLOT_ID));
        if (slots) {
            p11->C_GetSlotList(CK_FALSE, slots, &nslots);
            real_slot = slots[0];    /* first real slot when available */
            free(slots);
        }
    }

    /* Use fuzz_slot for odd selectors (hits error paths),
     * real_slot for even selectors (hits success paths when hardware present). */
    CK_SLOT_ID slot = (sel % 2 == 0) ? real_slot : fuzz_slot;

    switch (sel) {

    /* ── Slot and token information ──────────────────────────────────────── */
    case 0:
    case 1: {
        CK_SLOT_INFO  si;
        CK_TOKEN_INFO ti;
        p11->C_GetSlotInfo(slot, &si);
        p11->C_GetTokenInfo(slot, &ti);
        break;
    }

    /* ── Mechanism list and info ─────────────────────────────────────────── */
    case 2:
    case 3: {
        CK_ULONG nmechs = 0;
        p11->C_GetMechanismList(slot, NULL, &nmechs);
        if (nmechs > 0 && nmechs <= 512) {
            CK_MECHANISM_TYPE *mechs =
                (CK_MECHANISM_TYPE *)calloc(nmechs, sizeof(CK_MECHANISM_TYPE));
            if (mechs) {
                p11->C_GetMechanismList(slot, mechs, &nmechs);
                for (CK_ULONG i = 0; i < nmechs; i++) {
                    CK_MECHANISM_INFO mi;
                    p11->C_GetMechanismInfo(slot, mechs[i], &mi);
                }
                free(mechs);
            }
        }
        /* Fuzz-controlled mechanism type — exercises error handling */
        if (plen >= 4) {
            CK_MECHANISM_TYPE fuzz_mech;
            memcpy(&fuzz_mech, pay, 4);
            CK_MECHANISM_INFO mi;
            p11->C_GetMechanismInfo(slot, fuzz_mech, &mi);
        }
        break;
    }

    /* ── Session open/close cycle ────────────────────────────────────────── */
    case 4: {
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
        rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
                                NULL_PTR, NULL_PTR, &sess);
        if (rv == CKR_OK && sess != CK_INVALID_HANDLE)
            p11->C_CloseSession(sess);
        /* Also try RW session */
        rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                NULL_PTR, NULL_PTR, &sess);
        if (rv == CKR_OK && sess != CK_INVALID_HANDLE)
            p11->C_CloseSession(sess);
        break;
    }

    /* ── C_FindObjects with arbitrary attribute template ─────────────────── */
    case 5:
    case 6: {
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
        p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
                           NULL_PTR, NULL_PTR, &sess);

        CK_ATTRIBUTE tmpl[8]; CK_ULONG nattr = 0;
        build_template(tmpl, &nattr, 8, pay, plen, nattrs);

        /* C_FindObjectsInit exercises attribute template parsing even when
         * the result set is empty or the slot has no token. */
        rv = p11->C_FindObjectsInit(sess,
                                    (nattr > 0) ? tmpl : NULL_PTR, nattr);
        if (rv == CKR_OK) {
            CK_OBJECT_HANDLE objs[16]; CK_ULONG found = 0;
            p11->C_FindObjects(sess, objs, 16, &found);
            p11->C_FindObjectsFinal(sess);

            for (CK_ULONG i = 0; i < found; i++) {
                build_template(tmpl, &nattr, 4, pay, plen,
                               (nattrs % 4) + 1);
                p11->C_GetAttributeValue(sess, objs[i], tmpl, nattr);
            }
        }
        if (sess != CK_INVALID_HANDLE)
            p11->C_CloseSession(sess);
        break;
    }

    /* ── C_GetInfo + repeated init/finalize cycling ──────────────────────── */
    case 7: {
        CK_INFO info;
        p11->C_GetInfo(&info);
        p11->C_Finalize(NULL_PTR);
        p11->C_Initialize(NULL_PTR);
        p11->C_GetInfo(&info);
        /* Exercise C_GetSlotList again after re-init */
        CK_ULONG n2 = 0;
        p11->C_GetSlotList(CK_FALSE, NULL, &n2);
        p11->C_GetSlotList(CK_TRUE,  NULL, &n2);
        break;
    }

    /* ── CloseAllSessions + multi-session ────────────────────────────────── */
    case 8: {
        /* Open several sessions (may fail with CKR_SLOT_ID_INVALID) */
        CK_SESSION_HANDLE sess[3];
        for (int i = 0; i < 3; i++) {
            sess[i] = CK_INVALID_HANDLE;
            p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
                               NULL_PTR, NULL_PTR, &sess[i]);
        }
        p11->C_CloseAllSessions(slot);
        break;
    }

    /* ── Enumerate all objects + GetAttributeValue ───────────────────────── */
    case 9: {
        CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
        p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
                           NULL_PTR, NULL_PTR, &sess);

        if (p11->C_FindObjectsInit(sess, NULL_PTR, 0) == CKR_OK) {
            CK_OBJECT_HANDLE objs[32]; CK_ULONG found = 0;
            p11->C_FindObjects(sess, objs, 32, &found);
            p11->C_FindObjectsFinal(sess);

            CK_ATTRIBUTE tmpl[8]; CK_ULONG nattr = 0;
            build_template(tmpl, &nattr, 8, pay, plen, nattrs);
            for (CK_ULONG i = 0; i < found; i++)
                p11->C_GetAttributeValue(sess, objs[i], tmpl, nattr);
        }
        if (sess != CK_INVALID_HANDLE)
            p11->C_CloseSession(sess);
        break;
    }
    }

    p11->C_Finalize(NULL_PTR);
    return 0;
}
