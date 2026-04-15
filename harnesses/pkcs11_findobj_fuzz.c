/*
 * pkcs11_findobj_fuzz.c — Fuzz C_FindObjectsInit with arbitrary CKA templates.
 *
 * This harness interprets the fuzz input as a stream of PKCS#11 attribute
 * TLV tuples and feeds them to C_FindObjectsInit.  This exercises the
 * token's attribute parsing, type coercion, and search logic.
 *
 * Input format (repeating):
 *   [4 bytes: attribute type as uint32 LE]
 *   [2 bytes: value length as uint16 LE]
 *   [N bytes: value]
 * Up to MAX_ATTRS attributes are parsed from the buffer.
 */
#include "common.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ATTRS 16

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    pkcs11_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 6) return 0;

    CK_ATTRIBUTE tmpl[MAX_ATTRS];
    /* We keep value pointers pointing into 'data' directly — safe since
     * data is valid for the lifetime of this call. */
    CK_ULONG nattrs = 0;

    const uint8_t *p   = data;
    const uint8_t *end = data + size;

    while (p + 6 <= end && nattrs < MAX_ATTRS) {
        uint32_t atype;
        uint16_t alen;
        memcpy(&atype, p,     4);
        memcpy(&alen,  p + 4, 2);
        p += 6;

        /* Bounds check: value must fit in remaining data */
        if ((size_t)(end - p) < alen) break;

        tmpl[nattrs].type       = (CK_ATTRIBUTE_TYPE)atype;
        tmpl[nattrs].pValue     = (alen > 0) ? (void *)p : NULL_PTR;
        tmpl[nattrs].ulValueLen = alen;

        p += alen;
        nattrs++;
    }

    /* Also exercise a C_GetAttributeValue on each found object */
    CK_RV rv = p11->C_FindObjectsInit(sess, tmpl, nattrs);
    if (rv != CKR_OK) return 0;

    CK_OBJECT_HANDLE objs[8];
    CK_ULONG found = 0;
    p11->C_FindObjects(sess, objs, 8, &found);
    p11->C_FindObjectsFinal(sess);

    /* For each found object, exercise C_GetAttributeValue with fuzz types */
    for (CK_ULONG i = 0; i < found && i < 4; i++) {
        /* Reuse the same template as a get-attribute query */
        CK_ATTRIBUTE get_tmpl[MAX_ATTRS];
        for (CK_ULONG j = 0; j < nattrs && j < MAX_ATTRS; j++) {
            get_tmpl[j].type       = tmpl[j].type;
            get_tmpl[j].pValue     = NULL_PTR;
            get_tmpl[j].ulValueLen = 0;
        }
        /* First call: get lengths */
        p11->C_GetAttributeValue(sess, objs[i], get_tmpl, nattrs);
        /* Second call: get values (with NULL buffers — may return CKR_BUFFER_TOO_SMALL) */
        p11->C_GetAttributeValue(sess, objs[i], get_tmpl, nattrs);
    }

    return 0;
}
