/*
 * pkcs11_attrs_fuzz.c — Fuzz C_SetAttributeValue / C_GetAttributeValue
 *                       and C_CopyObject with arbitrary attribute templates.
 *
 * These entry points handle raw attribute data; they're prime targets for
 * type confusion, integer overflows, and buffer handling bugs.
 *
 * Input layout:
 *   byte 0:    object selector (0=RSA pub, 1=EC pub, 2=AES key, 3=RSA priv)
 *   byte 1:    attribute count (1..MAX_ATTRS, clamped)
 *   then per attribute:
 *     [4 bytes: type as uint32 LE]
 *     [2 bytes: value length as uint16 LE]
 *     [N bytes: value]
 */
#include "common.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ATTRS 8

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    pkcs11_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 8) return 0;

    /* Select which object to operate on */
    static const CK_OBJECT_HANDLE *objs_arr[] = {
        &rsa_pub, &ec_pub, &aes_key, &rsa_priv
    };
    CK_OBJECT_HANDLE obj = *objs_arr[data[0] % 4];
    if (obj == CK_INVALID_HANDLE) return 0;

    size_t nattrs_want = (data[1] % MAX_ATTRS) + 1;
    const uint8_t *p   = data + 2;
    const uint8_t *end = data + size;

    CK_ATTRIBUTE tmpl[MAX_ATTRS];
    size_t nattrs = 0;

    while (p + 6 <= end && nattrs < nattrs_want) {
        uint32_t atype;
        uint16_t alen;
        memcpy(&atype, p,     4);
        memcpy(&alen,  p + 4, 2);
        p += 6;
        if ((size_t)(end - p) < alen) break;

        tmpl[nattrs].type       = (CK_ATTRIBUTE_TYPE)atype;
        tmpl[nattrs].pValue     = (alen > 0) ? (void *)p : NULL_PTR;
        tmpl[nattrs].ulValueLen = alen;
        p += alen;
        nattrs++;
    }

    if (nattrs == 0) return 0;

    /* C_GetAttributeValue: probe attribute sizes */
    CK_ATTRIBUTE get_tmpl[MAX_ATTRS];
    for (size_t i = 0; i < nattrs; i++) {
        get_tmpl[i].type       = tmpl[i].type;
        get_tmpl[i].pValue     = NULL_PTR;
        get_tmpl[i].ulValueLen = 0;
    }
    p11->C_GetAttributeValue(sess, obj, get_tmpl, (CK_ULONG)nattrs);

    /* C_SetAttributeValue on a copyable object (public keys are modifiable) */
    if (obj == rsa_pub || obj == ec_pub) {
        p11->C_SetAttributeValue(sess, obj, tmpl, (CK_ULONG)nattrs);
    }

    /* C_CopyObject with the attribute template as overrides */
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    if (obj == rsa_pub || obj == ec_pub) {
        CK_RV rv = p11->C_CopyObject(sess, obj, tmpl, (CK_ULONG)nattrs, &copy);
        if (rv == CKR_OK && copy != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, copy);
    }

    return 0;
}
