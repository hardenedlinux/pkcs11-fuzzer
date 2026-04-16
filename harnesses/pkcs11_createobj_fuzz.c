/*
 * pkcs11_createobj_fuzz.c — Fuzz C_CreateObject with semi-valid templates.
 *
 * Raw attribute parsing has already produced one real SoftHSM issue in this
 * repo. This harness pushes that area further by starting from a small valid
 * base object template, then appending attacker-controlled CK_ATTRIBUTE TLVs.
 *
 * Input layout:
 *   byte 0: object selector
 *             0 = CKO_DATA
 *             1 = CKO_SECRET_KEY / CKK_GENERIC_SECRET
 *             2 = CKO_SECRET_KEY / CKK_AES
 *             3 = CKO_PUBLIC_KEY / CKK_RSA
 *   byte 1: requested fuzz attribute count (1..MAX_FUZZ_ATTRS)
 *   byte 2+: repeating TLVs:
 *             [4 bytes type as uint32 LE]
 *             [2 bytes value length as uint16 LE]
 *             [N bytes value]
 */
#include "common.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MAX_FUZZ_ATTRS 8
#define MAX_TOTAL_ATTRS 16

static size_t parse_fuzz_attrs(const uint8_t *data,
                               size_t size,
                               CK_ATTRIBUTE *tmpl,
                               size_t max_attrs)
{
    const uint8_t *p = data;
    const uint8_t *end = data + size;
    size_t nattrs = 0;

    while (p + 6 <= end && nattrs < max_attrs) {
        uint32_t atype;
        uint16_t alen;

        memcpy(&atype, p, 4);
        memcpy(&alen, p + 4, 2);
        p += 6;

        if ((size_t)(end - p) < alen) break;

        tmpl[nattrs].type = (CK_ATTRIBUTE_TYPE)atype;
        tmpl[nattrs].pValue = (alen > 0) ? (CK_VOID_PTR)p : NULL_PTR;
        tmpl[nattrs].ulValueLen = alen;
        p += alen;
        nattrs++;
    }

    return nattrs;
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
    static const CK_BBOOL true_val = CK_TRUE;
    static const CK_BBOOL false_val = CK_FALSE;
    static const CK_BYTE default_blob[32] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    };
    static const CK_BYTE rsa_modulus[64] = {
        0xd3, 0x7a, 0x4f, 0x91, 0x88, 0x2b, 0x4c, 0x5d,
        0x16, 0x73, 0xa8, 0xe1, 0x25, 0x9a, 0xcd, 0x77,
        0x94, 0x33, 0x11, 0xf0, 0x62, 0x7c, 0x98, 0xaa,
        0x5e, 0x19, 0x6d, 0x20, 0x87, 0x4a, 0x31, 0xc2,
        0x73, 0x8b, 0xfe, 0x54, 0x67, 0x91, 0x2e, 0x44,
        0xbc, 0x63, 0x7f, 0x1d, 0x29, 0x58, 0xa4, 0x9c,
        0x4e, 0xb7, 0x10, 0x83, 0xd9, 0x6a, 0x35, 0xf2,
        0x68, 0x21, 0x5c, 0xae, 0x17, 0x42, 0x8d, 0xf1,
    };
    static const CK_BYTE rsa_pubexp[] = { 0x01, 0x00, 0x01 };
    static const CK_BYTE label_data[] = "fz-data";
    static const CK_BYTE app_data[] = "pkcs11-fuzzer";
    CK_ATTRIBUTE tmpl[MAX_TOTAL_ATTRS];
    CK_ATTRIBUTE fuzz_attrs[MAX_FUZZ_ATTRS];
    CK_ATTRIBUTE get_tmpl[6];
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE copy = CK_INVALID_HANDLE;
    size_t base_count = 0;
    size_t fuzz_count;
    size_t get_count;
    uint8_t sel;
    const uint8_t *payload;
    size_t payload_len_local;
    const CK_BYTE *value_bytes;
    CK_ULONG value_len;

    CK_OBJECT_CLASS cls;
    CK_KEY_TYPE key_type;

    if (size < 2) return 0;

    sel = data[0] % 4;
    payload = data + 2;
    payload_len_local = size - 2;
    value_bytes = (payload_len_local > 0) ? payload : default_blob;
    value_len = (payload_len_local > 0 && payload_len_local < sizeof(default_blob))
        ? (CK_ULONG)payload_len_local
        : (CK_ULONG)sizeof(default_blob);

    switch (sel) {
    case 0:
        cls = CKO_DATA;
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_CLASS, &cls, sizeof(cls) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_TOKEN, (CK_VOID_PTR)&false_val, sizeof(false_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_PRIVATE, (CK_VOID_PTR)&false_val, sizeof(false_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_LABEL, (CK_VOID_PTR)label_data, sizeof(label_data) - 1 };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_APPLICATION, (CK_VOID_PTR)app_data, sizeof(app_data) - 1 };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_VALUE, (CK_VOID_PTR)value_bytes, value_len };
        break;

    case 1:
        cls = CKO_SECRET_KEY;
        key_type = CKK_GENERIC_SECRET;
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_CLASS, &cls, sizeof(cls) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_KEY_TYPE, &key_type, sizeof(key_type) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_TOKEN, (CK_VOID_PTR)&false_val, sizeof(false_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_SIGN, (CK_VOID_PTR)&true_val, sizeof(true_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_VERIFY, (CK_VOID_PTR)&true_val, sizeof(true_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_VALUE, (CK_VOID_PTR)value_bytes, value_len };
        break;

    case 2:
        cls = CKO_SECRET_KEY;
        key_type = CKK_AES;
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_CLASS, &cls, sizeof(cls) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_KEY_TYPE, &key_type, sizeof(key_type) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_TOKEN, (CK_VOID_PTR)&false_val, sizeof(false_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_ENCRYPT, (CK_VOID_PTR)&true_val, sizeof(true_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_DECRYPT, (CK_VOID_PTR)&true_val, sizeof(true_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_VALUE, (CK_VOID_PTR)default_blob, 16 };
        break;

    default:
        cls = CKO_PUBLIC_KEY;
        key_type = CKK_RSA;
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_CLASS, &cls, sizeof(cls) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_KEY_TYPE, &key_type, sizeof(key_type) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_TOKEN, (CK_VOID_PTR)&false_val, sizeof(false_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_VERIFY, (CK_VOID_PTR)&true_val, sizeof(true_val) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_MODULUS, (CK_VOID_PTR)rsa_modulus, sizeof(rsa_modulus) };
        tmpl[base_count++] = (CK_ATTRIBUTE){ CKA_PUBLIC_EXPONENT, (CK_VOID_PTR)rsa_pubexp, sizeof(rsa_pubexp) };
        break;
    }

    fuzz_count = parse_fuzz_attrs(payload,
                                  payload_len_local,
                                  fuzz_attrs,
                                  (data[1] % MAX_FUZZ_ATTRS) + 1);
    if (base_count + fuzz_count > MAX_TOTAL_ATTRS) {
        fuzz_count = MAX_TOTAL_ATTRS - base_count;
    }
    for (size_t i = 0; i < fuzz_count; i++) {
        tmpl[base_count + i] = fuzz_attrs[i];
    }

    if (p11->C_CreateObject(sess, tmpl, (CK_ULONG)(base_count + fuzz_count), &obj) != CKR_OK ||
        obj == CK_INVALID_HANDLE) {
        return 0;
    }

    get_count = (base_count + fuzz_count < 6) ? (base_count + fuzz_count) : 6;
    for (size_t i = 0; i < get_count; i++) {
        get_tmpl[i].type = tmpl[i].type;
        get_tmpl[i].pValue = NULL_PTR;
        get_tmpl[i].ulValueLen = 0;
    }
    p11->C_GetAttributeValue(sess, obj, get_tmpl, (CK_ULONG)get_count);
    p11->C_CopyObject(sess, obj, fuzz_attrs, (CK_ULONG)fuzz_count, &copy);

    if (copy != CK_INVALID_HANDLE) {
        p11->C_DestroyObject(sess, copy);
    }
    p11->C_DestroyObject(sess, obj);
    return 0;
}
