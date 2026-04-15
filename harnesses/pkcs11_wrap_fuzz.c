/*
 * pkcs11_wrap_fuzz.c — Fuzz C_WrapKey, C_UnwrapKey, and C_DeriveKey.
 *
 * Input layout:
 *   byte 0:     operation selector
 *                 0-2 → C_WrapKey variants
 *                 3-5 → C_UnwrapKey variants (wraps then unwraps)
 *                 6-7 → C_DeriveKey (ECDH)
 *   byte 1...:  operation-specific data
 *
 * Key wrapping exercises the token's key export/import path.
 * ECDH derivation exercises the EC key handling path.
 */
#include "common.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    pkcs11_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;

    uint8_t sel = data[0] % 8;
    const uint8_t *pay = payload_ptr(data, size);
    size_t         plen = payload_len(size);

    switch (sel) {

    /* ---- C_WrapKey -------------------------------------------------------- */
    case 0: {
        /* Wrap RSA public key with AES-ECB */
        CK_MECHANISM mech = { CKM_AES_ECB, NULL_PTR, 0 };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, aes_key, rsa_pub, out, &outlen);
        break;
    }
    case 1: {
        /* Wrap EC public key with AES-CBC using fuzzed IV */
        CK_BYTE iv[16] = {0};
        if (plen >= 16) memcpy(iv, pay, 16);
        CK_MECHANISM mech = { CKM_AES_CBC, iv, 16 };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, aes_key, ec_pub, out, &outlen);
        break;
    }
    case 2: {
        /* Wrap AES key with RSA-OAEP */
        CK_RSA_PKCS_OAEP_PARAMS oaep = {
            CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_MECHANISM mech = { CKM_RSA_PKCS_OAEP, &oaep, sizeof(oaep) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_UnwrapKey (fuzz the wrapped blob) ------------------------------ */
    case 3:
    case 4:
    case 5: {
        /* Try to unwrap the fuzz payload as an AES key using AES-ECB */
        CK_MECHANISM mech = { CKM_AES_ECB, NULL_PTR, 0 };
        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE ktype   = CKK_AES;
        CK_BBOOL sensitive  = CK_TRUE;
        CK_BBOOL extractable = CK_FALSE;
        CK_ATTRIBUTE unwrap_tmpl[] = {
            { CKA_CLASS,       &cls,        sizeof(cls) },
            { CKA_KEY_TYPE,    &ktype,      sizeof(ktype) },
            { CKA_SENSITIVE,   &sensitive,  sizeof(sensitive) },
            { CKA_EXTRACTABLE, &extractable, sizeof(extractable) },
        };
        CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
        p11->C_UnwrapKey(sess, &mech, aes_key,
                         (CK_BYTE_PTR)pay, (CK_ULONG)plen,
                         unwrap_tmpl, 4, &new_key);
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        break;
    }

    /* ---- C_DeriveKey (ECDH) ----------------------------------------------- */
    case 6:
    case 7: {
        /* Use fuzz bytes as the "other party's EC point" for ECDH */
        CK_ECDH1_DERIVE_PARAMS ecdh = {0};
        ecdh.kdf            = CKD_NULL;
        ecdh.ulSharedDataLen = 0;
        ecdh.pSharedData    = NULL_PTR;
        ecdh.ulPublicDataLen = (CK_ULONG)plen;
        ecdh.pPublicData    = (plen > 0) ? (CK_BYTE_PTR)pay : NULL_PTR;

        CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &ecdh, sizeof(ecdh) };
        CK_OBJECT_CLASS cls  = CKO_SECRET_KEY;
        CK_KEY_TYPE ktype    = CKK_AES;
        CK_ULONG keylen      = 32;
        CK_BBOOL extractable = CK_FALSE;
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,     &cls,    sizeof(cls) },
            { CKA_KEY_TYPE,  &ktype,  sizeof(ktype) },
            { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
            { CKA_EXTRACTABLE, &extractable, sizeof(extractable) },
        };
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
        p11->C_DeriveKey(sess, &mech, ec_priv, tmpl, 4, &derived);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }
    }

    return 0;
}
