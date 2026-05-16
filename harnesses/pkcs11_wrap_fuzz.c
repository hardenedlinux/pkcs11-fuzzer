/*
 * pkcs11_wrap_fuzz.c — Fuzz C_WrapKey, C_UnwrapKey, and C_DeriveKey.
 *
 * Input layout:
 *   byte 0:     operation selector
 *                 0-2  → C_WrapKey variants
 *                 3-5  → C_UnwrapKey variants (wraps then unwraps)
 *                 6    → C_DeriveKey (ECDH with SHA1_KDF)
 *                 7    → C_DeriveKey (ECDH with CKD_NULL)
 *                 8-9  → C_WrapKey + C_UnwrapKey with CKM_AES_KEY_WRAP
 *                 10   → C_DeriveKey with CKM_CONCATENATE_DATA_AND_BASE
 *                 11   → C_WrapKey + C_UnwrapKey with CKM_AES_KEY_WRAP_PAD
 *                 12   → C_WrapKey + C_UnwrapKey with CKM_RSA_PKCS
 *                 13   → C_WrapKey + C_UnwrapKey with CKM_RSA_AES_KEY_WRAP (256-bit AES)
 *                 14-15 → DES3 key gen + AES-CBC-PAD wrap + DES3-CBC-PAD unwrap
 *                 16   → AES-CBC wrap + unwrap
 *                 17   → C_DeriveKey with CKM_CONCATENATE_BASE_AND_DATA
 *                 18   → C_WrapKey + C_UnwrapKey with CKM_RSA_AES_KEY_WRAP (128-bit AES)
 *                 19   → C_WrapKey + C_UnwrapKey with CKM_RSA_AES_KEY_WRAP (192-bit AES)
 *                 20   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (NULL pParameter)
 *                 21   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (bad param length)
 *                 22   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (invalid ulAESKeyBits)
 *                 23   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (NULL pOAEPParams)
 *                 24   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (mgf=0)
 *                 25   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (mgf=6)
 *                 26   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (bad source type)
 *                 27   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (non-NULL pSourceData)
 *                 28   → C_DeriveKey with CKM_CONCATENATE_BASE_AND_KEY
 *                 29   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (non-zero ulSourceDataLen with NULL pSourceData)
 *                 30   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (mgf=CKG_MGF1_SHA256=2)
 *                 31   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (mgf=CKG_MGF1_SHA384=3)
 *                 32   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (mgf=CKG_MGF1_SHA512=4)
 *                 33   → C_WrapKey with CKM_RSA_AES_KEY_WRAP (mgf=CKG_MGF1_SHA224=5)
 *   byte 1...:  operation-specific data
 *
 * Key wrapping exercises the token's key export/import path.
 * ECDH derivation exercises the EC key handling path.
 * AES key wrap exercises the RFC3394 key wrap code path.
 * RSA key wrap exercises the asymmetric key wrap code path.
 * RSA-AES key wrap exercises combined RSA-OAEP + AES key wrap.
 * RSA-AES error path cases (20-27) exercise MechParamCheckRSAAESKEYWRAP validation.
 * RSA-AES error path case 29 exercises ulSourceDataLen != 0 check.
 * RSA-AES cases 30-33 exercise different MGF values within valid range (1-5).
 * CONCATENATE derive exercises the key concatenation code path.
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

    CK_RV rv;
    uint8_t sel = data[0] % 34;
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
            CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
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
        /* Try to unwrap the fuzz payload as an AES key using AES-CBC-PAD.
         * The first 16 bytes of payload are the IV, remainder is the
         * ciphertext to attempt to unwrap. AES-CBC-PAD needs at least 32
         * bytes (IV + 1 cipher block with padding). */
        if (plen < 32) break;
        CK_BYTE iv[16];
        memcpy(iv, pay, 16);
        CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, 16 };
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
                         (CK_BYTE_PTR)pay + 16, (CK_ULONG)plen - 16,
                         unwrap_tmpl, 4, &new_key);
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        break;
    }

    /* ---- C_DeriveKey (ECDH) ----------------------------------------------- */
    case 6: {
        /* Use fuzz bytes as the "other party's EC point" for ECDH with SHA1 KDF */
        CK_ECDH1_DERIVE_PARAMS ecdh = {0};
        ecdh.kdf            = CKD_SHA1_KDF;
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
    case 7: {
        /* Use fuzz bytes as the "other party's EC point" for ECDH with CKD_NULL */
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

    /* ---- C_WrapKey + C_UnwrapKey with CKM_AES_KEY_WRAP -------------------- */
    case 8: {
        CK_MECHANISM wrap_mech = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
        CK_BYTE wrapped[256];
        CK_ULONG wrapped_len = sizeof(wrapped);
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 16;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                gen_tmpl, 7, &derived);
        if (rv != CKR_OK) break;

        rv = p11->C_WrapKey(sess, &wrap_mech, aes_key, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_MECHANISM unwrap_mech = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
            p11->C_UnwrapKey(sess, &unwrap_mech, aes_key,
                             wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
            if (new_key != CK_INVALID_HANDLE)
                p11->C_DestroyObject(sess, new_key);
        }
        p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_WrapKey + C_UnwrapKey with CKM_AES_KEY_WRAP_PAD ---------------- */
    case 9: {
        CK_MECHANISM wrap_mech = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
        CK_BYTE wrapped[256];
        CK_ULONG wrapped_len = sizeof(wrapped);
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 16;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                gen_tmpl, 7, &derived);
        if (rv != CKR_OK) break;

        rv = p11->C_WrapKey(sess, &wrap_mech, aes_key, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_MECHANISM unwrap_mech = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
            p11->C_UnwrapKey(sess, &unwrap_mech, aes_key,
                             wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
            if (new_key != CK_INVALID_HANDLE)
                p11->C_DestroyObject(sess, new_key);
        }
        p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_DeriveKey with CKM_CONCATENATE_DATA_AND_BASE ------------------ */
    case 10: {
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_GENERIC_SECRET;
        CK_ULONG keylen    = (CK_ULONG)plen;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_KEY_DERIVATION_STRING_DATA param;
        param.pData = (CK_BYTE_PTR)pay;
        param.ulLen = (CK_ULONG)plen;
        CK_MECHANISM derive_mech = {
            CKM_CONCATENATE_DATA_AND_BASE,
            &param,
            sizeof(param)
        };

        rv = p11->C_DeriveKey(sess, &derive_mech, aes_key,
                              gen_tmpl, 4, &derived);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- AES key wrap + unwrap with CKM_AES_KEY_WRAP_PAD ------------------ */
    case 11: {
        CK_MECHANISM wrap_mech = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
        CK_MECHANISM unwrap_mech = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE, new_key = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 32;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                gen_tmpl, 7, &derived);
        if (rv != CKR_OK) break;

        CK_BYTE wrapped[256];
        CK_ULONG wrapped_len = sizeof(wrapped);
        rv = p11->C_WrapKey(sess, &wrap_mech, aes_key, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            p11->C_UnwrapKey(sess, &unwrap_mech, aes_key,
                             wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
        }
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_WrapKey + C_UnwrapKey with CKM_RSA_PKCS ---------------------- */
    case 12: {
        CK_MECHANISM wrap_mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE, new_key = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 32;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                gen_tmpl, 7, &derived);
        if (rv != CKR_OK) break;

        CK_BYTE wrapped[256];
        CK_ULONG wrapped_len = sizeof(wrapped);
        rv = p11->C_WrapKey(sess, &wrap_mech, rsa_pub, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_MECHANISM unwrap_mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            p11->C_UnwrapKey(sess, &unwrap_mech, rsa_priv,
                             wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
        }
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_WrapKey + C_UnwrapKey with CKM_RSA_AES_KEY_WRAP ------------ */
    case 13: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;

        CK_MECHANISM wrap_mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE, new_key = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 32;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                gen_tmpl, 7, &derived);
        if (rv != CKR_OK) break;

        CK_BYTE wrapped[512];
        CK_ULONG wrapped_len = sizeof(wrapped);
        rv = p11->C_WrapKey(sess, &wrap_mech, rsa_pub, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_RSA_PKCS_OAEP_PARAMS unwrap_oaep_params = {
                CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
            };
            CK_RSA_AES_KEY_WRAP_PARAMS unwrap_params;
            unwrap_params.ulAESKeyBits = 256;
            unwrap_params.pOAEPParams = &unwrap_oaep_params;

            CK_MECHANISM unwrap_mech = { CKM_RSA_AES_KEY_WRAP, &unwrap_params, sizeof(unwrap_params) };
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            p11->C_UnwrapKey(sess, &unwrap_mech, rsa_priv,
                             wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
        }
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- DES3 key gen + AES-CBC-PAD wrap + DES3-CBC-PAD unwrap ---- */
    case 14:
    case 15: {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES3;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_WRAP,        &true_val,  sizeof(true_val)  },
            { CKA_UNWRAP,      &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE des3_key = CK_INVALID_HANDLE;

        rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 8, &des3_key);
        if (rv != CKR_OK) break;

        CK_BYTE iv[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        CK_MECHANISM wrap_mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
        CK_BYTE wrapped[256];
        CK_ULONG wrapped_len = sizeof(wrapped);

        rv = p11->C_WrapKey(sess, &wrap_mech, aes_key, des3_key, wrapped, &wrapped_len);
        if (rv != CKR_OK || wrapped_len == 0) {
            p11->C_DestroyObject(sess, des3_key);
            break;
        }

        CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
        CK_KEY_TYPE unwrap_ktype = CKK_DES3;
        CK_BBOOL sensitive = CK_TRUE;
        CK_BBOOL extractable = CK_FALSE;
        CK_ATTRIBUTE unwrap_tmpl[] = {
            { CKA_CLASS,       &cls,          sizeof(cls)          },
            { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
            { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
            { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
        };

        CK_MECHANISM unwrap_mech = { CKM_DES3_CBC_PAD, iv, sizeof(iv) };
        CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
        rv = p11->C_UnwrapKey(sess, &unwrap_mech, aes_key,
                               wrapped, wrapped_len,
                               unwrap_tmpl, 4, &new_key);
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        p11->C_DestroyObject(sess, des3_key);
        break;
    }

    /* ---- AES-CBC wrap + unwrap (case 16) -------------------------------- */
    case 16: {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 16;

        CK_ATTRIBUTE wrap_key_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_WRAP,        &true_val,  sizeof(true_val)  },
            { CKA_UNWRAP,      &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE wrap_key = CK_INVALID_HANDLE;
        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                wrap_key_tmpl, 9, &wrap_key);
        if (rv != CKR_OK) break;

        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                &(CK_ATTRIBUTE){ CKA_KEY_TYPE, &ktype, sizeof(ktype) }, 1, &derived);
        if (rv != CKR_OK) {
            p11->C_DestroyObject(sess, wrap_key);
            break;
        }

        CK_BYTE iv[16] = {0};
        CK_MECHANISM wrap_mech = { CKM_AES_CBC, iv, sizeof(iv) };
        CK_BYTE wrapped[256];
        CK_ULONG wrapped_len = sizeof(wrapped);
        rv = p11->C_WrapKey(sess, &wrap_mech, wrap_key, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_MECHANISM unwrap_mech = { CKM_AES_CBC, iv, sizeof(iv) };
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
            p11->C_UnwrapKey(sess, &unwrap_mech, wrap_key,
                              wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
            if (new_key != CK_INVALID_HANDLE)
                p11->C_DestroyObject(sess, new_key);
        }
        p11->C_DestroyObject(sess, derived);
        p11->C_DestroyObject(sess, wrap_key);
        break;
    }

    /* ---- C_DeriveKey with CKM_CONCATENATE_BASE_AND_DATA --------------- */
    case 17: {
        if (plen == 0) break;
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_GENERIC_SECRET;
        CK_ULONG keylen    = (CK_ULONG)plen;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_KEY_DERIVATION_STRING_DATA param;
        param.pData = (CK_BYTE_PTR)pay;
        param.ulLen = (CK_ULONG)plen;
        CK_MECHANISM derive_mech = {
            CKM_CONCATENATE_BASE_AND_DATA,
            &param,
            sizeof(param)
        };

        rv = p11->C_DeriveKey(sess, &derive_mech, aes_key,
                              gen_tmpl, 4, &derived);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_WrapKey + C_UnwrapKey with CKM_RSA_AES_KEY_WRAP (128-bit AES) ---- */
    case 18: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 128;
        wrap_params.pOAEPParams = &oaep_params;

        CK_MECHANISM wrap_mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE, new_key = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 16;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                gen_tmpl, 7, &derived);
        if (rv != CKR_OK) break;

        CK_BYTE wrapped[512];
        CK_ULONG wrapped_len = sizeof(wrapped);
        rv = p11->C_WrapKey(sess, &wrap_mech, rsa_pub, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_RSA_PKCS_OAEP_PARAMS unwrap_oaep_params = {
                CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
            };
            CK_RSA_AES_KEY_WRAP_PARAMS unwrap_params;
            unwrap_params.ulAESKeyBits = 128;
            unwrap_params.pOAEPParams = &unwrap_oaep_params;

            CK_MECHANISM unwrap_mech = { CKM_RSA_AES_KEY_WRAP, &unwrap_params, sizeof(unwrap_params) };
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            p11->C_UnwrapKey(sess, &unwrap_mech, rsa_priv,
                             wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
        }
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_WrapKey + C_UnwrapKey with CKM_RSA_AES_KEY_WRAP (192-bit AES) ---- */
    case 19: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 192;
        wrap_params.pOAEPParams = &oaep_params;

        CK_MECHANISM wrap_mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE, new_key = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;
        CK_ULONG keylen    = 24;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        rv = p11->C_GenerateKey(sess, &(CK_MECHANISM){ CKM_AES_KEY_GEN, NULL_PTR, 0 },
                                gen_tmpl, 7, &derived);
        if (rv != CKR_OK) break;

        CK_BYTE wrapped[512];
        CK_ULONG wrapped_len = sizeof(wrapped);
        rv = p11->C_WrapKey(sess, &wrap_mech, rsa_pub, derived, wrapped, &wrapped_len);
        if (rv == CKR_OK && wrapped_len > 0) {
            CK_RSA_PKCS_OAEP_PARAMS unwrap_oaep_params = {
                CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
            };
            CK_RSA_AES_KEY_WRAP_PARAMS unwrap_params;
            unwrap_params.ulAESKeyBits = 192;
            unwrap_params.pOAEPParams = &unwrap_oaep_params;

            CK_MECHANISM unwrap_mech = { CKM_RSA_AES_KEY_WRAP, &unwrap_params, sizeof(unwrap_params) };
            CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
            CK_KEY_TYPE unwrap_ktype = CKK_AES;
            CK_BBOOL sensitive = CK_TRUE;
            CK_BBOOL extractable = CK_FALSE;
            CK_ATTRIBUTE unwrap_tmpl[] = {
                { CKA_CLASS,       &cls,          sizeof(cls)          },
                { CKA_KEY_TYPE,    &unwrap_ktype, sizeof(unwrap_ktype) },
                { CKA_SENSITIVE,   &sensitive,    sizeof(sensitive)    },
                { CKA_EXTRACTABLE, &extractable,  sizeof(extractable)  },
            };
            p11->C_UnwrapKey(sess, &unwrap_mech, rsa_priv,
                             wrapped, wrapped_len, unwrap_tmpl, 4, &new_key);
        }
        if (new_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, new_key);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - NULL pParameter ---- */
    case 20: {
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, NULL_PTR, 0 };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - bad param length ---- */
    case 21: {
        CK_BYTE params[4] = {0x00, 0x01, 0x02, 0x03};
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, params, sizeof(params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - bad ulAESKeyBits ---- */
    case 22: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 64;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - NULL pOAEPParams ---- */
    case 23: {
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = NULL_PTR;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - mgf out of range (0) ---- */
    case 24: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, 0, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - mgf out of range (6) ---- */
    case 25: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, 6, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - bad source type ---- */
    case 26: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, CKG_MGF1_SHA1, 0, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - non-NULL pSourceData ---- */
    case 27: {
        CK_BYTE source_data = 0x42;
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, &source_data, 1
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_DeriveKey with CKM_CONCATENATE_BASE_AND_KEY --------------- */
    case 28: {
        if (hmac_key == CK_INVALID_HANDLE) break;
        CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_GENERIC_SECRET;
        CK_ULONG keylen    = 32;
        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &keylen,    sizeof(keylen)    },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE other_key_handle = hmac_key;
        CK_MECHANISM derive_mech = {
            CKM_CONCATENATE_BASE_AND_KEY,
            &other_key_handle,
            sizeof(other_key_handle)
        };

        rv = p11->C_DeriveKey(sess, &derive_mech, aes_key,
                              gen_tmpl, 4, &derived);
        if (derived != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - non-zero ulSourceDataLen with NULL pSourceData ---- */
    case 29: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL_PTR, 5
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - mgf=CKG_MGF1_SHA256 (2) ---- */
    case 30: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, 2, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - mgf=CKG_MGF1_SHA384 (3) ---- */
    case 31: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, 3, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - mgf=CKG_MGF1_SHA512 (4) ---- */
    case 32: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, 4, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }

    /* ---- C_WrapKey with CKM_RSA_AES_KEY_WRAP - mgf=CKG_MGF1_SHA224 (5) ---- */
    case 33: {
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
            CKM_SHA_1, 5, CKZ_DATA_SPECIFIED, NULL_PTR, 0
        };
        CK_RSA_AES_KEY_WRAP_PARAMS wrap_params;
        wrap_params.ulAESKeyBits = 256;
        wrap_params.pOAEPParams = &oaep_params;
        CK_MECHANISM mech = { CKM_RSA_AES_KEY_WRAP, &wrap_params, sizeof(wrap_params) };
        CK_BYTE out[4096];
        CK_ULONG outlen = sizeof(out);
        p11->C_WrapKey(sess, &mech, rsa_pub, aes_key, out, &outlen);
        break;
    }
    }

    return 0;
}
