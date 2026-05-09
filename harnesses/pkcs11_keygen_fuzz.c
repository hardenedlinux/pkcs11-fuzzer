/*
 * pkcs11_keygen_fuzz.c — Fuzz C_GenerateKey / C_GenerateKeyPair.
 *
 * Key generation is the most computationally intense PKCS#11 operation and
 * exercises fundamentally different code paths from sign/decrypt:
 *   - RSA prime generation (trial division, Miller-Rabin)
 *   - EC point validation and conversion
 *   - SoftHSM2's attribute template parsing and validation
 *   - Key storage serialization
 *
 * RSA key sizes are capped at 1024 bits normally, but 2048 is available.
 *
 * Input layout:
 *   byte 0:  key type / operation selector
 *   byte 1+: additional attribute bytes
 *
 * Selectors:
 *   0  RSA-512  GenerateKeyPair
 *   1  RSA-768  GenerateKeyPair
 *   2  RSA-1024 GenerateKeyPair (use byte 1..4 as public exponent)
 *   3  EC P-256 GenerateKeyPair
 *   4  EC P-384 GenerateKeyPair
 *   5  EC P-521 GenerateKeyPair
 *   6  AES-128  GenerateKey
 *   7  AES-192  GenerateKey
 *   8  AES-256  GenerateKey
 *   9  AES with key length from fuzz byte
 *  10  Generic secret key, fuzz length
 *  11  Ed25519 key pair
 *  12  Ed448 key pair
 *  13  X25519 key pair
 *  14  X448 key pair
 *  15  RSA-2048 GenerateKeyPair (Slow!)
 *  16  AES-128 GenerateKey + AES-ECB encrypt/decrypt
 *  17  RSA-1024 GenerateKeyPair + RSA-PKCS encrypt/decrypt
 *  18  EC P-256 GenerateKeyPair + ECDSA sign/verify
 *  19  C_GetAttributeValue on token keys
 *  20  C_GetObjectSize on token keys
 *  21  DH key derivation
 *  22  RSA-PSS sign (SHA-256)
 *  23  AES-CBC encrypt/decrypt
 *  24  EC P-384 GenerateKeyPair + ECDSA sign/verify
 *  25  ECDH derive + AES-ECB encrypt
 *  26  ECDSA sign/verify SHA-384 (token ec_priv/ec_pub)
 *  27  HMAC-SHA384 sign/verify (token hmac_key)
 *  28  RSA-PKCS sign (token rsa_priv)
 *  29  Get RSA modulus attribute
 *  30  Get EC POINT attribute
 *  31  ECDH derive + AES-CBC encrypt
 *  32  AES-CMAC generation
 *  33  DSA key pair gen + sign + verify
 *  34  AES-128 GenerateKey + AES-GCM encrypt/decrypt
 *  35  RSA-1024 GenerateKeyPair + RSA-OAEP encrypt/decrypt
 *  36  AES-128 GenerateKey + AES-CCM encrypt/decrypt
 *  37  DES key GenerateKey
 *  38  Triple-DES key GenerateKey
 *  39  AES-CTR encrypt/decrypt (token aes_key)
 *  40  HMAC-SHA1 sign/verify (token hmac_key)
 *  41  HMAC-SHA256 sign/verify (token hmac_key)
 *  42  HMAC-SHA512 sign/verify (token hmac_key)
 *  43  DES2 key GenerateKey (112-bit)
  *  44  ML-DSA-44 key pair gen + sign + verify
 *  45  ML-DSA-65 key pair gen + sign + verify
 *  46  ML-DSA-87 key pair gen + sign + verify
 *  47  DES3-CMAC generation
 *  48  DES3-CBC encrypt/decrypt
 *  49  DES ECB ENCRYPT_DATA derive
 *  50  DES CBC ENCRYPT_DATA derive
 *  51  DES3 ECB ENCRYPT_DATA derive
 *  52  DES3 CBC ENCRYPT_DATA derive
 *  53  AES ECB ENCRYPT_DATA derive
 *  54  AES CBC ENCRYPT_DATA derive
 *  */
#include "common.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    pkcs11_init();
    return 0;
}

/* EC OIDs for GenerateKeyPair */
static const CK_BYTE OID_P256[] = { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };
static const CK_BYTE OID_P384[] = { 0x06,0x05,0x2b,0x81,0x04,0x00,0x22 };
static const CK_BYTE OID_P521[] = { 0x06,0x05,0x2b,0x81,0x04,0x00,0x23 };
static const CK_BYTE OID_ED25519[] = { 0x06, 0x03, 0x2b, 0x65, 0x70 };
static const CK_BYTE OID_ED448[]   = { 0x06, 0x03, 0x2b, 0x65, 0x71 };
static const CK_BYTE OID_X25519[]  = { 0x06, 0x03, 0x2b, 0x65, 0x6e };
static const CK_BYTE OID_X448[]    = { 0x06, 0x03, 0x2b, 0x65, 0x6f };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    uint8_t sel = data[0] % 70;

    /* ── RSA key pair generation ─────────────────────────────────────────── */
    if (sel <= 2 || sel == 15) {
        CK_ULONG bits;
        switch (sel) {
        case 0: bits = 512;  break;
        case 1: bits = 768;  break;
        case 2: bits = 1024; break;
        default: bits = 2048; break;
        }

        /* Use fuzz bytes as the public exponent (first 4 bytes, big-endian).
         * The default (0x010001 = 65537) is used if the bytes produce zero. */
        CK_BYTE  exp_bytes[4] = { 0x00, 0x01, 0x00, 0x01 }; /* 65537 */
        if (size >= 5) memcpy(exp_bytes, data + 1, 4);
        /* Ensure odd — RSA public exponent must be odd */
        exp_bytes[3] |= 0x01;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_MODULUS_BITS,  &bits,      sizeof(bits) },
            { CKA_PUBLIC_EXPONENT, exp_bytes, sizeof(exp_bytes) },
            { CKA_VERIFY,        &true_val,  sizeof(true_val) },
            { CKA_ENCRYPT,       &true_val,  sizeof(true_val) },
            { CKA_TOKEN,         &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SIGN,          &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,       &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,     &true_val,  sizeof(true_val) },
            { CKA_EXTRACTABLE,   &false_val, sizeof(false_val) },
            { CKA_TOKEN,         &false_val, sizeof(false_val) },
        };

        CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &mech,
                                           pub_tmpl,  5,
                                           priv_tmpl, 5,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── EC key pair generation ──────────────────────────────────────────── */
    if ((sel >= 3 && sel <= 5) || (sel >= 11 && sel <= 14)) {
        const CK_BYTE *oid;
        CK_ULONG oid_len;
        CK_MECHANISM_TYPE mech_type = CKM_EC_KEY_PAIR_GEN;

        switch (sel) {
        case 3: oid = OID_P256; oid_len = sizeof(OID_P256); break;
        case 4: oid = OID_P384; oid_len = sizeof(OID_P384); break;
        case 5: oid = OID_P521; oid_len = sizeof(OID_P521); break;
        case 11: oid = OID_ED25519; oid_len = sizeof(OID_ED25519); mech_type = CKM_EC_EDWARDS_KEY_PAIR_GEN; break;
        case 12: oid = OID_ED448;   oid_len = sizeof(OID_ED448);   mech_type = CKM_EC_EDWARDS_KEY_PAIR_GEN; break;
        case 13: oid = OID_X25519;  oid_len = sizeof(OID_X25519);  mech_type = CKM_EC_MONTGOMERY_KEY_PAIR_GEN; break;
        default: oid = OID_X448;    oid_len = sizeof(OID_X448);    mech_type = CKM_EC_MONTGOMERY_KEY_PAIR_GEN; break;
        }

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_EC_PARAMS,  (CK_VOID_PTR)oid, oid_len },
            { CKA_VERIFY,     &true_val,  sizeof(true_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SIGN,       &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,  &true_val,  sizeof(true_val) },
            { CKA_EXTRACTABLE, &false_val, sizeof(false_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };

        CK_MECHANISM mech = { mech_type, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &mech,
                                           pub_tmpl,  3,
                                           priv_tmpl, 4,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── AES secret key generation ───────────────────────────────────────── */
    if (sel >= 6 && sel <= 9) {
        CK_ULONG keybits;
        if (sel == 9 && size >= 2) {
            /* Fuzz the key length — exercises boundary validation */
            keybits = 8 * (CK_ULONG)data[1];  /* 0–2040 bits */
        } else {
            switch (sel) {
            case 6:  keybits = 128; break;
            case 7:  keybits = 192; break;
            default: keybits = 256; break;
            }
        }
        CK_ULONG keylen = keybits / 8;

        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_KEY_TYPE,   &ktype,     sizeof(ktype) },
            { CKA_VALUE_LEN,  &keylen,    sizeof(keylen) },
            { CKA_ENCRYPT,    &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,    &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,  &true_val,  sizeof(true_val) },
            { CKA_EXTRACTABLE, &false_val, sizeof(false_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };

        CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &mech, tmpl, 7, &key_h);
        if (rv == CKR_OK)
            p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── Generic secret key generation (HMAC key) ───────────────────────── */
    if (sel == 10) {
        CK_ULONG keylen = (size >= 2) ? ((CK_ULONG)data[1] % 64) + 1 : 32;
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_GENERIC_SECRET;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_KEY_TYPE,   &ktype,    sizeof(ktype)    },
            { CKA_VALUE_LEN,  &keylen,   sizeof(keylen)   },
            { CKA_SIGN,       &true_val, sizeof(true_val) },
            { CKA_VERIFY,     &true_val, sizeof(true_val) },
            { CKA_SENSITIVE,  &true_val, sizeof(true_val) },
            { CKA_EXTRACTABLE, &false_val, sizeof(false_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };

        CK_MECHANISM mech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &mech, tmpl, 7, &key_h);
        if (rv == CKR_OK)
            p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── RSA key pair + encrypt/decrypt (selector 17) ──────────────────── */
    if (sel == 17) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_MODULUS_BITS, &(CK_ULONG){1024}, sizeof(CK_ULONG) },
            { CKA_PUBLIC_EXPONENT, (CK_BYTE[]){0x01, 0x00, 0x01}, 3 },
            { CKA_ENCRYPT,       &true_val,  sizeof(true_val) },
            { CKA_VERIFY,        &true_val,  sizeof(true_val) },
            { CKA_TOKEN,         &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_DECRYPT,       &true_val,  sizeof(true_val) },
            { CKA_SIGN,          &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,     &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE,   &true_val,  sizeof(true_val) },
            { CKA_TOKEN,         &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl, 5,
                                           priv_tmpl, 5,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE in[16] = {0};
            CK_BYTE out[128];
            CK_ULONG olen = sizeof(out);

            CK_MECHANISM enc_mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
            if (p11->C_EncryptInit(sess, &enc_mech, priv_h) == CKR_OK) {
                olen = sizeof(out);
                p11->C_Encrypt(sess, in, 16, out, &olen);
            }
            if (p11->C_DecryptInit(sess, &enc_mech, priv_h) == CKR_OK) {
                CK_BYTE dec[128];
                CK_ULONG dlen = sizeof(dec);
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── AES key generation + encrypt/decrypt (selector 16) ─────────────── */
    if (sel == 16) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &(CK_ULONG){16}, sizeof(CK_ULONG) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE,  &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,        &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 7, &key_h);
        if (rv == CKR_OK) {
            CK_BYTE in[16] = {0};
            CK_BYTE out[32];
            CK_ULONG olen = sizeof(out);

            CK_MECHANISM enc_mech = { CKM_AES_ECB, NULL_PTR, 0 };
            if (p11->C_EncryptInit(sess, &enc_mech, key_h) == CKR_OK) {
                olen = sizeof(out);
                p11->C_Encrypt(sess, in, 16, out, &olen);
            }
            if (p11->C_DecryptInit(sess, &enc_mech, key_h) == CKR_OK) {
                CK_BYTE dec[16];
                CK_ULONG dlen = sizeof(dec);
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
            p11->C_DestroyObject(sess, key_h);
        }
        return 0;
    }

    /* ── EC P-256 key pair + ECDSA sign/verify (selector 18) ─────────── */
    if (sel == 18) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_EC_PARAMS,  (CK_VOID_PTR)OID_P256, sizeof(OID_P256) },
            { CKA_VERIFY,     &true_val,  sizeof(true_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SIGN,       &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl,  3,
                                           priv_tmpl, 4,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE data_buf[32] = {0x01, 0x02, 0x03};
            CK_BYTE sig[128];
            CK_ULONG sig_len = sizeof(sig);

            CK_MECHANISM sign_mech = { CKM_ECDSA, NULL_PTR, 0 };
            if (p11->C_SignInit(sess, &sign_mech, priv_h) == CKR_OK) {
                sig_len = sizeof(sig);
                p11->C_Sign(sess, data_buf, 3, sig, &sig_len);
            }

            if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, pub_h) == CKR_OK) {
                p11->C_Verify(sess, data_buf, 3, sig, sig_len);
            }

            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── C_GetAttributeValue on token keys (selector 19) ─────────────────── */
    if (sel == 19) {
        CK_OBJECT_HANDLE keys[] = { aes_key, hmac_key, rsa_priv, ec_priv };
        CK_ATTRIBUTE attr_tmpl[] = {
            { CKA_CLASS, NULL, 0 },
            { CKA_KEY_TYPE, NULL, 0 },
            { CKA_ENCRYPT, NULL, 0 },
            { CKA_DECRYPT, NULL, 0 },
            { CKA_SIGN, NULL, 0 },
            { CKA_VERIFY, NULL, 0 },
            { CKA_SENSITIVE, NULL, 0 },
            { CKA_EXTRACTABLE, NULL, 0 },
            { CKA_LABEL, NULL, 0 },
        };
        CK_ULONG nattr = sizeof(attr_tmpl) / sizeof(attr_tmpl[0]);

        for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            if (keys[i] == CK_INVALID_HANDLE) continue;
            p11->C_GetAttributeValue(sess, keys[i], attr_tmpl, nattr);
        }
        return 0;
    }

    /* ── C_GetObjectSize on token keys (selector 20) ────────────────────── */
    if (sel == 20) {
        CK_OBJECT_HANDLE keys[] = { aes_key, hmac_key, rsa_priv, ec_priv };
        for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            if (keys[i] == CK_INVALID_HANDLE) continue;
            CK_ULONG size = 0;
            p11->C_GetObjectSize(sess, keys[i], &size);
        }
        return 0;
    }

    /* ── DH key derivation (selector 21) ────────────────────────────────── */
    if (sel == 21) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_ULONG bits = 1024;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_PRIME_BITS, &bits, sizeof(bits) },
            { CKA_PUBLIC_EXPONENT, (CK_BYTE[]){0x01, 0x00, 0x01}, 3 },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl, 3,
                                           priv_tmpl, 3,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_MECHANISM derive_mech = { CKM_DH_PKCS_DERIVE, NULL_PTR, 0 };
            CK_BYTE shared_data[] = {0x01, 0x02, 0x03};
            CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;

            CK_ATTRIBUTE derive_tmpl[] = {
                { CKA_SENSITIVE, &false_val, sizeof(false_val) },
                { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
                { CKA_TOKEN, &false_val, sizeof(false_val) },
            };

            p11->C_DeriveKey(sess, &derive_mech, priv_h, derive_tmpl, 3, &derived_key);
            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── RSA-PSS sign (selector 22) ────────────────────────────────────── */
    if (sel == 22) {
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        CK_MECHANISM sign_mech = { CKM_RSA_PKCS_PSS, NULL_PTR, 0 };
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03};
        CK_BYTE sig[256];
        CK_ULONG sig_len = sizeof(sig);

        if (p11->C_SignInit(sess, &sign_mech, rsa_priv) == CKR_OK) {
            p11->C_Sign(sess, data_buf, 3, sig, &sig_len);
        }
        return 0;
    }

    /* ── AES-CBC encrypt/decrypt (selector 23) ─────────────────────────── */
    if (sel == 23) {
        if (aes_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE iv[16] = {0};
        CK_BYTE in[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE out[32];
        CK_ULONG olen = sizeof(out);

        CK_MECHANISM enc_mech = { CKM_AES_CBC, iv, sizeof(iv) };
        if (p11->C_EncryptInit(sess, &enc_mech, aes_key) == CKR_OK) {
            olen = sizeof(out);
            p11->C_Encrypt(sess, in, 16, out, &olen);
        }
        if (olen > 0) {
            CK_MECHANISM dec_mech = { CKM_AES_CBC, iv, sizeof(iv) };
            if (p11->C_DecryptInit(sess, &dec_mech, aes_key) == CKR_OK) {
                CK_BYTE dec[16];
                CK_ULONG dlen = sizeof(dec);
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }
        return 0;
    }

    /* ── EC P-384 GenerateKeyPair + ECDSA sign/verify (selector 24) ────── */
    if (sel == 24) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_EC_PARAMS, (CK_VOID_PTR)OID_P384, sizeof(OID_P384) },
            { CKA_VERIFY, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl, 3,
                                           priv_tmpl, 4,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE data_buf[] = {0x01, 0x02, 0x03};
            CK_BYTE sig[128];
            CK_ULONG sig_len = sizeof(sig);

            CK_MECHANISM sign_mech = { CKM_ECDSA, NULL_PTR, 0 };
            if (p11->C_SignInit(sess, &sign_mech, priv_h) == CKR_OK) {
                sig_len = sizeof(sig);
                p11->C_Sign(sess, data_buf, 3, sig, &sig_len);
            }

            if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, pub_h) == CKR_OK) {
                p11->C_Verify(sess, data_buf, 3, sig, sig_len);
            }

            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── ECDH derive + AES-ECB encrypt (selector 25) ───────────────────── */
    if (sel == 25) {
        if (ec_priv == CK_INVALID_HANDLE) return 0;
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_MECHANISM derive_mech = { CKM_ECDH1_DERIVE, NULL_PTR, 0 };
        CK_BYTE shared_data[] = {0x01, 0x02, 0x03};

        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
            { CKA_ENCRYPT, &true_val, sizeof(true_val) },
            { CKA_DECRYPT, &true_val, sizeof(true_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        CK_RV rv = p11->C_DeriveKey(sess, &derive_mech, ec_priv,
                                      derive_tmpl, 5, &derived_key);
        if (rv == CKR_OK) {
            CK_MECHANISM enc_mech = { CKM_AES_ECB, NULL_PTR, 0 };
            CK_BYTE in[16] = {0};
            CK_BYTE out[32];
            CK_ULONG olen = sizeof(out);

            if (p11->C_EncryptInit(sess, &enc_mech, derived_key) == CKR_OK) {
                olen = sizeof(out);
                p11->C_Encrypt(sess, in, 16, out, &olen);
            }
            p11->C_DestroyObject(sess, derived_key);
        }
        return 0;
    }

    /* ── ECDSA sign/verify with SHA-384 (selector 26) ─────────────────── */
    if (sel == 26) {
        if (ec_priv == CK_INVALID_HANDLE || ec_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03};
        CK_BYTE sig[128];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_ECDSA, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, ec_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 3, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, ec_pub) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 3, sig, sig_len);
        }
        return 0;
    }

    /* ── HMAC-SHA384 sign/verify (selector 27) ────────────────────────── */
    if (sel == 27) {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[64];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM hmac_mech = { CKM_SHA384_HMAC, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ── RSA-PKCS#1.5 sign using token's rsa_priv (selector 28) ─────── */
    if (sel == 28) {
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[256];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, rsa_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }
        return 0;
    }

    /* ── Get RSA modulus attribute (selector 29) ──────────────────────── */
    if (sel == 29) {
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        CK_ATTRIBUTE attr_tmpl[] = {
            { CKA_MODULUS, NULL, 0 },
        };
        if (p11->C_GetAttributeValue(sess, rsa_priv, attr_tmpl, 1) == CKR_OK) {
            if (attr_tmpl[0].ulValueLen > 0) {
                CK_BYTE buf[256];
                attr_tmpl[0].pValue = buf;
                attr_tmpl[0].ulValueLen = sizeof(buf);
                p11->C_GetAttributeValue(sess, rsa_priv, attr_tmpl, 1);
            }
        }
        return 0;
    }

    /* ── Get EC POINT attribute (selector 30) ─────────────────────────── */
    if (sel == 30) {
        if (ec_pub == CK_INVALID_HANDLE) return 0;
        CK_ATTRIBUTE attr_tmpl[] = {
            { CKA_EC_POINT, NULL, 0 },
        };
        if (p11->C_GetAttributeValue(sess, ec_pub, attr_tmpl, 1) == CKR_OK) {
            if (attr_tmpl[0].ulValueLen > 0) {
                CK_BYTE buf[256];
                attr_tmpl[0].pValue = buf;
                attr_tmpl[0].ulValueLen = sizeof(buf);
                p11->C_GetAttributeValue(sess, ec_pub, attr_tmpl, 1);
            }
        }
        return 0;
    }

    /* ── ECDH derive + AES-CBC encrypt (selector 31) ─────────────────── */
    if (sel == 31) {
        if (ec_priv == CK_INVALID_HANDLE) return 0;
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_MECHANISM derive_mech = { CKM_ECDH1_DERIVE, NULL_PTR, 0 };
        CK_BYTE shared_data[] = {0x01, 0x02, 0x03, 0x04};

        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
            { CKA_ENCRYPT, &true_val, sizeof(true_val) },
            { CKA_DECRYPT, &true_val, sizeof(true_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        CK_RV rv = p11->C_DeriveKey(sess, &derive_mech, ec_priv,
                                      derive_tmpl, 5, &derived_key);
        if (rv == CKR_OK) {
            CK_BYTE iv[16] = {0};
            CK_BYTE in[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
            CK_BYTE out[32];
            CK_ULONG olen = sizeof(out);

            CK_MECHANISM enc_mech = { CKM_AES_CBC, iv, sizeof(iv) };
            if (p11->C_EncryptInit(sess, &enc_mech, derived_key) == CKR_OK) {
                olen = sizeof(out);
                p11->C_Encrypt(sess, in, 16, out, &olen);
            }
            p11->C_DestroyObject(sess, derived_key);
        }
        return 0;
    }

    /* ── AES-CMAC generation (selector 32) ─────────────────────────────── */
    if (sel == 32) {
        if (aes_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        CK_BYTE sig[16];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM cmac_mech = { CKM_AES_CMAC, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &cmac_mech, aes_key) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 8, sig, &sig_len);
        }
        return 0;
    }

    /* ── DSA key pair gen + sign + verify (selector 33) ───────────────── */
    if (sel == 33) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_ULONG bits = 1024;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_PRIME_BITS, &bits, sizeof(bits) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl, 2,
                                           priv_tmpl, 4,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE data_buf[] = {0x01, 0x02, 0x03};
            CK_BYTE sig[40];
            CK_ULONG sig_len = sizeof(sig);

            CK_MECHANISM sign_mech = { CKM_DSA, NULL_PTR, 0 };
            if (p11->C_SignInit(sess, &sign_mech, priv_h) == CKR_OK) {
                sig_len = sizeof(sig);
                p11->C_Sign(sess, data_buf, 3, sig, &sig_len);
            }

            if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, pub_h) == CKR_OK) {
                p11->C_Verify(sess, data_buf, 3, sig, sig_len);
            }

            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── AES key generation + AES-GCM encrypt/decrypt (selector 34) ────────── */
    if (sel == 34) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &(CK_ULONG){16}, sizeof(CK_ULONG) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE,  &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,        &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 7, &key_h);
        if (rv != CKR_OK) return 0;

        CK_BYTE iv[12] = {0};
        CK_BYTE in[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE out[32];
        CK_ULONG olen = sizeof(out);

        CK_GCM_PARAMS gcm_params;
        gcm_params.pIv = iv;
        gcm_params.ulIvLen = sizeof(iv);
        gcm_params.ulIvBits = 96;
        gcm_params.pAAD = NULL;
        gcm_params.ulAADLen = 0;
        gcm_params.ulTagBits = 128;

        CK_MECHANISM enc_mech = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };
        if (p11->C_EncryptInit(sess, &enc_mech, key_h) == CKR_OK) {
            olen = sizeof(out);
            rv = p11->C_Encrypt(sess, in, sizeof(in), out, &olen);
        }

        if (rv == CKR_OK && olen == 32) {
            CK_BYTE dec[16];
            CK_ULONG dlen = sizeof(dec);

            CK_MECHANISM dec_mech = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };
            if (p11->C_DecryptInit(sess, &dec_mech, key_h) == CKR_OK) {
                p11->C_Decrypt(sess, out, 32, dec, &dlen);
            }
        }

        p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── RSA-OAEP encrypt/decrypt (selector 35) ─────────────────────────── */
    if (sel == 35) {
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        CK_BBOOL true_val = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_MODULUS_BITS, &(CK_ULONG){1024}, sizeof(CK_ULONG) },
            { CKA_PUBLIC_EXPONENT, (CK_BYTE[]){0x01, 0x00, 0x01}, 3 },
            { CKA_ENCRYPT, &true_val, sizeof(true_val) },
            { CKA_VERIFY, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_DECRYPT, &true_val, sizeof(true_val) },
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl, 5,
                                           priv_tmpl, 5,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE in[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
            CK_BYTE out[256];
            CK_ULONG olen = sizeof(out);

            CK_BYTE label[] = {0x01, 0x02, 0x03};
            CK_MECHANISM enc_mech = { CKM_RSA_PKCS_OAEP, label, sizeof(label) };
            if (p11->C_EncryptInit(sess, &enc_mech, pub_h) == CKR_OK) {
                olen = sizeof(out);
                rv = p11->C_Encrypt(sess, in, 16, out, &olen);
            }

            if (rv == CKR_OK && olen > 0) {
                CK_BYTE dec[16];
                CK_ULONG dlen = sizeof(dec);
                CK_MECHANISM dec_mech = { CKM_RSA_PKCS_OAEP, label, sizeof(label) };
                if (p11->C_DecryptInit(sess, &dec_mech, priv_h) == CKR_OK) {
                    p11->C_Decrypt(sess, out, olen, dec, &dlen);
                }
            }
            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── AES key generation + AES-CCM encrypt/decrypt (selector 36) ────────── */
    if (sel == 36) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_AES;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_VALUE_LEN,   &(CK_ULONG){16}, sizeof(CK_ULONG) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE,  &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,        &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 7, &key_h);
        if (rv != CKR_OK) return 0;

        CK_BYTE nonce[13] = {0};
        CK_BYTE in[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE out[32];
        CK_ULONG olen = sizeof(out);

        CK_CCM_PARAMS ccm_params;
        ccm_params.ulDataLen = sizeof(in);
        ccm_params.nonce = nonce;
        ccm_params.ulNonceLen = sizeof(nonce);
        ccm_params.aad = NULL;
        ccm_params.ulAADLen = 0;
        ccm_params.ulMACLen = 16;

        CK_MECHANISM enc_mech = { CKM_AES_CCM, &ccm_params, sizeof(ccm_params) };
        if (p11->C_EncryptInit(sess, &enc_mech, key_h) == CKR_OK) {
            olen = sizeof(out);
            rv = p11->C_Encrypt(sess, in, sizeof(in), out, &olen);
        }

        if (rv == CKR_OK && olen > 16) {
            CK_BYTE dec[16];
            CK_ULONG dlen = sizeof(dec);
            CK_CCM_PARAMS dec_ccm_params;
            dec_ccm_params.ulDataLen = dlen;
            dec_ccm_params.nonce = nonce;
            dec_ccm_params.ulNonceLen = sizeof(nonce);
            dec_ccm_params.aad = NULL;
            dec_ccm_params.ulAADLen = 0;
            dec_ccm_params.ulMACLen = 16;

            CK_MECHANISM dec_mech = { CKM_AES_CCM, &dec_ccm_params, sizeof(dec_ccm_params) };
            if (p11->C_DecryptInit(sess, &dec_mech, key_h) == CKR_OK) {
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }

        p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── DES key generation (selector 37) ─────────────────────────────── */
    if (sel == 37) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_KEY_TYPE,   &ktype,     sizeof(ktype) },
            { CKA_ENCRYPT,    &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,    &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,  &true_val,  sizeof(true_val) },
            { CKA_EXTRACTABLE, &false_val, sizeof(false_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };

        CK_MECHANISM mech = { CKM_DES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &mech, tmpl, 6, &key_h);
        if (rv == CKR_OK)
            p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── Triple-DES key generation (selector 38) ───────────────────────── */
    if (sel == 38) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES3;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_KEY_TYPE,   &ktype,     sizeof(ktype) },
            { CKA_ENCRYPT,    &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,    &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,  &true_val,  sizeof(true_val) },
            { CKA_EXTRACTABLE, &false_val, sizeof(false_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };

        CK_MECHANISM mech = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &mech, tmpl, 6, &key_h);
        if (rv == CKR_OK)
            p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── AES-CTR encrypt/decrypt (selector 39) ────────────────────────── */
    if (sel == 39) {
        if (aes_key == CK_INVALID_HANDLE) return 0;
        CK_AES_CTR_PARAMS ctr_params;
        ctr_params.ulCounterBits = 64;
        memset(ctr_params.cb, 0, sizeof(ctr_params.cb));

        CK_BYTE in[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE out[32];
        CK_ULONG olen = sizeof(out);

        CK_MECHANISM enc_mech = { CKM_AES_CTR, &ctr_params, sizeof(ctr_params) };
        if (p11->C_EncryptInit(sess, &enc_mech, aes_key) == CKR_OK) {
            olen = sizeof(out);
            p11->C_Encrypt(sess, in, 16, out, &olen);
        }

        if (olen > 16) {
            CK_BYTE dec[16];
            CK_ULONG dlen = sizeof(dec);
            if (p11->C_DecryptInit(sess, &enc_mech, aes_key) == CKR_OK) {
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }
        return 0;
    }

    /* ---- HMAC-SHA1 sign/verify (selector 40) ------------------------------- */
    if (sel == 40) {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[64];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM hmac_mech = { CKM_SHA_1_HMAC, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ---- HMAC-SHA256 sign/verify (selector 41) ---------------------------- */
    if (sel == 41) {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[64];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM hmac_mech = { CKM_SHA256_HMAC, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ---- HMAC-SHA512 sign/verify (selector 42) ---------------------------- */
    if (sel == 42) {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[64];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM hmac_mech = { CKM_SHA512_HMAC, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ── DES2 key generation (selector 43) ──────────────────────────────── */
    if (sel == 43) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES2;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,    &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,  &true_val,  sizeof(true_val) },
            { CKA_EXTRACTABLE, &false_val, sizeof(false_val) },
            { CKA_TOKEN,      &false_val, sizeof(false_val) },
        };

        CK_MECHANISM mech = { CKM_DES2_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &mech, tmpl, 6, &key_h);
        if (rv == CKR_OK)
            p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── ML-DSA key pair gen + sign + verify ──────────────────────────── */
    if (sel >= 44 && sel <= 46) {
        CK_ULONG parameterSet;
        switch (sel) {
        case 44: parameterSet = 1; break; /* ML-DSA-44 */
        case 45: parameterSet = 2; break; /* ML-DSA-65 */
        default: parameterSet = 3; break;  /* ML-DSA-87 */
        }

        CK_RV rv;
        CK_KEY_TYPE keyType = CKK_ML_DSA;
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_BYTE label[] = { 0x12, 0x34 };
        CK_BYTE id[] = { 123 };

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
            { CKA_LABEL, &label[0], sizeof(label) },
            { CKA_ID, &id[0], sizeof(id) },
            { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
            { CKA_VERIFY, &true_val, sizeof(true_val) },
            { CKA_ENCRYPT, &false_val, sizeof(false_val) },
            { CKA_WRAP, &false_val, sizeof(false_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
            { CKA_PRIVATE, &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_LABEL, &label[0], sizeof(label) },
            { CKA_ID, &id[0], sizeof(id) },
            { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_DECRYPT, &false_val, sizeof(false_val) },
            { CKA_UNWRAP, &false_val, sizeof(false_val) },
            { CKA_SENSITIVE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
            { CKA_PRIVATE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                     pub_tmpl, 9,
                                     priv_tmpl, 10,
                                     &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
            CK_BYTE sig[64 * 1024];
            CK_ULONG sig_len = sizeof(sig);

            CK_MECHANISM sign_mech = { CKM_ML_DSA, NULL_PTR, 0 };
            if (p11->C_SignInit(sess, &sign_mech, priv_h) == CKR_OK) {
                sig_len = sizeof(sig);
                rv = p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
            }

            if (rv == CKR_OK && sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, pub_h) == CKR_OK) {
                p11->C_Verify(sess, data_buf, 5, sig, sig_len);
            }

            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── DES3-CMAC generation (selector 47) ─────────────────────────────── */
    if (sel == 47) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES3;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype) },
            { CKA_SIGN,        &true_val,  sizeof(true_val) },
            { CKA_VERIFY,      &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, tmpl, 6, &key_h);
        if (rv == CKR_OK) {
            CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            CK_BYTE sig[64];
            CK_ULONG sig_len = sizeof(sig);

            CK_MECHANISM cmac_mech = { CKM_DES3_CMAC, NULL_PTR, 0 };
            if (p11->C_SignInit(sess, &cmac_mech, key_h) == CKR_OK) {
                sig_len = sizeof(sig);
                p11->C_Sign(sess, data_buf, 8, sig, &sig_len);
            }
            p11->C_DestroyObject(sess, key_h);
        }
        return 0;
    }

    /* ── DES3-CBC encrypt/decrypt (selector 48) ────────────────────────── */
    if (sel == 48) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES3;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE,  &true_val,  sizeof(true_val)  },
            { CKA_TOKEN,        &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 6, &key_h);
        if (rv != CKR_OK) return 0;

        CK_BYTE iv[8] = {0};
        CK_BYTE in[24] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                         0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        CK_BYTE out[32];
        CK_ULONG olen = sizeof(out);

        CK_MECHANISM enc_mech = { CKM_DES3_CBC, iv, sizeof(iv) };
        if (p11->C_EncryptInit(sess, &enc_mech, key_h) == CKR_OK) {
            olen = sizeof(out);
            rv = p11->C_Encrypt(sess, in, 24, out, &olen);
        }

        if (rv == CKR_OK && olen > 0) {
            CK_BYTE dec[24];
            CK_ULONG dlen = sizeof(dec);

            if (p11->C_DecryptInit(sess, &enc_mech, key_h) == CKR_OK) {
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }

        p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── DES ECB ENCRYPT_DATA derive (selector 49) ──────────────────────── */
    if (sel == 49) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DERIVE,      &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 7, &key_h);
        if (rv != CKR_OK) return 0;

        CK_BYTE derive_data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_KEY_DERIVATION_STRING_DATA params;
        params.pData = derive_data;
        params.ulLen = 16;

        CK_MECHANISM derive_mech = { CKM_DES_ECB_ENCRYPT_DATA, &params, sizeof(params) };
        CK_KEY_TYPE derived_ktype = CKK_DES;
        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_KEY_TYPE,    &derived_ktype, sizeof(derived_ktype) },
            { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        rv = p11->C_DeriveKey(sess, &derive_mech, key_h, derive_tmpl, 4, &derived_key);
        if (derived_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived_key);

        p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── DES CBC ENCRYPT_DATA derive (selector 50) ───────────────────────── */
    if (sel == 50) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DERIVE,      &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 7, &key_h);
        if (rv != CKR_OK) return 0;

        CK_BYTE derive_data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE iv[8] = {0};
        CK_DES_CBC_ENCRYPT_DATA_PARAMS params;
        params.iv[0] = iv[0]; params.iv[1] = iv[1]; params.iv[2] = iv[2]; params.iv[3] = iv[3];
        params.iv[4] = iv[4]; params.iv[5] = iv[5]; params.iv[6] = iv[6]; params.iv[7] = iv[7];
        params.pData = derive_data;
        params.length = 16;

        CK_MECHANISM derive_mech = { CKM_DES_CBC_ENCRYPT_DATA, &params, sizeof(params) };
        CK_KEY_TYPE derived_ktype = CKK_DES;
        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_KEY_TYPE,    &derived_ktype, sizeof(derived_ktype) },
            { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        rv = p11->C_DeriveKey(sess, &derive_mech, key_h, derive_tmpl, 4, &derived_key);
        if (derived_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived_key);

        p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── DES3 ECB ENCRYPT_DATA derive (selector 51) ─────────────────────── */
    if (sel == 51) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES3;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DERIVE,      &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 7, &key_h);
        if (rv != CKR_OK) return 0;

        CK_BYTE derive_data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_KEY_DERIVATION_STRING_DATA params;
        params.pData = derive_data;
        params.ulLen = 16;

        CK_MECHANISM derive_mech = { CKM_DES3_ECB_ENCRYPT_DATA, &params, sizeof(params) };
        CK_KEY_TYPE derived_ktype = CKK_DES3;
        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_KEY_TYPE,    &derived_ktype, sizeof(derived_ktype) },
            { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        rv = p11->C_DeriveKey(sess, &derive_mech, key_h, derive_tmpl, 4, &derived_key);
        if (derived_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived_key);

        p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── DES3 CBC ENCRYPT_DATA derive (selector 52) ─────────────────────── */
    if (sel == 52) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype  = CKK_DES3;

        CK_ATTRIBUTE gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype,     sizeof(ktype) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DECRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DERIVE,      &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech, gen_tmpl, 7, &key_h);
        if (rv != CKR_OK) return 0;

        CK_BYTE derive_data[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE iv[8] = {0};
        CK_DES_CBC_ENCRYPT_DATA_PARAMS params;
        params.iv[0] = iv[0]; params.iv[1] = iv[1]; params.iv[2] = iv[2]; params.iv[3] = iv[3];
        params.iv[4] = iv[4]; params.iv[5] = iv[5]; params.iv[6] = iv[6]; params.iv[7] = iv[7];
        params.pData = derive_data;
        params.length = 16;

        CK_MECHANISM derive_mech = { CKM_DES3_CBC_ENCRYPT_DATA, &params, sizeof(params) };
        CK_KEY_TYPE derived_ktype = CKK_DES3;
        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_KEY_TYPE,    &derived_ktype, sizeof(derived_ktype) },
            { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        rv = p11->C_DeriveKey(sess, &derive_mech, key_h, derive_tmpl, 4, &derived_key);
        if (derived_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived_key);

        p11->C_DestroyObject(sess, key_h);
        return 0;
    }

    /* ── AES ECB ENCRYPT_DATA derive (selector 53) ───────────────────────── */
    if (sel == 53) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype = CKK_AES;

        CK_ATTRIBUTE aes_gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype, sizeof(ktype) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DERIVE,      &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };
        CK_MECHANISM aes_gen_mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
        CK_RV rv = p11->C_GenerateKey(sess, &aes_gen_mech, aes_gen_tmpl, 6, &base_key);
        if (rv != CKR_OK) return 0;

        CK_BYTE derive_data[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
        CK_KEY_DERIVATION_STRING_DATA params;
        params.pData = derive_data;
        params.ulLen = 32;

        CK_MECHANISM derive_mech = { CKM_AES_ECB_ENCRYPT_DATA, &params, sizeof(params) };
        CK_KEY_TYPE derived_ktype = CKK_AES;
        CK_ULONG keylen = 16;
        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_KEY_TYPE,    &derived_ktype, sizeof(derived_ktype) },
            { CKA_VALUE_LEN,  &keylen, sizeof(keylen) },
            { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        rv = p11->C_DeriveKey(sess, &derive_mech, base_key, derive_tmpl, 5, &derived_key);
        if (derived_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived_key);

        p11->C_DestroyObject(sess, base_key);
        return 0;
    }

    /* ── AES CBC ENCRYPT_DATA derive (selector 54) ──────────────────────── */
    if (sel == 54) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_KEY_TYPE ktype = CKK_AES;

        CK_ATTRIBUTE aes_gen_tmpl[] = {
            { CKA_KEY_TYPE,    &ktype, sizeof(ktype) },
            { CKA_ENCRYPT,     &true_val,  sizeof(true_val) },
            { CKA_DERIVE,      &true_val,  sizeof(true_val) },
            { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };
        CK_MECHANISM aes_gen_mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE base_key = CK_INVALID_HANDLE;
        CK_RV rv = p11->C_GenerateKey(sess, &aes_gen_mech, aes_gen_tmpl, 6, &base_key);
        if (rv != CKR_OK) return 0;

        CK_BYTE derive_data[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
        CK_BYTE iv[16] = {0};
        CK_AES_CBC_ENCRYPT_DATA_PARAMS params;
        params.iv[0] = iv[0]; /* rest is zero-initialized */
        params.pData = derive_data;
        params.length = 32;

        CK_MECHANISM derive_mech = { CKM_AES_CBC_ENCRYPT_DATA, &params, sizeof(params) };
        CK_KEY_TYPE derived_ktype = CKK_AES;
        CK_ULONG keylen = 16;
        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_KEY_TYPE,    &derived_ktype, sizeof(derived_ktype) },
            { CKA_VALUE_LEN,  &keylen, sizeof(keylen) },
            { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
            { CKA_TOKEN,       &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        rv = p11->C_DeriveKey(sess, &derive_mech, base_key, derive_tmpl, 5, &derived_key);
        if (derived_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived_key);

        p11->C_DestroyObject(sess, base_key);
        return 0;
    }

    /* ── GOSTR3410 key pair gen + sign + verify (selector 55) ───────────── */
    if (sel == 55) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_BYTE gost_3410_params[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
        CK_BYTE gost_3411_params[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_GOSTR3410_PARAMS, gost_3410_params, sizeof(gost_3410_params) },
            { CKA_GOSTR3411_PARAMS, gost_3411_params, sizeof(gost_3411_params) },
            { CKA_VERIFY, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl, 4,
                                           priv_tmpl, 4,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
            CK_BYTE sig[64];
            CK_ULONG sig_len = sizeof(sig);

            CK_MECHANISM sign_mech = { CKM_GOSTR3410, NULL_PTR, 0 };
            if (p11->C_SignInit(sess, &sign_mech, priv_h) == CKR_OK) {
                sig_len = sizeof(sig);
                p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
            }

            if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, pub_h) == CKR_OK) {
                p11->C_Verify(sess, data_buf, 5, sig, sig_len);
            }

            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── GOSTR3410 sign/verify with pre-generated key (selector 56) ─────── */
    if (sel == 56) {
        if (ec_priv == CK_INVALID_HANDLE || ec_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[64];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_GOSTR3410, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, ec_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, ec_pub) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ── GOSTR3411 digest (selector 57) ─────────────────────────────────── */
    if (sel == 57) {
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE hash[32];
        CK_ULONG hlen = sizeof(hash);

        CK_MECHANISM digest_mech = { CKM_GOSTR3411, NULL_PTR, 0 };
        if (p11->C_DigestInit(sess, &digest_mech) == CKR_OK) {
            hlen = sizeof(hash);
            p11->C_Digest(sess, data_buf, sizeof(data_buf), hash, &hlen);
        }
        return 0;
    }

    /* ── GOSTR3411_HMAC sign/verify (selector 58) ──────────────────────── */
    if (sel == 58) {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        CK_BYTE sig[32];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM hmac_mech = { CKM_GOSTR3411_HMAC, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, sizeof(data_buf), sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &hmac_mech, hmac_key) == CKR_OK) {
            p11->C_Verify(sess, data_buf, sizeof(data_buf), sig, sig_len);
        }
        return 0;
    }

    /* ── ECDSA- SHA1 sign/verify (selector 59) ──────────────────────────── */
    if (sel == 59) {
        if (ec_priv == CK_INVALID_HANDLE || ec_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[128];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_ECDSA_SHA1, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, ec_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, ec_pub) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ── ECDSA-SHA224 sign/verify (selector 60) ─────────────────────────── */
    if (sel == 60) {
        if (ec_priv == CK_INVALID_HANDLE || ec_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[128];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_ECDSA_SHA224, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, ec_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, ec_pub) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ── ECDSA-SHA256 sign/verify (selector 61) ─────────────────────────── */
    if (sel == 61) {
        if (ec_priv == CK_INVALID_HANDLE || ec_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[128];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_ECDSA_SHA256, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, ec_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, ec_pub) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ── ECDSA-SHA384 sign/verify (selector 62) ─────────────────────────── */
    if (sel == 62) {
        if (ec_priv == CK_INVALID_HANDLE || ec_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[128];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_ECDSA_SHA384, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, ec_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, ec_pub) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /* ── ECDSA-SHA512 sign/verify (selector 63) ─────────────────────────── */
    if (sel == 63) {
        if (ec_priv == CK_INVALID_HANDLE || ec_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        CK_BYTE sig[128];
        CK_ULONG sig_len = sizeof(sig);

        CK_MECHANISM sign_mech = { CKM_ECDSA_SHA512, NULL_PTR, 0 };
        if (p11->C_SignInit(sess, &sign_mech, ec_priv) == CKR_OK) {
            sig_len = sizeof(sig);
            p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
        }

        if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, ec_pub) == CKR_OK) {
            p11->C_Verify(sess, data_buf, 5, sig, sig_len);
        }
        return 0;
    }

    /*  65  RSA-X.509 encrypt/decrypt (token rsa_pub/rsa_priv)
     *  66  AES-KEY-WRAP encrypt/decrypt (token aes_key)
     *  67  AES-KEY-WRAP-PAD encrypt/decrypt (token aes_key)
     *  68  DSA key pair gen + DSA-SHA256 sign + verify
     *  69  CONCATENATE_BASE_AND_DATA derive
     *  */

    /* ── AES-CBC-PAD encrypt/decrypt (selector 64) ─────────────────────── */
    if (sel == 64) {
        if (aes_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE iv[16] = {0};
        CK_BYTE in[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                           0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                           0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
        CK_BYTE out[64];
        CK_ULONG olen = sizeof(out);

        CK_MECHANISM enc_mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
        if (p11->C_EncryptInit(sess, &enc_mech, aes_key) == CKR_OK) {
            olen = sizeof(out);
            p11->C_Encrypt(sess, in, 32, out, &olen);
        }

        if (olen > 0) {
            CK_MECHANISM dec_mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
            if (p11->C_DecryptInit(sess, &dec_mech, aes_key) == CKR_OK) {
                CK_BYTE dec[32];
                CK_ULONG dlen = sizeof(dec);
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }
        return 0;
    }

    /* ── RSA-X.509 encrypt/decrypt (selector 65) ────────────────────────── */
    if (sel == 65) {
        if (rsa_priv == CK_INVALID_HANDLE || rsa_pub == CK_INVALID_HANDLE) return 0;
        CK_BYTE in[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                          0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                          0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
        CK_BYTE out[256];
        CK_ULONG olen = sizeof(out);

        CK_MECHANISM enc_mech = { CKM_RSA_X_509, NULL_PTR, 0 };
        if (p11->C_EncryptInit(sess, &enc_mech, rsa_pub) == CKR_OK) {
            olen = sizeof(out);
            p11->C_Encrypt(sess, in, 32, out, &olen);
        }

        if (olen > 0) {
            CK_BYTE dec[32];
            CK_ULONG dlen = sizeof(dec);
            if (p11->C_DecryptInit(sess, &enc_mech, rsa_priv) == CKR_OK) {
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }
        return 0;
    }

    /* ── AES-KEY-WRAP encrypt/decrypt (selector 66) ─────────────────────── */
    if (sel == 66) {
        if (aes_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE in[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                          0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                          0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
        CK_BYTE out[48];
        CK_ULONG olen = sizeof(out);

        CK_MECHANISM wrap_mech = { CKM_AES_KEY_WRAP, NULL_PTR, 0 };
        if (p11->C_EncryptInit(sess, &wrap_mech, aes_key) == CKR_OK) {
            olen = sizeof(out);
            p11->C_Encrypt(sess, in, 32, out, &olen);
        }

        if (olen > 0) {
            CK_BYTE dec[32];
            CK_ULONG dlen = sizeof(dec);
            if (p11->C_DecryptInit(sess, &wrap_mech, aes_key) == CKR_OK) {
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }
        return 0;
    }

    /* ── AES-KEY-WRAP-PAD encrypt/decrypt (selector 67) ────────────────── */
    if (sel == 67) {
        if (aes_key == CK_INVALID_HANDLE) return 0;
        CK_BYTE in[33] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                          0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                          0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                          0x21};
        CK_BYTE out[56];
        CK_ULONG olen = sizeof(out);

        CK_MECHANISM wrap_mech = { CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0 };
        if (p11->C_EncryptInit(sess, &wrap_mech, aes_key) == CKR_OK) {
            olen = sizeof(out);
            p11->C_Encrypt(sess, in, 33, out, &olen);
        }

        if (olen > 0) {
            CK_BYTE dec[33];
            CK_ULONG dlen = sizeof(dec);
            if (p11->C_DecryptInit(sess, &wrap_mech, aes_key) == CKR_OK) {
                p11->C_Decrypt(sess, out, olen, dec, &dlen);
            }
        }
        return 0;
    }

    /* ── DSA key pair gen + DSA-SHA256 sign + verify (selector 68) ─────── */
    if (sel == 68) {
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;
        CK_ULONG bits = 1024;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_PRIME_BITS, &bits, sizeof(bits) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_SIGN, &true_val, sizeof(true_val) },
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };

        CK_MECHANISM key_gen_mech = { CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
        CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, priv_h = CK_INVALID_HANDLE;

        CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                           pub_tmpl, 2,
                                           priv_tmpl, 4,
                                           &pub_h, &priv_h);
        if (rv == CKR_OK) {
            CK_BYTE data_buf[] = {0x01, 0x02, 0x03, 0x04, 0x05};
            CK_BYTE sig[40];
            CK_ULONG sig_len = sizeof(sig);

            CK_MECHANISM sign_mech = { CKM_DSA_SHA256, NULL_PTR, 0 };
            if (p11->C_SignInit(sess, &sign_mech, priv_h) == CKR_OK) {
                sig_len = sizeof(sig);
                p11->C_Sign(sess, data_buf, 5, sig, &sig_len);
            }

            if (sig_len > 0 && p11->C_VerifyInit(sess, &sign_mech, pub_h) == CKR_OK) {
                p11->C_Verify(sess, data_buf, 5, sig, sig_len);
            }

            p11->C_DestroyObject(sess, pub_h);
            p11->C_DestroyObject(sess, priv_h);
        }
        return 0;
    }

    /* ── CONCATENATE_BASE_AND_DATA derive (selector 69) ────────────────── */
    if (sel == 69) {
        if (ec_priv == CK_INVALID_HANDLE) return 0;
        CK_BBOOL true_val  = CK_TRUE;
        CK_BBOOL false_val = CK_FALSE;

        CK_BYTE shared_data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

        CK_MECHANISM derive_mech = { CKM_CONCATENATE_BASE_AND_DATA, shared_data, sizeof(shared_data) };
        CK_KEY_TYPE derived_ktype = CKK_GENERIC_SECRET;
        CK_ATTRIBUTE derive_tmpl[] = {
            { CKA_KEY_TYPE, &derived_ktype, sizeof(derived_ktype) },
            { CKA_SENSITIVE, &false_val, sizeof(false_val) },
            { CKA_EXTRACTABLE, &true_val, sizeof(true_val) },
            { CKA_TOKEN, &false_val, sizeof(false_val) },
        };

        CK_OBJECT_HANDLE derived_key = CK_INVALID_HANDLE;
        CK_RV rv = p11->C_DeriveKey(sess, &derive_mech, ec_priv,
                                      derive_tmpl, 4, &derived_key);
        if (derived_key != CK_INVALID_HANDLE)
            p11->C_DestroyObject(sess, derived_key);
        return 0;
    }

    return 0;
}
