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
 * RSA key sizes are capped at 1024 bits to keep throughput reasonable
 * (1024-bit RSA keygen takes ~5 ms; 2048-bit takes ~50 ms).  EC and AES
 * generation is fast at any supported size.
 *
 * Input layout:
 *   byte 0:  key type / operation selector (0–9)
 *   byte 1+: additional attribute bytes (interpreted per selector)
 *
 * Selectors:
 *   0  RSA-512  GenerateKeyPair
 *   1  RSA-768  GenerateKeyPair
 *   2  RSA-1024 GenerateKeyPair (use byte 1..2 as public exponent high bytes)
 *   3  EC P-256 GenerateKeyPair
 *   4  EC P-384 GenerateKeyPair
 *   5  EC P-521 GenerateKeyPair
 *   6  AES-128  GenerateKey
 *   7  AES-192  GenerateKey
 *   8  AES-256  GenerateKey
 *   9  AES with key length from fuzz byte (to hit boundary validation)
 */
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

/* EC OIDs for GenerateKeyPair: the curve is specified via CKA_EC_PARAMS
 * which is DER-encoded OID of the named curve. */
static const CK_BYTE OID_P256[] = {
    0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07
};
static const CK_BYTE OID_P384[] = {
    0x06,0x05,0x2b,0x81,0x04,0x00,0x22
};
static const CK_BYTE OID_P521[] = {
    0x06,0x05,0x2b,0x81,0x04,0x00,0x23
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    uint8_t sel = data[0] % 10;

    /* ── RSA key pair generation ─────────────────────────────────────────── */
    if (sel <= 2) {
        CK_ULONG bits;
        switch (sel) {
        case 0: bits = 512;  break;
        case 1: bits = 768;  break;
        default: bits = 1024; break;
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
    if (sel >= 3 && sel <= 5) {
        const CK_BYTE *oid;
        CK_ULONG oid_len;
        switch (sel) {
        case 3: oid = OID_P256; oid_len = sizeof(OID_P256); break;
        case 4: oid = OID_P384; oid_len = sizeof(OID_P384); break;
        default: oid = OID_P521; oid_len = sizeof(OID_P521); break;
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

        CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
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
    {
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
    }

    return 0;
}
