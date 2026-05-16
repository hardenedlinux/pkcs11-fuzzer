/*
 * pkcs11_multipart_fuzz.c — Fuzz multi-part sign/verify/encrypt/decrypt.
 *
 * Single-operation harnesses reach the top-level PKCS#11 dispatch.  This
 * harness exercises the stateful streaming API (Init → Update × N → Final)
 * which goes through a different code path in SoftHSM2 — specifically the
 * per-session active-operation state machine and the incremental buffering
 * in the crypto backend.
 *
 * Input layout:
 *   byte 0:  operation selector (0–51, see table)
 *   byte 1:  number of Update chunks (1–8)
 *   byte 2+: payload data — divided evenly across chunks
 *
 * Operations:
 *   0  C_SignInit(RSA-PKCS1-SHA256)    + C_SignUpdate × N + C_SignFinal
 *   1  C_SignInit(RSA-PSS-SHA256)      + C_SignUpdate × N + C_SignFinal
 *   2  C_SignInit(ECDSA-SHA256)        + C_SignUpdate × N + C_SignFinal
 *   3  C_SignInit(RSA-PKCS1-SHA1)      + C_SignUpdate × N + C_SignFinal
 *   4  C_VerifyInit(RSA-PKCS1-SHA256)  + C_VerifyUpdate × N + C_VerifyFinal
 *   5  C_VerifyInit(ECDSA-SHA256)      + C_VerifyUpdate × N + C_VerifyFinal
 *   6  C_EncryptInit(AES-CBC)          + C_EncryptUpdate × N + C_EncryptFinal
 *   7  C_DecryptInit(AES-CBC-PAD)      + C_EncryptUpdate × N + C_EncryptFinal
 *   8  C_EncryptInit(AES-GCM)          + C_EncryptUpdate × N + C_EncryptFinal
 *   9  C_DecryptInit(AES-GCM)          + C_EncryptUpdate × N + C_EncryptFinal
 *  10  C_SignInit(EdDSA-Ed25519)       + C_SignUpdate × N + C_SignFinal
 *  11  C_VerifyInit(EdDSA-Ed25519)     + C_VerifyUpdate × N + C_VerifyFinal
 *  12  C_SignInit(SHA256-HMAC)         + C_SignUpdate × N + C_SignFinal
 *  13  C_SignInit(SHA256-HMAC) verify  + C_SignUpdate × N + C_SignFinal
 *  14  C_SignInit(RSA-PKCS1-SHA224)    + C_SignUpdate × N + C_SignFinal
 *  15  C_SignInit(RSA-PSS-SHA224)      + C_SignUpdate × N + C_SignFinal
 *  16  C_SignInit(DSA-SHA224)          + C_SignUpdate × N + C_SignFinal
 *  17  C_SignInit(DSA-SHA256)          + C_SignUpdate × N + C_SignFinal
 *  18  C_SignInit(DSA-SHA384)          + C_SignUpdate × N + C_SignFinal
 *  19  C_SignInit(DSA-SHA512)          + C_SignUpdate × N + C_SignFinal
 *  20  C_SignInit(RSA-PKCS1-SHA384)   + C_SignUpdate × N + C_SignFinal
 *  21  C_SignInit(RSA-PKCS1-SHA512)   + C_SignUpdate × N + C_SignFinal
 *  22  C_SignInit(RSA-PSS-SHA384)     + C_SignUpdate × N + C_SignFinal
 *  23  C_SignInit(RSA-PSS-SHA512)     + C_SignUpdate × N + C_SignFinal
 *  24  C_EncryptInit(DES3-CBC-PAD)    + C_EncryptUpdate × N + C_EncryptFinal
 *  25  C_DecryptInit(DES3-CBC-PAD)    + C_EncryptUpdate × N + C_EncryptFinal
 *  26  C_SignInit(DSA-SHA1)           + C_SignUpdate × N + C_SignFinal
 *  27  C_EncryptInit(AES-CTR)         + C_EncryptUpdate × N + C_EncryptFinal
 *  28  C_DecryptInit(AES-CTR)        + C_EncryptUpdate × N + C_EncryptFinal
 *  29  C_EncryptInit(AES-ECB)         + C_EncryptUpdate × N + C_EncryptFinal
 *  30  C_DecryptInit(AES-ECB)        + C_EncryptUpdate × N + C_EncryptFinal
 *  31  C_SignInit(RSA-X_509)          + C_SignUpdate × N + C_SignFinal
 *  32  C_VerifyInit(RSA-X_509)        + C_VerifyUpdate × N + C_VerifyFinal
 *  33  C_EncryptInit(AES-CTR, ulCounterBits=0)  -> CKR_MECHANISM_PARAM_INVALID
 *  34  C_EncryptInit(AES-CTR, ulCounterBits=200) -> CKR_MECHANISM_PARAM_INVALID
 *  35  C_EncryptInit(AES-GCM, ulTagBits=1)       -> CKR_ARGUMENTS_BAD
 *  36  C_EncryptInit(AES-GCM, ulTagBits=200)      -> CKR_ARGUMENTS_BAD
 *  37  C_SignInit(ECDSA-SHA384)         + C_SignUpdate × N + C_SignFinal
 *  38  C_SignInit(ECDSA-SHA512)         + C_SignUpdate × N + C_SignFinal
 *  39  C_EncryptInit(DES3-ECB)         + C_EncryptUpdate × N + C_EncryptFinal
 *  40  C_DecryptInit(DES3-ECB)        + C_EncryptUpdate × N + C_EncryptFinal
 *  41  C_EncryptInit(DES3-CBC)         + C_EncryptUpdate × N + C_EncryptFinal
 *  42  C_DecryptInit(DES3-CBC)        + C_EncryptUpdate × N + C_EncryptFinal
 *  43  C_EncryptInit(AES-CBC-PAD)      + C_EncryptUpdate × N + C_EncryptFinal
 *  44  C_SignInit(SHA1-HMAC)           + C_SignUpdate × N + C_SignFinal
 *  45  C_VerifyInit(SHA1-HMAC)        + C_VerifyUpdate × N + C_VerifyFinal
 *  46  C_SignInit(SHA224-HMAC)        + C_SignUpdate × N + C_SignFinal
 *  47  C_VerifyInit(SHA224-HMAC)      + C_VerifyUpdate × N + C_VerifyFinal
 *  48  C_SignInit(SHA384-HMAC)        + C_SignUpdate × N + C_SignFinal
 *  49  C_VerifyInit(SHA384-HMAC)      + C_VerifyUpdate × N + C_VerifyFinal
 *  50  C_SignInit(SHA512-HMAC)        + C_SignUpdate × N + C_SignFinal
 *  51  C_VerifyInit(SHA512-HMAC)      + C_VerifyUpdate × N + C_VerifyFinal
 *
 * For verify operations (4–5, 11, 13, 32, 45, 47, 49, 51) we sign the data first with a real key so the
 * signature format is valid — this exercises the actual verification logic
 * rather than bailing out early on a bad signature header.  The fuzz payload
 * is still used as the message, so variations in message content influence
 * the hash computation path.
 *
 * EdDSA (selectors 10–11) is a pureEdDSA signature algorithm using
 * Curve25519/Ed25519 - it does not use a hash function, unlike RSA-PSS
 * or ECDSA which use SHA-256/SHA-1. This exercises distinct code paths.
 *
 * DES3-CBC-PAD (selectors 24–25) exercises the Triple-DES cipher with
 * CBC mode and PKCS#7 padding, a distinct code path from AES-CBC-PAD.
 *
 * DES3-ECB (selectors 39–40) exercises Triple-DES in ECB mode - a
 * distinct code path from CBC mode (no chaining, no padding).
 *
 * DES3-CBC (selectors 41–42) exercises Triple-DES in CBC mode without
 * padding - a distinct code path from CBC-PAD.
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

/* Helper: sign data and return a heap-allocated signature (caller frees). */
static CK_BYTE *make_signature(CK_MECHANISM_TYPE mtype,
                                CK_OBJECT_HANDLE  key,
                                CK_MECHANISM_PTR  extra_mech,
                                const uint8_t    *data,
                                size_t            dlen,
                                CK_ULONG         *siglen_out)
{
    CK_MECHANISM mech = { mtype, NULL_PTR, 0 };
    if (extra_mech) mech = *extra_mech;
    else            mech.mechanism = mtype;

    if (p11->C_SignInit(sess, &mech, key) != CKR_OK) return NULL;

    CK_BYTE  tmp[512];
    CK_ULONG slen = sizeof(tmp);
    if (p11->C_Sign(sess, (CK_BYTE_PTR)data, (CK_ULONG)dlen, tmp, &slen) != CKR_OK)
        return NULL;

    CK_BYTE *sig = (CK_BYTE *)malloc(slen);
    if (sig) { memcpy(sig, tmp, slen); *siglen_out = slen; }
    return sig;
}

/* DSA key pair cached for multipart operations */
static CK_OBJECT_HANDLE dsa_pub = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE dsa_priv = CK_INVALID_HANDLE;

static void ensure_dsa_keys(void)
{
    if (dsa_priv != CK_INVALID_HANDLE) return;

    CK_BBOOL true_val  = CK_TRUE;
    CK_BBOOL false_val = CK_FALSE;
    CK_ULONG bits = 1024;

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_PRIME_BITS, &bits, sizeof(bits) },
        { CKA_TOKEN,      &false_val, sizeof(false_val) },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_SIGN,       &true_val,  sizeof(true_val) },
        { CKA_SENSITIVE,  &false_val, sizeof(false_val) },
        { CKA_EXTRACTABLE, &true_val,  sizeof(true_val) },
        { CKA_TOKEN,      &false_val, sizeof(false_val) },
    };

    CK_MECHANISM key_gen_mech = { CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_RV rv = p11->C_GenerateKeyPair(sess, &key_gen_mech,
                                       pub_tmpl, 2,
                                       priv_tmpl, 4,
                                       &dsa_pub, &dsa_priv);
    if (rv != CKR_OK) {
        dsa_priv = CK_INVALID_HANDLE;
        dsa_pub = CK_INVALID_HANDLE;
    }
}

/* DES3 key cached for multipart operations */
static CK_OBJECT_HANDLE des3_key = CK_INVALID_HANDLE;

static void ensure_des3_key(void)
{
    if (des3_key != CK_INVALID_HANDLE) return;

    CK_BBOOL true_val  = CK_TRUE;
    CK_BBOOL false_val = CK_FALSE;
    CK_KEY_TYPE ktype = CKK_DES3;

    CK_ATTRIBUTE gen_tmpl[] = {
        { CKA_KEY_TYPE,    &ktype,     sizeof(ktype)     },
        { CKA_ENCRYPT,     &true_val,  sizeof(true_val)  },
        { CKA_DECRYPT,     &true_val,  sizeof(true_val)  },
        { CKA_SENSITIVE,   &false_val, sizeof(false_val) },
        { CKA_EXTRACTABLE, &true_val,  sizeof(true_val)  },
        { CKA_TOKEN,       &false_val, sizeof(false_val) },
    };

    CK_MECHANISM key_gen_mech = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
    CK_RV rv = p11->C_GenerateKey(sess, &key_gen_mech,
                                   gen_tmpl, 6, &des3_key);
    if (rv != CKR_OK) {
        des3_key = CK_INVALID_HANDLE;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;

    uint8_t sel     = data[0] % 52;
    uint8_t nchunks = (data[1] % 8) + 1;   /* 1–8 */

    const uint8_t *pay  = (size > 2) ? data + 2 : (const uint8_t *)"";
    size_t         plen = (size > 2) ? size - 2 : 0;

    /* Chunk the payload */
    size_t chunk = (plen > 0 && nchunks > 0)
                   ? (plen + nchunks - 1) / nchunks : 0;

    CK_MECHANISM mech = { 0, NULL_PTR, 0 };
    CK_RSA_PKCS_PSS_PARAMS pss = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_RSA_PKCS_PSS_PARAMS pss224 = { CKM_SHA224, CKG_MGF1_SHA224, 28 };
    CK_RSA_PKCS_PSS_PARAMS pss384 = { CKM_SHA384, CKG_MGF1_SHA384, 48 };
    CK_RSA_PKCS_PSS_PARAMS pss512 = { CKM_SHA512, CKG_MGF1_SHA512, 64 };
    CK_BYTE iv[16]   = {0};
    CK_BYTE gcm_iv[12] = {0};
    CK_GCM_PARAMS gcm  = {0};
    CK_BYTE des3_iv[8] = {0};
    CK_AES_CTR_PARAMS ctr_params;
    memset(&ctr_params, 0, sizeof(ctr_params));
    ctr_params.ulCounterBits = 64;
    CK_BYTE ctr_cb[16] = {0};

    /* IV bytes come from the last bytes of the payload to keep mutation useful */
    if (plen >= 16) memcpy(iv,     pay + plen - 16, 16);
    if (plen >= 12) memcpy(gcm_iv, pay + plen - 12, 12);
    if (plen >= 8)  memcpy(des3_iv, pay + plen - 8, 8);
    if (plen >= 12) memcpy(gcm_iv, pay + plen - 12, 12);
    if (plen >= 16) memcpy(ctr_cb, pay + plen - 16, 16);
    gcm.pIv = gcm_iv; gcm.ulIvLen = 12; gcm.ulIvBits = 96; gcm.ulTagBits = 128;
    memcpy(ctr_params.cb, ctr_cb, 16);

    switch (sel) {

    /* ── Multi-part Sign ─────────────────────────────────────────────────── */
    case 0:
        mech.mechanism = CKM_SHA256_RSA_PKCS;
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;
    case 1:
        mech.mechanism      = CKM_SHA256_RSA_PKCS_PSS;
        mech.pParameter     = &pss;
        mech.ulParameterLen = sizeof(pss);
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;
    case 2:
        mech.mechanism = CKM_ECDSA_SHA256;
        if (ec_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, ec_priv) != CKR_OK) return 0;
        goto do_sign_update;
    case 3:
        mech.mechanism = CKM_SHA1_RSA_PKCS;
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;

    do_sign_update: {
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[512];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part Verify ───────────────────────────────────────────────── */
    case 4: {
        /* Sign to get a real signature, then verify multi-part */
        CK_ULONG slen = 0;
        if (rsa_pub == CK_INVALID_HANDLE || rsa_priv == CK_INVALID_HANDLE) return 0;
        CK_BYTE *sig = make_signature(CKM_SHA256_RSA_PKCS, rsa_priv, NULL,
                                      pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_SHA256_RSA_PKCS;
        if (p11->C_VerifyInit(sess, &mech, rsa_pub) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }
    case 5: {
        CK_ULONG slen = 0;
        if (ec_pub == CK_INVALID_HANDLE || ec_priv == CK_INVALID_HANDLE) return 0;
        CK_BYTE *sig = make_signature(CKM_ECDSA_SHA256, ec_priv, NULL,
                                      pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_ECDSA_SHA256;
        if (p11->C_VerifyInit(sess, &mech, ec_pub) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    /* ── Multi-part Encrypt (AES-CBC) ─────────────────────────────────────── */
    case 6:
        mech.mechanism      = CKM_AES_CBC_PAD;
        mech.pParameter     = iv;
        mech.ulParameterLen = 16;
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_EncryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Decrypt (AES-CBC) ─────────────────────────────────────── */
    case 7:
        mech.mechanism      = CKM_AES_CBC_PAD;
        mech.pParameter     = iv;
        mech.ulParameterLen = 16;
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_DecryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_DecryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_DecryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Encrypt (AES-GCM) ─────────────────────────────────────── */
    case 8:
        mech.mechanism      = CKM_AES_GCM;
        mech.pParameter     = &gcm;
        mech.ulParameterLen = sizeof(gcm);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_EncryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Decrypt (AES-GCM) ─────────────────────────────────────── */
    case 9:
        mech.mechanism      = CKM_AES_GCM;
        mech.pParameter     = &gcm;
        mech.ulParameterLen = sizeof(gcm);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_DecryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_DecryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_DecryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Sign (EdDSA-Ed25519) ─────────────────────────────────── */
    case 10: {
        mech.mechanism = CKM_EDDSA;
        if (ed_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, ed_priv) != CKR_OK) return 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[64];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part Verify (EdDSA-Ed25519) ───────────────────────────────── */
    case 11: {
        if (ed_pub == CK_INVALID_HANDLE || ed_priv == CK_INVALID_HANDLE) return 0;
        CK_ULONG slen = 0;
        CK_BYTE *sig = make_signature(CKM_EDDSA, ed_priv, NULL, pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_EDDSA;
        if (p11->C_VerifyInit(sess, &mech, ed_pub) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    /* ── Multi-part HMAC Sign (SHA256-HMAC) ─────────────────────────────── */
    case 12: {
        mech.mechanism = CKM_SHA256_HMAC;
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, hmac_key) != CKR_OK) return 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[64];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part HMAC Verify (SHA256-HMAC) ──────────────────────────── */
    case 13: {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_ULONG slen = 0;
        CK_BYTE *sig = make_signature(CKM_SHA256_HMAC, hmac_key, NULL,
                                      pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_SHA256_HMAC;
        if (p11->C_VerifyInit(sess, &mech, hmac_key) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    /* ── Multi-part Sign RSA-PKCS-SHA224 ────────────────────────────── */
    case 14:
        mech.mechanism = CKM_SHA224_RSA_PKCS;
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;

    /* ── Multi-part Sign RSA-PSS-SHA224 ─────────────────────────────── */
    case 15:
        mech.mechanism      = CKM_SHA224_RSA_PKCS_PSS;
        mech.pParameter     = &pss224;
        mech.ulParameterLen = sizeof(pss224);
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;

    /* ── Multi-part Sign DSA-SHA224 ────────────────────────────── */
    case 16: {
        ensure_dsa_keys();
        if (dsa_priv == CK_INVALID_HANDLE) return 0;
        mech.mechanism = CKM_DSA_SHA224;
        if (p11->C_SignInit(sess, &mech, dsa_priv) != CKR_OK) return 0;
        goto do_sign_update;
    }

    /* ── Multi-part Sign DSA-SHA256 ────────────────────────────── */
    case 17: {
        ensure_dsa_keys();
        if (dsa_priv == CK_INVALID_HANDLE) return 0;
        mech.mechanism = CKM_DSA_SHA256;
        if (p11->C_SignInit(sess, &mech, dsa_priv) != CKR_OK) return 0;
        goto do_sign_update;
    }

    /* ── Multi-part Sign DSA-SHA384 ────────────────────────────── */
    case 18: {
        ensure_dsa_keys();
        if (dsa_priv == CK_INVALID_HANDLE) return 0;
        mech.mechanism = CKM_DSA_SHA384;
        if (p11->C_SignInit(sess, &mech, dsa_priv) != CKR_OK) return 0;
        goto do_sign_update;
    }

    /* ── Multi-part Sign DSA-SHA512 ────────────────────────────── */
    case 19: {
        ensure_dsa_keys();
        if (dsa_priv == CK_INVALID_HANDLE) return 0;
        mech.mechanism = CKM_DSA_SHA512;
        if (p11->C_SignInit(sess, &mech, dsa_priv) != CKR_OK) return 0;
        goto do_sign_update;
    }

    /* ── Multi-part Sign RSA-PKCS-SHA384 ───────────────────────── */
    case 20:
        mech.mechanism = CKM_SHA384_RSA_PKCS;
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;

    /* ── Multi-part Sign RSA-PKCS-SHA512 ───────────────────────── */
    case 21:
        mech.mechanism = CKM_SHA512_RSA_PKCS;
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;

    /* ── Multi-part Sign RSA-PSS-SHA384 ───────────────────────── */
    case 22:
        mech.mechanism      = CKM_SHA384_RSA_PKCS_PSS;
        mech.pParameter     = &pss384;
        mech.ulParameterLen = sizeof(pss384);
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;

    /* ── Multi-part Sign RSA-PSS-SHA512 ───────────────────────── */
    case 23:
        mech.mechanism      = CKM_SHA512_RSA_PKCS_PSS;
        mech.pParameter     = &pss512;
        mech.ulParameterLen = sizeof(pss512);
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        goto do_sign_update;

    /* ── Multi-part Encrypt (DES3-CBC-PAD) ─────────────────── */
    case 24:
        ensure_des3_key();
        if (des3_key == CK_INVALID_HANDLE) return 0;
        mech.mechanism      = CKM_DES3_CBC_PAD;
        mech.pParameter     = des3_iv;
        mech.ulParameterLen = 8;
        if (p11->C_EncryptInit(sess, &mech, des3_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Decrypt (DES3-CBC-PAD) ─────────────────── */
    case 25:
        ensure_des3_key();
        if (des3_key == CK_INVALID_HANDLE) return 0;
        mech.mechanism      = CKM_DES3_CBC_PAD;
        mech.pParameter     = des3_iv;
        mech.ulParameterLen = 8;
        if (p11->C_DecryptInit(sess, &mech, des3_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_DecryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_DecryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Sign (DSA-SHA1) ─────────────────────────────── */
    case 26: {
        ensure_dsa_keys();
        if (dsa_priv == CK_INVALID_HANDLE) return 0;
        mech.mechanism = CKM_DSA_SHA1;
        if (p11->C_SignInit(sess, &mech, dsa_priv) != CKR_OK) return 0;
        goto do_sign_update;
    }

    /* ── Multi-part Encrypt (AES-CTR) ─────────────────────────── */
    case 27:
        mech.mechanism      = CKM_AES_CTR;
        mech.pParameter     = &ctr_params;
        mech.ulParameterLen = sizeof(ctr_params);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_EncryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Decrypt (AES-CTR) ─────────────────────────── */
    case 28:
        mech.mechanism      = CKM_AES_CTR;
        mech.pParameter     = &ctr_params;
        mech.ulParameterLen = sizeof(ctr_params);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_DecryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_DecryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_DecryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Encrypt (AES-ECB) ─────────────────────────── */
    case 29:
        mech.mechanism      = CKM_AES_ECB;
        mech.pParameter     = NULL_PTR;
        mech.ulParameterLen = 0;
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_EncryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Decrypt (AES-ECB) ─────────────────────────── */
    case 30:
        mech.mechanism      = CKM_AES_ECB;
        mech.pParameter     = NULL_PTR;
        mech.ulParameterLen = 0;
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_DecryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_DecryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_DecryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Sign (RSA-X_509) ─────────────────────────── */
    case 31: {
        mech.mechanism = CKM_RSA_X_509;
        if (rsa_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, rsa_priv) != CKR_OK) return 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[512];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part Verify (RSA-X_509) ───────────────────────── */
    case 32: {
        if (rsa_pub == CK_INVALID_HANDLE || rsa_priv == CK_INVALID_HANDLE) return 0;
        CK_ULONG slen = 0;
        CK_BYTE *sig = make_signature(CKM_RSA_X_509, rsa_priv, NULL, pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_RSA_X_509;
        if (p11->C_VerifyInit(sess, &mech, rsa_pub) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    /* ── AES-CTR error path testing (invalid ulCounterBits) ─────── */
    case 33: {
        /* ulCounterBits = 0 is invalid (must be 1-128) */
        CK_AES_CTR_PARAMS bad_ctr = { 0, {0x01, 0x02, 0x03, 0x04,
                                          0x05, 0x06, 0x07, 0x08,
                                          0x09, 0x0a, 0x0b, 0x0c,
                                          0x0d, 0x0e, 0x0f, 0x10} };
        mech.mechanism = CKM_AES_CTR;
        mech.pParameter = &bad_ctr;
        mech.ulParameterLen = sizeof(bad_ctr);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        p11->C_EncryptInit(sess, &mech, aes_key);
        break;
    }

    case 34: {
        /* ulCounterBits = 200 is invalid (>128) */
        CK_AES_CTR_PARAMS bad_ctr = { 200, {0x01, 0x02, 0x03, 0x04,
                                            0x05, 0x06, 0x07, 0x08,
                                            0x09, 0x0a, 0x0b, 0x0c,
                                            0x0d, 0x0e, 0x0f, 0x10} };
        mech.mechanism = CKM_AES_CTR;
        mech.pParameter = &bad_ctr;
        mech.ulParameterLen = sizeof(bad_ctr);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        p11->C_EncryptInit(sess, &mech, aes_key);
        break;
    }

    /* ── AES-GCM error path testing (invalid ulTagBits) ────────── */
    case 35: {
        /* ulTagBits = 1 is invalid (must be 0 or divisible by 8) */
        CK_GCM_PARAMS bad_gcm = { gcm_iv, 12, 96, NULL, 0, 1 };
        mech.mechanism = CKM_AES_GCM;
        mech.pParameter = &bad_gcm;
        mech.ulParameterLen = sizeof(bad_gcm);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        p11->C_EncryptInit(sess, &mech, aes_key);
        break;
    }

    case 36: {
        /* ulTagBits = 200 is invalid (>128) */
        CK_GCM_PARAMS bad_gcm = { gcm_iv, 12, 96, NULL, 0, 200 };
        mech.mechanism = CKM_AES_GCM;
        mech.pParameter = &bad_gcm;
        mech.ulParameterLen = sizeof(bad_gcm);
        if (aes_key == CK_INVALID_HANDLE) return 0;
        p11->C_EncryptInit(sess, &mech, aes_key);
        break;
    }

    /* ── Multi-part Sign ECDSA-SHA384/512 ───────────────────────────── */
    case 37: {
        mech.mechanism = CKM_ECDSA_SHA384;
        if (ec_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, ec_priv) != CKR_OK) return 0;
        goto do_sign_update;
    }

    case 38: {
        mech.mechanism = CKM_ECDSA_SHA512;
        if (ec_priv == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, ec_priv) != CKR_OK) return 0;
        goto do_sign_update;
    }

    /* ── Multi-part Encrypt (DES3-ECB) ─────────────────────── */
    case 39:
        ensure_des3_key();
        if (des3_key == CK_INVALID_HANDLE) return 0;
        mech.mechanism      = CKM_DES3_ECB;
        mech.pParameter     = NULL_PTR;
        mech.ulParameterLen = 0;
        if (p11->C_EncryptInit(sess, &mech, des3_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Decrypt (DES3-ECB) ───────────────────── */
    case 40:
        ensure_des3_key();
        if (des3_key == CK_INVALID_HANDLE) return 0;
        mech.mechanism      = CKM_DES3_ECB;
        mech.pParameter     = NULL_PTR;
        mech.ulParameterLen = 0;
        if (p11->C_DecryptInit(sess, &mech, des3_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_DecryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_DecryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Encrypt (DES3-CBC) ─────────────────────── */
    case 41:
        ensure_des3_key();
        if (des3_key == CK_INVALID_HANDLE) return 0;
        mech.mechanism      = CKM_DES3_CBC;
        mech.pParameter     = des3_iv;
        mech.ulParameterLen = 8;
        if (p11->C_EncryptInit(sess, &mech, des3_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Decrypt (DES3-CBC) ───────────────────── */
    case 42:
        ensure_des3_key();
        if (des3_key == CK_INVALID_HANDLE) return 0;
        mech.mechanism      = CKM_DES3_CBC;
        mech.pParameter     = des3_iv;
        mech.ulParameterLen = 8;
        if (p11->C_DecryptInit(sess, &mech, des3_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_DecryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_DecryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Encrypt (AES-CBC-PAD) ──────────────────────────── */
    case 43:
        mech.mechanism      = CKM_AES_CBC_PAD;
        mech.pParameter     = iv;
        mech.ulParameterLen = 16;
        if (aes_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_EncryptInit(sess, &mech, aes_key) != CKR_OK) return 0;
        {
            CK_BYTE out[4096]; CK_ULONG olen;
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                olen = sizeof(out);
                p11->C_EncryptUpdate(sess,
                    (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc, out, &olen);
                off += tc;
                if (off >= plen) break;
            }
            olen = sizeof(out);
            p11->C_EncryptFinal(sess, out, &olen);
        }
        break;

    /* ── Multi-part Sign (SHA1-HMAC) ─────────────────────────── */
    case 44: {
        mech.mechanism = CKM_SHA_1_HMAC;
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, hmac_key) != CKR_OK) return 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[64];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part HMAC Verify (SHA1-HMAC) ──────────────────── */
    case 45: {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_ULONG slen = 0;
        CK_BYTE *sig = make_signature(CKM_SHA_1_HMAC, hmac_key, NULL,
                                      pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_SHA_1_HMAC;
        if (p11->C_VerifyInit(sess, &mech, hmac_key) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    /* ── Multi-part Sign (SHA224-HMAC) ─────────────────────────── */
    case 46: {
        mech.mechanism = CKM_SHA224_HMAC;
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, hmac_key) != CKR_OK) return 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[64];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part HMAC Verify (SHA224-HMAC) ──────────────────── */
    case 47: {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_ULONG slen = 0;
        CK_BYTE *sig = make_signature(CKM_SHA224_HMAC, hmac_key, NULL,
                                      pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_SHA224_HMAC;
        if (p11->C_VerifyInit(sess, &mech, hmac_key) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    /* ── Multi-part Sign (SHA384-HMAC) ─────────────────────────── */
    case 48: {
        mech.mechanism = CKM_SHA384_HMAC;
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, hmac_key) != CKR_OK) return 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[64];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part HMAC Verify (SHA384-HMAC) ──────────────────── */
    case 49: {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_ULONG slen = 0;
        CK_BYTE *sig = make_signature(CKM_SHA384_HMAC, hmac_key, NULL,
                                      pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_SHA384_HMAC;
        if (p11->C_VerifyInit(sess, &mech, hmac_key) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    /* ── Multi-part Sign (SHA512-HMAC) ─────────────────────────── */
    case 50: {
        mech.mechanism = CKM_SHA512_HMAC;
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        if (p11->C_SignInit(sess, &mech, hmac_key) != CKR_OK) return 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_SignUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  sig[64];
        CK_ULONG slen = sizeof(sig);
        p11->C_SignFinal(sess, sig, &slen);
        break;
    }

    /* ── Multi-part HMAC Verify (SHA512-HMAC) ──────────────────── */
    case 51: {
        if (hmac_key == CK_INVALID_HANDLE) return 0;
        CK_ULONG slen = 0;
        CK_BYTE *sig = make_signature(CKM_SHA512_HMAC, hmac_key, NULL,
                                      pay, plen, &slen);
        if (!sig) return 0;
        mech.mechanism = CKM_SHA512_HMAC;
        if (p11->C_VerifyInit(sess, &mech, hmac_key) == CKR_OK) {
            size_t off = 0;
            for (uint8_t i = 0; i < nchunks; i++) {
                size_t tc = (off + chunk <= plen) ? chunk : plen - off;
                p11->C_VerifyUpdate(sess, (CK_BYTE_PTR)(pay + off), (CK_ULONG)tc);
                off += tc;
                if (off >= plen) break;
            }
            p11->C_VerifyFinal(sess, sig, slen);
        }
        free(sig);
        break;
    }

    }

    return 0;
}
