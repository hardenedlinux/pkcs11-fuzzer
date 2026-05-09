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
 *   byte 0:  operation selector (0–15, see table)
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
 *   7  C_DecryptInit(AES-CBC)          + C_DecryptUpdate × N + C_DecryptFinal
 *   8  C_EncryptInit(AES-GCM)          + C_EncryptUpdate × N + C_EncryptFinal
 *   9  C_DecryptInit(AES-GCM)          + C_DecryptUpdate × N + C_EncryptFinal
 *  10  C_SignInit(EdDSA-Ed25519)       + C_SignUpdate × N + C_SignFinal
 *  11  C_VerifyInit(EdDSA-Ed25519)     + C_VerifyUpdate × N + C_VerifyFinal
 *  12  C_SignInit(SHA256-HMAC)         + C_SignUpdate × N + C_SignFinal
 *  13  C_SignInit(SHA256-HMAC) verify  + C_SignUpdate × N + C_SignFinal
 *  14  C_SignInit(RSA-PKCS1-SHA224)    + C_SignUpdate × N + C_SignFinal
 *  15  C_SignInit(RSA-PSS-SHA224)      + C_SignUpdate × N + C_SignFinal
 *
 * For verify operations (4–5, 11) we sign the data first with a real key so the
 * signature format is valid — this exercises the actual verification logic
 * rather than bailing out early on a bad signature header.  The fuzz payload
 * is still used as the message, so variations in message content influence
 * the hash computation path.
 *
 * EdDSA (selectors 10–11) is a pureEdDSA signature algorithm using
 * Curve25519/Ed25519 - it does not use a hash function, unlike RSA-PSS
 * or ECDSA which use SHA-256/SHA-1. This exercises distinct code paths.
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;

    uint8_t sel     = data[0] % 16;
    uint8_t nchunks = (data[1] % 8) + 1;   /* 1–8 */

    const uint8_t *pay  = (size > 2) ? data + 2 : (const uint8_t *)"";
    size_t         plen = (size > 2) ? size - 2 : 0;

    /* Chunk the payload */
    size_t chunk = (plen > 0 && nchunks > 0)
                   ? (plen + nchunks - 1) / nchunks : 0;

    CK_MECHANISM mech = { 0, NULL_PTR, 0 };
    CK_RSA_PKCS_PSS_PARAMS pss = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_RSA_PKCS_PSS_PARAMS pss224 = { CKM_SHA224, CKG_MGF1_SHA224, 28 };
    CK_BYTE iv[16]   = {0};
    CK_BYTE gcm_iv[12] = {0};
    CK_GCM_PARAMS gcm  = {0};

    /* IV bytes come from the last bytes of the payload to keep mutation useful */
    if (plen >= 16) memcpy(iv,     pay + plen - 16, 16);
    if (plen >= 12) memcpy(gcm_iv, pay + plen - 12, 12);
    gcm.pIv = gcm_iv; gcm.ulIvLen = 12; gcm.ulIvBits = 96; gcm.ulTagBits = 128;

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

    }

    return 0;
}
