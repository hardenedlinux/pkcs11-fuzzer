/*
 * pkcs11_sign_fuzz.c — Fuzz C_SignInit + C_Sign across RSA, ECDSA, EDDSA, and HMAC mechanisms.
 *
 * Input layout:
 *   byte 0: mechanism selector (0-22, see table below)
 *   byte 1..?: for CKM_RSA_PKCS_PSS — first sizeof(CK_RSA_PKCS_PSS_PARAMS)
 *              bytes are used as mechanism parameters; rest is data to sign.
 *              For all other mechanisms the full payload is data to sign.
 *
 * Mechanisms tested:
 *   0 CKM_RSA_PKCS          (RSA PKCS#1 v1.5 raw, no hash)
 *   1 CKM_SHA1_RSA_PKCS     (RSA PKCS#1 v1.5 with SHA-1)
 *   2 CKM_SHA256_RSA_PKCS   (RSA PKCS#1 v1.5 with SHA-256)
 *   3 CKM_SHA384_RSA_PKCS   (RSA PKCS#1 v1.5 with SHA-384)
 *   4 CKM_RSA_PKCS_PSS      (RSA-PSS with fuzzed CK_RSA_PKCS_PSS_PARAMS)
 *   5 CKM_ECDSA             (ECDSA raw)
 *   6 CKM_ECDSA_SHA1        (ECDSA with SHA-1)
 *   7 CKM_ECDSA_SHA256      (ECDSA with SHA-256)
 *   8 CKM_SHA512_RSA_PKCS   (RSA PKCS#1 v1.5 with SHA-512)
 *   9 CKM_MD5_RSA_PKCS      (RSA PKCS#1 v1.5 with MD5)
 *  10 CKM_ECDSA_SHA384      (ECDSA with SHA-384)
 *  11 CKM_ECDSA_SHA512      (ECDSA with SHA-512)
 *  12 CKM_EDDSA             (Ed25519/Ed448 pure signature)
 *  13 CKM_SHA224_RSA_PKCS  (RSA PKCS#1 v1.5 with SHA-224)
 *  14 CKM_SHA256_RSA_PKCS_PSS (RSA-PSS-SHA256)
 *  15 CKM_SHA384_RSA_PKCS_PSS (RSA-PSS-SHA384)
 *  16 CKM_SHA512_RSA_PKCS_PSS (RSA-PSS-SHA512)
 *  17 CKM_ECDSA_SHA224      (ECDSA with SHA-224)
 *  18 CKM_SHA256_HMAC       (HMAC-SHA256 with generic secret key)
 *  19 CKM_SHA_1_HMAC        (HMAC-SHA1 with generic secret key)
 *  20 CKM_SHA384_HMAC       (HMAC-SHA384 with generic secret key)
 *  21 CKM_SHA512_HMAC       (HMAC-SHA512 with generic secret key)
 *  22 CKM_SHA224_HMAC       (HMAC-SHA224 with generic secret key)
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    static const CK_MECHANISM_TYPE mechs[] = {
        CKM_RSA_PKCS,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_RSA_PKCS_PSS,
        CKM_ECDSA,
        CKM_ECDSA_SHA1,
        CKM_ECDSA_SHA256,
        CKM_SHA512_RSA_PKCS,
        CKM_MD5_RSA_PKCS,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
        CKM_EDDSA,
        CKM_SHA224_RSA_PKCS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
        CKM_ECDSA_SHA224,
        CKM_SHA256_HMAC,
        CKM_SHA_1_HMAC,
        CKM_SHA384_HMAC,
        CKM_SHA512_HMAC,
        CKM_SHA224_HMAC,
    };
    static const size_t N = sizeof(mechs) / sizeof(mechs[0]);

    uint8_t sel = data[0] % N;
    CK_MECHANISM_TYPE mtype = mechs[sel];

    const uint8_t *pay = payload_ptr(data, size);
    size_t         plen = payload_len(size);

    /* Build mechanism struct — may include parameters for PSS */
    CK_RSA_PKCS_PSS_PARAMS pss = {0};
    CK_MECHANISM mech = { mtype, NULL_PTR, 0 };

    if (mtype == CKM_RSA_PKCS_PSS) {
        if (plen >= sizeof(pss)) {
            memcpy(&pss, pay, sizeof(pss));
            mech.pParameter    = &pss;
            mech.ulParameterLen = sizeof(pss);
            pay  += sizeof(pss);
            plen -= sizeof(pss);
        } else {
            /* Not enough bytes for PSS params — use defaults */
            pss.hashAlg   = CKM_SHA256;
            pss.mgf       = CKG_MGF1_SHA256;
            pss.sLen      = 32;
            mech.pParameter    = &pss;
            mech.ulParameterLen = sizeof(pss);
        }
    } else if (mtype == CKM_SHA256_RSA_PKCS_PSS) {
        pss.hashAlg = CKM_SHA256;
        pss.mgf     = CKG_MGF1_SHA256;
        pss.sLen    = 32;
        mech.pParameter    = &pss;
        mech.ulParameterLen = sizeof(pss);
    } else if (mtype == CKM_SHA384_RSA_PKCS_PSS) {
        pss.hashAlg = CKM_SHA384;
        pss.mgf     = CKG_MGF1_SHA384;
        pss.sLen    = 32;
        mech.pParameter    = &pss;
        mech.ulParameterLen = sizeof(pss);
    } else if (mtype == CKM_SHA512_RSA_PKCS_PSS) {
        pss.hashAlg = CKM_SHA512;
        pss.mgf     = CKG_MGF1_SHA512;
        pss.sLen    = 32;
        mech.pParameter    = &pss;
        mech.ulParameterLen = sizeof(pss);
    } else if (mtype == CKM_SHA224_RSA_PKCS_PSS) {
        pss.hashAlg = CKM_SHA224;
        pss.mgf     = CKG_MGF1_SHA224;
        pss.sLen    = 28;
        mech.pParameter    = &pss;
        mech.ulParameterLen = sizeof(pss);
    }

    /* Choose key handle based on mechanism family */
    CK_OBJECT_HANDLE key;
    if (mtype == CKM_EDDSA) {
        key = ed_priv;
    } else if (mtype == CKM_ECDSA       ||
               mtype == CKM_ECDSA_SHA1   ||
               mtype == CKM_ECDSA_SHA224 ||
               mtype == CKM_ECDSA_SHA256 ||
               mtype == CKM_ECDSA_SHA384 ||
               mtype == CKM_ECDSA_SHA512) {
        key = ec_priv;
    } else if (mtype == CKM_SHA256_HMAC ||
               mtype == CKM_SHA_1_HMAC   ||
               mtype == CKM_SHA384_HMAC  ||
               mtype == CKM_SHA512_HMAC  ||
               mtype == CKM_SHA224_HMAC) {
        key = hmac_key;
    } else {
        key = rsa_priv;
    }
    if (key == CK_INVALID_HANDLE) return 0;

    /* C_SignInit — try the mechanism (may be rejected by the token) */
    CK_RV rv = p11->C_SignInit(sess, &mech, key);
    if (rv != CKR_OK) return 0;

    /* C_Sign — we don't care about the return value, we're hunting memory bugs */
    CK_BYTE  sig[512];
    CK_ULONG siglen = sizeof(sig);
    p11->C_Sign(sess, (CK_BYTE_PTR)pay, (CK_ULONG)plen, sig, &siglen);

    return 0;
}
