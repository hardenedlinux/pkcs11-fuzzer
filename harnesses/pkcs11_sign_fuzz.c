/*
 * pkcs11_sign_fuzz.c — Fuzz C_SignInit + C_Sign across RSA and ECDSA mechanisms.
 *
 * Input layout:
 *   byte 0: mechanism selector (0-7, see table below)
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
 *   9 CKM_ECDSA_SHA384      (ECDSA with SHA-384)
 *  10 CKM_ECDSA_SHA512      (ECDSA with SHA-512)
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
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
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
    }

    /* Choose key handle based on mechanism family */
    CK_OBJECT_HANDLE key = (mtype == CKM_ECDSA       ||
                             mtype == CKM_ECDSA_SHA1   ||
                             mtype == CKM_ECDSA_SHA256 ||
                             mtype == CKM_ECDSA_SHA384 ||
                             mtype == CKM_ECDSA_SHA512)
                           ? ec_priv : rsa_priv;
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
