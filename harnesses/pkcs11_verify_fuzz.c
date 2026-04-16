/*
 * pkcs11_verify_fuzz.c — Fuzz C_VerifyInit + C_Verify (single-part).
 *
 * C_Verify is entirely absent from all other harnesses.  It exercises the
 * signature-verification paths in SoftHSM2 + OpenSSL, including RSA PKCS#1
 * padding checks, ECDSA DER/raw signature parsing, and the big-number
 * arithmetic underneath — all distinct from C_Sign.
 *
 * Strategy: sign a fixed known message during LLVMFuzzerInitialize with each
 * key type, store the valid signature.  Each fuzzing iteration then:
 *   odd selectors  — valid sig, fuzz message  (exercises full verify path,
 *                    reaches rejection on hash mismatch)
 *   even selectors — fixed message, fuzz sig   (exercises padding/DER parser)
 *
 * Mechanisms:
 *   0  CKM_SHA256_RSA_PKCS  fuzz-sig   fixed-msg
 *   1  CKM_SHA256_RSA_PKCS  valid-sig  fuzz-msg
 *   2  CKM_RSA_PKCS         fuzz-sig   fixed-msg  (raw, no hash)
 *   3  CKM_RSA_PKCS         valid-sig  fuzz-msg
 *   4  CKM_ECDSA_SHA256     fuzz-sig   fixed-msg
 *   5  CKM_ECDSA_SHA256     valid-sig  fuzz-msg
 *   6  CKM_ECDSA            fuzz-sig   fixed-msg  (raw hash input)
 *   7  CKM_ECDSA            valid-sig  fuzz-msg
 */
#include "common.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static const CK_BYTE FIXED_MSG[]  = "pkcs11-verify-fuzz-fixed-message";
static const CK_ULONG FIXED_MLEN  = 32;

static CK_BYTE  rsa_sha256_sig[256]; static CK_ULONG rsa_sha256_siglen;
static CK_BYTE  rsa_raw_sig[256];    static CK_ULONG rsa_raw_siglen;
static CK_BYTE  ec_sha256_sig[72];   static CK_ULONG ec_sha256_siglen;
static CK_BYTE  ec_raw_sig[72];      static CK_ULONG ec_raw_siglen;

static void presign(CK_MECHANISM_TYPE mtype, CK_OBJECT_HANDLE key,
                    CK_BYTE *sig, CK_ULONG *siglen,
                    const CK_BYTE *msg, CK_ULONG mlen)
{
    CK_MECHANISM mech = { mtype, NULL_PTR, 0 };
    if (p11->C_SignInit(sess, &mech, key) != CKR_OK) return;
    p11->C_Sign(sess, (CK_BYTE_PTR)msg, mlen, sig, siglen);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    pkcs11_init();

    /* Pre-compute valid signatures for each mechanism */
    rsa_sha256_siglen = sizeof(rsa_sha256_sig);
    presign(CKM_SHA256_RSA_PKCS, rsa_priv,
            rsa_sha256_sig, &rsa_sha256_siglen, FIXED_MSG, FIXED_MLEN);

    /* RSA raw sign: data must be padded to block size; we hash manually */
    rsa_raw_siglen = sizeof(rsa_raw_sig);
    presign(CKM_RSA_PKCS, rsa_priv,
            rsa_raw_sig, &rsa_raw_siglen, FIXED_MSG, FIXED_MLEN);

    ec_sha256_siglen = sizeof(ec_sha256_sig);
    presign(CKM_ECDSA_SHA256, ec_priv,
            ec_sha256_sig, &ec_sha256_siglen, FIXED_MSG, FIXED_MLEN);

    ec_raw_siglen = sizeof(ec_raw_sig);
    presign(CKM_ECDSA, ec_priv,
            ec_raw_sig, &ec_raw_siglen, FIXED_MSG, FIXED_MLEN);

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    uint8_t sel = data[0] % 8;
    const uint8_t *pay  = payload_ptr(data, size);
    size_t         plen = payload_len(size);

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE pub;
    CK_BYTE  *vsig; CK_ULONG vsiglen;
    int fuzz_sig = (sel % 2 == 0);  /* even → fuzz signature, odd → fuzz message */

    switch (sel / 2) {
    case 0:
        mech = (CK_MECHANISM){ CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
        pub  = rsa_pub;
        vsig = rsa_sha256_sig; vsiglen = rsa_sha256_siglen;
        break;
    case 1:
        mech = (CK_MECHANISM){ CKM_RSA_PKCS, NULL_PTR, 0 };
        pub  = rsa_pub;
        vsig = rsa_raw_sig; vsiglen = rsa_raw_siglen;
        break;
    case 2:
        mech = (CK_MECHANISM){ CKM_ECDSA_SHA256, NULL_PTR, 0 };
        pub  = ec_pub;
        vsig = ec_sha256_sig; vsiglen = ec_sha256_siglen;
        break;
    default:
        mech = (CK_MECHANISM){ CKM_ECDSA, NULL_PTR, 0 };
        pub  = ec_pub;
        vsig = ec_raw_sig; vsiglen = ec_raw_siglen;
        break;
    }

    if (pub == CK_INVALID_HANDLE || vsiglen == 0) return 0;

    CK_RV rv = p11->C_VerifyInit(sess, &mech, pub);
    if (rv != CKR_OK) return 0;

    if (fuzz_sig) {
        /* fuzz signature bytes, fixed message */
        p11->C_Verify(sess,
                      (CK_BYTE_PTR)FIXED_MSG, FIXED_MLEN,
                      (CK_BYTE_PTR)pay, (CK_ULONG)plen);
    } else {
        /* valid (stored) signature, fuzz message */
        p11->C_Verify(sess,
                      (CK_BYTE_PTR)pay, (CK_ULONG)plen,
                      vsig, vsiglen);
    }

    return 0;
}
