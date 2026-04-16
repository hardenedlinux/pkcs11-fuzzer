/*
 * pkcs11_hmac_fuzz.c — Fuzz HMAC and CMAC mechanisms via C_SignInit + C_Sign.
 *
 * HMAC (SHA-1/256/384/512, MD5) and AES-CMAC are entirely absent from all
 * other harnesses.  They exercise SoftHSM2's symmetric MAC implementation and
 * a different code branch in the OpenSSL HMAC EVP layer.
 *
 * Uses two keys from the token:
 *   hmac_key (id=04, CKM_GENERIC_SECRET_KEY_GEN) — for SHA-{1,256,384,512} and MD5 HMAC
 *   aes_key  (id=03, CKM_AES_KEY_GEN, CKA_SIGN)  — for AES-CMAC
 *
 * Input layout:
 *   byte 0:  mechanism selector (0-5)
 *   byte 1+: data to MAC
 *
 * Mechanisms:
 *   0  CKM_SHA_1_HMAC
 *   1  CKM_SHA256_HMAC
 *   2  CKM_SHA384_HMAC
 *   3  CKM_SHA512_HMAC
 *   4  CKM_MD5_HMAC
 *   5  CKM_AES_CMAC
 */
#include "common.h"
#include <stdint.h>
#include <stddef.h>

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
        CKM_SHA_1_HMAC,
        CKM_SHA256_HMAC,
        CKM_SHA384_HMAC,
        CKM_SHA512_HMAC,
        CKM_MD5_HMAC,
        CKM_AES_CMAC,
    };
    static const size_t N = sizeof(mechs) / sizeof(mechs[0]);

    uint8_t sel   = data[0] % N;
    CK_MECHANISM_TYPE mtype = mechs[sel];

    const uint8_t *pay  = payload_ptr(data, size);
    size_t         plen = payload_len(size);

    /* AES-CMAC uses the AES key; all HMAC variants use the generic HMAC key */
    CK_OBJECT_HANDLE key = (mtype == CKM_AES_CMAC) ? aes_key : hmac_key;
    if (key == CK_INVALID_HANDLE) return 0;

    CK_MECHANISM mech = { mtype, NULL_PTR, 0 };

    CK_RV rv = p11->C_SignInit(sess, &mech, key);
    if (rv != CKR_OK) return 0;

    CK_BYTE  mac[64];
    CK_ULONG maclen = sizeof(mac);
    p11->C_Sign(sess, (CK_BYTE_PTR)pay, (CK_ULONG)plen, mac, &maclen);

    return 0;
}
