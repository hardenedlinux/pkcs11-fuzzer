/*
 * pkcs11_decrypt_fuzz.c — Fuzz C_DecryptInit + C_Decrypt for RSA and AES.
 *
 * Input layout:
 *   byte 0:     mechanism selector
 *   byte 1..2:  (big-endian uint16) parameter length (0 if none)
 *   byte 3..(3+paramlen-1): raw mechanism parameter bytes
 *   remaining:  ciphertext to decrypt (usually garbage, which is the point)
 *
 * Mechanisms tested:
 *   0 CKM_RSA_PKCS          (RSA PKCS#1 v1.5 decrypt)
 *   1 CKM_RSA_PKCS_OAEP     (RSA-OAEP with fuzzed CK_RSA_PKCS_OAEP_PARAMS)
 *   2 CKM_AES_ECB           (AES-ECB, no IV, block-aligned)
 *   3 CKM_AES_CBC           (AES-CBC with 16-byte IV from params)
 *   4 CKM_AES_CBC_PAD       (AES-CBC with PKCS padding + 16-byte IV)
 *   5 CKM_AES_GCM           (AES-GCM with fuzzed CK_GCM_PARAMS)
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
    if (size < 3) return 0;

    static const CK_MECHANISM_TYPE mechs[] = {
        CKM_RSA_PKCS,
        CKM_RSA_PKCS_OAEP,
        CKM_AES_ECB,
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_GCM,
    };
    static const size_t N = sizeof(mechs) / sizeof(mechs[0]);

    uint8_t sel = data[0] % N;
    CK_MECHANISM_TYPE mtype = mechs[sel];

    /* Parse param length (2 bytes big-endian, bounded to 256) */
    uint16_t paramlen_raw = ((uint16_t)data[1] << 8) | data[2];
    size_t   paramlen = paramlen_raw & 0xff;   /* cap at 255 */
    if (size < 3 + paramlen) return 0;

    const uint8_t *param_bytes = data + 3;
    const uint8_t *ct          = data + 3 + paramlen;
    size_t         ct_len      = size - 3 - paramlen;

    /* Build mechanism struct */
    CK_MECHANISM mech = { mtype, NULL_PTR, 0 };

    /* Typed parameter structs (filled from fuzz bytes or zeroed) */
    CK_RSA_PKCS_OAEP_PARAMS oaep = {0};
    CK_BYTE iv[16] = {0};
    CK_GCM_PARAMS gcm = {0};
    CK_BYTE gcm_iv[12] = {0};
    CK_BYTE gcm_aad[32] = {0};

    switch (mtype) {
    case CKM_RSA_PKCS_OAEP:
        if (paramlen >= sizeof(oaep))
            memcpy(&oaep, param_bytes, sizeof(oaep));
        else {
            oaep.hashAlg  = CKM_SHA256;
            oaep.mgf      = CKG_MGF1_SHA256;
            oaep.source   = CKZ_DATA_SPECIFIED;
            oaep.pSourceData = NULL_PTR;
            oaep.ulSourceDataLen = 0;
        }
        mech.pParameter    = &oaep;
        mech.ulParameterLen = sizeof(oaep);
        break;

    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
        if (paramlen >= 16) memcpy(iv, param_bytes, 16);
        mech.pParameter    = iv;
        mech.ulParameterLen = 16;
        break;

    case CKM_AES_GCM:
        if (paramlen >= 12) memcpy(gcm_iv, param_bytes, 12);
        gcm.pIv            = gcm_iv;
        gcm.ulIvLen        = 12;
        gcm.ulIvBits       = 96;
        gcm.pAAD           = gcm_aad;
        gcm.ulAADLen       = (paramlen > 12) ? (paramlen - 12 < 32 ? paramlen - 12 : 32) : 0;
        if (gcm.ulAADLen > 0)
            memcpy(gcm_aad, param_bytes + 12, gcm.ulAADLen);
        gcm.ulTagBits      = 128;
        mech.pParameter    = &gcm;
        mech.ulParameterLen = sizeof(gcm);
        break;

    default:
        /* CKM_RSA_PKCS, CKM_AES_ECB: no parameters */
        break;
    }

    /* Select key */
    CK_OBJECT_HANDLE key;
    switch (mtype) {
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
    case CKM_AES_GCM:
        key = aes_key;
        break;
    default:
        key = rsa_priv;
        break;
    }
    if (key == CK_INVALID_HANDLE) return 0;

    /* C_DecryptInit */
    CK_RV rv = p11->C_DecryptInit(sess, &mech, key);
    if (rv != CKR_OK) return 0;

    /* C_Decrypt — output buffer large enough for RSA-2048 */
    CK_BYTE  out[4096];
    CK_ULONG outlen = sizeof(out);
    p11->C_Decrypt(sess, (CK_BYTE_PTR)ct, (CK_ULONG)ct_len, out, &outlen);

    return 0;
}
