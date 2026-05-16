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
 *   0  CKM_RSA_PKCS          (RSA PKCS#1 v1.5 decrypt)
 *   1  CKM_RSA_PKCS_OAEP     (RSA-OAEP with fuzzed CK_RSA_PKCS_OAEP_PARAMS, SHA-256 default)
 *   2  CKM_AES_ECB           (AES-ECB, no IV, block-aligned)
 *   3  CKM_AES_CBC           (AES-CBC with 16-byte IV from params)
 *   4  CKM_AES_CBC_PAD       (AES-CBC with PKCS padding + 16-byte IV)
 *   5  CKM_AES_GCM           (AES-GCM with fuzzed CK_GCM_PARAMS)
 *   6  CKM_AES_CTR           (AES-CTR with fuzzed counter block)
 *   7  CKM_RSA_X_509         (Raw RSA decrypt without padding)
 *   8  CKM_AES_CTR            (error path: ulCounterBits from params, triggers counterBits==0 or >128)
 *   9  CKM_AES_GCM            (error path: ulTagBits from params, triggers tagBits >128 or %8!=0)
 *  10  CKM_RSA_PKCS_OAEP     (RSA-OAEP with SHA-384)
 *  11  CKM_RSA_PKCS_OAEP     (RSA-OAEP with SHA-512)
 *  12  CKM_AES_CMAC          (AES-CMAC decryption)
 *
 * Error path testing (selectors 8-9):
 *   Selector 8 exercises AES-CTR with invalid ulCounterBits (SoftHSM.cpp:3143):
 *     counterBits == 0 || counterBits > 128 -> CKR_MECHANISM_PARAM_INVALID
 *   Selector 9 exercises AES-GCM with invalid ulTagBits (SoftHSM.cpp:3168):
 *     tagBytes > 128 || tagBytes % 8 != 0 -> CKR_MECHANISM_PARAM_INVALID
 *
 * OAEP hash variants (selectors 1, 10, 11):
 *   Selector 1 uses SHA-256 as default hash when params are not fully specified
 *   Selector 10 uses SHA-384 as default hash
 *   Selector 11 uses SHA-512 as default hash
 *   All three can be fully fuzzed via CK_RSA_PKCS_OAEP_PARAMS when paramlen >= sizeof(oaep)
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
        CKM_AES_CTR,
        CKM_RSA_X_509,
        CKM_AES_CTR,
        CKM_AES_GCM,
        CKM_RSA_PKCS_OAEP,
        CKM_RSA_PKCS_OAEP,
        CKM_AES_CMAC,
    };
    static const size_t N = sizeof(mechs) / sizeof(mechs[0]);

    uint8_t sel = data[0] % N;
    CK_MECHANISM_TYPE mtype = mechs[sel];
    int is_error_ctr = (sel == 8);
    int is_error_gcm = (sel == 9);
    int is_oaep_sha384 = (sel == 10);
    int is_oaep_sha512 = (sel == 11);

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
    CK_AES_CTR_PARAMS ctr = {0};

    switch (mtype) {
    case CKM_RSA_PKCS_OAEP:
        if (paramlen >= sizeof(oaep))
            memcpy(&oaep, param_bytes, sizeof(oaep));
        else {
            if (is_oaep_sha384) {
                oaep.hashAlg  = CKM_SHA384;
                oaep.mgf      = CKG_MGF1_SHA384;
            } else if (is_oaep_sha512) {
                oaep.hashAlg  = CKM_SHA512;
                oaep.mgf      = CKG_MGF1_SHA512;
            } else {
                oaep.hashAlg  = CKM_SHA256;
                oaep.mgf      = CKG_MGF1_SHA256;
            }
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
        if (is_error_gcm) {
            if (paramlen >= 12) memcpy(gcm_iv, param_bytes, 12);
            gcm.pIv            = gcm_iv;
            gcm.ulIvLen        = 12;
            gcm.ulIvBits       = 96;
            gcm.pAAD           = NULL_PTR;
            gcm.ulAADLen       = 0;
            gcm.ulTagBits      = (paramlen > 12) ? (uint8_t)param_bytes[12] : 0;
            mech.pParameter    = &gcm;
            mech.ulParameterLen = sizeof(gcm);
            break;
        }
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

    case CKM_AES_CTR:
        if (is_error_ctr) {
            ctr.ulCounterBits = (paramlen > 12) ? (uint8_t)param_bytes[12] : 0;
            if (paramlen >= 16) memcpy(ctr.cb, param_bytes, 16);
            else memset(ctr.cb, 0, 16);
            mech.pParameter    = &ctr;
            mech.ulParameterLen = sizeof(ctr);
            break;
        }
        ctr.ulCounterBits = 128;
        if (paramlen >= 16) memcpy(ctr.cb, param_bytes, 16);
        mech.pParameter    = &ctr;
        mech.ulParameterLen = sizeof(ctr);
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
    case CKM_AES_CTR:
    case CKM_AES_CMAC:
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
