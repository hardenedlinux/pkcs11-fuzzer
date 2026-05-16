/*
 * pkcs11_encrypt_fuzz.c — Fuzz C_EncryptInit + C_Encrypt (single-part).
 *
 * Covers the single-part encrypt path that pkcs11_multipart_fuzz does not
 * reach (multipart uses C_EncryptUpdate/C_EncryptFinal).  Also adds
 * AES-CTR which is absent from all other harnesses.
 *
 * Input layout:
 *   byte 0:     mechanism selector
 *   byte 1..16: IV / CTR block (interpreted per mechanism)
 *   byte 17+:   plaintext to encrypt
 *
 * Mechanisms (0-6 are AES, 7-12 are DES/3DES, 13-14 are RSA):
 *   0  CKM_AES_ECB      (no IV; plaintext at byte 17)
 *   1  CKM_AES_CBC      (16-byte IV from bytes 1-16, plaintext at byte 17)
 *   2  CKM_AES_CBC_PAD  (16-byte IV from bytes 1-16, PKCS#7 pad applied)
 *   3  CKM_AES_CTR      (16-byte counter block from bytes 1-16, 128-bit counter)
 *   4  CKM_AES_GCM      (12-byte IV + fuzzed AAD)
 *   5  CKM_AES_CTR      (error path: ulCounterBits from byte 17, triggers counterBits==0 or >128)
 *   6  CKM_AES_GCM      (error path: ulTagBits from byte 17, triggers tagBits >128 or %8!=0)
 *   7  CKM_DES_ECB      (no IV; plaintext at byte 17)
 *   8  CKM_DES_CBC      (8-byte IV from bytes 1-8, plaintext at byte 9)
 *   9  CKM_DES3_ECB     (no IV; plaintext at byte 17)
 *  10  CKM_DES3_CBC     (8-byte IV from bytes 1-8, plaintext at byte 9)
 *  11  CKM_DES3_CBC_PAD (8-byte IV from bytes 1-8, plaintext at byte 9, PKCS#7 pad)
 *  12  CKM_DES3_CBC_PAD (same as 11, for additional coverage)
 *  13  CKM_RSA_PKCS     (RSA PKCS#1 v1.5 encryption with public key)
 *  14  CKM_RSA_X_509    (raw RSA encryption with public key)
 *
 * Note: CKM_AES_CCM was removed as it is not implemented in SoftHSM2.
 *
 * Error path testing (selectors 5-6):
 *   Selector 5 exercises AES-CTR with invalid ulCounterBits (SoftHSM.cpp:2409):
 *     counterBits == 0 || counterBits > 128 -> CKR_MECHANISM_PARAM_INVALID
 *   Selector 6 exercises AES-GCM with invalid ulTagBits (SoftHSM.cpp:2434):
 *     tagBytes > 128 || tagBytes % 8 != 0 -> CKR_ARGUMENTS_BAD
 */
#include "common.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

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

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    pkcs11_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const CK_MECHANISM_TYPE mechs[] = {
        CKM_AES_ECB,
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_CTR,
        CKM_AES_GCM,
        CKM_AES_CTR,
        CKM_AES_GCM,
        CKM_DES_ECB,
        CKM_DES_CBC,
        CKM_DES3_ECB,
        CKM_DES3_CBC,
        CKM_DES3_CBC_PAD,
        CKM_DES3_CBC_PAD,
        CKM_RSA_PKCS,
        CKM_RSA_X_509,
    };
    static const size_t N = sizeof(mechs) / sizeof(mechs[0]);

    uint8_t sel   = data[0] % N;
    CK_MECHANISM_TYPE mtype = mechs[sel];
    int is_error_ctr = (sel == 5);
    int is_error_gcm = (sel == 6);

    int uses_des = (sel >= 7);
    int uses_rsa = (sel >= 13);
    int uses_8byte_iv = (sel == 8 || sel == 10 || sel == 11 || sel == 12);
    int needs_des_key = uses_des;

    if (aes_key == CK_INVALID_HANDLE) return 0;
    if (size < 17 && !uses_rsa) return 0;
    if (size < 2 && uses_rsa) return 0;

    if (needs_des_key) {
        ensure_des3_key();
        if (des3_key == CK_INVALID_HANDLE) return 0;
    }

    const uint8_t *iv_bytes = data + 1;
    const uint8_t *pt;
    size_t pt_len;

    if (uses_rsa) {
        pt = data + 1;
        pt_len = (size > 1) ? size - 1 : 0;
    } else if (uses_8byte_iv) {
        if (size < 9) return 0;
        pt = data + 9;
        pt_len = (size > 9) ? size - 9 : 0;
    } else {
        pt = data + 17;
        pt_len = (size > 17) ? size - 17 : 0;
    }

    CK_MECHANISM        mech = { mtype, NULL_PTR, 0 };
    CK_BYTE             iv[16];
    CK_AES_CTR_PARAMS   ctr_params;
    CK_GCM_PARAMS       gcm;
    CK_BYTE             gcm_iv[12], gcm_aad[16];
    CK_BYTE             des_iv[8];

    memcpy(iv, iv_bytes, 16);
    memcpy(des_iv, iv_bytes, 8);

    switch (mtype) {
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
        mech.pParameter    = iv;
        mech.ulParameterLen = 16;
        break;

    case CKM_AES_CTR:
        if (is_error_ctr) {
            ctr_params.ulCounterBits = (pt_len > 0) ? (uint8_t)pt[0] : 0;
            memcpy(ctr_params.cb, iv, 16);
            mech.pParameter    = &ctr_params;
            mech.ulParameterLen = sizeof(ctr_params);
            break;
        }
        ctr_params.ulCounterBits = 128;
        memcpy(ctr_params.cb, iv, 16);
        mech.pParameter    = &ctr_params;
        mech.ulParameterLen = sizeof(ctr_params);
        break;

    case CKM_AES_GCM:
        if (is_error_gcm) {
            memcpy(gcm_iv, iv_bytes, 12);
            memcpy(gcm_aad, iv_bytes + 4,
                   (size - 17 > 16) ? 16 : (size > 17 ? size - 17 : 0));
            gcm.pIv       = gcm_iv;
            gcm.ulIvLen   = 12;
            gcm.ulIvBits  = 96;
            gcm.pAAD      = gcm_aad;
            gcm.ulAADLen  = (pt_len > 0 && pt_len < 16) ? pt_len : 16;
            gcm.ulTagBits = (pt_len > 0) ? (uint8_t)pt[0] : 0;
            mech.pParameter    = &gcm;
            mech.ulParameterLen = sizeof(gcm);
            break;
        }
        memcpy(gcm_iv, iv_bytes, 12);
        memcpy(gcm_aad, iv_bytes + 4,
               (size - 17 > 16) ? 16 : (size > 17 ? size - 17 : 0));
        gcm.pIv       = gcm_iv;
        gcm.ulIvLen   = 12;
        gcm.ulIvBits  = 96;
        gcm.pAAD      = gcm_aad;
        gcm.ulAADLen  = (pt_len > 0 && pt_len < 16) ? pt_len : 16;
        gcm.ulTagBits = 128;
        mech.pParameter    = &gcm;
        mech.ulParameterLen = sizeof(gcm);
        break;

    case CKM_DES_CBC:
        mech.pParameter    = des_iv;
        mech.ulParameterLen = 8;
        break;

    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
        mech.pParameter    = des_iv;
        mech.ulParameterLen = 8;
        break;

    default: /* AES_ECB, DES_ECB, DES3_ECB */ break;
    }

    CK_OBJECT_HANDLE key;
    if (uses_des) {
        key = des3_key;
    } else if (uses_rsa) {
        key = rsa_pub;
    } else {
        key = aes_key;
    }
    if (key == CK_INVALID_HANDLE) return 0;

    CK_RV rv = p11->C_EncryptInit(sess, &mech, key);
    if (rv != CKR_OK) return 0;

    CK_BYTE  out[4096 + 16];
    CK_ULONG outlen = sizeof(out);
    p11->C_Encrypt(sess, (CK_BYTE_PTR)pt, (CK_ULONG)pt_len, out, &outlen);

    return 0;
}