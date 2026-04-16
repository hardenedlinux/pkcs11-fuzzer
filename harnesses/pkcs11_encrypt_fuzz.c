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
 * Mechanisms:
 *   0  CKM_AES_ECB      (no IV; plaintext zero-padded to 16-byte boundary)
 *   1  CKM_AES_CBC      (16-byte IV from bytes 1-16)
 *   2  CKM_AES_CBC_PAD  (16-byte IV from bytes 1-16, PKCS#7 pad applied)
 *   3  CKM_AES_CTR      (16-byte counter block from bytes 1-16, 128-bit counter)
 *   4  CKM_AES_GCM      (12-byte IV + fuzzed AAD)
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
    if (size < 17 || aes_key == CK_INVALID_HANDLE) return 0;

    static const CK_MECHANISM_TYPE mechs[] = {
        CKM_AES_ECB,
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_CTR,
        CKM_AES_GCM,
    };
    static const size_t N = sizeof(mechs) / sizeof(mechs[0]);

    uint8_t sel   = data[0] % N;
    CK_MECHANISM_TYPE mtype = mechs[sel];

    const uint8_t *iv_bytes = data + 1;         /* up to 16 bytes of IV/CTR */
    const uint8_t *pt       = data + 17;
    size_t         pt_len   = size - 17;

    CK_MECHANISM        mech = { mtype, NULL_PTR, 0 };
    CK_BYTE             iv[16];
    CK_AES_CTR_PARAMS   ctr_params;
    CK_GCM_PARAMS       gcm;
    CK_BYTE             gcm_iv[12], gcm_aad[16];

    memcpy(iv, iv_bytes, 16);

    switch (mtype) {
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
        mech.pParameter    = iv;
        mech.ulParameterLen = 16;
        break;

    case CKM_AES_CTR:
        ctr_params.ulCounterBits = 128;
        memcpy(ctr_params.cb, iv, 16);
        mech.pParameter    = &ctr_params;
        mech.ulParameterLen = sizeof(ctr_params);
        break;

    case CKM_AES_GCM:
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

    default: /* CKM_AES_ECB */ break;
    }

    CK_RV rv = p11->C_EncryptInit(sess, &mech, aes_key);
    if (rv != CKR_OK) return 0;

    /* Output buffer: plaintext + 16-byte tag headroom */
    CK_BYTE  out[4096 + 16];
    CK_ULONG outlen = sizeof(out);
    p11->C_Encrypt(sess, (CK_BYTE_PTR)pt, (CK_ULONG)pt_len, out, &outlen);

    return 0;
}
