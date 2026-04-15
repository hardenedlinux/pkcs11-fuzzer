/*
 * pkcs11_digest_fuzz.c — Fuzz C_Digest and multi-part C_DigestUpdate/Final.
 *
 * These operations exercise SoftHSM2's hash implementation wrappers and the
 * OpenSSL digest EVP layer underneath.  Multi-part updates exercise the
 * streaming buffer management code that is not reached by C_Sign (which
 * hashes internally) or by single-part C_Digest.
 *
 * Input layout:
 *   byte 0:    mechanism selector (0–7, see table)
 *   byte 1:    number of C_DigestUpdate chunks for multi-part ops (1–8)
 *   byte 2...: data payload — split into chunks by dividing evenly
 *
 * Mechanisms / modes:
 *   0  CKM_SHA_1   single-part C_Digest
 *   1  CKM_SHA256  single-part C_Digest
 *   2  CKM_SHA384  single-part C_Digest
 *   3  CKM_SHA512  single-part C_Digest
 *   4  CKM_MD5     single-part C_Digest
 *   5  CKM_SHA_1   multi-part  C_DigestUpdate × N + C_DigestFinal
 *   6  CKM_SHA256  multi-part  C_DigestUpdate × N + C_DigestFinal
 *   7  CKM_SHA512  multi-part  C_DigestUpdate × N + C_DigestFinal
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
    if (size < 2) return 0;

    static const CK_MECHANISM_TYPE mechs[] = {
        CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_MD5,  /* single */
        CKM_SHA_1, CKM_SHA256, CKM_SHA512,                         /* multi  */
    };
    static const size_t N = sizeof(mechs) / sizeof(mechs[0]);

    uint8_t sel      = data[0] % N;
    uint8_t nchunks  = (data[1] % 8) + 1;   /* 1–8 chunks */
    int     multipart = (sel >= 5);

    CK_MECHANISM_TYPE mtype = mechs[sel];
    CK_MECHANISM mech = { mtype, NULL_PTR, 0 };

    const uint8_t *pay  = data + 2;
    size_t         plen = (size > 2) ? size - 2 : 0;

    CK_RV rv = p11->C_DigestInit(sess, &mech);
    if (rv != CKR_OK) return 0;

    if (!multipart) {
        /* Single-part digest */
        CK_BYTE  digest[64];
        CK_ULONG dlen = sizeof(digest);
        p11->C_Digest(sess, (CK_BYTE_PTR)pay, (CK_ULONG)plen, digest, &dlen);
    } else {
        /* Multi-part: divide payload into nchunks equal parts */
        size_t chunk = (plen > 0) ? (plen + nchunks - 1) / nchunks : 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks; i++) {
            size_t this_chunk = (off + chunk <= plen) ? chunk : plen - off;
            p11->C_DigestUpdate(sess,
                                (CK_BYTE_PTR)(pay + off),
                                (CK_ULONG)this_chunk);
            off += this_chunk;
            if (off >= plen) break;
        }
        CK_BYTE  digest[64];
        CK_ULONG dlen = sizeof(digest);
        p11->C_DigestFinal(sess, digest, &dlen);
    }

    return 0;
}
