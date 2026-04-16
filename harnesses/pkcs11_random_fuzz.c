/*
 * pkcs11_random_fuzz.c — Fuzz C_GenerateRandom, C_SeedRandom,
 *                        C_GetSessionInfo, and C_GetObjectSize.
 *
 * All four functions are implemented in SoftHSM2 but uncalled by any other
 * harness.  They are individually simple but exercise distinct code paths:
 *   C_GenerateRandom  — DRBG output path, length validation
 *   C_SeedRandom      — DRBG seed injection
 *   C_GetSessionInfo  — session state struct marshalling
 *   C_GetObjectSize   — object storage size query on each token key
 *
 * Input layout:
 *   byte 0:   operation selector (0-3)
 *   byte 1+:  operation-specific payload
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

    uint8_t sel = data[0] % 4;
    const uint8_t *pay  = payload_ptr(data, size);
    size_t         plen = payload_len(size);

    switch (sel) {
    case 0: {
        /* C_GenerateRandom: length derived from first payload byte (1-256) */
        CK_ULONG len = (plen > 0) ? ((CK_ULONG)pay[0] % 256) + 1 : 32;
        CK_BYTE  buf[256];
        p11->C_GenerateRandom(sess, buf, len);
        break;
    }
    case 1:
        /* C_SeedRandom: seed with raw fuzz bytes */
        p11->C_SeedRandom(sess, (CK_BYTE_PTR)pay, (CK_ULONG)plen);
        break;

    case 2: {
        /* C_GetSessionInfo */
        CK_SESSION_INFO info;
        p11->C_GetSessionInfo(sess, &info);
        break;
    }
    case 3: {
        /* C_GetObjectSize on all known token objects */
        static const CK_OBJECT_HANDLE *objs[] = {
            &rsa_priv, &rsa_pub, &ec_priv, &ec_pub, &aes_key, &hmac_key
        };
        static const size_t nobjs = sizeof(objs) / sizeof(objs[0]);
        size_t idx = (plen > 0) ? pay[0] % nobjs : 0;
        CK_ULONG obj_size;
        p11->C_GetObjectSize(sess, *objs[idx], &obj_size);
        break;
    }
    }

    return 0;
}
