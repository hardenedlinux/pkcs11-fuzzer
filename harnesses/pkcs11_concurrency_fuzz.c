/*
 * pkcs11_concurrency_fuzz.c — Parallel PKCS#11 workload for TSan and racey
 * teardown/state paths.
 *
 * The existing harnesses are almost entirely single-threaded. This harness
 * runs two worker threads in parallel, each opening a session and executing a
 * small operation chosen from the input. That gives the tsan build something
 * meaningful to observe.
 */
#include "common.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MAX_THREADS 2

typedef struct {
    CK_SLOT_ID slot;
    const uint8_t *data;
    size_t size;
    uint8_t op;
    uint8_t mode;
    pthread_barrier_t *barrier;
} worker_ctx_t;

static CK_SLOT_ID get_active_slot(void)
{
    CK_SESSION_INFO info;

    if (sess == CK_INVALID_HANDLE) return CK_INVALID_HANDLE;
    if (p11->C_GetSessionInfo(sess, &info) != CKR_OK) return CK_INVALID_HANDLE;
    return info.slotID;
}

static CK_OBJECT_HANDLE pick_key(uint8_t which)
{
    switch (which % 4) {
    case 0: return rsa_priv;
    case 1: return ec_priv;
    case 2: return aes_key;
    default: return hmac_key;
    }
}

static void *worker_main(void *arg)
{
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    CK_SESSION_HANDLE local = CK_INVALID_HANDLE;
    CK_FLAGS flags = CKF_SERIAL_SESSION;
    CK_RV rv;

    if (ctx->slot == CK_INVALID_HANDLE) return NULL;
    if (ctx->mode & 1) flags |= CKF_RW_SESSION;

    rv = p11->C_OpenSession(ctx->slot, flags, NULL_PTR, NULL_PTR, &local);
    if (rv != CKR_OK || local == CK_INVALID_HANDLE) {
        pthread_barrier_wait(ctx->barrier);
        return NULL;
    }

    if (ctx->mode & 2) {
        CK_UTF8CHAR pin[16];
        CK_ULONG pin_len = (ctx->size < sizeof(pin)) ? (CK_ULONG)ctx->size : (CK_ULONG)sizeof(pin);

        memset(pin, 0, sizeof(pin));
        if (pin_len > 0) memcpy(pin, ctx->data, pin_len);
        p11->C_Login(local, CKU_USER, pin, pin_len);
    } else {
        p11->C_Login(local, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
    }

    pthread_barrier_wait(ctx->barrier);

    switch (ctx->op % 8) {
    case 0: {
        CK_INFO info;
        CK_TOKEN_INFO ti;
        p11->C_GetInfo(&info);
        p11->C_GetTokenInfo(ctx->slot, &ti);
        break;
    }

    case 1: {
        CK_MECHANISM mech = { CKM_SHA256, NULL_PTR, 0 };
        CK_BYTE out[32];
        CK_ULONG out_len = sizeof(out);

        if (p11->C_DigestInit(local, &mech) == CKR_OK) {
            if (ctx->size > 0) p11->C_DigestUpdate(local, (CK_BYTE_PTR)ctx->data, (CK_ULONG)ctx->size);
            p11->C_DigestFinal(local, out, &out_len);
        }
        break;
    }

    case 2: {
        CK_OBJECT_HANDLE key = pick_key(ctx->mode);
        CK_MECHANISM mech;
        CK_BYTE sig[512];
        CK_ULONG sig_len = sizeof(sig);

        if (key == rsa_priv) {
            mech = (CK_MECHANISM){ CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
        } else if (key == ec_priv) {
            mech = (CK_MECHANISM){ CKM_ECDSA_SHA256, NULL_PTR, 0 };
        } else if (key == hmac_key) {
            mech = (CK_MECHANISM){ CKM_SHA256_HMAC, NULL_PTR, 0 };
        } else {
            break;
        }

        if (p11->C_SignInit(local, &mech, key) == CKR_OK) {
            p11->C_Sign(local,
                        (CK_BYTE_PTR)ctx->data,
                        (CK_ULONG)ctx->size,
                        sig,
                        &sig_len);
        }
        break;
    }

    case 3: {
        CK_OBJECT_CLASS cls = (ctx->mode & 1) ? CKO_SECRET_KEY : CKO_PRIVATE_KEY;
        CK_BYTE id = (ctx->mode % 4) + 1;
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_ID, &id, sizeof(id) },
        };
        CK_OBJECT_HANDLE objs[8];
        CK_ULONG found = 0;

        if (p11->C_FindObjectsInit(local, tmpl, 2) == CKR_OK) {
            p11->C_FindObjects(local, objs, 8, &found);
            p11->C_FindObjectsFinal(local);
        }
        break;
    }

    case 4: {
        CK_BYTE out[128];
        CK_ULONG out_len = (ctx->size > sizeof(out)) ? sizeof(out) : (CK_ULONG)ctx->size;
        p11->C_GenerateRandom(local, out, out_len);
        p11->C_SeedRandom(local, (CK_BYTE_PTR)ctx->data, (CK_ULONG)ctx->size);
        break;
    }

    case 5: {
        CK_SESSION_INFO info;
        p11->C_Logout(local);
        p11->C_GetSessionInfo(local, &info);
        p11->C_Login(local, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
        break;
    }

    case 6: {
        CK_OBJECT_CLASS cls = CKO_DATA;
        CK_BBOOL token = CK_FALSE;
        CK_BBOOL priv = CK_FALSE;
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS, &cls, sizeof(cls) },
            { CKA_TOKEN, &token, sizeof(token) },
            { CKA_PRIVATE, &priv, sizeof(priv) },
            { CKA_VALUE, (CK_VOID_PTR)ctx->data, (CK_ULONG)ctx->size },
        };

        if (p11->C_CreateObject(local, tmpl, 4, &obj) == CKR_OK && obj != CK_INVALID_HANDLE) {
            p11->C_DestroyObject(local, obj);
        }
        break;
    }

    case 7: {
        CK_MECHANISM mech;
        CK_BYTE iv[16] = {0};
        CK_BYTE out[512];
        CK_ULONG out_len = sizeof(out);

        if (ctx->size >= sizeof(iv)) memcpy(iv, ctx->data, sizeof(iv));
        mech.mechanism = (ctx->mode & 1) ? CKM_AES_CBC : CKM_AES_GCM;
        if (mech.mechanism == CKM_AES_CBC) {
            mech.pParameter = iv;
            mech.ulParameterLen = sizeof(iv);
        } else {
            CK_GCM_PARAMS gcm = {
                iv,
                sizeof(iv),
                sizeof(iv) * 8,
                NULL_PTR,
                0,
                128,
            };
            mech.pParameter = &gcm;
            mech.ulParameterLen = sizeof(gcm);
            p11->C_EncryptInit(local, &mech, aes_key);
            p11->C_Encrypt(local,
                           (CK_BYTE_PTR)ctx->data,
                           (CK_ULONG)ctx->size,
                           out,
                           &out_len);
            break;
        }

        p11->C_EncryptInit(local, &mech, aes_key);
        p11->C_Encrypt(local,
                       (CK_BYTE_PTR)ctx->data,
                       (CK_ULONG)ctx->size,
                       out,
                       &out_len);
        break;
    }
    }

    p11->C_CloseSession(local);
    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    pkcs11_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pthread_t threads[MAX_THREADS];
    worker_ctx_t ctx[MAX_THREADS];
    pthread_barrier_t barrier;
    CK_SLOT_ID slot;

    if (size < MAX_THREADS * 2) return 0;

    slot = get_active_slot();
    if (slot == CK_INVALID_HANDLE) return 0;

    if (pthread_barrier_init(&barrier, NULL, MAX_THREADS) != 0) {
        return 0;
    }

    for (size_t i = 0; i < MAX_THREADS; i++) {
        size_t start = 2 + i * ((size - 2) / MAX_THREADS);
        size_t end = (i + 1 == MAX_THREADS) ? size : 2 + (i + 1) * ((size - 2) / MAX_THREADS);

        ctx[i].slot = slot;
        ctx[i].op = data[i * 2];
        ctx[i].mode = data[i * 2 + 1];
        ctx[i].data = data + start;
        ctx[i].size = (end > start) ? (end - start) : 0;
        ctx[i].barrier = &barrier;
        pthread_create(&threads[i], NULL, worker_main, &ctx[i]);
    }

    for (size_t i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_barrier_destroy(&barrier);

    p11->C_Login(sess, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
    return 0;
}
