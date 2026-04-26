/*
 * openssl_x509_store_fuzz.c — Fuzz OpenSSL X509 parsing, chain verification,
 * and OSSL_STORE (including PKCS#11 URIs).
 */
#include "common.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/store.h>
#include <openssl/engine.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static ENGINE *g_eng = NULL;

static ENGINE *load_pkcs11_engine(const char *engine_path,
                                  const char *module_path,
                                  const char *pin)
{
    ENGINE_load_dynamic();
    ENGINE *e = ENGINE_by_id("dynamic");
    if (!e) return NULL;

    ENGINE_ctrl_cmd_string(e, "SO_PATH", engine_path, 0);
    ENGINE_ctrl_cmd_string(e, "ID", "pkcs11", 0);
    ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0);
    ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);

    ENGINE_free(e);
    e = ENGINE_by_id("pkcs11");
    if (!e) return NULL;

    ENGINE_ctrl_cmd_string(e, "MODULE_PATH", module_path, 0);
    ENGINE_ctrl_cmd_string(e, "PIN", pin, 0);

    if (!ENGINE_init(e)) {
        ENGINE_free(e);
        return NULL;
    }
    return e;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    pkcs11_init();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

#ifndef ENGINE_PATH
#error "ENGINE_PATH must be defined via -DENGINE_PATH=..."
#endif
#ifndef SOFTHSM2_MODULE_PATH
#error "SOFTHSM2_MODULE_PATH must be defined via -DSOFTHSM2_MODULE_PATH=..."
#endif

    g_eng = load_pkcs11_engine(ENGINE_PATH, SOFTHSM2_MODULE_PATH, "1234");
    
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;

    uint8_t op = data[0] % 4;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (op) {
    case 0: { /* Fuzz X509 parsing */
        const uint8_t *p = payload;
        X509 *x509 = d2i_X509(NULL, &p, payload_len);
        if (x509) {
            X509_free(x509);
        }
        break;
    }
    case 1: { /* Fuzz X509 Store / Verification */
        X509_STORE *st = X509_STORE_new();
        if (st) {
            const uint8_t *p = payload;
            X509 *x509 = d2i_X509(NULL, &p, payload_len);
            if (x509) {
                X509_STORE_add_cert(st, x509);
                X509_free(x509);
            }
            X509_STORE_free(st);
        }
        break;
    }
    case 2: { /* Fuzz OSSL_STORE with PKCS#11 URI */
        /* Use the payload as a potential URI or URI suffix */
        char uri[256];
        if (payload_len > 200) payload_len = 200;
        snprintf(uri, sizeof(uri), "pkcs11:%.*s", (int)payload_len, (const char *)payload);
        
        OSSL_STORE_CTX *sctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
        if (sctx) {
            while (!OSSL_STORE_eof(sctx)) {
                OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
                if (info) OSSL_STORE_INFO_free(info);
                else break;
            }
            OSSL_STORE_close(sctx);
        }
        break;
    }
    case 3: { /* Fuzz OSSL_STORE with raw data via BIO */
        BIO *bio = BIO_new_mem_buf(payload, payload_len);
        if (bio) {
            OSSL_STORE_CTX *sctx = OSSL_STORE_attach(bio, "file", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            if (sctx) {
                while (!OSSL_STORE_eof(sctx)) {
                    OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
                    if (info) OSSL_STORE_INFO_free(info);
                    else break;
                }
                OSSL_STORE_close(sctx);
                /* bio is owned and freed by OSSL_STORE_close */
            } else {
                BIO_free(bio);
            }
        }
        break;
    }
    }

    ERR_clear_error();
    return 0;
}
