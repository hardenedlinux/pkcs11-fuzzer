/*
 * tls_pkcs11_fuzz.c — Fuzz TLS handshake data when the server private key
 *                     is held in SoftHSM2 via the libp11 OpenSSL engine.
 *
 * Architecture:
 *   - LLVMFuzzerInitialize: load libp11 engine, create SSL_CTX with
 *     PKCS#11-backed RSA private key, create a BIO pair for I/O.
 *   - LLVMFuzzerTestOneInput: feed fuzz bytes as "client TLS data" into the
 *     BIO, call SSL_accept (server side), read any response, reset state.
 *
 * This tests the path:
 *   fuzzed TLS record → OpenSSL parsing → signature call → libp11 engine
 *   → C_SignInit/C_Sign → SoftHSM2 → RSA-2048 private key
 *
 * Note: The server SSL object is recreated on each iteration to avoid
 * state accumulation.  The SSL_CTX (with loaded engine and key) is cached.
 */
#include "common.h"

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

static SSL_CTX *g_ctx = NULL;

/* ---------------------------------------------------------------------------
 * load_pkcs11_engine()
 *
 * Loads the libp11 engine and configures it to use our SoftHSM2 module.
 * Returns the loaded ENGINE or NULL on failure.
 * --------------------------------------------------------------------------- */
static ENGINE *load_pkcs11_engine(const char *engine_path,
                                   const char *module_path,
                                   const char *pin)
{
    ENGINE_load_dynamic();
    ENGINE *e = ENGINE_by_id("dynamic");
    if (!e) return NULL;

    ENGINE_ctrl_cmd_string(e, "SO_PATH",    engine_path, 0);
    ENGINE_ctrl_cmd_string(e, "ID",         "pkcs11",    0);
    ENGINE_ctrl_cmd_string(e, "LIST_ADD",   "1",         0);
    ENGINE_ctrl_cmd_string(e, "LOAD",       NULL,        0);

    /* Reload by the pkcs11 id */
    ENGINE_free(e);
    e = ENGINE_by_id("pkcs11");
    if (!e) return NULL;

    ENGINE_ctrl_cmd_string(e, "MODULE_PATH", module_path, 0);
    ENGINE_ctrl_cmd_string(e, "PIN",         pin,         0);

    if (!ENGINE_init(e)) {
        ENGINE_free(e);
        return NULL;
    }
    return e;
}

/* ---------------------------------------------------------------------------
 * Self-signed certificate for the fuzz server
 * (Generated once and reused; signing uses OpenSSL's software key, not PKCS#11.
 *  The PKCS#11 key is only used for the TLS handshake's CertificateVerify.)
 * --------------------------------------------------------------------------- */
static X509 *g_cert = NULL;

static X509 *make_selfsigned_cert(EVP_PKEY *pkey)
{
    X509 *x = X509_new();
    if (!x) return NULL;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x),  365 * 24 * 3600);
    X509_set_pubkey(x, pkey);

    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"fuzz-server", -1, -1, 0);
    X509_set_issuer_name(x, name);

    /* Sign with the SAME pkey — OK for TLS fuzz purposes */
    X509_sign(x, pkey, EVP_sha256());
    return x;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;

    /* Set up PKCS#11 token */
    pkcs11_init();

    /* Suppress OpenSSL error queue noise during fuzzing */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
                     | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

#ifndef ENGINE_PATH
#  error "ENGINE_PATH must be defined via -DENGINE_PATH=..."
#endif
#ifndef SOFTHSM2_MODULE_PATH
#  error "SOFTHSM2_MODULE_PATH must be defined via -DSOFTHSM2_MODULE_PATH=..."
#endif

    /* Load libp11 engine */
    ENGINE *eng = load_pkcs11_engine(ENGINE_PATH,
                                      SOFTHSM2_MODULE_PATH,
                                      "1234");
    /* Declare pkey before any goto so C++ does not complain about
     * jumping over a variable initialization. */
    EVP_PKEY *pkey = NULL;

    if (!eng) {
        fprintf(stderr, "[tls] Failed to load pkcs11 engine\n");
        /* Continue without engine — harness still exercises TLS parsing */
        goto no_engine;
    }

    /* Load private key via PKCS#11 URI */
    pkey = ENGINE_load_private_key(
        eng,
        "pkcs11:token=fuzz-token;id=%01;pin-value=1234",
        NULL, NULL);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        ENGINE_finish(eng);
        ENGINE_free(eng);
        goto no_engine;
    }

    /* Create self-signed cert */
    g_cert = make_selfsigned_cert(pkey);
    if (!g_cert) goto no_engine;

    /* Build SSL_CTX */
    g_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ctx) goto no_engine;

    SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
    SSL_CTX_use_PrivateKey(g_ctx, pkey);
    SSL_CTX_use_certificate(g_ctx, g_cert);
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
    EVP_PKEY_free(pkey);
    ENGINE_finish(eng);
    ENGINE_free(eng);
    return 0;

no_engine:
    /* Fallback: build ctx without PKCS#11 key (still exercises TLS parsing) */
    g_ctx = SSL_CTX_new(TLS_server_method());
    if (g_ctx)
        SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_ctx || size == 0) return 0;

    /* Create a memory BIO pair: client_bio ← fuzz data, server reads from it */
    BIO *rbio = BIO_new_mem_buf(data, (int)size);
    BIO *wbio = BIO_new(BIO_s_mem());
    if (!rbio || !wbio) {
        BIO_free(rbio);
        BIO_free(wbio);
        return 0;
    }

    SSL *ssl = SSL_new(g_ctx);
    if (!ssl) {
        BIO_free(rbio);
        BIO_free(wbio);
        return 0;
    }

    SSL_set_bio(ssl, rbio, wbio);  /* ssl owns rbio and wbio now */
    SSL_set_accept_state(ssl);

    /* Attempt the handshake — will likely fail with garbage input */
    SSL_do_handshake(ssl);

    /* Drain any output the server generated (and discard it) */
    char buf[4096];
    while (BIO_read(wbio, buf, sizeof(buf)) > 0);

    SSL_free(ssl);
    ERR_clear_error();
    return 0;
}
