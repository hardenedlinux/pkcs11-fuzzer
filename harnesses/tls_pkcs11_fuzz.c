/*
 * tls_pkcs11_fuzz.c — Drive a client/server TLS state machine where the server
 * private key lives in SoftHSM2 via the libp11 OpenSSL engine.
 *
 * Instead of feeding one raw record into SSL_accept(), this harness uses a
 * scripted sequence of SSL_do_handshake/SSL_write_ex/SSL_read_ex/shutdown calls
 * across both peers. That reaches much more of OpenSSL's handshake and record
 * logic while still exercising PKCS#11-backed server signatures.
 */
#include "common.h"

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MAX_STEPS 48
#define MAX_IO_CHUNK 256

static SSL_CTX *g_server_ctx = NULL;
static SSL_CTX *g_client_ctx = NULL;
static X509 *g_cert = NULL;

static uint8_t take_u8(const uint8_t *data, size_t size, size_t *off)
{
    if (*off >= size) return 0;
    return data[(*off)++];
}

/* ---------------------------------------------------------------------------
 * load_pkcs11_engine()
 * --------------------------------------------------------------------------- */
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

static X509 *make_selfsigned_cert(EVP_PKEY *pkey)
{
    X509 *x = X509_new();
    if (!x) return NULL;

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 365 * 24 * 3600);
    X509_set_pubkey(x, pkey);

    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"fuzz-server", -1, -1, 0);
    X509_set_issuer_name(x, name);

    X509_sign(x, pkey, EVP_sha256());
    return x;
}

static void configure_ssl(SSL *ssl, uint8_t cfg, int is_server)
{
    int min_version = (cfg & 1) ? TLS1_3_VERSION : TLS1_2_VERSION;

    SSL_set_min_proto_version(ssl, min_version);
    if (cfg & 2) SSL_set_options(ssl, SSL_OP_NO_TICKET);
    if (cfg & 4) SSL_set_options(ssl, SSL_OP_NO_COMPRESSION);
    if (cfg & 8) SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (!is_server && (cfg & 16)) SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    SSL_set_read_ahead(ssl, (cfg & 32) ? 1 : 0);
}

static void drain_peer(SSL *ssl)
{
    unsigned char tmp[MAX_IO_CHUNK];
    size_t out_len = 0;

    while (SSL_has_pending(ssl) || SSL_pending(ssl) > 0) {
        if (SSL_read_ex(ssl, tmp, sizeof(tmp), &out_len) != 1 || out_len == 0) {
            break;
        }
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    pkcs11_init();
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

#ifndef ENGINE_PATH
#error "ENGINE_PATH must be defined via -DENGINE_PATH=..."
#endif
#ifndef SOFTHSM2_MODULE_PATH
#error "SOFTHSM2_MODULE_PATH must be defined via -DSOFTHSM2_MODULE_PATH=..."
#endif

    ENGINE *eng = load_pkcs11_engine(ENGINE_PATH, SOFTHSM2_MODULE_PATH, "1234");
    EVP_PKEY *pkey = NULL;

    if (eng) {
        pkey = ENGINE_load_private_key(
            eng,
            "pkcs11:token=fuzz-token;id=%01;pin-value=1234",
            NULL,
            NULL);
    }

    if (pkey) {
        g_cert = make_selfsigned_cert(pkey);
        g_server_ctx = SSL_CTX_new(TLS_server_method());
        if (g_server_ctx && g_cert) {
            SSL_CTX_set_min_proto_version(g_server_ctx, TLS1_2_VERSION);
            SSL_CTX_set_verify(g_server_ctx, SSL_VERIFY_NONE, NULL);
            SSL_CTX_use_PrivateKey(g_server_ctx, pkey);
            SSL_CTX_use_certificate(g_server_ctx, g_cert);
        }
        EVP_PKEY_free(pkey);
    }

    if (eng) {
        ENGINE_finish(eng);
        ENGINE_free(eng);
    }

    if (!g_server_ctx) {
        g_server_ctx = SSL_CTX_new(TLS_server_method());
        if (g_server_ctx) SSL_CTX_set_verify(g_server_ctx, SSL_VERIFY_NONE, NULL);
    }

    g_client_ctx = SSL_CTX_new(TLS_client_method());
    if (g_client_ctx) {
        SSL_CTX_set_min_proto_version(g_client_ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(g_client_ctx, SSL_VERIFY_NONE, NULL);
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    SSL *server = NULL;
    SSL *client = NULL;
    BIO *server_bio = NULL;
    BIO *client_bio = NULL;
    size_t off = 0;

    if (!g_server_ctx || !g_client_ctx || size < 2) return 0;

    server = SSL_new(g_server_ctx);
    client = SSL_new(g_client_ctx);
    if (!server || !client) goto out;

    if (BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) != 1) goto out;

    SSL_set_bio(server, server_bio, server_bio);
    SSL_set_bio(client, client_bio, client_bio);
    server_bio = NULL;
    client_bio = NULL;

    SSL_set_accept_state(server);
    SSL_set_connect_state(client);
    configure_ssl(server, take_u8(data, size, &off), 1);
    configure_ssl(client, take_u8(data, size, &off), 0);

    for (size_t step = 0; step < MAX_STEPS && off < size; step++) {
        unsigned char buf[MAX_IO_CHUNK];
        size_t io_len = 0;
        size_t chunk;
        uint8_t op = take_u8(data, size, &off) % 10;

        switch (op) {
        case 0:
            SSL_do_handshake(client);
            break;
        case 1:
            SSL_do_handshake(server);
            break;
        case 2:
            chunk = take_u8(data, size, &off) % MAX_IO_CHUNK;
            if (chunk > size - off) chunk = size - off;
            SSL_write_ex(client, data + off, chunk, &io_len);
            off += chunk;
            break;
        case 3:
            SSL_read_ex(server, buf, sizeof(buf), &io_len);
            break;
        case 4:
            chunk = take_u8(data, size, &off) % MAX_IO_CHUNK;
            if (chunk > size - off) chunk = size - off;
            SSL_write_ex(server, data + off, chunk, &io_len);
            off += chunk;
            break;
        case 5:
            SSL_read_ex(client, buf, sizeof(buf), &io_len);
            break;
        case 6:
            if (take_u8(data, size, &off) & 1) {
                SSL_shutdown(client);
            } else {
                SSL_shutdown(server);
            }
            break;
        case 7:
            drain_peer(server);
            drain_peer(client);
            break;
        case 8:
            SSL_peek_ex((take_u8(data, size, &off) & 1) ? client : server,
                        buf,
                        sizeof(buf),
                        &io_len);
            break;
        case 9:
            SSL_get_error((take_u8(data, size, &off) & 1) ? client : server, 0);
            break;
        }
    }

out:
    SSL_free(client);
    SSL_free(server);
    BIO_free(client_bio);
    BIO_free(server_bio);
    ERR_clear_error();
    return 0;
}
