/*
 * openssl_cms_fuzz.c — Fuzz OpenSSL CMS (Cryptographic Message Syntax)
 * using PKCS#11 keys via libp11.
 */
#include "common.h"

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static ENGINE *g_eng = NULL;
static EVP_PKEY *g_rsa_priv = NULL;
static EVP_PKEY *g_rsa_pub = NULL;
static X509 *g_cert_rsa = NULL;

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
                               (const unsigned char *)"fuzz-cms-server", -1, -1, 0);
    X509_set_issuer_name(x, name);

    X509_sign(x, pkey, EVP_sha256());
    return x;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    pkcs11_init();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

#ifndef ENGINE_PATH
#error "ENGINE_PATH must be defined via -DENGINE_PATH=..."
#endif
#ifndef SOFTHSM2_MODULE_PATH
#error "SOFTHSM2_MODULE_PATH must be defined via -DSOFTHSM2_MODULE_PATH=..."
#endif

    g_eng = load_pkcs11_engine(ENGINE_PATH, SOFTHSM2_MODULE_PATH, "1234");
    if (!g_eng) return 0;

    g_rsa_priv = ENGINE_load_private_key(g_eng, "pkcs11:token=fuzz-token;id=%01;pin-value=1234", NULL, NULL);
    g_rsa_pub  = ENGINE_load_public_key(g_eng, "pkcs11:token=fuzz-token;id=%01;pin-value=1234", NULL, NULL);

    if (g_rsa_priv) {
        g_cert_rsa = make_selfsigned_cert(g_rsa_priv);
    }

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || !g_rsa_priv || !g_cert_rsa) return 0;

    uint8_t op = data[0] % 4;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    BIO *in = BIO_new_mem_buf(payload, payload_len);
    BIO *out = BIO_new(BIO_s_mem());
    CMS_ContentInfo *cms = NULL;

    switch (op) {
    case 0: /* CMS Sign */
        cms = CMS_sign(g_cert_rsa, g_rsa_priv, NULL, in, CMS_BINARY);
        if (cms) {
            i2d_CMS_bio(out, cms);
        }
        break;

    case 1: /* CMS Verify (fuzzed content) */
        /* This probably won't verify, but exercises the parser */
        cms = d2i_CMS_bio(in, NULL);
        if (cms) {
            CMS_verify(cms, NULL, NULL, NULL, out, CMS_BINARY);
        }
        break;

    case 2: /* CMS Encrypt */
    {
        STACK_OF(X509) *certs = sk_X509_new_null();
        sk_X509_push(certs, g_cert_rsa);
        cms = CMS_encrypt(certs, in, EVP_aes_128_cbc(), CMS_BINARY);
        if (cms) {
            i2d_CMS_bio(out, cms);
        }
        sk_X509_free(certs);
    }
        break;

    case 3: /* CMS Decrypt (fuzzed content) */
        cms = d2i_CMS_bio(in, NULL);
        if (cms) {
            CMS_decrypt(cms, g_rsa_priv, g_cert_rsa, NULL, out, CMS_BINARY);
        }
        break;
    }

    CMS_ContentInfo_free(cms);
    BIO_free(in);
    BIO_free(out);
    ERR_clear_error();

    return 0;
}
