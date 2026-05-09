/*
 * openssl_asn1_fuzz.c — Fuzz various OpenSSL ASN.1 parsers and encoders.
 */
#include "common.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/dh.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef const ASN1_ITEM *(*asn1_item_fn)(void);

static const asn1_item_fn items[] = {
    ASN1_ITEM_ref(X509),
    ASN1_ITEM_ref(X509_CRL),
    ASN1_ITEM_ref(X509_REQ),
    ASN1_ITEM_ref(X509_SIG),
    ASN1_ITEM_ref(PKCS7),
    ASN1_ITEM_ref(PKCS8_PRIV_KEY_INFO),
    ASN1_ITEM_ref(RSAPublicKey),
    ASN1_ITEM_ref(RSAPrivateKey),
    ASN1_ITEM_ref(OCSP_REQUEST),
    ASN1_ITEM_ref(OCSP_RESPONSE),
    ASN1_ITEM_ref(CMS_ContentInfo),
    ASN1_ITEM_ref(PKCS12),
    ASN1_ITEM_ref(DHparams),
    ASN1_ITEM_ref(X509_EXTENSIONS),
};

#define NUM_ITEMS (sizeof(items) / sizeof(items[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;

    uint8_t op = data[0] % 4;
    uint8_t item_idx = data[1] % NUM_ITEMS;
    const uint8_t *payload = data + 2;
    size_t payload_len = size - 2;

    ASN1_VALUE *val = NULL;
    const unsigned char *p = payload;

    if (op == 0) {
        val = ASN1_item_d2i(NULL, &p, payload_len, items[item_idx]());
        if (val) {
            ASN1_item_free(val, items[item_idx]());
        }
    } else if (op == 1) {
        val = ASN1_item_d2i(NULL, &p, payload_len, items[item_idx]());
        if (val) {
            unsigned char *out = NULL;
            int len = ASN1_item_i2d(val, &out, items[item_idx]());
            if (len > 0 && out) {
                OPENSSL_free(out);
            }
            ASN1_item_free(val, items[item_idx]());
        }
    } else if (op == 2) {
        val = ASN1_item_d2i(NULL, &p, payload_len, items[item_idx]());
        if (val) {
            unsigned char *out = NULL;
            int len = ASN1_item_i2d(val, &out, items[item_idx]());
            if (len > 0 && out) {
                const unsigned char *p2 = out;
                ASN1_VALUE *v2 = ASN1_item_d2i(NULL, &p2, len, items[item_idx]());
                if (v2) ASN1_item_free(v2, items[item_idx]());
                OPENSSL_free(out);
            }
            ASN1_item_free(val, items[item_idx]());
        }
    } else {
        val = ASN1_item_d2i(NULL, &p, payload_len, items[item_idx]());
        if (val) {
            BIO *bio = BIO_new(BIO_s_mem());
            if (bio) {
                ASN1_item_print(bio, val, 0, items[item_idx](), NULL);
                BIO_free(bio);
            }
            ASN1_item_free(val, items[item_idx]());
        }
    }

    ERR_clear_error();
    return 0;
}
