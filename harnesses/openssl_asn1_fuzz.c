/*
 * openssl_asn1_fuzz.c — Fuzz various OpenSSL ASN.1 parsers using ASN1_item_d2i.
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
};

#define NUM_ITEMS (sizeof(items) / sizeof(items[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    uint8_t item_idx = data[0] % NUM_ITEMS;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    ASN1_VALUE *val = NULL;
    const unsigned char *p = payload;
    
    val = ASN1_item_d2i(NULL, &p, payload_len, items[item_idx]());
    if (val) {
        ASN1_item_free(val, items[item_idx]());
    }

    ERR_clear_error();
    return 0;
}
