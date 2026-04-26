/*
 * openssl_conf_fuzz.c — Fuzz OpenSSL configuration file parser.
 */
#include "common.h"

#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    BIO *bio = BIO_new_mem_buf(data, size);
    if (!bio) return 0;

    CONF *conf = NCONF_new(NULL);
    if (conf) {
        /* Fuzz the configuration parser */
        NCONF_load_bio(conf, bio, NULL);
        
        /* Optionally try to get some values */
        char *v = NCONF_get_string(conf, "default", "key");
        (void)v;

        NCONF_free(conf);
    }

    BIO_free(bio);
    ERR_clear_error();
    return 0;
}
