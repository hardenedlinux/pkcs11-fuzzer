/*
 * opensc_pkcs15_card_fuzz.c — Deep fuzzing of OpenSC PKCS#15 card binding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"

#ifndef OPENSC_LIB_PATH
#define OPENSC_LIB_PATH "builds/libfuzzer/lib/libopensc.so"
#endif

/* Exported for libopensc mock driver */
uint8_t fuzz_resp_buffer[8192];
size_t fuzz_resp_len = 0;

typedef int (*sc_establish_context_t)(sc_context_t **ctx, const char *appname);
typedef int (*sc_connect_card_t)(sc_reader_t *reader, sc_card_t **card);
typedef int (*sc_pkcs15_bind_t)(sc_card_t *card, struct sc_pkcs15_reg_apps *apps, struct sc_pkcs15_card **p15card);
typedef unsigned int (*sc_ctx_get_reader_count_t)(sc_context_t *ctx);
typedef sc_reader_t * (*sc_ctx_get_reader_t)(sc_context_t *ctx, unsigned int i);

static void *dl = NULL;
static sc_context_t *g_ctx = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    dl = dlopen(OPENSC_LIB_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!dl) return 0;

    sc_establish_context_t p_sc_establish_context = (sc_establish_context_t)dlsym(dl, "sc_establish_context");
    if (p_sc_establish_context) p_sc_establish_context(&g_ctx, "fuzz");
    
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_ctx || size < 32) return 0;

    /* Use the first part of data to set up "card responses" */
    size_t resp_len = data[0] * 4;
    if (resp_len > size - 1) resp_len = size - 1;
    if (resp_len > sizeof(fuzz_resp_buffer)) resp_len = sizeof(fuzz_resp_buffer);
    
    memcpy(fuzz_resp_buffer, data + 1, resp_len);
    fuzz_resp_len = resp_len;

    sc_ctx_get_reader_count_t p_sc_ctx_get_reader_count = (sc_ctx_get_reader_count_t)dlsym(dl, "sc_ctx_get_reader_count");
    sc_ctx_get_reader_t p_sc_ctx_get_reader = (sc_ctx_get_reader_t)dlsym(dl, "sc_ctx_get_reader");

    if (!p_sc_ctx_get_reader_count || !p_sc_ctx_get_reader) return 0;

    unsigned int reader_count = p_sc_ctx_get_reader_count(g_ctx);
    if (reader_count == 0) return 0;

    sc_reader_t *reader = p_sc_ctx_get_reader(g_ctx, data[0] % reader_count);
    if (!reader) return 0;

    sc_card_t *card = NULL;
    sc_connect_card_t p_sc_connect_card = (sc_connect_card_t)dlsym(dl, "sc_connect_card");
    if (p_sc_connect_card && p_sc_connect_card(reader, &card) == SC_SUCCESS) {
        struct sc_pkcs15_card *p15card = NULL;
        sc_pkcs15_bind_t p_sc_pkcs15_bind = (sc_pkcs15_bind_t)dlsym(dl, "sc_pkcs15_bind");
        if (p_sc_pkcs15_bind) {
            p_sc_pkcs15_bind(card, NULL, &p15card);
        }
        
        typedef int (*sc_pkcs15_card_free_t)(struct sc_pkcs15_card *);
        sc_pkcs15_card_free_t p_sc_pkcs15_card_free = (sc_pkcs15_card_free_t)dlsym(dl, "sc_pkcs15_card_free");
        if (p15card && p_sc_pkcs15_card_free) p_sc_pkcs15_card_free(p15card);

        typedef int (*sc_disconnect_card_t)(sc_card_t *);
        sc_disconnect_card_t p_sc_disconnect_card = (sc_disconnect_card_t)dlsym(dl, "sc_disconnect_card");
        if (p_sc_disconnect_card) p_sc_disconnect_card(card);
    }

    return 0;
}
