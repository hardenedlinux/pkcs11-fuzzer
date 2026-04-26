/*
 * opensc_asn1_fuzz.c — Fuzz OpenSC's ASN.1 decoder directly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/pkcs15.h"

#ifndef OPENSC_LIB_PATH
#define OPENSC_LIB_PATH "builds/libfuzzer/lib/libopensc.so"
#endif

typedef int (*sc_establish_context_t)(sc_context_t **ctx, const char *appname);
typedef int (*sc_asn1_decode_t)(sc_context_t *ctx, struct sc_asn1_entry *asn1,
                               const u8 *in, size_t len, const u8 **newp, size_t *left);

static void *dl = NULL;
static sc_context_t *g_ctx = NULL;
static sc_asn1_decode_t p_sc_asn1_decode = NULL;

static const struct sc_asn1_entry c_asn1_tokeninfo[] = {
    { "version", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
    { "serialNumber", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
    { "manufacturerID", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
    { "label", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
    { "flags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
    { NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_entry_seq[] = {
    { "TokenInfo", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
    { NULL, 0, 0, 0, NULL, NULL }
};

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    dl = dlopen(OPENSC_LIB_PATH, RTLD_NOW | RTLD_GLOBAL);
    if (!dl) return 0;

    sc_establish_context_t p_sc_establish_context = (sc_establish_context_t)dlsym(dl, "sc_establish_context");
    p_sc_asn1_decode = (sc_asn1_decode_t)dlsym(dl, "sc_asn1_decode");

    if (p_sc_establish_context) p_sc_establish_context(&g_ctx, "fuzz");
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_ctx || !p_sc_asn1_decode || size < 1) return 0;

    uint8_t op = data[0] % 2;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    /* Local copies because the decoder modifies entry->flags */
    struct sc_asn1_entry info_tmpl[6];
    struct sc_asn1_entry seq_tmpl[2];
    
    int version = 0;
    unsigned char serial[128], manid[128], label[128], flags[128];
    size_t serial_len = sizeof(serial), manid_len = sizeof(manid), label_len = sizeof(label), flags_len = sizeof(flags);

    memcpy(info_tmpl, c_asn1_tokeninfo, sizeof(c_asn1_tokeninfo));
    info_tmpl[0].parm = &version;
    info_tmpl[1].parm = serial; info_tmpl[1].arg = &serial_len;
    info_tmpl[2].parm = manid;  info_tmpl[2].arg = &manid_len;
    info_tmpl[3].parm = label;  info_tmpl[3].arg = &label_len;
    info_tmpl[4].parm = flags;  info_tmpl[4].arg = &flags_len;

    if (op == 0) {
        memcpy(seq_tmpl, c_asn1_entry_seq, sizeof(c_asn1_entry_seq));
        seq_tmpl[0].parm = info_tmpl;
        p_sc_asn1_decode(g_ctx, seq_tmpl, payload, payload_len, NULL, NULL);
    } else {
        p_sc_asn1_decode(g_ctx, info_tmpl, payload, payload_len, NULL, NULL);
    }

    return 0;
}
