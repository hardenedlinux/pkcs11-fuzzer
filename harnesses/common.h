/*
 * common.h — shared PKCS#11 session setup for all libFuzzer harnesses.
 *
 * Each harness calls pkcs11_init() from LLVMFuzzerInitialize() to:
 *   1. Restore the token snapshot to a tmpfs path.
 *   2. Load the SoftHSM2 module.
 *   3. Open a PKCS#11 session and log in.
 *   4. Find the key handles (RSA, EC, AES) for use in fuzzing.
 *
 * The session is reused across all LLVMFuzzerTestOneInput() calls for speed.
 * Key handles are stored as global variables so harnesses can use them directly.
 */
#pragma once

#include <assert.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* PKCS#11 header — prefer the build-tree install, but keep a source-tree
 * fallback so editor tooling can parse harnesses before the targets are built. */
#if __has_include(<pkcs11.h>)
#include <pkcs11.h>
#elif __has_include("../src/softhsm2/src/lib/pkcs11/pkcs11.h")
#include "../src/softhsm2/src/lib/pkcs11/pkcs11.h"
#else
#error "pkcs11.h not found"
#endif

/* ---------------------------------------------------------------------------
 * Globals set by pkcs11_init(); read-only in harnesses.
 * --------------------------------------------------------------------------- */
static CK_FUNCTION_LIST_PTR p11   = NULL;  /* PKCS#11 function table          */
static CK_SESSION_HANDLE    sess  = CK_INVALID_HANDLE; /* open session        */
static CK_OBJECT_HANDLE     rsa_priv = CK_INVALID_HANDLE; /* RSA-2048 private */
static CK_OBJECT_HANDLE     rsa_pub  = CK_INVALID_HANDLE; /* RSA-2048 public  */
static CK_OBJECT_HANDLE     ec_priv  = CK_INVALID_HANDLE; /* EC P-256 private */
static CK_OBJECT_HANDLE     ec_pub   = CK_INVALID_HANDLE; /* EC P-256 public  */
static CK_OBJECT_HANDLE     aes_key  = CK_INVALID_HANDLE; /* AES-256 secret   */
static CK_OBJECT_HANDLE     hmac_key = CK_INVALID_HANDLE; /* Generic-256 HMAC */

/* PIN used for the fuzz token */
#define FUZZ_PIN        ((CK_UTF8CHAR_PTR)"1234")
#define FUZZ_PIN_LEN    4
#define FUZZ_TOKEN_LABEL "fuzz-token"

/* ---------------------------------------------------------------------------
 * restore_token_snapshot()
 *
 * Copies the read-only token snapshot (produced by init-token.sh) to a
 * fresh per-process tmpfs path and writes a matching softhsm2.conf.
 * Sets SOFTHSM2_CONF environment variable so SoftHSM2 finds the token.
 *
 * Call once from LLVMFuzzerInitialize().
 * --------------------------------------------------------------------------- */
static void restore_token_snapshot(void)
{
    /* Locate the project root relative to this header's expected install path.
     * HARNESS_PROJECT_ROOT is injected by the Makefile via -D. */
#ifndef HARNESS_PROJECT_ROOT
#define HARNESS_PROJECT_ROOT ".."
#endif
    const char *tmpl  = HARNESS_PROJECT_ROOT "/token-template";

    /* Create a per-process token directory under /tmp */
    char token_dir[PATH_MAX];
    snprintf(token_dir, sizeof(token_dir), "/tmp/fuzz-token-%d", (int)getpid());
    {
        char cmd[PATH_MAX * 2 + 64];
        snprintf(cmd, sizeof(cmd), "cp -a '%s/.' '%s/' 2>/dev/null || true", tmpl, token_dir);
        /* mkdir first */
        mkdir(token_dir, 0700);
        system(cmd);
    }

    /* Write softhsm2.conf pointing at our tmpdir */
    static char conf_path[PATH_MAX];
    snprintf(conf_path, sizeof(conf_path), "/tmp/softhsm2-%d.conf", (int)getpid());
    {
        FILE *f = fopen(conf_path, "w");
        assert(f != NULL);
        fprintf(f,
                "directories.tokendir = %s\n"
                "objectstore.backend = file\n"
                "log.level = ERROR\n"
                "slots.removable = false\n",
                token_dir);
        fclose(f);
    }

    setenv("SOFTHSM2_CONF", conf_path, 1);
}

/* ---------------------------------------------------------------------------
 * find_objects_by_id()
 *
 * Returns the first object matching the given id and class.
 * --------------------------------------------------------------------------- */
static CK_OBJECT_HANDLE find_object(CK_SESSION_HANDLE s,
                                    CK_OBJECT_CLASS   cls,
                                    CK_BYTE           id)
{
    CK_BYTE id_val = id;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &cls,    sizeof(cls) },
        { CKA_ID,       &id_val, sizeof(id_val) }
    };
    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG count = 0;

    if (p11->C_FindObjectsInit(s, tmpl, 2) != CKR_OK) return CK_INVALID_HANDLE;
    p11->C_FindObjects(s, &h, 1, &count);
    p11->C_FindObjectsFinal(s);
    return (count > 0) ? h : CK_INVALID_HANDLE;
}

/* ---------------------------------------------------------------------------
 * pkcs11_init()
 *
 * Call once from LLVMFuzzerInitialize().
 * Loads SoftHSM2, opens a session, finds all key handles.
 * --------------------------------------------------------------------------- */
static void pkcs11_init(void)
{
    /* Restore snapshot and configure the module path */
    restore_token_snapshot();

#ifndef SOFTHSM2_MODULE_PATH
#define SOFTHSM2_MODULE_PATH "libsofthsm2.so"
#endif
    const char *mod_path = SOFTHSM2_MODULE_PATH;

    /* Load the SoftHSM2 PKCS#11 module */
    void *dl = dlopen(mod_path, RTLD_NOW | RTLD_GLOBAL);
    if (!dl) {
        fprintf(stderr, "[harness] dlopen(%s) failed: %s\n", mod_path, dlerror());
        abort();
    }

    CK_C_GetFunctionList get_fl =
        (CK_C_GetFunctionList)dlsym(dl, "C_GetFunctionList");
    if (!get_fl) {
        fprintf(stderr, "[harness] C_GetFunctionList not found\n");
        abort();
    }

    CK_RV rv = get_fl(&p11);
    assert(rv == CKR_OK && p11 != NULL);

    /* Initialize the library */
    rv = p11->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        fprintf(stderr, "[harness] C_Initialize failed: 0x%lx\n", rv);
        abort();
    }

    /* Find the fuzz token slot */
    CK_SLOT_ID slot = CK_INVALID_HANDLE;
    {
        CK_ULONG nslots = 0;
        p11->C_GetSlotList(CK_TRUE, NULL, &nslots);
        CK_SLOT_ID *slots = (CK_SLOT_ID *)calloc(nslots, sizeof(*slots));
        assert(slots != NULL);
        p11->C_GetSlotList(CK_TRUE, slots, &nslots);
        for (CK_ULONG i = 0; i < nslots; i++) {
            CK_TOKEN_INFO ti;
            if (p11->C_GetTokenInfo(slots[i], &ti) == CKR_OK) {
                /* Token label is space-padded to 32 chars */
                char label[33] = {0};
                memcpy(label, ti.label, 32);
                /* rtrim */
                for (int j = 31; j >= 0 && label[j] == ' '; j--) label[j] = '\0';
                if (strncmp(label, FUZZ_TOKEN_LABEL, strlen(FUZZ_TOKEN_LABEL)) == 0) {
                    slot = slots[i];
                    break;
                }
            }
        }
        free(slots);
    }
    if (slot == (CK_SLOT_ID)CK_INVALID_HANDLE) {
        fprintf(stderr, "[harness] fuzz-token not found. Was init-token.sh run?\n");
        abort();
    }

    /* Open a RW session */
    rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL_PTR, NULL_PTR, &sess);
    assert(rv == CKR_OK);

    /* Login as user */
    rv = p11->C_Login(sess, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
    assert(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN);

    /* Locate key handles */
    rsa_priv = find_object(sess, CKO_PRIVATE_KEY, 0x01);
    rsa_pub  = find_object(sess, CKO_PUBLIC_KEY,  0x01);
    ec_priv  = find_object(sess, CKO_PRIVATE_KEY, 0x02);
    ec_pub   = find_object(sess, CKO_PUBLIC_KEY,  0x02);
    aes_key  = find_object(sess, CKO_SECRET_KEY,  0x03);
    hmac_key = find_object(sess, CKO_SECRET_KEY,  0x04);

    fprintf(stderr,
            "[harness] PKCS#11 ready — RSA priv=%lu ec_priv=%lu aes=%lu\n",
            rsa_priv, ec_priv, aes_key);
}

/* ---------------------------------------------------------------------------
 * Convenience: clamp fuzz data split
 * data[0]        → selector byte (picks mechanism / operation variant)
 * data[1..]      → payload for the operation
 * --------------------------------------------------------------------------- */
static inline const uint8_t *payload_ptr(const uint8_t *data, size_t size)
{
    return (size > 1) ? data + 1 : (const uint8_t *)"";
}
static inline size_t payload_len(size_t size)
{
    return (size > 1) ? size - 1 : 0;
}
