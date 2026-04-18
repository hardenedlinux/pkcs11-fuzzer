/*
 * pkcs11_token_reset_fuzz.c — Per-iteration isolated token-management fuzzer.
 *
 * C_InitPIN, C_SetPIN, and C_InitToken are awkward for normal in-process
 * fuzzing because they mutate the token state for subsequent iterations. This
 * harness restores a fresh SoftHSM token snapshot every iteration, fuzzes one
 * token-management sequence, then finalizes and tears the temp token down.
 */
#include "common.h"

#include <dlfcn.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PIN_LEN 16

#ifndef FUZZ_SO_PIN
#define FUZZ_SO_PIN ((CK_UTF8CHAR_PTR)"12345678")
#define FUZZ_SO_PIN_LEN 8
#endif

/* Keep the instrumented PKCS#11 module mapped for process lifetime. Unloading it
 * per input leaves libFuzzer/ASan with stale sancov tables and crashes later in
 * coverage bookkeeping instead of in the target code. */
static void *cached_dl = NULL;
static CK_FUNCTION_LIST_PTR cached_p11 = NULL;

static void fill_pin(const uint8_t *data,
                     size_t size,
                     size_t *off,
                     CK_UTF8CHAR *out,
                     CK_ULONG *out_len)
{
    CK_ULONG len;

    memset(out, 0, MAX_PIN_LEN);
    if (*off >= size) {
        *out_len = 0;
        return;
    }

    len = (CK_ULONG)(data[(*off)++] % (MAX_PIN_LEN + 1));
    if (*off + len > size) {
        len = (CK_ULONG)(size - *off);
    }
    if (len > 0) {
        memcpy(out, data + *off, len);
        *off += len;
    }
    *out_len = len;
}

static void fill_label32(const uint8_t *data, size_t size, size_t *off, CK_UTF8CHAR label[32])
{
    memset(label, ' ', 32);
    if (*off >= size) return;

    size_t len = data[(*off)++] % 32;
    if (*off + len > size) {
        len = size - *off;
    }
    if (len > 0) {
        memcpy(label, data + *off, len);
        *off += len;
    }
}

static int create_token_copy(char *token_dir, size_t token_dir_size, char *conf_path, size_t conf_path_size)
{
    const char *tmpl = HARNESS_PROJECT_ROOT "/token-template";
    char cmd[PATH_MAX * 2 + 64];

    snprintf(token_dir, token_dir_size, "/tmp/fuzz-token-reset-XXXXXX");
    if (!mkdtemp(token_dir)) return -1;

    snprintf(cmd, sizeof(cmd), "cp -a '%s/.' '%s/' 2>/dev/null || true", tmpl, token_dir);
    if (system(cmd) == -1) return -1;

    snprintf(conf_path, conf_path_size, "/tmp/softhsm2-reset-%d-%ld.conf",
             (int)getpid(), (long)random());
    {
        FILE *f = fopen(conf_path, "w");
        if (!f) return -1;
        fprintf(f,
                "directories.tokendir = %s\n"
                "objectstore.backend = file\n"
                "log.level = ERROR\n"
                "slots.removable = false\n",
                token_dir);
        fclose(f);
    }

    return 0;
}

static void cleanup_token_copy(const char *token_dir, const char *conf_path)
{
    char cmd[PATH_MAX + 32];

    if (conf_path && conf_path[0] != '\0') unlink(conf_path);
    if (token_dir && token_dir[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", token_dir);
        system(cmd);
    }
}

static CK_RV load_local_module(CK_FUNCTION_LIST_PTR *out_p11,
                               void **out_dl,
                               CK_SLOT_ID *out_slot)
{
    CK_C_GetFunctionList get_fl;
    CK_ULONG nslots = 0;
    CK_SLOT_ID slots[8];
    CK_RV rv;

    if (!cached_dl) {
        cached_dl = dlopen(SOFTHSM2_MODULE_PATH, RTLD_NOW | RTLD_GLOBAL);
        if (!cached_dl) return CKR_FUNCTION_FAILED;

        get_fl = (CK_C_GetFunctionList)dlsym(cached_dl, "C_GetFunctionList");
        if (!get_fl) return CKR_FUNCTION_FAILED;

        rv = get_fl(&cached_p11);
        if (rv != CKR_OK || !cached_p11) return CKR_FUNCTION_FAILED;
    }

    *out_dl = cached_dl;
    *out_p11 = cached_p11;

    rv = (*out_p11)->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) return rv;

    rv = (*out_p11)->C_GetSlotList(CK_TRUE, NULL_PTR, &nslots);
    if (rv != CKR_OK || nslots == 0 || nslots > 8) return CKR_SLOT_ID_INVALID;

    rv = (*out_p11)->C_GetSlotList(CK_TRUE, slots, &nslots);
    if (rv != CKR_OK || nslots == 0) return CKR_SLOT_ID_INVALID;

    *out_slot = slots[0];
    return CKR_OK;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    srandom((unsigned)getpid());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CK_FUNCTION_LIST_PTR mod = NULL;
    void *dl = NULL;
    CK_SLOT_ID slot = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE local = CK_INVALID_HANDLE;
    char token_dir[PATH_MAX] = {0};
    char conf_path[PATH_MAX] = {0};
    const char *old_conf = getenv("SOFTHSM2_CONF");
    char old_conf_buf[PATH_MAX] = {0};
    size_t off = 1;
    CK_RV rv;

    if (size < 1) return 0;
    if (old_conf) {
        snprintf(old_conf_buf, sizeof(old_conf_buf), "%s", old_conf);
    }

    if (create_token_copy(token_dir, sizeof(token_dir), conf_path, sizeof(conf_path)) != 0) {
        return 0;
    }

    setenv("SOFTHSM2_CONF", conf_path, 1);
    rv = load_local_module(&mod, &dl, &slot);
    if (rv != CKR_OK) goto out;

    switch (data[0] % 7) {
    case 0: {
        CK_UTF8CHAR new_pin[MAX_PIN_LEN];
        CK_ULONG new_pin_len;

        fill_pin(data, size, &off, new_pin, &new_pin_len);
        if (mod->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, &local) == CKR_OK) {
            mod->C_Login(local, CKU_SO, FUZZ_SO_PIN, FUZZ_SO_PIN_LEN);
            mod->C_InitPIN(local, new_pin, new_pin_len);
        }
        break;
    }

    case 1: {
        CK_UTF8CHAR old_pin[MAX_PIN_LEN];
        CK_UTF8CHAR new_pin[MAX_PIN_LEN];
        CK_ULONG old_pin_len;
        CK_ULONG new_pin_len;

        fill_pin(data, size, &off, old_pin, &old_pin_len);
        fill_pin(data, size, &off, new_pin, &new_pin_len);
        if (mod->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, &local) == CKR_OK) {
            CK_UTF8CHAR_PTR login_pin = (old_pin_len > 0) ? old_pin : FUZZ_PIN;
            CK_ULONG login_pin_len = (old_pin_len > 0) ? old_pin_len : FUZZ_PIN_LEN;

            mod->C_Login(local, CKU_USER, login_pin, login_pin_len);
            mod->C_SetPIN(local, old_pin, old_pin_len, new_pin, new_pin_len);
        }
        break;
    }

    case 2: {
        CK_UTF8CHAR user_pin[MAX_PIN_LEN];
        CK_ULONG user_pin_len;

        fill_pin(data, size, &off, user_pin, &user_pin_len);
        if (mod->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, &local) == CKR_OK) {
            mod->C_Login(local, CKU_USER, user_pin, user_pin_len);
            mod->C_Logout(local);
            mod->C_Login(local, CKU_USER, FUZZ_PIN, FUZZ_PIN_LEN);
        }
        break;
    }

    case 3: {
        CK_UTF8CHAR so_pin[MAX_PIN_LEN];
        CK_ULONG so_pin_len;

        fill_pin(data, size, &off, so_pin, &so_pin_len);
        if (mod->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, &local) == CKR_OK) {
            mod->C_Login(local, CKU_SO, so_pin, so_pin_len);
            mod->C_Logout(local);
        }
        break;
    }

    case 4: {
        CK_UTF8CHAR so_pin[MAX_PIN_LEN];
        CK_ULONG so_pin_len;
        CK_UTF8CHAR label[32];

        fill_pin(data, size, &off, so_pin, &so_pin_len);
        fill_label32(data, size, &off, label);
        mod->C_InitToken(slot,
                         (so_pin_len > 0) ? so_pin : FUZZ_SO_PIN,
                         (so_pin_len > 0) ? so_pin_len : FUZZ_SO_PIN_LEN,
                         label);
        break;
    }

    case 5: {
        CK_UTF8CHAR init_pin[MAX_PIN_LEN];
        CK_UTF8CHAR new_pin[MAX_PIN_LEN];
        CK_ULONG init_pin_len;
        CK_ULONG new_pin_len;

        fill_pin(data, size, &off, init_pin, &init_pin_len);
        fill_pin(data, size, &off, new_pin, &new_pin_len);
        if (mod->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, &local) == CKR_OK) {
            mod->C_Login(local, CKU_SO, FUZZ_SO_PIN, FUZZ_SO_PIN_LEN);
            mod->C_InitPIN(local, init_pin, init_pin_len);
            mod->C_Logout(local);
            mod->C_Login(local, CKU_USER, init_pin, init_pin_len);
            mod->C_SetPIN(local, init_pin, init_pin_len, new_pin, new_pin_len);
        }
        break;
    }

    case 6: {
        CK_UTF8CHAR label[32];

        fill_label32(data, size, &off, label);
        if (mod->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL_PTR, NULL_PTR, &local) == CKR_OK) {
            mod->C_InitToken(slot, FUZZ_SO_PIN, FUZZ_SO_PIN_LEN, label);
            mod->C_Login(local, CKU_SO, FUZZ_SO_PIN, FUZZ_SO_PIN_LEN);
            mod->C_InitPIN(local, FUZZ_PIN, FUZZ_PIN_LEN);
        }
        break;
    }
    }

out:
    if (local != CK_INVALID_HANDLE) mod->C_CloseSession(local);
    if (mod) mod->C_Finalize(NULL_PTR);
    cleanup_token_copy(token_dir, conf_path);
    if (old_conf_buf[0] != '\0') {
        setenv("SOFTHSM2_CONF", old_conf_buf, 1);
    } else {
        unsetenv("SOFTHSM2_CONF");
    }
    return 0;
}
