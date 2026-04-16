/*
 * tools/pkcs11-keygen.c — Minimal PKCS#11 key generator for token init.
 *
 * WHY THIS EXISTS
 * ---------------
 * pkcs11-tool (OpenSC) loads PKCS#11 modules with RTLD_DEEPBIND via
 * sc_dlopen_deep().  The libfuzzer tree's pkcs11-tool has ASan statically
 * linked; the statically-linked ASan interceptor for dlopen hard-aborts on
 * RTLD_DEEPBIND (sanitizers issue #611) and there is no ASAN_OPTIONS knob to
 * suppress the check.  LD_PRELOAD cannot help either: ASan's dlopen symbol is
 * a weak alias for __interceptor_trampoline_dlopen which is resolved at link
 * time inside the binary, before the dynamic linker processes LD_PRELOAD.
 *
 * This binary owns the dlopen call and uses RTLD_NOW | RTLD_GLOBAL — exactly
 * what the fuzzing harnesses use in common.h.  No RTLD_DEEPBIND means no
 * abort; the ASan runtime is present (we are compiled with -fsanitize=address)
 * so the ASan-instrumented libsofthsm2.so loads without missing symbols.
 *
 * WHAT IT DOES
 * ------------
 * Creates three key objects in the named PKCS#11 token, then lists all
 * objects for verification:
 *   id=01  RSA-2048 key pair    label=rsa-fuzz-key
 *   id=02  EC P-256  key pair   label=ec-fuzz-key
 *   id=03  AES-256   secret key label=aes-fuzz-key
 *
 * Usage:
 *   SOFTHSM2_CONF=<conf> pkcs11-keygen <module.so> <token-label> <user-pin>
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkcs11.h>

/* -------------------------------------------------------------------------- */

static CK_FUNCTION_LIST_PTR p11 = NULL;

static void die_rv(const char *msg, CK_RV rv)
{
    fprintf(stderr, "[pkcs11-keygen] %s: rv=0x%08lx\n", msg, (unsigned long)rv);
    exit(1);
}

#define CHECK(msg, rv) \
    do { CK_RV _r = (rv); if (_r != CKR_OK) die_rv(msg, _r); } while (0)

/* -------------------------------------------------------------------------- */
/* Find the slot that holds the named token                                   */
/* -------------------------------------------------------------------------- */
static CK_SLOT_ID find_slot(const char *label)
{
    CK_ULONG n = 0;
    p11->C_GetSlotList(CK_TRUE, NULL, &n);
    if (n == 0) {
        fprintf(stderr, "[pkcs11-keygen] no tokens found\n");
        exit(1);
    }

    CK_SLOT_ID *slots = calloc(n, sizeof(*slots));
    assert(slots != NULL);
    p11->C_GetSlotList(CK_TRUE, slots, &n);

    for (CK_ULONG i = 0; i < n; i++) {
        CK_TOKEN_INFO ti;
        if (p11->C_GetTokenInfo(slots[i], &ti) != CKR_OK)
            continue;
        /* Token label is space-padded to 32 chars — rtrim before compare */
        char lbl[33] = {0};
        memcpy(lbl, ti.label, 32);
        for (int j = 31; j >= 0 && lbl[j] == ' '; j--) lbl[j] = '\0';
        if (strcmp(lbl, label) == 0) {
            CK_SLOT_ID s = slots[i];
            free(slots);
            return s;
        }
    }

    free(slots);
    fprintf(stderr, "[pkcs11-keygen] token '%s' not found\n", label);
    exit(1);
}

/* -------------------------------------------------------------------------- */
/* Generate RSA-2048 key pair  (id=01, label=rsa-fuzz-key)                   */
/* -------------------------------------------------------------------------- */
static void gen_rsa2048(CK_SESSION_HANDLE sess)
{
    printf("--- Generating RSA-2048 key pair (id=01) ---\n");

    CK_ULONG     bits     = 2048;
    CK_BYTE      exp[]    = {0x01, 0x00, 0x01};   /* 65537 */
    CK_BYTE      id       = 0x01;
    CK_BBOOL     yes      = CK_TRUE, no = CK_FALSE;
    CK_UTF8CHAR *lbl      = (CK_UTF8CHAR *)"rsa-fuzz-key";
    CK_ULONG     lbl_len  = 12;

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,           &yes,  sizeof(yes)   },
        { CKA_ENCRYPT,         &yes,  sizeof(yes)   },
        { CKA_VERIFY,          &yes,  sizeof(yes)   },
        { CKA_MODULUS_BITS,    &bits, sizeof(bits)  },
        { CKA_PUBLIC_EXPONENT, exp,   sizeof(exp)   },
        { CKA_ID,              &id,   sizeof(id)    },
        { CKA_LABEL,           lbl,   lbl_len       },
    };
    CK_ATTRIBUTE prv_tmpl[] = {
        { CKA_TOKEN,       &yes, sizeof(yes) },
        { CKA_PRIVATE,     &yes, sizeof(yes) },
        { CKA_SENSITIVE,   &yes, sizeof(yes) },
        { CKA_DECRYPT,     &yes, sizeof(yes) },
        { CKA_SIGN,        &yes, sizeof(yes) },
        { CKA_EXTRACTABLE, &no,  sizeof(no)  },
        { CKA_ID,          &id,  sizeof(id)  },
        { CKA_LABEL,       lbl,  lbl_len     },
    };

    CK_MECHANISM  mech  = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, prv_h = CK_INVALID_HANDLE;

    CHECK("C_GenerateKeyPair(RSA-2048)",
          p11->C_GenerateKeyPair(sess, &mech,
                                 pub_tmpl,  7,
                                 prv_tmpl,  8,
                                 &pub_h, &prv_h));
    printf("  pub_handle=%lu  priv_handle=%lu\n", pub_h, prv_h);
}

/* -------------------------------------------------------------------------- */
/* Generate EC P-256 key pair  (id=02, label=ec-fuzz-key)                    */
/* -------------------------------------------------------------------------- */
static void gen_ec_p256(CK_SESSION_HANDLE sess)
{
    printf("--- Generating EC P-256 key pair (id=02) ---\n");

    /* DER-encoded OID for prime256v1 (1.2.840.10045.3.1.7) */
    CK_BYTE      oid[]   = {0x06, 0x08, 0x2a, 0x86, 0x48,
                             0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_BYTE      id      = 0x02;
    CK_BBOOL     yes     = CK_TRUE, no = CK_FALSE;
    CK_UTF8CHAR *lbl     = (CK_UTF8CHAR *)"ec-fuzz-key";
    CK_ULONG     lbl_len = 11;

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,     &yes,  sizeof(yes)  },
        { CKA_VERIFY,    &yes,  sizeof(yes)  },
        { CKA_EC_PARAMS, oid,   sizeof(oid)  },
        { CKA_ID,        &id,   sizeof(id)   },
        { CKA_LABEL,     lbl,   lbl_len      },
    };
    CK_ATTRIBUTE prv_tmpl[] = {
        { CKA_TOKEN,       &yes, sizeof(yes) },
        { CKA_PRIVATE,     &yes, sizeof(yes) },
        { CKA_SENSITIVE,   &yes, sizeof(yes) },
        { CKA_SIGN,        &yes, sizeof(yes) },
        { CKA_EXTRACTABLE, &no,  sizeof(no)  },
        { CKA_ID,          &id,  sizeof(id)  },
        { CKA_LABEL,       lbl,  lbl_len     },
    };

    CK_MECHANISM  mech  = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE pub_h = CK_INVALID_HANDLE, prv_h = CK_INVALID_HANDLE;

    CHECK("C_GenerateKeyPair(EC P-256)",
          p11->C_GenerateKeyPair(sess, &mech,
                                 pub_tmpl, 5,
                                 prv_tmpl, 7,
                                 &pub_h, &prv_h));
    printf("  pub_handle=%lu  priv_handle=%lu\n", pub_h, prv_h);
}

/* -------------------------------------------------------------------------- */
/* Generate AES-256 secret key  (id=03, label=aes-fuzz-key)                  */
/* -------------------------------------------------------------------------- */
static void gen_aes256(CK_SESSION_HANDLE sess)
{
    printf("--- Generating AES-256 secret key (id=03) ---\n");

    CK_ULONG     keylen  = 32;   /* 256 bits */
    CK_BYTE      id      = 0x03;
    CK_BBOOL     yes     = CK_TRUE;
    CK_UTF8CHAR *lbl     = (CK_UTF8CHAR *)"aes-fuzz-key";
    CK_ULONG     lbl_len = 12;

    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &yes,    sizeof(yes)    },
        { CKA_SENSITIVE, &yes,    sizeof(yes)    },
        { CKA_PRIVATE,   &yes,    sizeof(yes)    },
        { CKA_ENCRYPT,   &yes,    sizeof(yes)    },
        { CKA_DECRYPT,   &yes,    sizeof(yes)    },
        { CKA_SIGN,      &yes,    sizeof(yes)    },  /* for AES-CMAC */
        { CKA_VERIFY,    &yes,    sizeof(yes)    },  /* for AES-CMAC */
        { CKA_WRAP,      &yes,    sizeof(yes)    },
        { CKA_UNWRAP,    &yes,    sizeof(yes)    },
        { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
        { CKA_ID,        &id,     sizeof(id)     },
        { CKA_LABEL,     lbl,     lbl_len        },
    };

    CK_MECHANISM  mech  = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

    CHECK("C_GenerateKey(AES-256)",
          p11->C_GenerateKey(sess, &mech, tmpl, 12, &key_h));
    printf("  key_handle=%lu\n", key_h);
}

/* -------------------------------------------------------------------------- */
/* Generate generic 256-bit HMAC key  (id=04, label=hmac-fuzz-key)           */
/* -------------------------------------------------------------------------- */
static void gen_hmac256(CK_SESSION_HANDLE sess)
{
    printf("--- Generating Generic-256 HMAC key (id=04) ---\n");

    CK_ULONG     keylen  = 32;   /* 256 bits */
    CK_BYTE      id      = 0x04;
    CK_BBOOL     yes     = CK_TRUE;
    CK_UTF8CHAR *lbl     = (CK_UTF8CHAR *)"hmac-fuzz-key";
    CK_ULONG     lbl_len = 13;

    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN,     &yes,    sizeof(yes)    },
        { CKA_SENSITIVE, &yes,    sizeof(yes)    },
        { CKA_PRIVATE,   &yes,    sizeof(yes)    },
        { CKA_SIGN,      &yes,    sizeof(yes)    },
        { CKA_VERIFY,    &yes,    sizeof(yes)    },
        { CKA_VALUE_LEN, &keylen, sizeof(keylen) },
        { CKA_ID,        &id,     sizeof(id)     },
        { CKA_LABEL,     lbl,     lbl_len        },
    };

    CK_MECHANISM  mech  = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
    CK_OBJECT_HANDLE key_h = CK_INVALID_HANDLE;

    CHECK("C_GenerateKey(Generic-256 HMAC)",
          p11->C_GenerateKey(sess, &mech, tmpl, 8, &key_h));
    printf("  key_handle=%lu\n", key_h);
}

/* -------------------------------------------------------------------------- */
/* List every object in the open session (verification)                       */
/* -------------------------------------------------------------------------- */
static void list_objects(CK_SESSION_HANDLE sess)
{
    printf("\n--- Objects in token ---\n");

    CK_RV rv = p11->C_FindObjectsInit(sess, NULL_PTR, 0);
    if (rv != CKR_OK) {
        fprintf(stderr, "  C_FindObjectsInit: 0x%lx\n", (unsigned long)rv);
        return;
    }

    CK_OBJECT_HANDLE handles[64];
    CK_ULONG count, total = 0;
    do {
        count = 0;
        rv = p11->C_FindObjects(sess, handles, 64, &count);
        if (rv != CKR_OK) break;

        for (CK_ULONG i = 0; i < count; i++) {
            CK_OBJECT_CLASS cls     = 0;
            CK_BYTE         id_val  = 0;
            char            label[64] = {0};
            CK_ULONG        label_len = sizeof(label) - 1;

            CK_ATTRIBUTE attrs[] = {
                { CKA_CLASS, &cls,     sizeof(cls)    },
                { CKA_ID,    &id_val,  sizeof(id_val) },
                { CKA_LABEL, label,    label_len      },
            };
            p11->C_GetAttributeValue(sess, handles[i], attrs, 3);

            /* null-terminate the label */
            label_len = (CK_ULONG)attrs[2].ulValueLen;
            if ((size_t)label_len < sizeof(label))
                label[label_len] = '\0';

            const char *cls_str =
                cls == CKO_PUBLIC_KEY  ? "pubkey"    :
                cls == CKO_PRIVATE_KEY ? "privkey"   :
                cls == CKO_SECRET_KEY  ? "secretkey" :
                cls == CKO_CERTIFICATE ? "cert"      : "other";

            printf("  handle=%-4lu  class=%-10s  id=0x%02x  label=%s\n",
                   handles[i], cls_str, (unsigned)id_val, label);
            total++;
        }
    } while (count > 0);

    p11->C_FindObjectsFinal(sess);
    printf("  %lu object(s) total\n", total);
}

/* -------------------------------------------------------------------------- */
/* main                                                                       */
/* -------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s <module.so> <token-label> <user-pin>\n", argv[0]);
        return 1;
    }
    const char *mod_path    = argv[1];
    const char *token_label = argv[2];
    const char *pin         = argv[3];

    /* ---------------------------------------------------------------------- */
    /* Load the PKCS#11 module WITHOUT RTLD_DEEPBIND.                         */
    /* Using RTLD_NOW | RTLD_GLOBAL — identical to common.h in the harnesses. */
    /* ---------------------------------------------------------------------- */
    void *dl = dlopen(mod_path, RTLD_NOW | RTLD_GLOBAL);
    if (!dl) {
        fprintf(stderr, "[pkcs11-keygen] dlopen(%s): %s\n", mod_path, dlerror());
        return 1;
    }

    /* Cast via uintptr_t to silence -Wpedantic on function-pointer casts */
    CK_C_GetFunctionList get_fl =
        (CK_C_GetFunctionList)(uintptr_t)dlsym(dl, "C_GetFunctionList");
    if (!get_fl) {
        fprintf(stderr, "[pkcs11-keygen] C_GetFunctionList not found\n");
        return 1;
    }

    CK_RV rv = get_fl(&p11);
    if (rv != CKR_OK || !p11) { die_rv("C_GetFunctionList", rv); }

    rv = p11->C_Initialize(NULL_PTR);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
        die_rv("C_Initialize", rv);

    CK_SLOT_ID slot = find_slot(token_label);

    CK_SESSION_HANDLE sess;
    CHECK("C_OpenSession",
          p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL_PTR, NULL_PTR, &sess));

    rv = p11->C_Login(sess, CKU_USER,
                      (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
        die_rv("C_Login", rv);

    gen_rsa2048(sess);
    printf("\n");
    gen_ec_p256(sess);
    printf("\n");
    gen_aes256(sess);
    printf("\n");
    gen_hmac256(sess);

    list_objects(sess);

    p11->C_Logout(sess);
    p11->C_CloseSession(sess);
    p11->C_Finalize(NULL_PTR);

    printf("\n[pkcs11-keygen] all keys generated successfully.\n");
    return 0;
}
