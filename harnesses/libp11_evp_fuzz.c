/*
 * libp11_evp_fuzz.c — Fuzz the libp11 ENGINE / OpenSSL EVP bridge.
 *
 * Code path: LLVMFuzzerTestOneInput
 *              → OpenSSL EVP API (EVP_DigestSign, EVP_DigestVerify, …)
 *              → libp11 ENGINE callbacks (pkcs11_rsa_sign, pkcs11_ec_sign, …)
 *              → PKCS#11 C API (C_SignInit, C_Sign, C_DecryptInit, …)
 *              → SoftHSM2
 *
 * This is distinct from pkcs11_*_fuzz harnesses which call the PKCS#11 C API
 * directly, bypassing libp11's translation layer entirely.  Here we exercise
 * libp11's EVP method tables, key loading, and error-handling code.
 *
 * Input layout:
 *   byte 0:  operation selector (0–7, see table)
 *   byte 1:  for multi-part ops — number of Update chunks (1–8)
 *   byte 2+: data payload
 *
 * Operations:
 *   0  EVP_DigestSign  (SHA-256, RSA private key)
 *   1  EVP_DigestSign  (SHA-384, RSA private key)
 *   2  EVP_DigestSign  (SHA-256, EC  private key)
 *   3  EVP_DigestVerify (SHA-256, RSA): sign with real key, verify fuzzed msg
 *   4  EVP_DigestVerify (SHA-256, EC):  sign with real key, verify fuzzed msg
 *   5  EVP_PKEY_encrypt + EVP_PKEY_decrypt (RSA-OAEP with fuzzed params)
 *   6  EVP_DigestSign multi-part RSA: DigestSignInit/Update×N/Final
 *   7  EVP_DigestSign multi-part EC:  DigestSignInit/Update×N/Final
 */
#pragma clang diagnostic ignored "-Wunused-function"
#include "common.h"

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* ── Module-level state ─────────────────────────────────────────────────── */
static ENGINE   *p11_eng         = NULL;
static EVP_PKEY *evp_rsa_priv    = NULL;   /* RSA-2048 via libp11 ENGINE */
static EVP_PKEY *evp_rsa_pub     = NULL;
static EVP_PKEY *evp_ec_priv     = NULL;   /* EC P-256 via libp11 ENGINE */
static EVP_PKEY *evp_ec_pub      = NULL;

/* ── Engine loader (same pattern as tls_pkcs11_fuzz.c) ─────────────────── */
static ENGINE *load_engine(const char *eng_path,
                            const char *mod_path,
                            const char *pin)
{
    ENGINE_load_dynamic();
    ENGINE *e = ENGINE_by_id("dynamic");
    if (!e) return NULL;

    ENGINE_ctrl_cmd_string(e, "SO_PATH",  eng_path, 0);
    ENGINE_ctrl_cmd_string(e, "ID",       "pkcs11", 0);
    ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1",      0);
    ENGINE_ctrl_cmd_string(e, "LOAD",     NULL,     0);
    ENGINE_free(e);

    e = ENGINE_by_id("pkcs11");
    if (!e) return NULL;

    ENGINE_ctrl_cmd_string(e, "MODULE_PATH", mod_path, 0);
    ENGINE_ctrl_cmd_string(e, "PIN",         pin,      0);

    if (!ENGINE_init(e)) { ENGINE_free(e); return NULL; }
    return e;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    restore_token_snapshot();   /* sets SOFTHSM2_CONF env var */

#ifndef ENGINE_PATH
#  error "ENGINE_PATH must be defined via -DENGINE_PATH=..."
#endif
    p11_eng = load_engine(ENGINE_PATH, SOFTHSM2_MODULE_PATH, "1234");
    if (!p11_eng) {
        fprintf(stderr, "[libp11_evp] Failed to load pkcs11 ENGINE\n");
        return 0;
    }

    /* Load key handles via PKCS#11 URI.  These go through libp11's
     * pkcs11_load_key() and create EVP_PKEY objects backed by the token. */
    evp_rsa_priv = ENGINE_load_private_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%01;pin-value=1234", NULL, NULL);
    evp_rsa_pub  = ENGINE_load_public_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%01;pin-value=1234", NULL, NULL);
    evp_ec_priv  = ENGINE_load_private_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%02;pin-value=1234", NULL, NULL);
    evp_ec_pub   = ENGINE_load_public_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%02;pin-value=1234", NULL, NULL);

    fprintf(stderr, "[libp11_evp] RSA priv=%p pub=%p  EC priv=%p pub=%p\n",
            (void *)evp_rsa_priv, (void *)evp_rsa_pub,
            (void *)evp_ec_priv,  (void *)evp_ec_pub);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || !p11_eng) return 0;

    uint8_t sel     = data[0] % 8;
    uint8_t nchunks = (data[1] % 8) + 1;
    const uint8_t *pay  = (size > 2) ? data + 2 : (const uint8_t *)"";
    size_t         plen = (size > 2) ? size - 2 : 0;

    ERR_clear_error();

    switch (sel) {

    /* ── Single-part EVP_DigestSign ──────────────────────────────────────── */
    case 0:
    case 1:
    case 2: {
        EVP_PKEY *pkey = (sel <= 1) ? evp_rsa_priv : evp_ec_priv;
        const EVP_MD *md = (sel == 1) ? EVP_sha384() : EVP_sha256();
        if (!pkey) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestSignInit(mctx, NULL, md, p11_eng, pkey) == 1) {
            CK_BYTE sig[512]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── EVP_DigestVerify (sign real sig, verify fuzzed message) ─────────── */
    case 3:
    case 4: {
        EVP_PKEY *priv = (sel == 3) ? evp_rsa_priv : evp_ec_priv;
        EVP_PKEY *pub  = (sel == 3) ? evp_rsa_pub  : evp_ec_pub;
        if (!priv || !pub) break;

        /* Sign the payload to obtain a valid signature */
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        CK_BYTE sig[512]; size_t slen = sizeof(sig);
        int ok = (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), p11_eng, priv) == 1)
              && (EVP_DigestSign(mctx, sig, &slen, pay, (int)plen) == 1);
        EVP_MD_CTX_free(mctx);

        if (!ok) break;

        /* Verify: use the fuzz payload as the message (real sig, fuzzed msg).
         * This exercises libp11's EVP_DigestVerify callback and OpenSSL's
         * RSA/EC verification path — with high probability the verify fails
         * (wrong message) but all the parsing code runs. */
        mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), p11_eng, pub) == 1)
            EVP_DigestVerify(mctx, sig, slen, pay, (int)plen);
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── RSA-OAEP encrypt + decrypt ──────────────────────────────────────── */
    case 5: {
        if (!evp_rsa_pub || !evp_rsa_priv) break;

        /* Encrypt with public key */
        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(evp_rsa_pub, p11_eng);
        if (!enc_ctx) break;
        CK_BYTE ct[512]; size_t ct_len = sizeof(ct);
        if (EVP_PKEY_encrypt_init(enc_ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
            EVP_PKEY_CTX_free(enc_ctx);
            break;
        }
        /* Limit plaintext to RSA-2048 OAEP max (214 bytes for SHA-1 OAEP) */
        size_t enc_plen = (plen > 214) ? 214 : plen;
        int enc_ok = (EVP_PKEY_encrypt(enc_ctx, ct, &ct_len,
                                        pay, enc_plen) == 1);
        EVP_PKEY_CTX_free(enc_ctx);

        if (!enc_ok) break;

        /* Decrypt through libp11 ENGINE — exercises pkcs11_private_decrypt() */
        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(evp_rsa_priv, p11_eng);
        if (!dec_ctx) break;
        CK_BYTE pt[512]; size_t pt_len = sizeof(pt);
        if (EVP_PKEY_decrypt_init(dec_ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) == 1)
            EVP_PKEY_decrypt(dec_ctx, pt, &pt_len, ct, ct_len);
        EVP_PKEY_CTX_free(dec_ctx);
        break;
    }

    /* ── Multi-part EVP_DigestSign RSA ───────────────────────────────────── */
    case 6:
    case 7: {
        EVP_PKEY *pkey = (sel == 6) ? evp_rsa_priv : evp_ec_priv;
        if (!pkey) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), p11_eng, pkey) != 1) {
            EVP_MD_CTX_free(mctx);
            break;
        }
        size_t chunk = (plen > 0 && nchunks > 0)
                       ? (plen + nchunks - 1) / nchunks : 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks && off < plen; i++) {
            size_t tc = ((off + chunk) <= plen) ? chunk : (plen - off);
            EVP_DigestSignUpdate(mctx, pay + off, tc);
            off += tc;
        }
        CK_BYTE sig[512]; size_t slen = sizeof(sig);
        EVP_DigestSignFinal(mctx, sig, &slen);
        EVP_MD_CTX_free(mctx);
        break;
    }
    }

    ERR_clear_error();
    return 0;
}
