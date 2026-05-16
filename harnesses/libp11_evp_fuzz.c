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
 *   byte 0:  operation selector (0–25, see table)
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
 *   8  EVP_DigestSign (Ed25519)
 *   9  EVP_PKEY_derive (ECDH with EC P-256 keys)
 *  10  EVP_DigestSign (RSA-PSS SHA-256)
 *  11  EVP_DigestVerify (Ed25519): sign with real key, verify fuzzed msg
 *  12  EVP_PKEY_encrypt + EVP_PKEY_decrypt (RSA-PKCS1-PADDING)
 *  13  EVP_PKEY_encrypt + EVP_PKEY_decrypt (RSA-OAEP SHA-256)
 *  14  EVP_DigestSign (RSA-PSS SHA-384)
 *  15  EVP_PKEY_encrypt + EVP_PKEY_decrypt (RSA NO_PADDING)
 *  16  EVP_DigestSign  (SHA-384, EC  private key)
 *  17  EVP_DigestSign (RSA-X9.31, exercises CKM_RSA_X9_31)
 *  18  EVP_DigestSign (EC-SHA1, exercises different hash code path)
 *  19  EVP_DigestVerify multi-part RSA: DigestVerifyInit/Update×N/Final
 *  20  EVP_DigestVerify multi-part EC:  DigestVerifyInit/Update×N/Final
 *  21  RSA-OAEP with SHA-384 encrypt + decrypt
 *  22  RSA-OAEP with SHA-512 encrypt + decrypt
 *  23  EVP_DigestSign (Ed448)
 *  24  EVP_DigestVerify (Ed448): sign with real key, verify fuzzed msg
 *  25  RSA-OAEP with SHA-224 encrypt + decrypt
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
static EVP_PKEY *evp_ed_priv     = NULL;   /* Ed25519 via libp11 ENGINE */
static EVP_PKEY *evp_ed_pub      = NULL;
static EVP_PKEY *evp_ed448_priv  = NULL;   /* Ed448 via libp11 ENGINE */
static EVP_PKEY *evp_ed448_pub   = NULL;

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
    evp_ed_priv  = ENGINE_load_private_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%05;pin-value=1234", NULL, NULL);
    evp_ed_pub   = ENGINE_load_public_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%05;pin-value=1234", NULL, NULL);
    evp_ed448_priv = ENGINE_load_private_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%06;pin-value=1234", NULL, NULL);
    evp_ed448_pub  = ENGINE_load_public_key(
        p11_eng, "pkcs11:token=fuzz-token;id=%06;pin-value=1234", NULL, NULL);

    fprintf(stderr, "[libp11_evp] RSA priv=%p pub=%p  EC priv=%p pub=%p  Ed priv=%p Ed448 priv=%p\n",
            (void *)evp_rsa_priv, (void *)evp_rsa_pub,
            (void *)evp_ec_priv,  (void *)evp_ec_pub,
            (void *)evp_ed_priv,  (void *)evp_ed448_priv);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2 || !p11_eng) return 0;

    uint8_t sel     = data[0] % 26;
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

    /* ── EdDSA Sign ──────────────────────────────────────────────────────── */
    case 8: {
        if (!evp_ed_priv) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        /* EdDSA uses NULL digest */
        if (EVP_DigestSignInit(mctx, NULL, NULL, p11_eng, evp_ed_priv) == 1) {
            CK_BYTE sig[64]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── ECDH Derive ─────────────────────────────────────────────────────── */
    case 9: {
        if (!evp_ec_priv || !evp_ec_pub) break;

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_ec_priv, p11_eng);
        if (!ctx) break;

        if (EVP_PKEY_derive_init(ctx) == 1 &&
            EVP_PKEY_derive_set_peer(ctx, evp_ec_pub) == 1) {
            CK_BYTE secret[64]; size_t slen = sizeof(secret);
            EVP_PKEY_derive(ctx, secret, &slen);
        }
        EVP_PKEY_CTX_free(ctx);
        break;
    }

    /* ── RSA-PSS Sign (SHA-256) ─────────────────────────────────────────── */
    case 10: {
        if (!evp_rsa_priv) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;

        if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), p11_eng, evp_rsa_priv) == 1) {
            EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if (pctx) {
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
            }
            CK_BYTE sig[512]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── EdDSA Verify ─────────────────────────────────────────────────── */
    case 11: {
        if (!evp_ed_priv || !evp_ed_pub) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;

        /* Sign the payload to obtain a valid signature */
        CK_BYTE sig[64]; size_t slen = sizeof(sig);
        int ok = (EVP_DigestSignInit(mctx, NULL, NULL, p11_eng, evp_ed_priv) == 1)
              && (EVP_DigestSign(mctx, sig, &slen, pay, (int)plen) == 1);
        EVP_MD_CTX_free(mctx);

        if (!ok || slen == 0) break;

        /* Verify: use the fuzz payload as the message (real sig, fuzzed msg) */
        mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestVerifyInit(mctx, NULL, NULL, p11_eng, evp_ed_pub) == 1)
            EVP_DigestVerify(mctx, sig, slen, pay, (int)plen);
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── RSA-PKCS1-PADDING encrypt + decrypt ─────────────────────────── */
    case 12: {
        if (!evp_rsa_pub || !evp_rsa_priv) break;

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(evp_rsa_pub, p11_eng);
        if (!enc_ctx) break;
        CK_BYTE ct[512]; size_t ct_len = sizeof(ct);
        if (EVP_PKEY_encrypt_init(enc_ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_PADDING) != 1) {
            EVP_PKEY_CTX_free(enc_ctx);
            break;
        }
        size_t enc_plen = (plen > 214) ? 214 : plen;
        if (enc_plen < 1) enc_plen = 1;
        int enc_ok = (EVP_PKEY_encrypt(enc_ctx, ct, &ct_len,
                                        pay, enc_plen) == 1);
        EVP_PKEY_CTX_free(enc_ctx);

        if (!enc_ok) break;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(evp_rsa_priv, p11_eng);
        if (!dec_ctx) break;
        CK_BYTE pt[512]; size_t pt_len = sizeof(pt);
        if (EVP_PKEY_decrypt_init(dec_ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_PADDING) == 1)
            EVP_PKEY_decrypt(dec_ctx, pt, &pt_len, ct, ct_len);
        EVP_PKEY_CTX_free(dec_ctx);
        break;
    }

    /* ── RSA-OAEP with SHA-256 encrypt + decrypt ───────────────────── */
    case 13: {
        if (!evp_rsa_pub || !evp_rsa_priv) break;

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(evp_rsa_pub, p11_eng);
        if (!enc_ctx) break;
        CK_BYTE ct[512]; size_t ct_len = sizeof(ct);
        if (EVP_PKEY_encrypt_init(enc_ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set0_rsa_oaep_label(enc_ctx, NULL, 0) != 1) {
            EVP_PKEY_CTX_free(enc_ctx);
            break;
        }
        EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256());
        EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, EVP_sha256());
        size_t enc_plen = (plen > 214) ? 214 : plen;
        if (enc_plen < 1) enc_plen = 1;
        int enc_ok = (EVP_PKEY_encrypt(enc_ctx, ct, &ct_len,
                                        pay, enc_plen) == 1);
        EVP_PKEY_CTX_free(enc_ctx);

        if (!enc_ok) break;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(evp_rsa_priv, p11_eng);
        if (!dec_ctx) break;
        CK_BYTE pt[512]; size_t pt_len = sizeof(pt);
        if (EVP_PKEY_decrypt_init(dec_ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256());
            EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, EVP_sha256());
            EVP_PKEY_decrypt(dec_ctx, pt, &pt_len, ct, ct_len);
        }
        EVP_PKEY_CTX_free(dec_ctx);
        break;
    }

    /* ── RSA-PSS Sign with SHA-384 ───────────────────────────────────── */
    case 14: {
        if (!evp_rsa_priv) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;

        if (EVP_DigestSignInit(mctx, NULL, EVP_sha384(), p11_eng, evp_rsa_priv) == 1) {
            EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if (pctx) {
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
            }
            CK_BYTE sig[512]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── RSA raw encrypt/decrypt (NO_PADDING) ─────────────────────────── */
    case 15: {
        if (!evp_rsa_pub || !evp_rsa_priv) break;

        /* RSA_NO_PADDING requires input size == RSA key size (256 bytes for RSA-2048) */
        size_t rsa_size = 256;
        CK_BYTE in[256];
        memset(in, 0, sizeof(in));
        size_t enc_plen = (plen > rsa_size) ? rsa_size : plen;
        if (enc_plen < 1) enc_plen = 1;
        memcpy(in, pay, enc_plen);

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(evp_rsa_pub, p11_eng);
        if (!enc_ctx) break;
        CK_BYTE ct[256]; size_t ct_len = sizeof(ct);
        if (EVP_PKEY_encrypt_init(enc_ctx) != 1) {
            EVP_PKEY_CTX_free(enc_ctx);
            break;
        }
        EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_NO_PADDING);
        int enc_ok = (EVP_PKEY_encrypt(enc_ctx, ct, &ct_len, in, enc_plen) == 1);
        EVP_PKEY_CTX_free(enc_ctx);

        if (!enc_ok) break;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(evp_rsa_priv, p11_eng);
        if (!dec_ctx) break;
        CK_BYTE pt[256]; size_t pt_len = sizeof(pt);
        if (EVP_PKEY_decrypt_init(dec_ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_NO_PADDING) == 1)
            EVP_PKEY_decrypt(dec_ctx, pt, &pt_len, ct, ct_len);
        EVP_PKEY_CTX_free(dec_ctx);
        break;
    }

    /* ── EC Sign with SHA-384 ──────────────────────────────────────────────── */
    case 16: {
        if (!evp_ec_priv) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestSignInit(mctx, NULL, EVP_sha384(), p11_eng, evp_ec_priv) == 1) {
            CK_BYTE sig[512]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── RSA Sign with X9.31 padding ──────────────────────────────────────── */
    case 17: {
        if (!evp_rsa_priv) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), p11_eng, evp_rsa_priv) == 1) {
            EVP_PKEY_CTX *pctx = EVP_MD_CTX_get_pkey_ctx(mctx);
            if (pctx) {
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_X931_PADDING);
            }
            CK_BYTE sig[512]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── EC Sign with SHA-1 (selector 18) ──────────────────────────────── */
    case 18: {
        if (!evp_ec_priv) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestSignInit(mctx, NULL, EVP_sha1(), p11_eng, evp_ec_priv) == 1) {
            CK_BYTE sig[512]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── Multi-part EVP_DigestVerify RSA (selector 19) ────────────────── */
    case 19: {
        if (!evp_rsa_priv || !evp_rsa_pub) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;

        /* Sign the payload to obtain a valid signature */
        if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), p11_eng, evp_rsa_priv) != 1) {
            EVP_MD_CTX_free(mctx);
            break;
        }
        CK_BYTE sig[512]; size_t slen = sizeof(sig);
        if (EVP_DigestSign(mctx, sig, &slen, pay, (int)plen) != 1) {
            EVP_MD_CTX_free(mctx);
            break;
        }
        EVP_MD_CTX_free(mctx);

        /* Multi-part verify: Init/Update×N/Final */
        mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), p11_eng, evp_rsa_pub) != 1) {
            EVP_MD_CTX_free(mctx);
            break;
        }
        size_t chunk = (plen > 0 && nchunks > 0)
                       ? (plen + nchunks - 1) / nchunks : 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks && off < plen; i++) {
            size_t tc = ((off + chunk) <= plen) ? chunk : (plen - off);
            EVP_DigestVerifyUpdate(mctx, pay + off, tc);
            off += tc;
        }
        EVP_DigestVerifyFinal(mctx, sig, slen);
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── Multi-part EVP_DigestVerify EC (selector 20) ─────────────────── */
    case 20: {
        if (!evp_ec_priv || !evp_ec_pub) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;

        /* Sign the payload to obtain a valid signature */
        if (EVP_DigestSignInit(mctx, NULL, EVP_sha256(), p11_eng, evp_ec_priv) != 1) {
            EVP_MD_CTX_free(mctx);
            break;
        }
        CK_BYTE sig[512]; size_t slen = sizeof(sig);
        if (EVP_DigestSign(mctx, sig, &slen, pay, (int)plen) != 1) {
            EVP_MD_CTX_free(mctx);
            break;
        }
        EVP_MD_CTX_free(mctx);

        /* Multi-part verify: Init/Update×N/Final */
        mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), p11_eng, evp_ec_pub) != 1) {
            EVP_MD_CTX_free(mctx);
            break;
        }
        size_t chunk = (plen > 0 && nchunks > 0)
                       ? (plen + nchunks - 1) / nchunks : 0;
        size_t off = 0;
        for (uint8_t i = 0; i < nchunks && off < plen; i++) {
            size_t tc = ((off + chunk) <= plen) ? chunk : (plen - off);
            EVP_DigestVerifyUpdate(mctx, pay + off, tc);
            off += tc;
        }
        EVP_DigestVerifyFinal(mctx, sig, slen);
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── RSA-OAEP with SHA-384 encrypt + decrypt (selector 21) ────────── */
    case 21: {
        if (!evp_rsa_pub || !evp_rsa_priv) break;

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(evp_rsa_pub, p11_eng);
        if (!enc_ctx) break;
        CK_BYTE ct[512]; size_t ct_len = sizeof(ct);
        if (EVP_PKEY_encrypt_init(enc_ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set0_rsa_oaep_label(enc_ctx, NULL, 0) != 1) {
            EVP_PKEY_CTX_free(enc_ctx);
            break;
        }
        EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha384());
        EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, EVP_sha384());
        size_t enc_plen = (plen > 178) ? 178 : plen;
        if (enc_plen < 1) enc_plen = 1;
        int enc_ok = (EVP_PKEY_encrypt(enc_ctx, ct, &ct_len,
                                        pay, enc_plen) == 1);
        EVP_PKEY_CTX_free(enc_ctx);

        if (!enc_ok) break;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(evp_rsa_priv, p11_eng);
        if (!dec_ctx) break;
        CK_BYTE pt[512]; size_t pt_len = sizeof(pt);
        if (EVP_PKEY_decrypt_init(dec_ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha384());
            EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, EVP_sha384());
            EVP_PKEY_decrypt(dec_ctx, pt, &pt_len, ct, ct_len);
        }
        EVP_PKEY_CTX_free(dec_ctx);
        break;
    }

    /* ── RSA-OAEP with SHA-512 encrypt + decrypt (selector 22) ────────── */
    case 22: {
        if (!evp_rsa_pub || !evp_rsa_priv) break;

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(evp_rsa_pub, p11_eng);
        if (!enc_ctx) break;
        CK_BYTE ct[512]; size_t ct_len = sizeof(ct);
        if (EVP_PKEY_encrypt_init(enc_ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set0_rsa_oaep_label(enc_ctx, NULL, 0) != 1) {
            EVP_PKEY_CTX_free(enc_ctx);
            break;
        }
        EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha512());
        EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, EVP_sha512());
        size_t enc_plen = (plen > 142) ? 142 : plen;
        if (enc_plen < 1) enc_plen = 1;
        int enc_ok = (EVP_PKEY_encrypt(enc_ctx, ct, &ct_len,
                                        pay, enc_plen) == 1);
        EVP_PKEY_CTX_free(enc_ctx);

        if (!enc_ok) break;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(evp_rsa_priv, p11_eng);
        if (!dec_ctx) break;
        CK_BYTE pt[512]; size_t pt_len = sizeof(pt);
        if (EVP_PKEY_decrypt_init(dec_ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha512());
            EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, EVP_sha512());
            EVP_PKEY_decrypt(dec_ctx, pt, &pt_len, ct, ct_len);
        }
        EVP_PKEY_CTX_free(dec_ctx);
        break;
    }

    /* ── Ed448 Sign (selector 23) ─────────────────────────────────────────── */
    case 23: {
        if (!evp_ed448_priv) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        /* Ed448 uses NULL digest, same as Ed25519 */
        if (EVP_DigestSignInit(mctx, NULL, NULL, p11_eng, evp_ed448_priv) == 1) {
            CK_BYTE sig[64]; size_t slen = sizeof(sig);
            EVP_DigestSign(mctx, sig, &slen, pay, (int)plen);
        }
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── Ed448 Verify (selector 24) ───────────────────────────────────────── */
    case 24: {
        if (!evp_ed448_priv || !evp_ed448_pub) break;

        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        if (!mctx) break;

        /* Sign the payload to obtain a valid signature */
        CK_BYTE sig[64]; size_t slen = sizeof(sig);
        int ok = (EVP_DigestSignInit(mctx, NULL, NULL, p11_eng, evp_ed448_priv) == 1)
              && (EVP_DigestSign(mctx, sig, &slen, pay, (int)plen) == 1);
        EVP_MD_CTX_free(mctx);

        if (!ok || slen == 0) break;

        /* Verify: use the fuzz payload as the message (real sig, fuzzed msg) */
        mctx = EVP_MD_CTX_new();
        if (!mctx) break;
        if (EVP_DigestVerifyInit(mctx, NULL, NULL, p11_eng, evp_ed448_pub) == 1)
            EVP_DigestVerify(mctx, sig, slen, pay, (int)plen);
        EVP_MD_CTX_free(mctx);
        break;
    }

    /* ── RSA-OAEP with SHA-224 encrypt + decrypt (selector 25) ────────── */
    case 25: {
        if (!evp_rsa_pub || !evp_rsa_priv) break;

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(evp_rsa_pub, p11_eng);
        if (!enc_ctx) break;
        CK_BYTE ct[512]; size_t ct_len = sizeof(ct);
        if (EVP_PKEY_encrypt_init(enc_ctx) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) != 1 ||
            EVP_PKEY_CTX_set0_rsa_oaep_label(enc_ctx, NULL, 0) != 1) {
            EVP_PKEY_CTX_free(enc_ctx);
            break;
        }
        EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha224());
        EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, EVP_sha224());
        size_t enc_plen = (plen > 190) ? 190 : plen;
        if (enc_plen < 1) enc_plen = 1;
        int enc_ok = (EVP_PKEY_encrypt(enc_ctx, ct, &ct_len,
                                        pay, enc_plen) == 1);
        EVP_PKEY_CTX_free(enc_ctx);

        if (!enc_ok) break;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(evp_rsa_priv, p11_eng);
        if (!dec_ctx) break;
        CK_BYTE pt[512]; size_t pt_len = sizeof(pt);
        if (EVP_PKEY_decrypt_init(dec_ctx) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) == 1) {
            EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha224());
            EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, EVP_sha224());
            EVP_PKEY_decrypt(dec_ctx, pt, &pt_len, ct, ct_len);
        }
        EVP_PKEY_CTX_free(dec_ctx);
        break;
    }
    }

    ERR_clear_error();
    return 0;
}
