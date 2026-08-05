#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "erebus/crypto.h"

int erebus_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > out_cap) return 0;
    for (size_t i = 0; i < n; i += 2) {
        unsigned v;
        char pair[3] = { hex[i], hex[i + 1], 0 };
        if (sscanf(pair, "%02x", &v) != 1) return 0;
        out[i / 2] = (uint8_t)v;
    }
    *out_len = n / 2;
    return 1;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int erebus_b64_decode(const char *b64, uint8_t **out, size_t *out_len) {
    size_t in_len = strlen(b64);
    uint8_t *buf = (uint8_t *)malloc(in_len);
    if (!buf) return 0;
    size_t o = 0;
    int val = 0, valb = -8;
    for (size_t i = 0; i < in_len; i++) {
        char c = b64[i];
        if (c == '=') break;
        const char *p = strchr(b64_table, c);
        if (!p) continue;
        val = (val << 6) + (int)(p - b64_table);
        valb += 6;
        if (valb >= 0) {
            buf[o++] = (uint8_t)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    *out = buf;
    *out_len = o;
    return 1;
}

int erebus_hmac_sha256(const uint8_t *key, size_t key_len,
    const uint8_t *implant_id, size_t id_len, int64_t timestamp,
    uint8_t out[32]) {
    uint8_t ts[8];
    for (int i = 7; i >= 0; i--) {
        ts[i] = (uint8_t)(timestamp & 0xFF);
        timestamp >>= 8;
    }
    unsigned int out_len = 32;
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) return 0;
    int ok = HMAC_Init_ex(ctx, key, (int)key_len, EVP_sha256(), NULL)
        && HMAC_Update(ctx, implant_id, id_len)
        && HMAC_Update(ctx, ts, 8)
        && HMAC_Final(ctx, out, &out_len);
    HMAC_CTX_free(ctx);
    return ok ? 1 : 0;
}

int erebus_aes_gcm_encrypt(const uint8_t key[32], const uint8_t *pt, size_t pt_len, uint8_t **out, size_t *out_len) {
    uint8_t nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    size_t total = 12 + pt_len + 16;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return 0; }
    memcpy(buf, nonce, 12);

    int len = 0, ct_len = 0;
    int ok = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto fail;
    if (pt_len && EVP_EncryptUpdate(ctx, buf + 12, &len, pt, (int)pt_len) != 1) goto fail;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, buf + 12 + ct_len, &len) != 1) goto fail;
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, buf + 12 + ct_len) != 1) goto fail;
    ok = 1;
    *out = buf;
    *out_len = 12 + (size_t)ct_len + 16;
    EVP_CIPHER_CTX_free(ctx);
    return 1;

fail:
    free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int erebus_aes_gcm_decrypt(const uint8_t key[32], const uint8_t *ct, size_t ct_len, uint8_t **out, size_t *out_len) {
    if (ct_len < 28) return 0;
    const uint8_t *nonce = ct;
    size_t enc_len = ct_len - 12 - 16;
    const uint8_t *tag = ct + 12 + enc_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    uint8_t *buf = (uint8_t *)malloc(enc_len + 1);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return 0; }

    int len = 0, pt_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto fail;
    if (enc_len && EVP_DecryptUpdate(ctx, buf, &len, ct + 12, (int)enc_len) != 1) goto fail;
    pt_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto fail;
    if (EVP_DecryptFinal_ex(ctx, buf + pt_len, &len) != 1) goto fail;
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    *out = buf;
    *out_len = (size_t)pt_len;
    return 1;

fail:
    free(buf);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

uint32_t erebus_jitter_ms(uint32_t base_ms, int jitter_pct) {
    if (jitter_pct <= 0) return base_ms;
    uint32_t r = 0;
    RAND_bytes((unsigned char *)&r, sizeof(r));
    double factor = (double)jitter_pct / 100.0;
    double jitter = (double)base_ms * factor * (((double)(r % 10000) / 5000.0) - 1.0);
    int64_t out = (int64_t)base_ms + (int64_t)jitter;
    return out < 0 ? base_ms : (uint32_t)out;
}
