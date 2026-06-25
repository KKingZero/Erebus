#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "erebus/crypto.h"

#pragma comment(lib, "bcrypt.lib")

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
    size_t cap = in_len;
    uint8_t *buf = (uint8_t *)malloc(cap);
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
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;
    DWORD obj_len = 0, data_len = 0;
    PBYTE obj = NULL;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st < 0) return 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &data_len, 0);
    obj = (PBYTE)malloc(obj_len);
    if (!obj) goto fail;
    st = BCryptCreateHash(alg, &hash, obj, obj_len, (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) goto fail;
    BCryptHashData(hash, (PUCHAR)implant_id, (ULONG)id_len, 0);
    uint8_t ts[8];
    for (int i = 7; i >= 0; i--) {
        ts[i] = (uint8_t)(timestamp & 0xFF);
        timestamp >>= 8;
    }
    BCryptHashData(hash, ts, 8, 0);
    st = BCryptFinishHash(hash, out, 32, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    free(obj);
    return st >= 0;

fail:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    free(obj);
    return 0;
}

int erebus_aes_gcm_encrypt(const uint8_t key[32], const uint8_t *pt, size_t pt_len, uint8_t **out, size_t *out_len) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS st;
    DWORD obj_len = 0, data_len = 0;
    PBYTE obj = NULL;
    UCHAR nonce[12];
    if (BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return 0;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) return 0;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &data_len, 0);
    obj = (PBYTE)malloc(obj_len);
    if (!obj) goto fail;
    st = BCryptGenerateSymmetricKey(alg, &hkey, obj, obj_len, (PUCHAR)key, 32, 0);
    if (st < 0) goto fail;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce;
    info.cbNonce = sizeof(nonce);
    info.pbTag = NULL;
    info.cbTag = 16;

    size_t total = 12 + pt_len + 16;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) goto fail;
    memcpy(buf, nonce, 12);
    UCHAR tag[16];
    info.pbTag = tag;
    ULONG produced = 0;
    st = BCryptEncrypt(hkey, (PUCHAR)pt, (ULONG)pt_len, &info, NULL, 0, buf + 12, (ULONG)pt_len, &produced, 0);
    if (st < 0) { free(buf); goto fail; }
    memcpy(buf + 12 + produced, tag, 16);
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    free(obj);
    *out = buf;
    *out_len = 12 + produced + 16;
    return 1;

fail:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    free(obj);
    return 0;
}

int erebus_aes_gcm_decrypt(const uint8_t key[32], const uint8_t *ct, size_t ct_len, uint8_t **out, size_t *out_len) {
    if (ct_len < 28) return 0;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    NTSTATUS st;
    DWORD obj_len = 0, data_len = 0;
    PBYTE obj = NULL;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) return 0;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &data_len, 0);
    obj = (PBYTE)malloc(obj_len);
    if (!obj) goto fail;
    st = BCryptGenerateSymmetricKey(alg, &hkey, obj, obj_len, (PUCHAR)key, 32, 0);
    if (st < 0) goto fail;

    const UCHAR *nonce = ct;
    size_t enc_len = ct_len - 12 - 16;
    const UCHAR *tag = ct + 12 + enc_len;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbTag = (PUCHAR)tag;
    info.cbTag = 16;

    uint8_t *buf = (uint8_t *)malloc(enc_len + 1);
    if (!buf) goto fail;
    ULONG produced = 0;
    st = BCryptDecrypt(hkey, (PUCHAR)(ct + 12), (ULONG)enc_len, &info, NULL, 0, buf, (ULONG)enc_len, &produced, 0);
    if (st < 0) { free(buf); goto fail; }
    BCryptDestroyKey(hkey);
    BCryptCloseAlgorithmProvider(alg, 0);
    free(obj);
    *out = buf;
    *out_len = produced;
    return 1;

fail:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    free(obj);
    return 0;
}

uint32_t erebus_jitter_ms(uint32_t base_ms, int jitter_pct) {
    if (jitter_pct <= 0) return base_ms;
    uint32_t r = 0;
    BCryptGenRandom(NULL, (PUCHAR)&r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    double factor = (double)jitter_pct / 100.0;
    double jitter = (double)base_ms * factor * (((double)(r % 10000) / 5000.0) - 1.0);
    int64_t out = (int64_t)base_ms + (int64_t)jitter;
    return out < 0 ? base_ms : (uint32_t)out;
}