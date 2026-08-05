/*
 * Kerberos AES128/256-CTS-HMAC-SHA1-96 (RFC 3961 / 3962).
 * Windows BCrypt for AES-ECB + HMAC-SHA1; CTS and DK done in-process.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include "erebus/krb5_internal.h"

/* ---- HMAC-SHA1 ---- */

static int hmac_sha1(const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len, uint8_t out[20]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st < 0) return 0;
    st = BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    if (data_len)
        st = BCryptHashData(h, (PUCHAR)data, (ULONG)data_len, 0);
    if (st >= 0)
        st = BCryptFinishHash(h, out, 20, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0;
}

static int pbkdf2_hmac_sha1(const char *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, uint32_t iter,
    uint8_t *out, size_t out_len) {
    /* RFC 2898 PBKDF2 */
    size_t nblocks = (out_len + 19) / 20;
    uint8_t *tmp = (uint8_t *)malloc(out_len + 20);
    if (!tmp) return 0;
    size_t produced = 0;
    for (uint32_t block = 1; block <= nblocks; block++) {
        uint8_t u[20], t[20];
        uint8_t *asalt = (uint8_t *)malloc(salt_len + 4);
        if (!asalt) { free(tmp); return 0; }
        memcpy(asalt, salt, salt_len);
        asalt[salt_len] = (uint8_t)((block >> 24) & 0xFF);
        asalt[salt_len + 1] = (uint8_t)((block >> 16) & 0xFF);
        asalt[salt_len + 2] = (uint8_t)((block >> 8) & 0xFF);
        asalt[salt_len + 3] = (uint8_t)(block & 0xFF);
        if (!hmac_sha1((const uint8_t *)pass, pass_len, asalt, salt_len + 4, u)) {
            free(asalt);
            free(tmp);
            return 0;
        }
        free(asalt);
        memcpy(t, u, 20);
        for (uint32_t i = 1; i < iter; i++) {
            if (!hmac_sha1((const uint8_t *)pass, pass_len, u, 20, u)) {
                free(tmp);
                return 0;
            }
            for (int j = 0; j < 20; j++) t[j] ^= u[j];
        }
        size_t copy = out_len - produced;
        if (copy > 20) copy = 20;
        memcpy(tmp + produced, t, copy);
        produced += copy;
    }
    memcpy(out, tmp, out_len);
    free(tmp);
    return 1;
}

/* ---- AES-ECB single block via BCrypt ---- */

static int aes_ecb_encrypt_block(const uint8_t *key, size_t key_len,
    const uint8_t in[16], uint8_t out[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE kh = NULL;
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) return 0;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    st = BCryptGenerateSymmetricKey(alg, &kh, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    ULONG cb = 0;
    st = BCryptEncrypt(kh, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &cb, 0);
    BCryptDestroyKey(kh);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0 && cb == 16;
}

static int aes_ecb_decrypt_block(const uint8_t *key, size_t key_len,
    const uint8_t in[16], uint8_t out[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE kh = NULL;
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st < 0) return 0;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
        (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    st = BCryptGenerateSymmetricKey(alg, &kh, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    ULONG cb = 0;
    st = BCryptDecrypt(kh, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &cb, 0);
    BCryptDestroyKey(kh);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0 && cb == 16;
}

/* RFC 3961 n-fold */
static void nfold(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
    /* lcm(in_len, out_len) / in_len iterations of rotated copies */
    size_t a = in_len, b = out_len;
    while (b) { size_t t = b; b = a % b; a = t; }
    size_t g = a;
    size_t L = in_len * out_len / g;
    memset(out, 0, out_len);
    for (size_t i = 0; i < L; i++) {
        size_t rot = 13 * (i / in_len);
        size_t src = (i + (rot / 8)) % in_len;
        size_t bit = rot % 8;
        uint8_t v;
        if (bit == 0)
            v = in[src];
        else
            v = (uint8_t)((in[src] << bit) | (in[(src + 1) % in_len] >> (8 - bit)));
        size_t oi = i % out_len;
        unsigned sum = out[oi] + v;
        out[oi] = (uint8_t)(sum & 0xFF);
        /* propagate carry */
        unsigned carry = sum >> 8;
        size_t j = (oi + 1) % out_len;
        while (carry) {
            unsigned s2 = out[j] + carry;
            out[j] = (uint8_t)(s2 & 0xFF);
            carry = s2 >> 8;
            j = (j + 1) % out_len;
            if (j == (oi + 1) % out_len && carry) break; /* safety */
        }
    }
}

/* DK(key, constant) per RFC 3961 */
static int dk(const uint8_t *key, size_t key_len, const uint8_t *constant, size_t clen,
    uint8_t *out, size_t out_len) {
    uint8_t nfold_out[16];
    nfold(constant, clen, nfold_out, 16);

    uint8_t *buf = (uint8_t *)malloc(out_len + 16);
    if (!buf) return 0;
    size_t produced = 0;
    uint8_t block[16];
    memcpy(block, nfold_out, 16);
    while (produced < out_len) {
        uint8_t enc[16];
        if (!aes_ecb_encrypt_block(key, key_len, block, enc)) {
            free(buf);
            return 0;
        }
        size_t copy = out_len - produced;
        if (copy > 16) copy = 16;
        memcpy(buf + produced, enc, copy);
        produced += copy;
        memcpy(block, enc, 16);
    }
    memcpy(out, buf, out_len);
    free(buf);
    return 1;
}

static void usage_to_const(int32_t usage, uint8_t which, uint8_t out[5]) {
    /* big-endian usage || one-byte constant */
    out[0] = (uint8_t)((usage >> 24) & 0xFF);
    out[1] = (uint8_t)((usage >> 16) & 0xFF);
    out[2] = (uint8_t)((usage >> 8) & 0xFF);
    out[3] = (uint8_t)(usage & 0xFF);
    out[4] = which;
}

/* AES-CTS encrypt (RFC 3962 / CBC-CS3 style) — ciphertext length == plaintext length */
static int aes_cts_encrypt(const uint8_t *key, size_t key_len,
    const uint8_t *plain, size_t plain_len, uint8_t *cipher) {
    if (plain_len == 0) return 0;
    size_t nblocks = (plain_len + 15) / 16;
    uint8_t *pbuf = (uint8_t *)calloc(1, nblocks * 16);
    uint8_t *cbuf = (uint8_t *)calloc(1, nblocks * 16);
    if (!pbuf || !cbuf) { free(pbuf); free(cbuf); return 0; }
    memcpy(pbuf, plain, plain_len);

    uint8_t prev[16];
    memset(prev, 0, 16);
    for (size_t i = 0; i < nblocks; i++) {
        uint8_t x[16];
        for (int j = 0; j < 16; j++) x[j] = pbuf[i * 16 + j] ^ prev[j];
        if (!aes_ecb_encrypt_block(key, key_len, x, cbuf + i * 16)) {
            free(pbuf); free(cbuf); return 0;
        }
        memcpy(prev, cbuf + i * 16, 16);
    }

    if (nblocks == 1 || plain_len % 16 == 0) {
        memcpy(cipher, cbuf, plain_len);
    } else {
        size_t m = plain_len % 16;
        size_t prefix = (nblocks - 2) * 16;
        memcpy(cipher, cbuf, prefix);
        memcpy(cipher + prefix, cbuf + (nblocks - 1) * 16, 16);
        memcpy(cipher + prefix + 16, cbuf + (nblocks - 2) * 16, m);
    }
    free(pbuf);
    free(cbuf);
    return 1;
}

static int aes_cts_decrypt(const uint8_t *key, size_t key_len,
    const uint8_t *cipher, size_t cipher_len, uint8_t *plain) {
    if (cipher_len == 0) return 0;
    size_t nblocks = (cipher_len + 15) / 16;
    if (nblocks == 1) {
        uint8_t tmp[16];
        memset(tmp, 0, 16);
        memcpy(tmp, cipher, cipher_len);
        if (!aes_ecb_decrypt_block(key, key_len, tmp, tmp)) return 0;
        memcpy(plain, tmp, cipher_len);
        return 1;
    }

    uint8_t *cbuf = (uint8_t *)calloc(1, nblocks * 16);
    uint8_t *pbuf = (uint8_t *)calloc(1, nblocks * 16);
    if (!cbuf || !pbuf) { free(cbuf); free(pbuf); return 0; }

    if (cipher_len % 16 == 0) {
        memcpy(cbuf, cipher, cipher_len);
    } else {
        size_t m = cipher_len % 16;
        size_t prefix = (nblocks - 2) * 16;
        memcpy(cbuf, cipher, prefix);
        /* restore CBC order: Cn-1 was truncated, Cn was full after steal */
        memcpy(cbuf + (nblocks - 1) * 16, cipher + prefix, 16);
        memcpy(cbuf + (nblocks - 2) * 16, cipher + prefix + 16, m);
        /* decrypt Cn to recover padding for Cn-1 */
        uint8_t dn[16];
        if (!aes_ecb_decrypt_block(key, key_len, cbuf + (nblocks - 1) * 16, dn)) {
            free(cbuf); free(pbuf); return 0;
        }
        memcpy(cbuf + (nblocks - 2) * 16 + m, dn + m, 16 - m);
    }

    uint8_t prev[16];
    memset(prev, 0, 16);
    for (size_t i = 0; i < nblocks; i++) {
        uint8_t dec[16];
        if (!aes_ecb_decrypt_block(key, key_len, cbuf + i * 16, dec)) {
            free(cbuf); free(pbuf); return 0;
        }
        for (int j = 0; j < 16; j++) pbuf[i * 16 + j] = dec[j] ^ prev[j];
        memcpy(prev, cbuf + i * 16, 16);
    }
    memcpy(plain, pbuf, cipher_len);
    free(cbuf);
    free(pbuf);
    return 1;
}

int erebus_aes_string_to_key(int etype, const char *password, const char *realm, const char *user,
    uint8_t *key_out, size_t *key_len_out) {
    if (!password || !realm || !user || !key_out || !key_len_out) return 0;
    size_t klen = (etype == EREBUS_KRB_ETYPE_AES128) ? 16 :
                  (etype == EREBUS_KRB_ETYPE_AES256) ? 32 : 0;
    if (!klen) return 0;

    char salt[512];
    char realm_up[256];
    size_t rl = strlen(realm);
    if (rl >= sizeof(realm_up)) return 0;
    for (size_t i = 0; i < rl; i++) {
        char c = realm[i];
        realm_up[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    realm_up[rl] = '\0';
    /* AD salt: REALM + username (username as provided; often case-sensitive) */
    if (snprintf(salt, sizeof(salt), "%s%s", realm_up, user) >= (int)sizeof(salt)) return 0;

    uint8_t seed[32];
    uint32_t iter = 4096;
    if (!pbkdf2_hmac_sha1(password, strlen(password),
            (const uint8_t *)salt, strlen(salt), iter, seed, klen))
        return 0;

    /* key = DK(seed, "kerberos") — seed is already key-sized from PBKDF2 for AES */
    static const uint8_t kerberos[] = { 'k','e','r','b','e','r','o','s' };
    if (!dk(seed, klen, kerberos, sizeof(kerberos), key_out, klen)) return 0;
    *key_len_out = klen;
    return 1;
}

int erebus_aes_cts_hmac_encrypt(const uint8_t *key, size_t key_len, int32_t usage,
    const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len) {
    uint8_t ke[32], ki[32];
    uint8_t c_ke[5], c_ki[5];
    usage_to_const(usage, 0xAA, c_ke);
    usage_to_const(usage, 0x55, c_ki);
    if (!dk(key, key_len, c_ke, 5, ke, key_len)) return 0;
    if (!dk(key, key_len, c_ki, 5, ki, key_len)) return 0;

    /* confounder (16) || plain */
    size_t data_len = 16 + plain_len;
    uint8_t *data = (uint8_t *)malloc(data_len);
    if (!data) return 0;
    if (!erebus_krb_random(data, 16)) { free(data); return 0; }
    memcpy(data + 16, plain, plain_len);

    uint8_t hmac[20];
    if (!hmac_sha1(ki, key_len, data, data_len, hmac)) { free(data); return 0; }

    uint8_t *ced = (uint8_t *)malloc(data_len);
    if (!ced) { free(data); return 0; }
    if (!aes_cts_encrypt(ke, key_len, data, data_len, ced)) {
        free(data); free(ced); return 0;
    }
    free(data);

    *out_len = data_len + 12;
    *out = (uint8_t *)malloc(*out_len);
    if (!*out) { free(ced); return 0; }
    memcpy(*out, ced, data_len);
    memcpy(*out + data_len, hmac, 12);
    free(ced);
    return 1;
}

int erebus_aes_cts_hmac_decrypt(const uint8_t *key, size_t key_len, int32_t usage,
    const uint8_t *cipher, size_t cipher_len, uint8_t **out, size_t *out_len) {
    if (cipher_len < 16 + 12) return 0;
    size_t edata_len = cipher_len - 12;
    const uint8_t *hmac_got = cipher + edata_len;

    uint8_t ke[32], ki[32];
    uint8_t c_ke[5], c_ki[5];
    usage_to_const(usage, 0xAA, c_ke);
    usage_to_const(usage, 0x55, c_ki);
    if (!dk(key, key_len, c_ke, 5, ke, key_len)) return 0;
    if (!dk(key, key_len, c_ki, 5, ki, key_len)) return 0;

    uint8_t *plain = (uint8_t *)malloc(edata_len);
    if (!plain) return 0;
    if (!aes_cts_decrypt(ke, key_len, cipher, edata_len, plain)) {
        free(plain);
        return 0;
    }

    uint8_t hmac[20];
    if (!hmac_sha1(ki, key_len, plain, edata_len, hmac)) { free(plain); return 0; }
    if (memcmp(hmac, hmac_got, 12) != 0) { free(plain); return 0; }

    /* strip 16-byte confounder */
    if (edata_len < 16) { free(plain); return 0; }
    *out_len = edata_len - 16;
    *out = (uint8_t *)malloc(*out_len ? *out_len : 1);
    if (!*out) { free(plain); return 0; }
    if (*out_len) memcpy(*out, plain + 16, *out_len);
    free(plain);
    return 1;
}
