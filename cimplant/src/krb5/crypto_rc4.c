#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include "erebus/krb5_internal.h"

/* ---- MD4 (RFC 1320) ---- */

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void erebus_md4(const uint8_t *msg, size_t msg_len, uint8_t out[16]) {
    uint32_t a0 = 0x67452301, b0 = 0xEFCDAB89, c0 = 0x98BADCFE, d0 = 0x10325476;
    size_t new_len = msg_len + 1;
    while (new_len % 64 != 56) new_len++;
    uint8_t *buf = (uint8_t *)calloc(1, new_len + 8);
    if (!buf) {
        memset(out, 0, 16);
        return;
    }
    memcpy(buf, msg, msg_len);
    buf[msg_len] = 0x80;
    uint64_t bits = (uint64_t)msg_len * 8;
    memcpy(buf + new_len, &bits, 8); /* little-endian on Windows/x86 */

    for (size_t offset = 0; offset < new_len + 8; offset += 64) {
        uint32_t X[16];
        for (int i = 0; i < 16; i++) {
            X[i] = (uint32_t)buf[offset + i * 4]
                 | ((uint32_t)buf[offset + i * 4 + 1] << 8)
                 | ((uint32_t)buf[offset + i * 4 + 2] << 16)
                 | ((uint32_t)buf[offset + i * 4 + 3] << 24);
        }
        uint32_t A = a0, B = b0, C = c0, D = d0;
#define F(x,y,z) (((x)&(y))|((~x)&(z)))
#define G(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define H(x,y,z) ((x)^(y)^(z))
#define FF(a,b,c,d,x,s) a = rol(a + F(b,c,d) + x, s)
#define GG(a,b,c,d,x,s) a = rol(a + G(b,c,d) + x + 0x5A827999, s)
#define HH(a,b,c,d,x,s) a = rol(a + H(b,c,d) + x + 0x6ED9EBA1, s)
        FF(A,B,C,D,X[0],3);  FF(D,A,B,C,X[1],7);  FF(C,D,A,B,X[2],11); FF(B,C,D,A,X[3],19);
        FF(A,B,C,D,X[4],3);  FF(D,A,B,C,X[5],7);  FF(C,D,A,B,X[6],11); FF(B,C,D,A,X[7],19);
        FF(A,B,C,D,X[8],3);  FF(D,A,B,C,X[9],7);  FF(C,D,A,B,X[10],11);FF(B,C,D,A,X[11],19);
        FF(A,B,C,D,X[12],3); FF(D,A,B,C,X[13],7); FF(C,D,A,B,X[14],11);FF(B,C,D,A,X[15],19);
        GG(A,B,C,D,X[0],3);  GG(D,A,B,C,X[4],5);  GG(C,D,A,B,X[8],9);  GG(B,C,D,A,X[12],13);
        GG(A,B,C,D,X[1],3);  GG(D,A,B,C,X[5],5);  GG(C,D,A,B,X[9],9);  GG(B,C,D,A,X[13],13);
        GG(A,B,C,D,X[2],3);  GG(D,A,B,C,X[6],5);  GG(C,D,A,B,X[10],9); GG(B,C,D,A,X[14],13);
        GG(A,B,C,D,X[3],3);  GG(D,A,B,C,X[7],5);  GG(C,D,A,B,X[11],9); GG(B,C,D,A,X[15],13);
        HH(A,B,C,D,X[0],3);  HH(D,A,B,C,X[8],9);  HH(C,D,A,B,X[4],11); HH(B,C,D,A,X[12],15);
        HH(A,B,C,D,X[2],3);  HH(D,A,B,C,X[10],9); HH(C,D,A,B,X[6],11); HH(B,C,D,A,X[14],15);
        HH(A,B,C,D,X[1],3);  HH(D,A,B,C,X[9],9);  HH(C,D,A,B,X[5],11); HH(B,C,D,A,X[13],15);
        HH(A,B,C,D,X[3],3);  HH(D,A,B,C,X[11],9); HH(C,D,A,B,X[7],11); HH(B,C,D,A,X[15],15);
#undef F
#undef G
#undef H
#undef FF
#undef GG
#undef HH
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    free(buf);
    out[0] = (uint8_t)(a0); out[1] = (uint8_t)(a0>>8); out[2] = (uint8_t)(a0>>16); out[3] = (uint8_t)(a0>>24);
    out[4] = (uint8_t)(b0); out[5] = (uint8_t)(b0>>8); out[6] = (uint8_t)(b0>>16); out[7] = (uint8_t)(b0>>24);
    out[8] = (uint8_t)(c0); out[9] = (uint8_t)(c0>>8); out[10]= (uint8_t)(c0>>16); out[11]= (uint8_t)(c0>>24);
    out[12]= (uint8_t)(d0); out[13]= (uint8_t)(d0>>8); out[14]= (uint8_t)(d0>>16); out[15]= (uint8_t)(d0>>24);
}

/* UTF-8 → UTF-16LE (BMP only) then MD4 → NT hash */
int erebus_nt_hash(const char *password_utf8, uint8_t out[16]) {
    if (!password_utf8) return 0;
    size_t n = strlen(password_utf8);
    uint8_t *u16 = (uint8_t *)malloc(n * 2 + 2);
    if (!u16) return 0;
    size_t ulen = 0;
    for (size_t i = 0; i < n; ) {
        unsigned char c = (unsigned char)password_utf8[i];
        uint32_t cp;
        if (c < 0x80) {
            cp = c;
            i += 1;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < n) {
            cp = ((c & 0x1F) << 6) | (password_utf8[i + 1] & 0x3F);
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < n) {
            cp = ((c & 0x0F) << 12) | ((password_utf8[i + 1] & 0x3F) << 6) | (password_utf8[i + 2] & 0x3F);
            i += 3;
        } else {
            free(u16);
            return 0;
        }
        if (cp > 0xFFFF) { free(u16); return 0; }
        u16[ulen++] = (uint8_t)(cp & 0xFF);
        u16[ulen++] = (uint8_t)((cp >> 8) & 0xFF);
    }
    erebus_md4(u16, ulen, out);
    free(u16);
    return 1;
}

/* ---- HMAC-MD5 via BCrypt ---- */

static int hmac_md5(const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len, uint8_t out[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st < 0) return 0;
    st = BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (st < 0) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    if (data_len)
        st = BCryptHashData(h, (PUCHAR)data, (ULONG)data_len, 0);
    if (st >= 0)
        st = BCryptFinishHash(h, out, 16, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st >= 0;
}

/* ---- RC4 ---- */

typedef struct {
    uint8_t S[256];
    int i, j;
} rc4_state;

static void rc4_init(rc4_state *st, const uint8_t *key, size_t key_len) {
    for (int i = 0; i < 256; i++) st->S[i] = (uint8_t)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + st->S[i] + key[i % key_len]) & 0xFF;
        uint8_t t = st->S[i];
        st->S[i] = st->S[j];
        st->S[j] = t;
    }
    st->i = st->j = 0;
}

static void rc4_crypt(rc4_state *st, uint8_t *buf, size_t n) {
    for (size_t k = 0; k < n; k++) {
        st->i = (st->i + 1) & 0xFF;
        st->j = (st->j + st->S[st->i]) & 0xFF;
        uint8_t t = st->S[st->i];
        st->S[st->i] = st->S[st->j];
        st->S[st->j] = t;
        buf[k] ^= st->S[(st->S[st->i] + st->S[st->j]) & 0xFF];
    }
}

int erebus_krb_random(uint8_t *buf, size_t n) {
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st >= 0;
}

/* RFC 4757 RC4-HMAC */
int erebus_rc4_hmac_encrypt(const uint8_t key[16], int32_t usage,
    const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len) {
    uint8_t confounder[8];
    if (!erebus_krb_random(confounder, 8)) return 0;

    size_t data_len = 8 + plain_len;
    uint8_t *data = (uint8_t *)malloc(data_len);
    if (!data) return 0;
    memcpy(data, confounder, 8);
    memcpy(data + 8, plain, plain_len);

    uint8_t T[4] = {
        (uint8_t)(usage & 0xFF),
        (uint8_t)((usage >> 8) & 0xFF),
        (uint8_t)((usage >> 16) & 0xFF),
        (uint8_t)((usage >> 24) & 0xFF),
    };
    uint8_t K1[16], K3[16], checksum[16];
    if (!hmac_md5(key, 16, T, 4, K1)) { free(data); return 0; }
    if (!hmac_md5(K1, 16, data, data_len, checksum)) { free(data); return 0; }
    if (!hmac_md5(K1, 16, checksum, 16, K3)) { free(data); return 0; }

    rc4_state st;
    rc4_init(&st, K3, 16);
    rc4_crypt(&st, data, data_len);

    *out_len = 16 + data_len;
    *out = (uint8_t *)malloc(*out_len);
    if (!*out) { free(data); return 0; }
    memcpy(*out, checksum, 16);
    memcpy(*out + 16, data, data_len);
    free(data);
    return 1;
}

int erebus_rc4_hmac_decrypt(const uint8_t key[16], int32_t usage,
    const uint8_t *cipher, size_t cipher_len, uint8_t **out, size_t *out_len) {
    if (cipher_len < 16 + 8) return 0;
    const uint8_t *checksum = cipher;
    const uint8_t *edata = cipher + 16;
    size_t edata_len = cipher_len - 16;

    uint8_t T[4] = {
        (uint8_t)(usage & 0xFF),
        (uint8_t)((usage >> 8) & 0xFF),
        (uint8_t)((usage >> 16) & 0xFF),
        (uint8_t)((usage >> 24) & 0xFF),
    };
    uint8_t K1[16], K3[16], exp[16];
    if (!hmac_md5(key, 16, T, 4, K1)) return 0;
    if (!hmac_md5(K1, 16, checksum, 16, K3)) return 0;

    uint8_t *plain = (uint8_t *)malloc(edata_len);
    if (!plain) return 0;
    memcpy(plain, edata, edata_len);
    rc4_state st;
    rc4_init(&st, K3, 16);
    rc4_crypt(&st, plain, edata_len);

    if (!hmac_md5(K1, 16, plain, edata_len, exp)) { free(plain); return 0; }
    if (memcmp(exp, checksum, 16) != 0) { free(plain); return 0; }

    /* strip 8-byte confounder */
    *out_len = edata_len - 8;
    *out = (uint8_t *)malloc(*out_len);
    if (!*out) { free(plain); return 0; }
    memcpy(*out, plain + 8, *out_len);
    free(plain);
    return 1;
}
