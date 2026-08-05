#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "erebus/ntlm_pth.h"

/* ---- HMAC-MD5 via BCrypt ---- */

static int hmac_md5(const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len, uint8_t out[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
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

static int utf8_to_utf16le(const char *s, uint8_t **out, size_t *out_len) {
    if (!s) s = "";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return 0;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return 0;
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n)) {
        free(w);
        return 0;
    }
    size_t bytes = ((size_t)n - 1) * 2; /* drop NUL */
    uint8_t *b = (uint8_t *)malloc(bytes ? bytes : 1);
    if (!b) { free(w); return 0; }
    memcpy(b, w, bytes);
    free(w);
    *out = b;
    *out_len = bytes;
    return 1;
}

/* erebus_ntlm_parse_hash / erebus_ntlm_split_user: ntlm_parse.c */

int erebus_ntlm_type1(const char *domain, uint8_t **out, size_t *out_len) {
    /* Minimal Negotiate: NTLMSSP\0 + type1 + flags (Unicode|NTLM|AlwaysSign|NegOEM|RequestTarget|128|56) */
    uint8_t msg[64];
    memset(msg, 0, sizeof(msg));
    memcpy(msg, "NTLMSSP\0", 8);
    msg[8] = 1; /* type 1 */
    /* flags LE at offset 12 */
    uint32_t flags = 0x00088207 | 0x00080000 | 0x20000000; /* UNICODE NTLM REQUEST_TARGET NTLM2 KEY_128 KEY_56 */
    flags = 0xE2088297; /* common negotiate set */
    msg[12] = (uint8_t)(flags);
    msg[13] = (uint8_t)(flags >> 8);
    msg[14] = (uint8_t)(flags >> 16);
    msg[15] = (uint8_t)(flags >> 24);
    /* domain/workstation empty fields already zero */
    (void)domain;
    *out = (uint8_t *)malloc(32);
    if (!*out) return 0;
    memcpy(*out, msg, 32);
    *out_len = 32;
    return 1;
}

static const uint8_t *extract_av_timestamp(const uint8_t *ti, size_t ti_len) {
    size_t i = 0;
    while (i + 4 <= ti_len) {
        uint16_t id = (uint16_t)(ti[i] | (ti[i + 1] << 8));
        uint16_t l = (uint16_t)(ti[i + 2] | (ti[i + 3] << 8));
        i += 4;
        if (id == 0) break;
        if (i + l > ti_len) break;
        if (id == 7 && l == 8) return ti + i;
        i += l;
    }
    return NULL;
}

int erebus_ntlm_type3_hash(const uint8_t *type2, size_t type2_len,
    const char *user, const char *domain, const uint8_t nt[16],
    uint8_t **out, size_t *out_len) {
    if (!type2 || type2_len < 32 || !user || !nt || !out) return 0;
    if (memcmp(type2, "NTLMSSP\0", 8) != 0) return 0;
    uint32_t msg_type = type2[8] | (type2[9] << 8) | (type2[10] << 16) | (type2[11] << 24);
    if (msg_type != 2) return 0;

    uint32_t flags = type2[20] | (type2[21] << 8) | (type2[22] << 16) | (type2[23] << 24);
    const uint8_t *server_chal = type2 + 24;

    const uint8_t *target_info = NULL;
    size_t target_info_len = 0;
    if (type2_len >= 48) {
        uint16_t ti_len = (uint16_t)(type2[40] | (type2[41] << 8));
        uint32_t ti_off = type2[44] | (type2[45] << 8) | (type2[46] << 16) | (type2[47] << 24);
        if (ti_off && ti_len && ti_off + ti_len <= type2_len) {
            target_info = type2 + ti_off;
            target_info_len = ti_len;
        }
    }

    /* NTOWFv2 = HMAC_MD5(NT, UTF16(Upper(User)+Domain)) */
    char user_up[256];
    size_t ul = 0;
    for (; user[ul] && ul + 1 < sizeof(user_up); ul++) {
        char c = user[ul];
        user_up[ul] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    user_up[ul] = '\0';
    if (!domain) domain = "";

    char blob[512];
    snprintf(blob, sizeof(blob), "%s%s", user_up, domain);
    uint8_t *blob_u16 = NULL;
    size_t blob_u16_len = 0;
    if (!utf8_to_utf16le(blob, &blob_u16, &blob_u16_len)) return 0;

    uint8_t ntowf[16];
    if (!hmac_md5(nt, 16, blob_u16, blob_u16_len, ntowf)) {
        free(blob_u16);
        return 0;
    }
    free(blob_u16);

    uint8_t timestamp[8];
    const uint8_t *av_ts = target_info ? extract_av_timestamp(target_info, target_info_len) : NULL;
    if (av_ts) {
        memcpy(timestamp, av_ts, 8);
    } else {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        timestamp[0] = (uint8_t)(ft.dwLowDateTime);
        timestamp[1] = (uint8_t)(ft.dwLowDateTime >> 8);
        timestamp[2] = (uint8_t)(ft.dwLowDateTime >> 16);
        timestamp[3] = (uint8_t)(ft.dwLowDateTime >> 24);
        timestamp[4] = (uint8_t)(ft.dwHighDateTime);
        timestamp[5] = (uint8_t)(ft.dwHighDateTime >> 8);
        timestamp[6] = (uint8_t)(ft.dwHighDateTime >> 16);
        timestamp[7] = (uint8_t)(ft.dwHighDateTime >> 24);
    }

    uint8_t client_chal[8];
    BCryptGenRandom(NULL, client_chal, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    /* temp = 01010000 00000000 | time | clientChal | 00000000 | targetInfo | 00000000 */
    size_t temp_len = 8 + 8 + 8 + 4 + target_info_len + 4;
    uint8_t *temp = (uint8_t *)malloc(temp_len);
    if (!temp) return 0;
    size_t tp = 0;
    temp[tp++] = 1; temp[tp++] = 1;
    memset(temp + tp, 0, 6); tp += 6;
    memcpy(temp + tp, timestamp, 8); tp += 8;
    memcpy(temp + tp, client_chal, 8); tp += 8;
    memset(temp + tp, 0, 4); tp += 4;
    if (target_info_len) {
        memcpy(temp + tp, target_info, target_info_len);
        tp += target_info_len;
    }
    memset(temp + tp, 0, 4); tp += 4;

    uint8_t chal_temp[8 + 512];
    if (8 + tp > sizeof(chal_temp)) {
        /* heap path */
        uint8_t *ct = (uint8_t *)malloc(8 + tp);
        if (!ct) { free(temp); return 0; }
        memcpy(ct, server_chal, 8);
        memcpy(ct + 8, temp, tp);
        uint8_t nt_proof[16];
        if (!hmac_md5(ntowf, 16, ct, 8 + tp, nt_proof)) {
            free(ct); free(temp); return 0;
        }
        free(ct);

        size_t nt_resp_len = 16 + tp;
        uint8_t *nt_resp = (uint8_t *)malloc(nt_resp_len);
        if (!nt_resp) { free(temp); return 0; }
        memcpy(nt_resp, nt_proof, 16);
        memcpy(nt_resp + 16, temp, tp);
        free(temp);

        uint8_t *user_u = NULL, *dom_u = NULL;
        size_t user_ul = 0, dom_ul = 0;
        if (!utf8_to_utf16le(user, &user_u, &user_ul)) { free(nt_resp); return 0; }
        if (!utf8_to_utf16le(domain, &dom_u, &dom_ul)) { free(user_u); free(nt_resp); return 0; }

        flags &= ~(uint32_t)0x02000000; /* clear VERSION */
        const size_t header = 64;
        size_t lm_len = 0;
        size_t total = header + lm_len + nt_resp_len + dom_ul + user_ul;
        uint8_t *msg = (uint8_t *)calloc(1, total);
        if (!msg) { free(user_u); free(dom_u); free(nt_resp); return 0; }
        memcpy(msg, "NTLMSSP\0", 8);
        msg[8] = 3;
        uint32_t off = (uint32_t)header;
        /* LM empty */
        msg[12] = msg[14] = 0;
        msg[16] = (uint8_t)off; msg[17] = (uint8_t)(off >> 8); msg[18] = (uint8_t)(off >> 16); msg[19] = (uint8_t)(off >> 24);
        /* NT response */
        msg[20] = (uint8_t)(nt_resp_len); msg[21] = (uint8_t)(nt_resp_len >> 8);
        msg[22] = msg[20]; msg[23] = msg[21];
        msg[24] = (uint8_t)off; msg[25] = (uint8_t)(off >> 8); msg[26] = (uint8_t)(off >> 16); msg[27] = (uint8_t)(off >> 24);
        memcpy(msg + off, nt_resp, nt_resp_len); off += (uint32_t)nt_resp_len;
        /* Domain */
        msg[28] = (uint8_t)(dom_ul); msg[29] = (uint8_t)(dom_ul >> 8);
        msg[30] = msg[28]; msg[31] = msg[29];
        msg[32] = (uint8_t)off; msg[33] = (uint8_t)(off >> 8); msg[34] = (uint8_t)(off >> 16); msg[35] = (uint8_t)(off >> 24);
        memcpy(msg + off, dom_u, dom_ul); off += (uint32_t)dom_ul;
        /* User */
        msg[36] = (uint8_t)(user_ul); msg[37] = (uint8_t)(user_ul >> 8);
        msg[38] = msg[36]; msg[39] = msg[37];
        msg[40] = (uint8_t)off; msg[41] = (uint8_t)(off >> 8); msg[42] = (uint8_t)(off >> 16); msg[43] = (uint8_t)(off >> 24);
        memcpy(msg + off, user_u, user_ul); off += (uint32_t)user_ul;
        /* Workstation empty at 44 */
        msg[44] = msg[46] = 0;
        msg[48] = (uint8_t)off; msg[49] = (uint8_t)(off >> 8); msg[50] = (uint8_t)(off >> 16); msg[51] = (uint8_t)(off >> 24);
        /* EncryptedRandomSessionKey empty 52 */
        msg[52] = msg[54] = 0;
        msg[56] = (uint8_t)off; msg[57] = (uint8_t)(off >> 8); msg[58] = (uint8_t)(off >> 16); msg[59] = (uint8_t)(off >> 24);
        msg[60] = (uint8_t)flags; msg[61] = (uint8_t)(flags >> 8);
        msg[62] = (uint8_t)(flags >> 16); msg[63] = (uint8_t)(flags >> 24);

        free(user_u); free(dom_u); free(nt_resp);
        *out = msg;
        *out_len = off;
        return 1;
    }

    memcpy(chal_temp, server_chal, 8);
    memcpy(chal_temp + 8, temp, tp);
    uint8_t nt_proof[16];
    if (!hmac_md5(ntowf, 16, chal_temp, 8 + tp, nt_proof)) {
        free(temp);
        return 0;
    }

    size_t nt_resp_len = 16 + tp;
    uint8_t *nt_resp = (uint8_t *)malloc(nt_resp_len);
    if (!nt_resp) { free(temp); return 0; }
    memcpy(nt_resp, nt_proof, 16);
    memcpy(nt_resp + 16, temp, tp);
    free(temp);

    uint8_t *user_u = NULL, *dom_u = NULL;
    size_t user_ul = 0, dom_ul = 0;
    if (!utf8_to_utf16le(user, &user_u, &user_ul)) { free(nt_resp); return 0; }
    if (!utf8_to_utf16le(domain, &dom_u, &dom_ul)) { free(user_u); free(nt_resp); return 0; }

    flags &= ~(uint32_t)0x02000000;
    const size_t header = 64;
    size_t total = header + nt_resp_len + dom_ul + user_ul;
    uint8_t *msg = (uint8_t *)calloc(1, total);
    if (!msg) { free(user_u); free(dom_u); free(nt_resp); return 0; }
    memcpy(msg, "NTLMSSP\0", 8);
    msg[8] = 3;
    uint32_t off = (uint32_t)header;
    msg[12] = msg[14] = 0;
    msg[16] = (uint8_t)off; msg[17] = (uint8_t)(off >> 8); msg[18] = (uint8_t)(off >> 16); msg[19] = (uint8_t)(off >> 24);
    msg[20] = (uint8_t)(nt_resp_len); msg[21] = (uint8_t)(nt_resp_len >> 8);
    msg[22] = msg[20]; msg[23] = msg[21];
    msg[24] = (uint8_t)off; msg[25] = (uint8_t)(off >> 8); msg[26] = (uint8_t)(off >> 16); msg[27] = (uint8_t)(off >> 24);
    memcpy(msg + off, nt_resp, nt_resp_len); off += (uint32_t)nt_resp_len;
    msg[28] = (uint8_t)(dom_ul); msg[29] = (uint8_t)(dom_ul >> 8);
    msg[30] = msg[28]; msg[31] = msg[29];
    msg[32] = (uint8_t)off; msg[33] = (uint8_t)(off >> 8); msg[34] = (uint8_t)(off >> 16); msg[35] = (uint8_t)(off >> 24);
    memcpy(msg + off, dom_u, dom_ul); off += (uint32_t)dom_ul;
    msg[36] = (uint8_t)(user_ul); msg[37] = (uint8_t)(user_ul >> 8);
    msg[38] = msg[36]; msg[39] = msg[37];
    msg[40] = (uint8_t)off; msg[41] = (uint8_t)(off >> 8); msg[42] = (uint8_t)(off >> 16); msg[43] = (uint8_t)(off >> 24);
    memcpy(msg + off, user_u, user_ul); off += (uint32_t)user_ul;
    msg[44] = msg[46] = 0;
    msg[48] = (uint8_t)off; msg[49] = (uint8_t)(off >> 8); msg[50] = (uint8_t)(off >> 16); msg[51] = (uint8_t)(off >> 24);
    msg[52] = msg[54] = 0;
    msg[56] = (uint8_t)off; msg[57] = (uint8_t)(off >> 8); msg[58] = (uint8_t)(off >> 16); msg[59] = (uint8_t)(off >> 24);
    msg[60] = (uint8_t)flags; msg[61] = (uint8_t)(flags >> 8);
    msg[62] = (uint8_t)(flags >> 16); msg[63] = (uint8_t)(flags >> 24);

    free(user_u); free(dom_u); free(nt_resp);
    *out = msg;
    *out_len = off;
    return 1;
}
