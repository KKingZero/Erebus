/*
 * Pure NTLM helpers (hash parse + user split) — host-testable without Win32.
 */
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "erebus/ntlm_pth.h"

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int erebus_ntlm_parse_hash(const char *hash_str, uint8_t nt[16]) {
    if (!hash_str || !nt) return 0;
    const char *p = hash_str;
    const char *colon = strchr(hash_str, ':');
    if (colon) p = colon + 1;
    while (*p == ' ' || *p == '\t') p++;
    char hex[33];
    size_t n = 0;
    for (; p[n] && n < 32; n++) {
        if (!isxdigit((unsigned char)p[n])) break;
        hex[n] = (char)tolower((unsigned char)p[n]);
    }
    hex[n] = '\0';
    if (n != 32) return 0;
    for (int i = 0; i < 16; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        nt[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

void erebus_ntlm_split_user(const char *user_in, const char *domain_in,
    char *domain_out, size_t domain_cap, char *user_out, size_t user_cap) {
    if (!domain_out || !domain_cap || !user_out || !user_cap) return;
    domain_out[0] = '\0';
    user_out[0] = '\0';
    if (domain_in && domain_in[0])
        snprintf(domain_out, domain_cap, "%s", domain_in);
    if (!user_in || !user_in[0]) return;

    const char *bs = strchr(user_in, '\\');
    const char *at = strchr(user_in, '@');
    if (bs && bs > user_in) {
        size_t dl = (size_t)(bs - user_in);
        if (dl >= domain_cap) dl = domain_cap - 1;
        memcpy(domain_out, user_in, dl);
        domain_out[dl] = '\0';
        snprintf(user_out, user_cap, "%s", bs + 1);
    } else if (at && at > user_in) {
        size_t ul = (size_t)(at - user_in);
        if (ul >= user_cap) ul = user_cap - 1;
        memcpy(user_out, user_in, ul);
        user_out[ul] = '\0';
        if (!domain_out[0])
            snprintf(domain_out, domain_cap, "%s", at + 1);
    } else {
        snprintf(user_out, user_cap, "%s", user_in);
    }
}
