#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/modules.h"

int erebus_mod_run_cmd(const char *cmdline, char **stdout_out, char **stderr_out, int32_t *exit_code) {
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

    char buf[8192];
    strncpy(buf, cmdline, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
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

uint32_t erebus_mod_find_pid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return 0; }
    do {
        if (_stricmp(pe.szExeFile, name) == 0) {
            uint32_t pid = pe.th32ProcessID;
            CloseHandle(snap);
            return pid;
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return 0;
}

void erebus_mod_domain_to_base_dn(const char *domain, char *out, size_t out_cap) {
    char tmp[256];
    strncpy(tmp, domain, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    out[0] = '\0';
    char *tok = strtok(tmp, ".");
    int first = 1;
    while (tok) {
        char part[280];
        snprintf(part, sizeof(part), "%sDC=%s", first ? "" : ",", tok);
        size_t len = strlen(out);
        snprintf(out + len, out_cap - len, "%s", part);
        first = 0;
        tok = strtok(NULL, ".");
    }
}