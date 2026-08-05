#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "erebus/pb_c2.h"
#include "erebus/task_handlers.h"

int erebus_task_net_ifconfig(uint8_t **out, size_t *out_len) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) return 0;

    size_t cap = 8, count = 0;
    erebus_net_interface *ifaces = (erebus_net_interface *)calloc(cap, sizeof(*ifaces));
    if (!ifaces) { freeifaddrs(ifaddr); return 0; }

    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)
            continue;

        /* find or create iface by name */
        erebus_net_interface *iface = NULL;
        for (size_t i = 0; i < count; i++) {
            if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
                iface = &ifaces[i];
                break;
            }
        }
        if (!iface) {
            if (count >= cap) {
                cap *= 2;
                erebus_net_interface *n = (erebus_net_interface *)realloc(ifaces, cap * sizeof(*ifaces));
                if (!n) goto fail;
                ifaces = n;
            }
            iface = &ifaces[count++];
            memset(iface, 0, sizeof(*iface));
            strncpy(iface->name, ifa->ifa_name, sizeof(iface->name) - 1);
            iface->up = (ifa->ifa_flags & IFF_UP) ? 1 : 0;
            iface->addresses = (char **)calloc(8, sizeof(char *));
            iface->address_count = 0;
        }

        char host[NI_MAXHOST];
        if (getnameinfo(ifa->ifa_addr,
                (ifa->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0)
            continue;
        if (iface->address_count < 8) {
            iface->addresses[iface->address_count] = strdup(host);
            if (iface->addresses[iface->address_count])
                iface->address_count++;
        }
    }

    freeifaddrs(ifaddr);
    int ok = erebus_pb_encode_net_ifconfig_result(ifaces, count, out, out_len);
    erebus_pb_free_net_ifconfig_result(ifaces, count);
    return ok;

fail:
    freeifaddrs(ifaddr);
    erebus_pb_free_net_ifconfig_result(ifaces, count);
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
    banner[0] = '\0';
    for (rp = res; rp; rp = rp->ai_next) {
        int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0) continue;
        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(s, rp->ai_addr, rp->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(s);
            continue;
        }
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(s, &wset);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        rc = select(s + 1, NULL, &wset, NULL, &tv);
        if (rc > 0) {
            int err = 0;
            socklen_t el = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &el);
            if (err == 0) {
                open = 1;
                fcntl(s, F_SETFL, flags);
                struct timeval rtv = {0, 200000};
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
                ssize_t n = recv(s, banner, banner_cap > 1 ? banner_cap - 1 : 0, 0);
                if (n > 0) banner[n] = '\0';
                else banner[0] = '\0';
            }
        }
        close(s);
        if (open) break;
    }
    freeaddrinfo(res);
    return open;
}

int erebus_task_net_portscan(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_portscan_task task;
    if (!erebus_pb_decode_portscan_task(data, data_len, &task) || !task.target[0])
        return 0;
    if (task.port_count == 0) return 0;

    uint32_t timeout = task.timeout_ms > 0 ? (uint32_t)task.timeout_ms : 500;
    erebus_port_result *results = (erebus_port_result *)calloc(task.port_count, sizeof(*results));
    if (!results) return 0;

    for (size_t i = 0; i < task.port_count; i++) {
        strncpy(results[i].host, task.target, sizeof(results[i].host) - 1);
        results[i].port = task.ports[i];
        char banner[256];
        results[i].open = try_connect(task.target, (uint16_t)task.ports[i], timeout, banner, sizeof(banner));
        if (results[i].open && banner[0])
            strncpy(results[i].service, banner, sizeof(results[i].service) - 1);
    }
    int ok = erebus_pb_encode_portscan_result(results, task.port_count, out, out_len);
    free(results);
    return ok;
}
