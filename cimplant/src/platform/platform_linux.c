#define _GNU_SOURCE
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "erebus/platform.h"

void erebus_sleep_ms(uint32_t ms) {
    usleep((useconds_t)ms * 1000u);
}

int64_t erebus_unix_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return (int64_t)time(NULL) * 1000;
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000L);
}

void erebus_get_identity(char *hostname, size_t hcap, char *username, size_t ucap,
    uint32_t *pid, char *integrity, size_t icap) {
    if (hostname && hcap) {
        hostname[0] = '\0';
        gethostname(hostname, hcap);
        hostname[hcap - 1] = '\0';
    }
    if (username && ucap) {
        username[0] = '\0';
        struct passwd *pw = getpwuid(getuid());
        if (pw && pw->pw_name)
            strncpy(username, pw->pw_name, ucap - 1);
        else
            snprintf(username, ucap, "%d", (int)getuid());
        username[ucap - 1] = '\0';
    }
    if (pid) *pid = (uint32_t)getpid();
    if (integrity && icap) {
        if (geteuid() == 0)
            strncpy(integrity, "root", icap - 1);
        else
            strncpy(integrity, "user", icap - 1);
        integrity[icap - 1] = '\0';
    }
}

const char *erebus_os_name(void) { return "linux"; }

const char *erebus_arch_name(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return "amd64";
#elif defined(__aarch64__)
    return "arm64";
#else
    return "unknown";
#endif
}

int erebus_platform_init(void) { return 1; }
