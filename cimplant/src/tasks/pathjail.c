#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#ifndef EREBUS_PATHJAIL_HOST_TEST
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <limits.h>
#include <unistd.h>
#endif
#endif

#include "erebus/pathjail.h"

#ifndef EREBUS_PATH_MAX
#define EREBUS_PATH_MAX 520
#endif

int erebus_path_is_absolute(const char *path) {
    if (!path || !path[0]) return 0;
    /* Unix-style absolute or UNC */
    if (path[0] == '/' || path[0] == '\\') return 1;
    /* Drive-letter absolute: C:\ or C:/ or C: */
    if (((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/' || path[2] == '\0')) {
        return 1;
    }
    return 0;
}

/* Reject paths that escape via ".." segments (after ignoring "." and collapsing separators). */
int erebus_path_has_dotdot_escape(const char *path) {
    if (!path || !path[0]) return 0;

    char buf[EREBUS_PATH_MAX];
    size_t len = 0;
    for (const char *p = path; *p && len + 1 < sizeof(buf); p++) {
        char c = (*p == '/') ? '\\' : *p;
        if (c == '\\' && len > 0 && buf[len - 1] == '\\') continue;
        buf[len++] = c;
    }
    buf[len] = '\0';

    const char *s = buf;
    int depth = 0;
    while (*s) {
        while (*s == '\\') s++;
        if (!*s) break;
        const char *end = s;
        while (*end && *end != '\\') end++;
        size_t seglen = (size_t)(end - s);
        if (seglen == 1 && s[0] == '.') {
            /* . */
        } else if (seglen == 2 && s[0] == '.' && s[1] == '.') {
            depth--;
            if (depth < 0) return 1;
        } else if (seglen > 0) {
            depth++;
        }
        s = end;
    }
    return 0;
}

#ifndef EREBUS_PATHJAIL_HOST_TEST

static int path_under_cwd(const char *cwd, const char *resolved) {
    size_t cl = strlen(cwd);
    if (cl == 0) return 0;
#ifdef _WIN32
    if (_strnicmp(resolved, cwd, cl) != 0) return 0;
#else
    if (strncmp(resolved, cwd, cl) != 0) return 0;
#endif
    if (resolved[cl] == '\0') return 1;
    if (resolved[cl] == '\\' || resolved[cl] == '/') return 1;
    return 0;
}

int erebus_resolve_jailed_path(const char *remote_path, char *out, size_t out_cap) {
    if (!remote_path || !remote_path[0] || !out || out_cap < 4) return 0;
    if (erebus_path_is_absolute(remote_path)) return 0;
    if (erebus_path_has_dotdot_escape(remote_path)) return 0;

#ifdef _WIN32
    char cwd[EREBUS_PATH_MAX];
    DWORD n = GetCurrentDirectoryA((DWORD)sizeof(cwd), cwd);
    if (n == 0 || n >= sizeof(cwd)) return 0;

    size_t cl = strlen(cwd);
    while (cl > 0 && (cwd[cl - 1] == '\\' || cwd[cl - 1] == '/')) {
        cwd[--cl] = '\0';
    }

    char joined[EREBUS_PATH_MAX];
    if (snprintf(joined, sizeof(joined), "%s\\%s", cwd, remote_path) >= (int)sizeof(joined))
        return 0;

    char full[EREBUS_PATH_MAX];
    DWORD flen = GetFullPathNameA(joined, (DWORD)sizeof(full), full, NULL);
    if (flen == 0 || flen >= sizeof(full)) return 0;

    char cwd_full[EREBUS_PATH_MAX];
    DWORD cflen = GetFullPathNameA(cwd, (DWORD)sizeof(cwd_full), cwd_full, NULL);
    if (cflen == 0 || cflen >= sizeof(cwd_full)) return 0;
    size_t cwl = strlen(cwd_full);
    while (cwl > 0 && (cwd_full[cwl - 1] == '\\' || cwd_full[cwl - 1] == '/')) {
        cwd_full[--cwl] = '\0';
    }

    if (!path_under_cwd(cwd_full, full)) return 0;

    if (strlen(full) + 1 > out_cap) return 0;
    memcpy(out, full, strlen(full) + 1);
    return 1;
#else
    char cwd[EREBUS_PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return 0;
    size_t cl = strlen(cwd);
    while (cl > 0 && cwd[cl - 1] == '/') cwd[--cl] = '\0';

    char joined[EREBUS_PATH_MAX];
    if (snprintf(joined, sizeof(joined), "%s/%s", cwd, remote_path) >= (int)sizeof(joined))
        return 0;

    char full[PATH_MAX];
    if (!realpath(joined, full)) {
        /* File may not exist yet (upload): resolve parent + basename */
        char parent[EREBUS_PATH_MAX];
        strncpy(parent, joined, sizeof(parent) - 1);
        parent[sizeof(parent) - 1] = '\0';
        char *slash = strrchr(parent, '/');
        if (!slash) return 0;
        *slash = '\0';
        const char *base = slash + 1;
        char parent_real[PATH_MAX];
        if (!realpath(parent[0] ? parent : "/", parent_real)) return 0;
        if (snprintf(full, sizeof(full), "%s/%s", parent_real, base) >= (int)sizeof(full))
            return 0;
    }

    if (!path_under_cwd(cwd, full)) {
        /* also try realpath of cwd for symlink cwd */
        char cwd_real[PATH_MAX];
        if (!realpath(cwd, cwd_real) || !path_under_cwd(cwd_real, full))
            return 0;
    }

    if (strlen(full) + 1 > out_cap) return 0;
    memcpy(out, full, strlen(full) + 1);
    return 1;
#endif
}

#endif /* !EREBUS_PATHJAIL_HOST_TEST */
