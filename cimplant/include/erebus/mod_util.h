#ifndef EREBUS_MOD_UTIL_H
#define EREBUS_MOD_UTIL_H

#include <stddef.h>
#include <stdint.h>

int erebus_mod_run_cmd(const char *cmdline, char **stdout_out, char **stderr_out, int32_t *exit_code);
uint32_t erebus_mod_find_pid(const char *name);
void erebus_mod_domain_to_base_dn(const char *domain, char *out, size_t out_cap);

#endif