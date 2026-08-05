#ifndef EREBUS_NTLM_PTH_H
#define EREBUS_NTLM_PTH_H

#include <stddef.h>
#include <stdint.h>

/* Parse NT hash: 32 hex chars or LM:NT (64 hex). Writes 16-byte NT key. */
int erebus_ntlm_parse_hash(const char *hash_str, uint8_t nt[16]);

/* Type 1 Negotiate message (domain optional, UTF-8). Caller frees *out. */
int erebus_ntlm_type1(const char *domain, uint8_t **out, size_t *out_len);

/*
 * Type 3 Authenticate from Type 2 challenge using NT hash (PTH).
 * user/domain are UTF-8; domain used for NTOWFv2 (may be empty for local).
 */
int erebus_ntlm_type3_hash(const uint8_t *type2, size_t type2_len,
    const char *user, const char *domain, const uint8_t nt[16],
    uint8_t **out, size_t *out_len);

/* UTF-8 domain\user or user@domain or bare user → domain + account (caps for NTLMv2 user). */
void erebus_ntlm_split_user(const char *user_in, const char *domain_in,
    char *domain_out, size_t domain_cap, char *user_out, size_t user_cap);

#endif
