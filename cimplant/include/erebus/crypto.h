#ifndef EREBUS_CRYPTO_H
#define EREBUS_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int erebus_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);
int erebus_b64_decode(const char *b64, uint8_t **out, size_t *out_len);

int erebus_hmac_sha256(const uint8_t *key, size_t key_len,
    const uint8_t *implant_id, size_t id_len, int64_t timestamp,
    uint8_t out[32]);

int erebus_aes_gcm_encrypt(const uint8_t key[32], const uint8_t *pt, size_t pt_len, uint8_t **out, size_t *out_len);
int erebus_aes_gcm_decrypt(const uint8_t key[32], const uint8_t *ct, size_t ct_len, uint8_t **out, size_t *out_len);

uint32_t erebus_jitter_ms(uint32_t base_ms, int jitter_pct);

#endif