#ifndef EREBUS_KRB5_H
#define EREBUS_KRB5_H

#include <stddef.h>
#include <stdint.h>

#define EREBUS_KRB_ETYPE_AES128 17
#define EREBUS_KRB_ETYPE_AES256 18
#define EREBUS_KRB_ETYPE_RC4    23

#define EREBUS_KRB_HASH_MAX  8192
#define EREBUS_KRB_SPN_MAX   512
#define EREBUS_KRB_SAM_MAX   256

typedef struct erebus_krb_hash {
    char spn[EREBUS_KRB_SPN_MAX];
    char sam[EREBUS_KRB_SAM_MAX];
    char hash[EREBUS_KRB_HASH_MAX];
    char enc[32]; /* e.g. "etype23" */
} erebus_krb_hash;

/*
 * Kerberoast via wire Kerberos (TCP/88): AS-REQ → TGT → TGS per SPN → hashcat line.
 * spns/sams are parallel arrays (sam may be empty). On success writes up to max_out hashes.
 * Returns 1 on protocol success (even if hash_count==0); 0 on hard failure.
 */
int erebus_krb_kerberoast(
    const char *dc_host,
    const char *domain,
    const char *username,
    const char *password,
    const char **spns,
    const char **sams,
    size_t spn_count,
    erebus_krb_hash *out,
    size_t max_out,
    size_t *out_count);

/* Format hashcat string into dst (cap). cipher is raw ticket enc-part bytes. */
int erebus_krb_format_hashcat(char *dst, size_t cap,
    int etype, const char *sam, const char *domain, const char *spn,
    const uint8_t *cipher, size_t cipher_len);

/* AS-REP roast: hashcat/john style line (mode 18200 for etype 23). */
int erebus_krb_format_asrep_hashcat(char *dst, size_t cap,
    int etype, const char *user, const char *domain,
    const uint8_t *cipher, size_t cipher_len);

/*
 * AS-REP roast one or more users (no pre-auth AS-REQ).
 * users may be empty → out_count 0, return 1.
 * Returns 1 if transport/protocol path ran; individual users may fail silently (skipped).
 */
int erebus_krb_asreproast(
    const char *dc_host,
    const char *domain,
    const char **users,
    size_t user_count,
    erebus_krb_hash *out,
    size_t max_out,
    size_t *out_count);

#endif
