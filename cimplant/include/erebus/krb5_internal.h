#ifndef EREBUS_KRB5_INTERNAL_H
#define EREBUS_KRB5_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "erebus/krb5.h"

/* ---- DER ---- */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} erebus_der_buf;

typedef struct {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
} erebus_der_reader;

int  erebus_der_init(erebus_der_buf *b, size_t cap);
void erebus_der_free(erebus_der_buf *b);
int  erebus_der_append(erebus_der_buf *b, const uint8_t *p, size_t n);
int  erebus_der_append_byte(erebus_der_buf *b, uint8_t v);
/* tag + length + value (raw content, not including tag/len). */
int  erebus_der_put_tl(erebus_der_buf *b, uint8_t tag, const uint8_t *val, size_t n);
int  erebus_der_put_int(erebus_der_buf *b, uint8_t tag, int32_t v);
int  erebus_der_put_general_string(erebus_der_buf *b, uint8_t tag, const char *s);
int  erebus_der_put_octet(erebus_der_buf *b, uint8_t tag, const uint8_t *p, size_t n);
int  erebus_der_put_bitstring_unused0(erebus_der_buf *b, uint8_t tag, const uint8_t *bits, size_t nbytes);
int  erebus_der_put_ctx_seq(erebus_der_buf *b, uint8_t ctx_num, const uint8_t *seq_content, size_t n);
int  erebus_der_put_seq(erebus_der_buf *b, const uint8_t *content, size_t n);
int  erebus_der_put_app(erebus_der_buf *b, uint8_t app_num, const uint8_t *content, size_t n);

void erebus_der_r_init(erebus_der_reader *r, const uint8_t *data, size_t len);
int  erebus_der_r_tag_len(erebus_der_reader *r, uint8_t *tag, const uint8_t **val, size_t *vlen);
int  erebus_der_r_expect(erebus_der_reader *r, uint8_t want_tag, const uint8_t **val, size_t *vlen);
int  erebus_der_r_int(const uint8_t *val, size_t n, int32_t *out);
int  erebus_der_r_find_ctx(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
        uint8_t *out_tag, const uint8_t **val, size_t *vlen);
int  erebus_der_r_ctx_inner(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
        uint8_t want_inner_tag, const uint8_t **val, size_t *vlen);
int  erebus_der_r_ctx_int(const uint8_t *seq, size_t seq_len, uint8_t ctx_num, int32_t *out);
int  erebus_der_r_ctx_octet(const uint8_t *seq, size_t seq_len, uint8_t ctx_num,
        const uint8_t **val, size_t *vlen);

/* ---- crypto (RC4-HMAC etype 23) ---- */
void erebus_md4(const uint8_t *msg, size_t msg_len, uint8_t out[16]);
int  erebus_nt_hash(const char *password_utf8, uint8_t out[16]);
int  erebus_rc4_hmac_encrypt(const uint8_t key[16], int32_t usage,
        const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len);
int  erebus_rc4_hmac_decrypt(const uint8_t key[16], int32_t usage,
        const uint8_t *cipher, size_t cipher_len, uint8_t **out, size_t *out_len);
int  erebus_krb_random(uint8_t *buf, size_t n);

/* ---- crypto (AES128/256-CTS-HMAC-SHA1-96 etype 17/18) ---- */
int erebus_aes_string_to_key(int etype, const char *password, const char *realm, const char *user,
        uint8_t *key_out, size_t *key_len_out);
int erebus_aes_cts_hmac_encrypt(const uint8_t *key, size_t key_len, int32_t usage,
        const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len);
int erebus_aes_cts_hmac_decrypt(const uint8_t *key, size_t key_len, int32_t usage,
        const uint8_t *cipher, size_t cipher_len, uint8_t **out, size_t *out_len);

/* ---- ticket blob ---- */
typedef struct {
    int32_t  etype;
    uint8_t *cipher;
    size_t   cipher_len;
    uint8_t *ticket_der; /* full Ticket APPLICATION 1 for reuse in AP-REQ */
    size_t   ticket_der_len;
} erebus_krb_enc_data;

typedef struct {
    uint8_t session_key[32];
    size_t  session_key_len;
    int32_t session_etype;
    erebus_krb_enc_data tgt; /* TGT ticket */
} erebus_krb_creds;

void erebus_krb_enc_data_free(erebus_krb_enc_data *e);
void erebus_krb_creds_free(erebus_krb_creds *c);

/* ---- wire ---- */
int erebus_krb_tcp_exchange(const char *host, uint16_t port,
    const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);

int erebus_krb_as_req(const char *dc, const char *realm, const char *user, const char *password,
    erebus_krb_creds *out_creds);

int erebus_krb_tgs_req(const char *dc, const char *realm, const char *spn,
    const erebus_krb_creds *creds, erebus_krb_enc_data *out_service_ticket);

#endif
