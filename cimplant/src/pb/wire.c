#include <stdlib.h>
#include <string.h>

#include "erebus/pb_wire.h"

static int w_grow(erebus_pb_writer *w, size_t need) {
    if (need <= w->cap) return 1;
    size_t ncap = w->cap ? w->cap : 256;
    while (ncap < need) ncap *= 2;
    uint8_t *p = (uint8_t *)realloc(w->data, ncap);
    if (!p) return 0;
    w->data = p;
    w->cap = ncap;
    return 1;
}

int erebus_pb_writer_init(erebus_pb_writer *w, size_t cap) {
    w->data = (uint8_t *)malloc(cap ? cap : 256);
    if (!w->data) return 0;
    w->len = 0;
    w->cap = cap ? cap : 256;
    return 1;
}

void erebus_pb_writer_free(erebus_pb_writer *w) {
    free(w->data);
    w->data = NULL;
    w->len = w->cap = 0;
}

int erebus_pb_write_tag(erebus_pb_writer *w, uint32_t field, uint8_t wire) {
    return erebus_pb_write_varint(w, (uint64_t)((field << 3) | wire));
}

int erebus_pb_write_varint(erebus_pb_writer *w, uint64_t v) {
    uint8_t buf[10];
    size_t n = 0;
    do {
        uint8_t b = (uint8_t)(v & 0x7F);
        v >>= 7;
        if (v) b |= 0x80;
        buf[n++] = b;
    } while (v);
    if (!w_grow(w, w->len + n)) return 0;
    memcpy(w->data + w->len, buf, n);
    w->len += n;
    return 1;
}

int erebus_pb_write_string(erebus_pb_writer *w, uint32_t field, const char *s) {
    if (!s) s = "";
    size_t slen = strlen(s);
    if (!erebus_pb_write_tag(w, field, 2)) return 0;
    if (!erebus_pb_write_varint(w, slen)) return 0;
    if (!w_grow(w, w->len + slen)) return 0;
    memcpy(w->data + w->len, s, slen);
    w->len += slen;
    return 1;
}

int erebus_pb_write_bytes(erebus_pb_writer *w, uint32_t field, const uint8_t *b, size_t n) {
    if (!erebus_pb_write_tag(w, field, 2)) return 0;
    if (!erebus_pb_write_varint(w, n)) return 0;
    if (!w_grow(w, w->len + n)) return 0;
    memcpy(w->data + w->len, b, n);
    w->len += n;
    return 1;
}

int erebus_pb_write_bool(erebus_pb_writer *w, uint32_t field, int v) {
    if (!erebus_pb_write_tag(w, field, 0)) return 0;
    return erebus_pb_write_varint(w, v ? 1 : 0);
}

int erebus_pb_write_int64(erebus_pb_writer *w, uint32_t field, int64_t v) {
    if (!erebus_pb_write_tag(w, field, 0)) return 0;
    return erebus_pb_write_varint(w, (uint64_t)v);
}

int erebus_pb_write_uint32(erebus_pb_writer *w, uint32_t field, uint32_t v) {
    if (!erebus_pb_write_tag(w, field, 0)) return 0;
    return erebus_pb_write_varint(w, v);
}

int erebus_pb_write_submsg_begin(erebus_pb_writer *w, uint32_t field, size_t *mark) {
    if (!erebus_pb_write_tag(w, field, 2)) return 0;
    *mark = w->len;
    return erebus_pb_write_varint(w, 0);
}

int erebus_pb_write_submsg_end(erebus_pb_writer *w, size_t mark) {
    size_t start = mark + 1;
    while (start < w->len && (w->data[start] & 0x80)) start++;
    if (start >= w->len) return 0;
    start++;
    size_t len = w->len - start;
    size_t var_len = start - mark;
    uint8_t tmp[10];
    size_t n = 0;
    uint64_t v = len;
    do {
        uint8_t b = (uint8_t)(v & 0x7F);
        v >>= 7;
        if (v) b |= 0x80;
        tmp[n++] = b;
    } while (v);
    if (n > var_len) return 0;
    memmove(w->data + mark + n, w->data + start, len);
    memcpy(w->data + mark, tmp, n);
    w->len = mark + n + len;
    return 1;
}

void erebus_pb_reader_init(erebus_pb_reader *r, const uint8_t *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

int erebus_pb_read_varint(erebus_pb_reader *r, uint64_t *v) {
    uint64_t out = 0;
    unsigned shift = 0;
    while (r->pos < r->len && shift < 64) {
        uint8_t b = r->data[r->pos++];
        out |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *v = out;
            return 1;
        }
        shift += 7;
    }
    return 0;
}

int erebus_pb_skip(erebus_pb_reader *r, uint8_t wire) {
    uint64_t v;
    switch (wire) {
    case 0:
        return erebus_pb_read_varint(r, &v);
    case 1:
        if (r->pos + 8 > r->len) return 0;
        r->pos += 8;
        return 1;
    case 2: {
        if (!erebus_pb_read_varint(r, &v)) return 0;
        if (r->pos + (size_t)v > r->len) return 0;
        r->pos += (size_t)v;
        return 1;
    }
    case 5:
        if (r->pos + 4 > r->len) return 0;
        r->pos += 4;
        return 1;
    default:
        return 0;
    }
}

int erebus_pb_reader_next(erebus_pb_reader *r, uint32_t *field, uint8_t *wire) {
    if (r->pos >= r->len) return 0;
    uint64_t tag;
    if (!erebus_pb_read_varint(r, &tag)) return 0;
    *field = (uint32_t)(tag >> 3);
    *wire = (uint8_t)(tag & 7);
    return 1;
}

int erebus_pb_read_bytes(erebus_pb_reader *r, const uint8_t **b, size_t *n) {
    uint64_t len;
    if (!erebus_pb_read_varint(r, &len)) return 0;
    if (r->pos + (size_t)len > r->len) return 0;
    *b = r->data + r->pos;
    *n = (size_t)len;
    r->pos += (size_t)len;
    return 1;
}

void erebus_pb_copy_bytes(char *dst, size_t cap, const uint8_t *src, size_t n) {
    if (!dst || cap == 0) return;
    if (!src || n == 0) {
        dst[0] = '\0';
        return;
    }
    size_t copy = n;
    if (copy > cap - 1) copy = cap - 1;
    memcpy(dst, src, copy);
    dst[copy] = '\0';
}