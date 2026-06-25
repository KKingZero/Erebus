#include <stdlib.h>
#include <string.h>

#include "erebus/buffer.h"

int erebus_buf_init(erebus_buf *b, size_t initial_cap) {
    b->data = (uint8_t *)malloc(initial_cap ? initial_cap : 256);
    if (!b->data) return 0;
    b->len = 0;
    b->cap = initial_cap ? initial_cap : 256;
    return 1;
}

void erebus_buf_free(erebus_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

int erebus_buf_reserve(erebus_buf *b, size_t need) {
    if (need <= b->cap) return 1;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < need) ncap *= 2;
    uint8_t *p = (uint8_t *)realloc(b->data, ncap);
    if (!p) return 0;
    b->data = p;
    b->cap = ncap;
    return 1;
}

int erebus_buf_append(erebus_buf *b, const void *data, size_t len) {
    if (!erebus_buf_reserve(b, b->len + len)) return 0;
    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 1;
}

void erebus_buf_reset(erebus_buf *b) {
    b->len = 0;
}