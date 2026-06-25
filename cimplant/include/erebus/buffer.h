#ifndef EREBUS_BUFFER_H
#define EREBUS_BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct erebus_buf {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} erebus_buf;

int  erebus_buf_init(erebus_buf *b, size_t initial_cap);
void erebus_buf_free(erebus_buf *b);
int  erebus_buf_append(erebus_buf *b, const void *data, size_t len);
int  erebus_buf_reserve(erebus_buf *b, size_t need);
void erebus_buf_reset(erebus_buf *b);

#endif