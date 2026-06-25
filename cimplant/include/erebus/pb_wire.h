#ifndef EREBUS_PB_WIRE_H
#define EREBUS_PB_WIRE_H

#include <stddef.h>
#include <stdint.h>

typedef struct erebus_pb_reader {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
} erebus_pb_reader;

typedef struct erebus_pb_writer {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} erebus_pb_writer;

int erebus_pb_writer_init(erebus_pb_writer *w, size_t cap);
void erebus_pb_writer_free(erebus_pb_writer *w);
int erebus_pb_write_tag(erebus_pb_writer *w, uint32_t field, uint8_t wire);
int erebus_pb_write_varint(erebus_pb_writer *w, uint64_t v);
int erebus_pb_write_string(erebus_pb_writer *w, uint32_t field, const char *s);
int erebus_pb_write_bytes(erebus_pb_writer *w, uint32_t field, const uint8_t *b, size_t n);
int erebus_pb_write_bool(erebus_pb_writer *w, uint32_t field, int v);
int erebus_pb_write_int64(erebus_pb_writer *w, uint32_t field, int64_t v);
int erebus_pb_write_uint32(erebus_pb_writer *w, uint32_t field, uint32_t v);
int erebus_pb_write_submsg_begin(erebus_pb_writer *w, uint32_t field, size_t *mark);
int erebus_pb_write_submsg_end(erebus_pb_writer *w, size_t mark);

void erebus_pb_reader_init(erebus_pb_reader *r, const uint8_t *data, size_t len);
int erebus_pb_reader_next(erebus_pb_reader *r, uint32_t *field, uint8_t *wire);
int erebus_pb_read_varint(erebus_pb_reader *r, uint64_t *v);
int erebus_pb_read_bytes(erebus_pb_reader *r, const uint8_t **b, size_t *n);
int erebus_pb_skip(erebus_pb_reader *r, uint8_t wire);

#endif