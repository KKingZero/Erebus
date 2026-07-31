/* Host unit test: protobuf string fields are not NUL-terminated. */
#include <stdio.h>
#include <string.h>

#include "erebus/pb_wire.h"

static int fails;

static void expect(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

int main(void) {
    /* Buffer: "hi" (2 bytes) followed by canary "XXX" with no NUL after hi. */
    uint8_t blob[] = { 'h', 'i', 'X', 'X', 'X', 'X' };
    char dst[8];
    memset(dst, 'Z', sizeof(dst));

    erebus_pb_copy_bytes(dst, sizeof(dst), blob, 2);
    expect("len", strlen(dst) == 2);
    expect("content", strcmp(dst, "hi") == 0);
    expect("no canary", dst[2] == '\0');

    /* Truncate to cap-1 */
    memset(dst, 'Z', sizeof(dst));
    erebus_pb_copy_bytes(dst, 3, blob, 6); /* would be "hiXXXX" but cap=3 → "hi" */
    expect("trunc", strcmp(dst, "hi") == 0);

    /* Empty / null src */
    erebus_pb_copy_bytes(dst, sizeof(dst), NULL, 5);
    expect("null src", dst[0] == '\0');
    erebus_pb_copy_bytes(dst, sizeof(dst), blob, 0);
    expect("zero n", dst[0] == '\0');

    /* Encode+decode a length-delimited string without trailing NUL in wire. */
    erebus_pb_writer w;
    expect("writer init", erebus_pb_writer_init(&w, 64));
    /* field 1, wire type 2, length 5, bytes "hello" (no extra NUL) */
    erebus_pb_write_string(&w, 1, "hello");

    erebus_pb_reader r;
    erebus_pb_reader_init(&r, w.data, w.len);
    uint32_t field;
    uint8_t wire;
    expect("next", erebus_pb_reader_next(&r, &field, &wire));
    expect("field1", field == 1 && wire == 2);
    const uint8_t *b;
    size_t n;
    expect("read_bytes", erebus_pb_read_bytes(&r, &b, &n));
    expect("n=5", n == 5);
    char cmd[16];
    memset(cmd, 'Q', sizeof(cmd));
    erebus_pb_copy_bytes(cmd, sizeof(cmd), b, n);
    expect("decoded", strcmp(cmd, "hello") == 0);

    erebus_pb_writer_free(&w);

    if (fails) {
        fprintf(stderr, "%d pb_copy host tests failed\n", fails);
        return 1;
    }
    printf("pb_copy host tests ok\n");
    return 0;
}
