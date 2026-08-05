/* Host unit test: multi-hash KerberoastResult protobuf encoding. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_modules.h"
#include "erebus/pb_wire.h"

static int fails;

static void expect(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

/* Count length-delimited field-1 submessages in a KerberoastResult. */
static int count_hash_fields(const uint8_t *data, size_t len) {
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, data, len);
    uint32_t field;
    uint8_t wire;
    int n = 0;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        if (field == 1 && wire == 2) {
            const uint8_t *b;
            size_t bl;
            if (!erebus_pb_read_bytes(&r, &b, &bl)) return -1;
            n++;
        } else {
            if (!erebus_pb_skip(&r, wire)) return -1;
        }
    }
    return n;
}

int main(void) {
    uint8_t *out = NULL;
    size_t out_len = 0;

    /* Empty multi result. */
    expect("empty multi", erebus_pb_encode_kerberoast_result_multi(NULL, 0, &out, &out_len));
    expect("empty len", out_len == 0 || count_hash_fields(out, out_len) == 0);
    free(out);
    out = NULL;

    erebus_kerberoast_hash hashes[2] = {
        { "HTTP/dc.lab.local", "svc_http", "$krb5tgs$23$*svc_http$LAB.LOCAL$HTTP/dc.lab.local*$ab", "etype23" },
        { "MSSQLSvc/db.lab.local:1433", "sql", "$krb5tgs$23$*sql$LAB.LOCAL$MSSQLSvc/db.lab.local:1433*$cd", "etype23" },
    };
    expect("multi encode", erebus_pb_encode_kerberoast_result_multi(hashes, 2, &out, &out_len));
    expect("out nonnull", out != NULL && out_len > 0);
    expect("count 2", count_hash_fields(out, out_len) == 2);
    free(out);
    out = NULL;

    expect("single", erebus_pb_encode_kerberoast_result("spn", "sam", "hash", "etype23", &out, &out_len));
    expect("single count", count_hash_fields(out, out_len) == 1);
    free(out);
    out = NULL;

    /* AS-REP multi result (repeated field 1 = ASREPHash). */
    expect("asrep empty", erebus_pb_encode_asreproast_result_multi(NULL, 0, &out, &out_len));
    expect("asrep empty count", count_hash_fields(out, out_len) == 0);
    free(out);
    out = NULL;

    erebus_asreproast_hash ar[2] = {
        { "user1", "$krb5asrep$23$user1@LAB.LOCAL:aa" },
        { "user2", "$krb5asrep$23$user2@LAB.LOCAL:bb" },
    };
    expect("asrep multi", erebus_pb_encode_asreproast_result_multi(ar, 2, &out, &out_len));
    expect("asrep multi count", count_hash_fields(out, out_len) == 2);
    free(out);
    out = NULL;

    expect("asrep single", erebus_pb_encode_asreproast_result("u", "h", &out, &out_len));
    expect("asrep single count", count_hash_fields(out, out_len) == 1);
    free(out);

    if (fails) {
        fprintf(stderr, "%d kerberoast_pb host tests failed\n", fails);
        return 1;
    }
    printf("kerberoast_pb host tests ok\n");
    return 0;
}
