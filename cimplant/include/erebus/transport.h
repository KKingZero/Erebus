#ifndef EREBUS_TRANSPORT_H
#define EREBUS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

typedef struct erebus_transport erebus_transport;

typedef struct erebus_transport_ops {
    int (*register_call)(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
    int (*beacon_call)(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
    void (*destroy)(erebus_transport *t);
} erebus_transport_ops;

struct erebus_transport {
    const erebus_transport_ops *ops;
    void *ctx;
};

int erebus_transport_create(const char *type, erebus_transport **out);
void erebus_transport_destroy(erebus_transport *t);
int erebus_transport_register(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
int erebus_transport_beacon(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len);
void erebus_transport_set_session_id(erebus_transport *t, const char *session_id);

int erebus_transport_create_https(erebus_transport **out);
int erebus_transport_create_dns(erebus_transport **out);

#endif