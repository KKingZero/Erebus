/*
 * Windows-only task surfaces on Linux C implant: fail with an explicit reason
 * so operator/AI does not spin on empty errors.
 *
 * SOCKS: reverse SOCKS over the beacon is Go-only for now. On HTB Linux
 * (FireFlow/Bedside-class) use SSH reverse tunnel to C2, then operator tools
 * or Ligolo for localhost pivots — see scripts/htb_reverse_tunnel.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/task_handlers.h"

static int fail_msg(const char *msg, uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return 0;
    size_t n = strlen(msg);
    *out = (uint8_t *)malloc(n + 1);
    if (!*out) {
        *out_len = 0;
        return 0;
    }
    memcpy(*out, msg, n + 1);
    *out_len = n;
    return 0;
}

int erebus_task_screenshot(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: screenshot", out, out_len);
}

int erebus_task_keylog_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: keylog_start", out, out_len);
}

int erebus_task_keylog_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: keylog_stop", out, out_len);
}

int erebus_task_keylog_dump(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: keylog_dump", out, out_len);
}

int erebus_task_inject(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: inject", out, out_len);
}

int erebus_task_peload(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("not supported on linux c implant: pe_load", out, out_len);
}

int erebus_task_socks_start(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg(
        "socks not on linux c implant: use scripts/htb_reverse_tunnel.sh (SSH -R) "
        "or Go implant reverse SOCKS / Ligolo for localhost pivots",
        out, out_len);
}

int erebus_task_socks_stop(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data; (void)data_len;
    return fail_msg("socks not on linux c implant (see socks_start)", out, out_len);
}
