#include <string.h>

#include "erebus/modules.h"
#include "erebus/pb_modules.h"

int erebus_mod_kerberoast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_kerberoast_config cfg;
    if (!erebus_pb_decode_kerberoast_config(config, config_len, &cfg)) return 0;

    if (!cfg.domain[0] || !cfg.target_dc[0]) {
        erebus_pb_free_kerberoast_config(&cfg);
        return 0;
    }

    const char *spn = cfg.target_spn_count ? cfg.target_spns[0] : "use_ldap_enum_kerberoastable";
    const char *sam = cfg.username[0] ? cfg.username : "unknown";
    const char *enc = cfg.encryption[0] ? cfg.encryption : "rc4";

    int ok = erebus_pb_encode_kerberoast_result(spn, sam,
        "ticket_extraction_not_ported_in_c_implant_use_go_implant", enc, out, out_len);
    erebus_pb_free_kerberoast_config(&cfg);
    return ok;
}

int erebus_mod_asreproast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_asreproast_config cfg;
    if (!erebus_pb_decode_asreproast_config(config, config_len, &cfg)) return 0;

    if (!cfg.domain[0] || !cfg.target_dc[0]) {
        erebus_pb_free_asreproast_config(&cfg);
        return 0;
    }

    const char *user = cfg.target_user_count ? cfg.target_users[0] : "use_ldap_enum_asrep_roastable";
    int ok = erebus_pb_encode_asreproast_result(user,
        "asrep_extraction_not_ported_in_c_implant_use_go_implant", out, out_len);
    erebus_pb_free_asreproast_config(&cfg);
    return ok;
}