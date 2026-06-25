#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/mod_util.h"
#include "erebus/modules.h"
#include "erebus/pb_modules.h"

#pragma comment(lib, "wldap32.lib")

static const char *ldap_filter_for(const char *query_type) {
    if (!query_type || !query_type[0]) return "(objectClass=*)";
    if (strcmp(query_type, "kerberoastable") == 0)
        return "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
    if (strcmp(query_type, "asrep_roastable") == 0)
        return "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
    if (strcmp(query_type, "computers") == 0) return "(objectCategory=computer)";
    if (strcmp(query_type, "users") == 0) return "(&(objectCategory=person)(objectClass=user))";
    if (strcmp(query_type, "groups") == 0) return "(objectCategory=group)";
    return "(objectClass=*)";
}

static int ldap_run_search(const erebus_ldap_enum_config *cfg, const char *filter,
    char **attrs, size_t attr_count, erebus_ldap_entry *entries, size_t *entry_count, size_t max_entries) {
    LDAP *ld = ldap_init((PCHAR)cfg->target_dc, 389);
    if (!ld) return 0;

    ULONG version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    if (cfg->username[0] && cfg->password[0]) {
        char bind[512];
        snprintf(bind, sizeof(bind), "%s@%s", cfg->username, cfg->domain);
        if (ldap_bind_s(ld, bind, cfg->password, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            return 0;
        }
    } else {
        if (ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
            ldap_unbind(ld);
            return 0;
        }
    }

    char base[512];
    erebus_mod_domain_to_base_dn(cfg->domain, base, sizeof(base));

    LDAPMessage *res = NULL;
    ULONG rc = ldap_search_s(ld, base, LDAP_SCOPE_SUBTREE, (PCHAR)filter, attrs, 0, &res);
    if (rc != LDAP_SUCCESS) {
        ldap_unbind(ld);
        return 0;
    }

    LDAPMessage *entry = ldap_first_entry(ld, res);
    while (entry && *entry_count < max_entries) {
        PCHAR dn = ldap_get_dn(ld, entry);
        erebus_ldap_entry *e = &entries[(*entry_count)++];
        memset(e, 0, sizeof(*e));
        if (dn) {
            strncpy(e->dn, dn, sizeof(e->dn) - 1);
            ldap_memfree(dn);
        }

        BerElement *ber = NULL;
        PCHAR attr = ldap_first_attribute(ld, entry, &ber);
        while (attr && e->attr_count < EREBUS_LDAP_ATTR_MAX) {
            PCHAR *vals = ldap_get_values(ld, entry, attr);
            if (vals && vals[0]) {
                e->attr_names[e->attr_count] = _strdup(attr);
                e->attr_values[e->attr_count] = _strdup(vals[0]);
                if (e->attr_names[e->attr_count] && e->attr_values[e->attr_count])
                    e->attr_count++;
            }
            if (vals) ldap_value_free(vals);
            ldap_memfree(attr);
            attr = ldap_next_attribute(ld, entry, ber);
        }
        entry = ldap_next_entry(ld, entry);
    }

    ldap_msgfree(res);
    ldap_unbind(ld);
    return 1;
}

int erebus_mod_ldap_enum(const uint8_t *config, size_t config_len, uint8_t **out, size_t *out_len) {
    erebus_ldap_enum_config cfg;
    if (!erebus_pb_decode_ldap_enum_config(config, config_len, &cfg)) return 0;
    if (!cfg.target_dc[0] || !cfg.domain[0]) {
        erebus_pb_free_ldap_enum_config(&cfg);
        return 0;
    }

    const char *filter = cfg.custom_filter[0] ? cfg.custom_filter : ldap_filter_for(cfg.query_type);
    char *attrs[EREBUS_LDAP_ATTR_MAX];
    size_t attr_count = cfg.attribute_count;
    if (attr_count == 0) {
        attr_count = 3;
        attrs[0] = "sAMAccountName";
        attrs[1] = "distinguishedName";
        attrs[2] = "servicePrincipalName";
    } else {
        for (size_t i = 0; i < attr_count; i++) attrs[i] = cfg.attributes[i];
    }

    erebus_ldap_entry entries[EREBUS_LDAP_ENTRY_MAX];
    size_t entry_count = 0;
    int ok = ldap_run_search(&cfg, filter, attrs, attr_count, entries, &entry_count, EREBUS_LDAP_ENTRY_MAX);

    int enc = 0;
    if (ok)
        enc = erebus_pb_encode_ldap_enum_result(cfg.domain, cfg.target_dc, cfg.query_type,
            entries, entry_count, (int32_t)entry_count, out, out_len);

    erebus_pb_free_ldap_entries(entries, entry_count);
    erebus_pb_free_ldap_enum_config(&cfg);
    return enc;
}