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

static void wchar_to_utf8(const wchar_t *ws, char *out, size_t cap) {
    if (!ws) { out[0] = '\0'; return; }
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, out, (int)cap, NULL, NULL);
    out[cap - 1] = '\0';
}

static wchar_t *utf8_to_wchar(const char *s) {
    if (!s) return NULL;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *ws = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!ws) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, ws, n);
    return ws;
}

static int ldap_run_search(const erebus_ldap_enum_config *cfg, const char *filter,
    char **attrs, size_t attr_count, erebus_ldap_entry *entries, size_t *entry_count, size_t max_entries) {
    wchar_t *whost = utf8_to_wchar(cfg->target_dc);
    if (!whost) return 0;

    LDAP *ld = ldap_initW(whost, 389);
    free(whost);
    if (!ld) return 0;

    ULONG version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    if (cfg->username[0] && cfg->password[0]) {
        char bind[512];
        snprintf(bind, sizeof(bind), "%s@%s", cfg->username, cfg->domain);
        wchar_t *wbind = utf8_to_wchar(bind);
        wchar_t *wpass = utf8_to_wchar(cfg->password);
        ULONG brc = ldap_bind_s(ld, wbind, wpass, LDAP_AUTH_SIMPLE);
        free(wbind);
        free(wpass);
        if (brc != LDAP_SUCCESS) {
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
    wchar_t *wbase = utf8_to_wchar(base);
    wchar_t *wfilter = utf8_to_wchar(filter);

    wchar_t **wattrs = NULL;
    if (attr_count > 0) {
        wattrs = (wchar_t **)calloc(attr_count + 1, sizeof(wchar_t *));
        for (size_t i = 0; i < attr_count; i++)
            wattrs[i] = utf8_to_wchar(attrs[i]);
    }

    LDAPMessage *res = NULL;
    ULONG rc = ldap_search_sW(ld, wbase, LDAP_SCOPE_SUBTREE, wfilter, wattrs, 0, &res);

    if (wattrs) {
        for (size_t i = 0; i < attr_count; i++) free(wattrs[i]);
        free(wattrs);
    }
    free(wbase);
    free(wfilter);

    if (rc != LDAP_SUCCESS) {
        ldap_unbind(ld);
        return 0;
    }

    LDAPMessage *entry = ldap_first_entry(ld, res);
    while (entry && *entry_count < max_entries) {
        wchar_t *wdn = ldap_get_dnW(ld, entry);
        erebus_ldap_entry *e = &entries[(*entry_count)++];
        memset(e, 0, sizeof(*e));
        if (wdn) { wchar_to_utf8(wdn, e->dn, sizeof(e->dn)); ldap_memfreeW(wdn); }

        BerElement *ber = NULL;
        wchar_t *attr = ldap_first_attributeW(ld, entry, &ber);
        while (attr && e->attr_count < EREBUS_LDAP_ATTR_MAX) {
            PWSTR *vals = ldap_get_valuesW(ld, entry, attr);
            if (vals && vals[0]) {
                char name[128], value[1024];
                wchar_to_utf8(attr, name, sizeof(name));
                wchar_to_utf8(vals[0], value, sizeof(value));
                e->attr_names[e->attr_count] = _strdup(name);
                e->attr_values[e->attr_count] = _strdup(value);
                if (e->attr_names[e->attr_count] && e->attr_values[e->attr_count])
                    e->attr_count++;
            }
            if (vals) ldap_value_freeW(vals);
            ldap_memfreeW(attr);
            attr = ldap_next_attributeW(ld, entry, ber);
        }
        if (ber) ber_free(ber, 0);
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