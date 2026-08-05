/* Host unit tests for pure NTLM parse/split helpers. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "erebus/ntlm_pth.h"

static int fails;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        fails++;
    }
}

int main(void) {
    uint8_t nt[16];
    memset(nt, 0, sizeof(nt));

    expect(erebus_ntlm_parse_hash("31d6cfe0d16ae931b73c59d7e0c089c0", nt), "32-hex NT");
    expect(nt[0] == 0x31 && nt[15] == 0xc0, "NT bytes");

    memset(nt, 0, sizeof(nt));
    expect(erebus_ntlm_parse_hash("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", nt),
        "LM:NT form");
    expect(nt[0] == 0x31, "NT from LM:NT");

    expect(!erebus_ntlm_parse_hash("deadbeef", nt), "short hash rejected");
    expect(!erebus_ntlm_parse_hash("", nt), "empty rejected");
    expect(!erebus_ntlm_parse_hash(NULL, nt), "null rejected");

    char dom[64], user[64];
    erebus_ntlm_split_user("CORP\\alice", "", dom, sizeof(dom), user, sizeof(user));
    expect(strcmp(dom, "CORP") == 0 && strcmp(user, "alice") == 0, "DOMAIN\\user");

    erebus_ntlm_split_user("alice@corp.local", "", dom, sizeof(dom), user, sizeof(user));
    expect(strcmp(user, "alice") == 0 && strcmp(dom, "corp.local") == 0, "user@domain");

    erebus_ntlm_split_user("bob", "LAB", dom, sizeof(dom), user, sizeof(user));
    expect(strcmp(dom, "LAB") == 0 && strcmp(user, "bob") == 0, "bare user + domain");

    erebus_ntlm_split_user("CORP\\eve", "IGNORED", dom, sizeof(dom), user, sizeof(user));
    expect(strcmp(dom, "CORP") == 0 && strcmp(user, "eve") == 0, "backslash overrides domain_in");

    if (fails) {
        fprintf(stderr, "%d ntlm_parse tests failed\n", fails);
        return 1;
    }
    printf("ntlm_parse_host_test: ok\n");
    return 0;
}
