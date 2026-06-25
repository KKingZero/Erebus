#ifndef EREBUS_TYPES_H
#define EREBUS_TYPES_H

#include <stdint.h>
#include <stddef.h>

typedef struct erebus_buffer {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} erebus_buffer;

typedef struct erebus_task {
    char     task_id[64];
    char     implant_id[64];
    int32_t  task_type;
    uint8_t *data;
    size_t   data_len;
    int64_t  timeout_ms;
} erebus_task;

typedef struct erebus_task_result {
    char     task_id[64];
    int      success;
    uint8_t *data;
    size_t   data_len;
    char     error[256];
    int64_t  execution_time_ms;
} erebus_task_result;

#endif