#include <stdlib.h>
#include <string.h>

#include "erebus/modules.h"
#include "erebus/pb_modules.h"
#include "erebus/task_handlers.h"

int erebus_task_module(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_module_task mt;
    if (!erebus_pb_decode_module_task(data, data_len, &mt)) return 0;

    int ok = erebus_module_execute(mt.module_name, mt.config, mt.config_len, out, out_len);
    erebus_pb_free_module_task(&mt);
    return ok;
}