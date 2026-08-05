#ifndef EREBUS_LATERAL_IMPL_H
#define EREBUS_LATERAL_IMPL_H

#include "erebus/pb_modules.h"

/* Returns 1 if result buffer filled (success may still be 0). */
int erebus_lateral_winrm(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success);
int erebus_lateral_psexec(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success);
int erebus_lateral_wmi(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success);
int erebus_lateral_dcom(const erebus_lateral_config *cfg, char *output, size_t output_cap, int *success);

#endif
