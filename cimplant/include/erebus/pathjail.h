#ifndef EREBUS_PATHJAIL_H
#define EREBUS_PATHJAIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve remote_path relative to the implant working directory.
 * Rejects absolute paths and ".." traversal (Go implant parity).
 * On success writes a NUL-terminated absolute path into out (capacity out_cap).
 * Returns 1 on success, 0 on reject/error. */
int erebus_resolve_jailed_path(const char *remote_path, char *out, size_t out_cap);

/* Pure helpers (host-testable). Return 1 if the path is absolute / escapes. */
int erebus_path_is_absolute(const char *path);
int erebus_path_has_dotdot_escape(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* EREBUS_PATHJAIL_H */
