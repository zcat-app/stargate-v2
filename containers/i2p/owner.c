// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t stopping;
static void stop(int signal) { (void)signal; stopping = 1; }
static int ready(pid_t child) {
    char path[64], line[256]; unsigned long long mask = 0;
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)child);
    FILE *f = fopen(path, "r"); if (!f) return 0;
    while (fgets(line, sizeof(line), f)) if (sscanf(line, "SigCgt: %llx", &mask) == 1) break;
    fclose(f); return !!(mask & (1ULL << (SIGHUP - 1)));
}
static int changed(const struct stat *a, const struct stat *b) {
    return a->st_dev != b->st_dev || a->st_ino != b->st_ino || a->st_size != b->st_size
        || a->st_mtim.tv_sec != b->st_mtim.tv_sec || a->st_mtim.tv_nsec != b->st_mtim.tv_nsec;
}
static unsigned long long counter(const char *name) {
    char path[256]; unsigned long long value = 0;
    snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", name);
    FILE *f = fopen(path, "r"); if (!f) return ULLONG_MAX;
    if (fscanf(f, "%llu", &value) != 1) value = ULLONG_MAX;
    fclose(f); return value;
}
static void resources(const char *config, pid_t child) {
    char path[4096], temp[4096];
    const char *slash = strrchr(config, '/'); if (!slash) return;
    int length = (int)(slash - config);
    if (length > 4000) return;
    snprintf(path, sizeof(path), "%.*s/resources", length, config);
    snprintf(temp, sizeof(temp), "%.*s/.resources-XXXXXX", length, config);
    unsigned long long memory=counter("memory.current"), maximum=counter("memory.max"), tasks=counter("pids.current"), taskmax=counter("pids.max");
    if (memory==ULLONG_MAX || maximum==ULLONG_MAX || tasks==ULLONG_MAX || taskmax==ULLONG_MAX) { unlink(path); return; }
    int fd = mkstemp(temp); if (fd < 0) return;
    FILE *f = fdopen(fd, "w"); if (!f) { close(fd); unlink(temp); return; }
    int written = fprintf(f, "%lld %llu %llu %llu %llu %ld\n", (long long)time(NULL),
        memory, maximum, tasks, taskmax, (long)child);
    int result = fclose(f);
    if (written > 0 && !result) { if (rename(temp, path)) unlink(temp); } else unlink(temp);
}
int main(int argc, char **argv) {
    if (argc < 3) return 64;
    struct stat observed; if (stat(argv[1], &observed) || !S_ISREG(observed.st_mode)) return 65;
    struct sigaction action = {0}; action.sa_handler = stop; sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 70;
    char ack[4096];
    if (snprintf(ack, sizeof(ack), "%s.applied", argv[1]) >= (int)sizeof(ack)) return 65;
    if (unlink(ack) && errno != ENOENT) return 65;
    pid_t child = fork(); if (child < 0) return 70;
    if (!child) { execv(argv[2], &argv[2]); _exit(127); }
    int status = 0, missing = 0, waiting = 0;
    while (!stopping) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) { fprintf(stderr, "I2P_PROCESS_EXITED\n"); return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status); }
        if (done < 0 && errno != EINTR) return 70;
        resources(argv[1], child);
        struct stat current; int absent = stat(argv[1], &current) != 0;
        if ((absent != missing) || (!absent && changed(&observed, &current))) {
            if (ready(child)) {
                if (kill(child, SIGHUP) == 0) { if (!absent) observed = current; missing = absent; waiting = 0; fprintf(stderr, "I2P_TUNNELS_RELOAD_REQUESTED\n"); }
            } else if (++waiting == 10) fprintf(stderr, "I2P_RELOAD_WAITING_FOR_HANDLER\n");
        }
        struct timespec delay = {1, 0}; nanosleep(&delay, NULL);
    }
    kill(child, SIGTERM);
    for (int n = 0; n < 100; n++) {
        if (waitpid(child, &status, WNOHANG) == child) return 0;
        struct timespec delay = {0, 100000000}; nanosleep(&delay, NULL);
    }
    fprintf(stderr, "I2P_FORCE_STOP\n");
    kill(child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    return 0;
}
