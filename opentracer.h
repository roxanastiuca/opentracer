#ifndef __OPENTRACER_H
#define __OPENTRACER_H

#define PATH_MAX_COUNT 32
#define PATH_MAX_LEN 32

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

struct args_t {
    const char *fname;
    int flags;
};

struct event {
    /* user terminology for pid: */
    __u64 ts;
    pid_t pid;
    uid_t uid;
    int ret;
    int flags;
    __u64 callers[2];
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];

    char path[PATH_MAX_COUNT][PATH_MAX_LEN]; // tb
    int path_len;
};

#endif /* __OPENTRACER_H */