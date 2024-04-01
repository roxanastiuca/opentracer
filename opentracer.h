#ifndef __OPENTRACER_H
#define __OPENTRACER_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define INVALID_UID ((uid_t)-1)

struct open_args {
    const char *fname;
    int dfd; // temporary
    int flags;
};

struct execve_args {
    const char *fname;
    // const char *const *argv;
    // const char *const *envp;
};

struct chdir_args {
    const char *path;
};

struct fchdir_args {
    int fd;
};

enum event_type {
    EVENT_TYPE_OPEN = 0,
    EVENT_TYPE_EXECVE = 1,
    EVENT_TYPE_CHDIR = 2,
    EVENT_TYPE_FCHDIR = 3,
};

struct event {
    // __u64 ts;
    char event_type;
    pid_t pid;
    uid_t uid;
    int ret;
    int flags;
    int dfd; // DFD for openat(), FD for fchdir()
    // __u64 callers[2];
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

#endif /* __OPENTRACER_H */