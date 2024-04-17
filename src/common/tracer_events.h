#ifndef __TRACER_EVENTS_H
#define __TRACER_EVENTS_H

#include <limits.h>

#define TASK_COMM_LEN 16


enum event_type {
    NO_EVENT = 0,
    EVENT_TYPE_OPEN = 1,
    EVENT_TYPE_EXECVE = 2,
    EVENT_TYPE_CHDIR = 3,
    EVENT_TYPE_FCHDIR = 4,
};

typedef struct {
    long int ts; // timestamp when the event is consumed by the user process
                 // (too expensive to get time in kernel space)
    char event_type;
    pid_t pid;
    uid_t uid;
    int ret;
    int flags;
    int dfd; // DFD for openat(), FD for fchdir()
    // __u64 callers[2]; // unused
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
} event_t;

#endif /* __TRACER_EVENTS_H */
