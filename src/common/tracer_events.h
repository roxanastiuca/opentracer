#ifndef __TRACER_EVENTS_H
#define __TRACER_EVENTS_H

/**
 * uid_t and pid_t are defined by vmlinux.h in kernel space,
 * so we don't want to redefine it */
#ifdef OPENTRACER_USERSPACE
#include <sys/types.h>
#include <stdint.h>
#endif /* OPENTRACER_USERSPACE */

#include <limits.h>

#define TASK_COMM_LEN 16

// avoid including vmlinux.h, use hardcoded values
#define AT_FDCWD                -100    /* Special value used to indicate openat should use the current working directory. */


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
    char event_type;    // kernel event type
    pid_t pid;          // process ID
    uid_t uid;          // user ID
    int ret;            // return value
    int flags;          // flags for open() and openat()
    int dfd;            // dfd argument for openat(), fd argument for fchdir()
    char comm[TASK_COMM_LEN];   // command name
    char fname[NAME_MAX];       // file name
} event_t;

#endif /* __TRACER_EVENTS_H */
