#ifndef __TRACER_EVENTS_H
#define __TRACER_EVENTS_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255

#define EVENTS_FILE_SIZE_LIMIT 1024 * 1024 * 1024 // 1GB
#define EVENTS_SAVE_PATH "../../events_save_dir"

enum event_type {
    NO_EVENT = 0,
    EVENT_TYPE_OPEN = 1,
    EVENT_TYPE_EXECVE = 2,
    EVENT_TYPE_CHDIR = 3,
    EVENT_TYPE_FCHDIR = 4,
};

struct event {
    // __u64 ts; // unused (TODO: use it for timestamping events)
    char event_type;
    pid_t pid;
    uid_t uid;
    int ret;
    int flags;
    int dfd; // DFD for openat(), FD for fchdir()
    // __u64 callers[2]; // unused
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};

/**
 * Memory-mapped file structure:
 * - first 8 bytes: read offset
 * - next 8 bytes: write offset
 * - rest of the file: events
*/
struct memory_mapped_file {
    void *addr;             /* start address of memory-mapped file */
    size_t *read_offset;    /* pointer to mapped memory of read offset */
    size_t *write_offset;   /* pointer to mapped memory of write offset */
    void *data;             /* start address of data (events) */
};

#endif /* __TRACER_EVENTS_H */
