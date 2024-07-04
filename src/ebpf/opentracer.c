#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "opentracer.skel.h"
#include "opentracer.h"
#include "../common/config.h"
#include "../common/mmf.h"
#include "../common/tracer_events.h"


static config_t config;
static memory_mapped_file_t mmf = {0};
static char file_name[MAX_FILE_NAME];


static volatile bool keep_running = true;
static void sig_handler(int signo)
{
    syslog(LOG_INFO, "sig_handler: Received signal %d, stopping eBPF", signo);
    keep_running = false;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
    /* Write data to memory-mapped file */
    if (mmf.addr == NULL) {
        syslog(LOG_CRIT, "handle_event: Memory-mapped file not initialized");
        return -1;
    }

    if ((*mmf.write_offset) + data_sz > config.events_file_size_limit) {
        munmap(mmf.addr, config.events_file_size_limit);
        /* Create a new file */
        if (create_memory_mapped_file(&config, file_name, &mmf) != 0) {
            syslog(LOG_CRIT, "handle_event: Failed to create new memory-mapped file");
            return -1;
        }
    }

    // Current timestamp:
    time_t ts;
    time(&ts);

    const event_t *const event = (event_t *)data;
    if (event->event_type == EVENT_TYPE_EXECVE) {
        event_t execve_event;
        memcpy(&execve_event, event, sizeof(event_t));
        execve_event.ts = ts;

        syslog(LOG_INFO, "handle_event: Execve event: %s", event->comm);

        // Get environ of event->pid
        char environ_path[256];
        snprintf(environ_path, sizeof(environ_path), "/proc/%d/environ", event->pid);
        FILE *f = fopen(environ_path, "r");
        if (f != NULL) {
            char buffer[4096];
            size_t length = fread(buffer, 1, sizeof(buffer), f);
            if (length != 0) {
                buffer[length] = '\0';

                char *ptr = buffer;
                while (ptr < buffer + length) {
                    if (strncmp(ptr, "PATH=", 5) == 0) {
                        strcpy(execve_event.fname, ptr + 5);
                    }
                    ptr += strlen(ptr) + 1;
                }
            }
            fclose(f);
        }

        memcpy((char*)mmf.data + *(mmf.write_offset), &execve_event, sizeof(event_t));
        *(mmf.write_offset) += sizeof(event_t);
    } else {
        // Overwrite ts in event_t with current timestamp:
        // (without actually changing data, to avoid multiple memcpy-s)
        memcpy((char*)mmf.data + *(mmf.write_offset), &ts, sizeof(time_t));
        memcpy((char*)mmf.data + *(mmf.write_offset) + sizeof(time_t),
            (char*)data + sizeof(time_t), data_sz - sizeof(time_t));
        *(mmf.write_offset) += data_sz;
    }


    return 0;
}


int run_opentracer()
{
    struct opentracer_bpf *obj = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    openlog("opentracer", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "run_opentracer: Starting eBPF");

    if (load_config(&config) != 0) {
        syslog(LOG_ERR, "run_opentracer: Failed to load config");
        return 1;
    }

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL); // TODO: check if this is necessary

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    obj = opentracer_bpf__open_opts(&open_opts);
    if (!obj) {
        syslog(LOG_ERR, "run_opentracer: Failed to open BPF object, errno: %d", errno);
        return 1;
    }

    // Add filters based on config
    obj->rodata->events_limit = config.events_limit;
    obj->rodata->targ_pid = config.targ_pid;
    obj->rodata->targ_tgid = config.targ_tgid;
    obj->rodata->targ_uid = config.targ_uid;
    obj->rodata->targ_uid_min = config.targ_uid_min;

    err = create_memory_mapped_file(&config, file_name, &mmf);
    if (err) {
        syslog(LOG_ERR, "run_opentracer: Failed to create memory-mapped file");
        goto cleanup;
    }

    err = opentracer_bpf__load(obj);
    if (err) {
        syslog(LOG_ERR, "run_opentracer: Failed to load BPF object: %d", err);
        goto cleanup;
    }

    err = opentracer_bpf__attach(obj);
    if (err) {
        syslog(LOG_ERR, "run_opentracer: Failed to attach BPF programs: %d", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        syslog(LOG_ERR, "run_opentracer: Failed to create ring buffer");
        goto cleanup;
    }

    syslog(LOG_INFO, "run_opentracer: eBPF setup done");

    while (keep_running) {
        err = ring_buffer__poll(rb, 10000);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            syslog(LOG_ERR, "run_opentracer: Error polling ring buffer: %d", err);
            break;
        }
    }

cleanup:
    syslog(LOG_INFO, "run_opentracer: Cleaning up");

    if (rb != NULL)     ring_buffer__free(rb);
    if (obj != NULL)    opentracer_bpf__destroy(obj);
    if (mmf.addr != NULL) {
        // Truncate the file and unmap the memory.
        close_memory_mapped_file(&config, file_name, &mmf);
    }

    syslog(LOG_INFO, "run_opentracer: Finished");
    closelog();

    return 0;
}
