#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "opentracer.skel.h"
#include "opentracer.h"
#include "../common/config.h"
#include "../common/tracer_events.h"

// avoid including vmlinux.h, use hardcoded values
#define AT_FDCWD                -100    /* Special value used to indicate openat should use the current working directory. */


static volatile bool keep_running = true;
static void sig_handler(int)
{
    printf("Shutting down\n");
    keep_running = false;
}

static config_t config;
static volatile memory_mapped_file_t mmf = {0};
static char file_name[256];

int create_memory_mapped_file()
{
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%y-%m-%d-%H-%M-%S", tm);

    snprintf(file_name, sizeof(file_name), "%s/events_%s",
             config.events_save_path, ts);
    
    int fd = open(file_name, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file %s\n", file_name);
        return -1;
    }

    if (ftruncate(fd, config.events_file_size_limit) < 0) {
        fprintf(stderr, "Failed to set memory-mapped file size %s\n", file_name);
        return -1;
    }

    void *addr = mmap(NULL, config.events_file_size_limit, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap file %s\n", file_name);
        return -1;
    }

    close(fd);

    mmf.addr = addr;
    mmf.read_offset = (size_t*)addr;
    mmf.write_offset = (size_t*)((char*)addr + sizeof(size_t));
    mmf.data = (char*)addr + 2 * sizeof(size_t);

    return 0;
}

int close_memory_mapped_file()
{
    size_t size = *(mmf.write_offset) + 2 * sizeof(size_t);
    munmap(mmf.addr, config.events_file_size_limit);

    mmf.addr = NULL;
    mmf.read_offset = NULL;
    mmf.write_offset = NULL;
    mmf.data = NULL;

    int fd = open(file_name, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file %s\n", file_name);
        return -1;
    }

    if (ftruncate(fd, size) < 0) {
        fprintf(stderr, "Failed to reset file size %s\n", file_name);
        return -1;
    }

    close(fd);

    return 0;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
    /* Write data to memory-mapped file */
    if (mmf.addr == NULL) {
        fprintf(stderr, "Memory-mapped file not initialized\n");
        keep_running = false;
        return -1;
    }

    if ((*mmf.write_offset) + data_sz > config.events_file_size_limit) {
        munmap(mmf.addr, config.events_file_size_limit);
        /* Create a new file */
        if (create_memory_mapped_file() != 0) {
            fprintf(stderr, "Failed to create new memory-mapped file\n");
            keep_running = false;
            return -1;
        }
    }

    // Current timestamp:
    time_t ts;
    time(&ts);

    // Overwrite ts in event_t with current timestamp:
    // (without actually changing data, to avoid multiple memcpy-s)
    memcpy((char*)mmf.data + *(mmf.write_offset), &ts, sizeof(time_t));
    memcpy((char*)mmf.data + *(mmf.write_offset) + sizeof(time_t),
           (char*)data + sizeof(time_t), data_sz - sizeof(time_t));
    *(mmf.write_offset) += data_sz;

    return 0;
}



int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    if (load_config(&config, argv[1]) < 0) {
        fprintf(stderr, "Failed to load config file %s\n", argv[1]);
        return 1;
    }

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct opentracer_bpf *obj = NULL;
    int err;

    struct ring_buffer *rb = NULL;

    /* clean handle Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = opentracer_bpf__open_opts(&open_opts);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = create_memory_mapped_file();
    if (err) {
        fprintf(stderr, "Failed to create memory-mapped file\n");
        goto cleanup;
    }

    err = opentracer_bpf__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = opentracer_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("SETUP DONE\n");

    while (keep_running) {
        err = ring_buffer__poll(rb, 10000);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    if (rb != NULL)     ring_buffer__free(rb);
    if (obj != NULL)    opentracer_bpf__destroy(obj);
    if (mmf.addr != NULL) {
        // Truncate the file and unmap the memory.
        close_memory_mapped_file();
    }

    return err != 0;
}