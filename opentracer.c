#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "opentracer.skel.h"
#include "opentracer.h"

static volatile bool keep_running = true;

static void sig_handler(int)
{
    keep_running = false;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = (const struct event*) data;

    if (strncmp(e->fname, "/dev/", 5) == 0) {
        return 0;
    }
    if (strncmp(e->fname, "/proc/", 6) == 0) {
        return 0;
    }

	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    switch (e->event_type) {
        case EVENT_TYPE_OPEN:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "OPEN", e->dfd, e->ret, e->pid, e->comm, e->fname);
            break;
        case EVENT_TYPE_CHDIR:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "CHDIR", e->dfd, e->ret, e->pid, e->comm, e->fname);
            break;
        case EVENT_TYPE_EXECVE:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "EXEC", e->dfd, e->ret, e->pid, e->comm, e->fname);
            break;
        case EVENT_TYPE_FCHDIR:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "FCHDIR", e->dfd, e->ret, e->pid, e->comm, e->fname);
            break;
        default:
            printf("Unknown event type\n");
    }

	return 0;
}

int main()
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct opentracer_bpf *obj;
    int err;
    
    struct ring_buffer *rb = NULL;

    /* clean handle Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = opentracer_bpf__open_opts(&open_opts);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

	// /* aarch64 and riscv64 don't have open syscall */
    // if (!tracepoint_exists("syscalls", "sys_enter_open")) {
	// 	bpf_program__set_autoload(obj->progs.tracepoint__syscalls__sys_enter_open, false);
	// }

    err = opentracer_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = opentracer_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        goto cleanup;
    }

    printf("OK\n");

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
    ring_buffer__free(rb);
	opentracer_bpf__destroy(obj);
	// cleanup_core_btf(&open_opts); // TODO: fix

    return err != 0;
}