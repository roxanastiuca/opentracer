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

// C++ std
#include <string>
#include <unordered_map>
#include <vector>

// avoid including vmlinux.h, use hardcoded values
#define AT_FDCWD                -100    /* Special value used to indicate openat should use the current working directory. */


static volatile bool keep_running = true;
static void sig_handler(int)
{
    keep_running = false;
}

std::unordered_map<int, std::string> pid_to_cwd;
std::unordered_map<int, std::vector<std::string>> pid_to_fds_paths;

int handle_event_open(const struct event *e)
{
    if (e->ret < 0) {
        return 0;
    }

    std::string abs_path;
    std::string slash_fname = "/" + std::string(e->fname);
    if (slash_fname == "/.") {
        // Don't stack /. on the path
        slash_fname = "";
    }

    if (e->fname[0] == '/') {
        // Absolute path
        abs_path = std::string(e->fname);
    } else if (e->dfd == AT_FDCWD) {
        // Relative path to CWD
        if (pid_to_cwd.find(e->pid) != pid_to_cwd.end()) {
            abs_path = pid_to_cwd[e->pid] + slash_fname;
        } else {
            abs_path = "?" + slash_fname;
        }
    } else {
        // Relative path to dfd
        if (pid_to_fds_paths.find(e->pid) != pid_to_fds_paths.end()) {
            auto &fds_to_paths = pid_to_fds_paths[e->pid];
            if (e->dfd < fds_to_paths.size() && fds_to_paths[e->dfd] != "") {
                abs_path = fds_to_paths[e->dfd] + slash_fname;
            } else {
                abs_path = "?" + slash_fname;
            }
        } else {
            abs_path = "?" + slash_fname;
        }
    }

    if (pid_to_fds_paths.find(e->pid) == pid_to_fds_paths.end()) {
        pid_to_fds_paths[e->pid] = std::vector<std::string>(100);
    }
    pid_to_fds_paths[e->pid][e->ret] = abs_path;

    printf("OPEN: %d -> %d -> %s\n", e->pid, e->ret, abs_path.c_str());

    return 0;
}

int handle_event_chdir(const struct event *e)
{
    if (e->ret < 0) {
        return 0;
    }

    pid_to_cwd[e->pid] = std::string(e->fname);
    printf("CHDIR: %d -> %s\n", e->pid, e->fname);

    return 0;
}

int handle_event_fchdir(const struct event *e)
{
    if (e->ret < 0) {
        return 0;
    }

    // If not found, set to "?"
    pid_to_cwd[e->pid] = "?";

    if (pid_to_fds_paths.find(e->pid) != pid_to_fds_paths.end()) {
        auto &fds_to_paths = pid_to_fds_paths[e->pid];
        if (e->dfd < fds_to_paths.size() && fds_to_paths[e->dfd] != "") {
            pid_to_cwd[e->pid] = fds_to_paths[e->dfd];
        }
    }

    printf("FCHDIR: %d -> %s\n", e->pid, pid_to_cwd[e->pid].c_str());

    return 0;
}

int handle_event_execve(const struct event *e)
{
    // e->pid = PID of the new process
    // e->ret = PID of the parent process (or <0 if error)
    if (e->ret < 0) {
        return 0;
    }

    if (pid_to_cwd.find(e->ret) != pid_to_cwd.end()) {
        printf("EXECVE: %d -> %s\n", e->pid, pid_to_cwd[e->ret].c_str());
        pid_to_cwd[e->pid] = pid_to_cwd[e->ret];
    } else {
        pid_to_cwd[e->pid] = "?";
    }

    return 0;
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
            return handle_event_open(e);
        case EVENT_TYPE_CHDIR:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "CHDIR", e->dfd, e->ret, e->pid, e->comm, e->fname);
            return handle_event_chdir(e);
        case EVENT_TYPE_FCHDIR:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "FCHDIR", e->dfd, e->ret, e->pid, e->comm, e->fname);
            return handle_event_fchdir(e);
        case EVENT_TYPE_EXECVE:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "EXEC", e->dfd, e->ret, e->pid, e->comm, e->fname);
            return handle_event_execve(e);
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