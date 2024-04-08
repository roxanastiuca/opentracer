#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "opentracer.h"


const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 501; /* TODO: set to 0, left to 501 for testing */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");


static __always_inline bool valid_uid(uid_t uid) {
    return uid != INVALID_UID;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
    u32 uid;

    /* filters */
    if (targ_tgid && targ_tgid != tgid)
        return false;
    if (targ_pid && targ_pid != pid)
        return false;
    if (valid_uid(targ_uid)) {
        uid = (u32)bpf_get_current_uid_gid();
        if (targ_uid != uid) {
            return false;
        }
    }

    return true;
}

///////////////////// OPEN SYSCALL //////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct open_args);
} open_start SEC(".maps");

// arch has no open syscall, but add it for cluster architecture
// SEC("tp/syscalls/sys_enter_open")
// int tracepoint__syscalls__sys_enter_open(struct trace_event_raw_sys_enter* ctx)

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct open_args args = {};
        args.fname = (const char *)ctx->args[1];
        args.flags = (int)ctx->args[2];
        args.dfd = (int)ctx->args[0];
        bpf_map_update_elem(&open_start, &pid, &args, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
    struct event *event;
    struct open_args *ap;
    // uintptr_t stack[3];
    u32 pid = bpf_get_current_pid_tgid();

    ap = bpf_map_lookup_elem(&open_start, &pid);
    if (!ap) {
        // bpf_printk("Openat - Exit for missed entry\n");
        return 0; /* missed entry */
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // bpf_printk("Openat - Exit for failed ringbuf reserve\n");
        return 0; /* TODO: handle? */
    }

    event->event_type = (char)EVENT_TYPE_OPEN;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->fname);
    event->flags = ap->flags;
    event->ret = ctx->ret;
    event->dfd = ap->dfd;

    // /* Unused: */
    // bpf_get_stack(ctx, &stack, sizeof(stack), BPF_F_USER_STACK);
    // event->callers[0] = stack[1];
    // event->callers[1] = stack[2];

    /* emit event */
    bpf_ringbuf_submit(event, 0);

    return 0;
}


///////////////////// EXECVE SYSCALL //////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct execve_args);
} execve_start SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct execve_args args = {};
        args.fname = (const char *)ctx->args[0];
        bpf_map_update_elem(&execve_start, &pid, &args, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
    struct event *event;
    struct execve_args *ap;
    u32 pid = bpf_get_current_pid_tgid();

    if (ctx->ret < 0) {
        return 0; /* failed syscall, don't record event */
    }

    ap = bpf_map_lookup_elem(&execve_start, &pid);
    if (!ap) {
        return 0; /* missed entry */
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0; /* allocation failed */
    }

    event->event_type = (char)EVENT_TYPE_EXECVE;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->fname);

    /* execve doesn't have a return value, use field for ppid (pid_t == int) */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read(&event->ret, sizeof(event->ret), &parent->pid);

    /* emit event */
    bpf_ringbuf_submit(event, 0);

    return 0;
}



///////////////////// CHDIR SYSCALL //////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct chdir_args);
} chdir_start SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_chdir")
int tracepoint__syscalls__sys_enter_chdir(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct chdir_args args = {};
        args.path = (const char *)ctx->args[0];
        bpf_map_update_elem(&chdir_start, &pid, &args, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int tracepoint__syscalls__sys_exit_chdir(struct trace_event_raw_sys_exit* ctx)
{
    struct event *event;
    struct chdir_args *ap;
    u32 pid = bpf_get_current_pid_tgid();

    if (ctx->ret < 0) {
        return 0; /* failed syscall, don't record event */
    }

    ap = bpf_map_lookup_elem(&chdir_start, &pid);
    if (!ap) {
        return 0; /* missed entry */
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0; /* allocation failed */
    }

    event->event_type = (char)EVENT_TYPE_CHDIR;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->path);
    event->ret = ctx->ret;

    /* emit event */
    bpf_ringbuf_submit(event, 0);

    return 0;
}

///////////////////// FCHDIR SYSCALL //////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct fchdir_args);
} fchdir_start SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_fchdir")
int tracepoint__syscalls__sys_enter_fchdir(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct fchdir_args args = {};
        args.fd = (int)ctx->args[0];
        bpf_map_update_elem(&fchdir_start, &pid, &args, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int tracepoint__syscalls__sys_exit_fchdir(struct trace_event_raw_sys_exit* ctx)
{
    struct event *event;
    struct fchdir_args *ap;
    u32 pid = bpf_get_current_pid_tgid();

    if (ctx->ret < 0) {
        return 0; /* failed syscall, don't record event */
    }

    ap = bpf_map_lookup_elem(&fchdir_start, &pid);
    if (!ap) {
        return 0; /* missed entry */
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0; /* allocation failed */
    }

    event->event_type = (char)EVENT_TYPE_FCHDIR;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->dfd = ap->fd;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->ret = ctx->ret;

    /* emit event */
    bpf_ringbuf_submit(event, 0);

    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";
