#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../common/tracer_events.h"

/* Options for filtering: */
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 0;
const volatile uid_t targ_uid_min = 0;
const volatile long int events_limit = 0;

volatile long int events_count = 0;


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");


static __always_inline bool valid_uid(uid_t uid) {
    return uid != 0 && uid != (uid_t)-1;
}

static __always_inline
bool trace_allowed(u32 tgid, u32 pid)
{
    if (events_limit > 0 && events_count >= events_limit)
        return false;

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
    if (valid_uid(targ_uid_min)) {
        uid = (u32)bpf_get_current_uid_gid();
        if (uid < targ_uid_min) {
            return false;
        }
    }

    return true;
}

///////////////////// OPEN SYSCALL //////////////////////////

struct open_args {
    const char *fname;
    int dfd;
    int flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct open_args);
} open_start SEC(".maps");

struct sys_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct sys_enter_openat_args* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct open_args args = {};
        args.dfd = (int)ctx->dfd;
        args.fname = (const char *)ctx->filename;
        args.flags = (int)ctx->flags;
        bpf_map_update_elem(&open_start, &pid, &args, 0);
    }

    return 0;
}

struct sys_enter_open_args {
    unsigned long long unused;
    long syscall_nr;
    const char *filename;
    long flags;
    long mode;
};

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open(struct sys_enter_open_args* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct open_args args = {};
        args.fname = (const char *)ctx->filename;
        args.flags = (int)ctx->flags;
        args.dfd = AT_FDCWD;
        bpf_map_update_elem(&open_start, &pid, &args, 0);
    }

    return 0;
}

struct sys_exit_open_common_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

static __always_inline
int common__sys_exit_open(struct sys_exit_open_common_args* ctx)
{
    event_t *event;
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
    event->dfd = ap->dfd;
    event->ret = ctx->ret;

    /* Unused: */
    // bpf_get_stack(ctx, &stack, sizeof(stack), BPF_F_USER_STACK);
    // event->callers[0] = stack[1];
    // event->callers[1] = stack[2];

    /* emit event */
    events_count++;
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct sys_exit_open_common_args* ctx)
{
    return common__sys_exit_open(ctx);
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct sys_exit_open_common_args* ctx)
{
    return common__sys_exit_open(ctx);
}



///////////////////// EXECVE SYSCALL //////////////////////////

struct execve_args {
    const char *fname;
    int dfd;
    // const char *const *argv; // unused
    // const char *const *envp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct execve_args);
} execve_start SEC(".maps");


struct sys_enter_execve_args {
    unsigned long long unused;
    long syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct sys_enter_execve_args* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct execve_args args = {};
        args.dfd = AT_FDCWD;
        args.fname = (const char *)ctx->filename;
        // args.envp = (const char *const *)ctx->args[2];
        bpf_map_update_elem(&execve_start, &pid, &args, 0);
    }

    return 0;
}

struct sys_enter_execveat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
    long flags;
};

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct sys_enter_execveat_args* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct execve_args args = {};
        args.dfd = (int)ctx->dfd;
        args.fname = (const char *)ctx->filename;
        // args.envp = (const char *const *)ctx->args[3];
        bpf_map_update_elem(&execve_start, &pid, &args, 0);
    }

    return 0;
}

struct sys_exit_execve_common_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

static __always_inline
int common__sys_exit_execve(struct sys_exit_execve_common_args* ctx)
{
    event_t *event;
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
    event->dfd = ap->dfd;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->fname);

    /* execve doesn't have a return value, use field for ppid (pid_t == int) */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    event->ret = 0;
    bpf_probe_read(&event->ret, sizeof(parent->pid), &parent->pid);

    /* get env_start */
    // struct mm_struct *mm;
    // bpf_probe_read(&mm, sizeof(mm), &task->mm);
    // long unsigned env_start, env_end;
    // bpf_probe_read(&env_start, sizeof(env_start), &mm->env_start);
    // bpf_probe_read(&env_end, sizeof(env_end), &mm->env_end);

    // int l = 0;

    // char **envp = (char **) env_start;
    // while (envp < (char **) env_end) {
    //     char env[100];
    //     char *var;
    //     bpf_probe_read(&var, sizeof(var), &envp[0]);
    //     // bpf_probe_read_user_str(&env, sizeof(env), var);
    //     // bpf_probe_read_str(&env, sizeof(env), &var);
    //     envp++;
    // }

    /* emit event */
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct sys_exit_execve_common_args* ctx)
{
    return common__sys_exit_execve(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint__syscalls__sys_exit_execveat(struct sys_exit_execve_common_args* ctx)
{
    return common__sys_exit_execve(ctx);
}


///////////////////// CHDIR SYSCALL //////////////////////////

struct chdir_args {
    const char *path;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct chdir_args);
} chdir_start SEC(".maps");


struct sys_enter_chdir_args {
    unsigned long long unused;
    long syscall_nr;
    const char *filename;
};

SEC("tracepoint/syscalls/sys_enter_chdir")
int tracepoint__syscalls__sys_enter_chdir(struct sys_enter_chdir_args* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct chdir_args args = {};
        args.path = ctx->filename;
        bpf_map_update_elem(&chdir_start, &pid, &args, 0);
    }

    return 0;
}

struct sys_exit_chdir_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_chdir")
int tracepoint__syscalls__sys_exit_chdir(struct sys_exit_chdir_args* ctx)
{
    event_t *event;
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

struct fchdir_args {
    int fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct fchdir_args);
} fchdir_start SEC(".maps");


struct sys_enter_fchdir_args {
    unsigned long long unused;
    long syscall_nr;
    long fd;
};

SEC("tracepoint/syscalls/sys_enter_fchdir")
int tracepoint__syscalls__sys_enter_fchdir(struct sys_enter_fchdir_args* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;

    if (trace_allowed(tgid, pid)) {
        struct fchdir_args args = {};
        args.fd = ctx->fd;
        bpf_map_update_elem(&fchdir_start, &pid, &args, 0);
    }

    return 0;
}


struct sys_exit_fchdir_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_fchdir")
int tracepoint__syscalls__sys_exit_fchdir(struct sys_exit_fchdir_args* ctx)
{
    event_t *event;
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
