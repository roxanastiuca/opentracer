#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "opentracer.h"

// #include <linux/fs_struct.h>

// #include <linux/dcache.h>
// #include <linux/fdtable.h>
// #include <linux/fs.h>
// #include <linux/fs_struct.h>
// #include <linux/path.h>



const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 501; /* TODO: set to 0, left to 501/1000 for testing */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct args_t);
} start SEC(".maps");

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
        struct args_t args = {};
        args.fname = (const char *)ctx->args[1];
        args.flags = (int)ctx->args[2];

        bpf_map_update_elem(&start, &pid, &args, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
    struct event *event;
    struct args_t *ap;
    uintptr_t stack[3];
    u32 pid = bpf_get_current_pid_tgid();

    ap = bpf_map_lookup_elem(&start, &pid);
    if (!ap) {
        // bpf_printk("Openat - Exit for missed entry\n");
        return 0; /* missed entry */
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // bpf_printk("Openat - Exit for failed ringbuf reserve\n");
        return 0; /* TODO: handle? */
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_user_str(&event->fname, sizeof(event->fname), ap->fname);
    event->flags = ap->flags;
    event->ret = ctx->ret;

    if (event->ret > 0) {
        // current->files->fdt->fd[fd]->f.path.dentry->d_iname
        // current->files->fdt->fd[fd]->f.path.dentry->d_name.name
        int fd;
        struct task_struct* t;
        struct files_struct* f;
        struct fdtable* fdt;
        struct file** fdd;
        struct file* file;
        struct path path;
        struct dentry* dentry;
        struct dentry dtry;
        struct qstr pathname;

        fd = event->ret;
        t = (struct task_struct*)bpf_get_current_task(); // current

        bpf_probe_read(&f, sizeof(f), (void*)&t->files); // current->files
        bpf_probe_read(&fdt, sizeof(fdt), (void*)&f->fdt); // current->files->fdt
        bpf_probe_read(&fdd, sizeof(fdd), (void*)&fdt->fd);
        bpf_probe_read(&file, sizeof(file), (void*)&fdd[fd]);
        bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);

        dentry = path.dentry;

        // Reconstruct path
        event->path_len = 0;

        bpf_probe_read(&dtry, sizeof(struct dentry), dentry);
        bpf_probe_read_str(event->path[0], PATH_MAX_LEN, dtry.d_name.name);
        (event->path_len)++;
        for (int i = 1; i < PATH_MAX_COUNT; i++) {
            if (dtry.d_parent != dentry) {
                dentry = dtry.d_parent;
                bpf_probe_read(&dtry, sizeof(struct dentry), dtry.d_parent);
                bpf_probe_read_str(event->path[i], PATH_MAX_LEN, dtry.d_name.name);
                (event->path_len)++;
            } else {
                break;
            }
        }

        // for (int i = 0; i < PATH_MAX_COUNT; i++) {
        //     bpf_probe_read(&dtry, sizeof(struct dentry), dentry);
        //     bpf_probe_read_str(event->path[i], PATH_MAX_LEN, dtry.d_name.name);
        //     if (dtry.d_parent && dtry.d_parent != dentry) {
        //         dentry = dtry.d_parent;
        //     } else {
        //         event->path_len = i;
        //         break;
        //     }
        // }

        // bpf_probe_read(&pathname, sizeof(pathname), (const void*)&dentry->d_name);
        // bpf_probe_read_str((void*)event->path, sizeof(event->path), (const void*)pathname.name);
    }

    bpf_get_stack(ctx, &stack, sizeof(stack), BPF_F_USER_STACK);
    event->callers[0] = stack[1];
    event->callers[1] = stack[2];

    /* emit event */
    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";



// int kprobe__vfs_fstat(struct pt_regs *ctx, unsigned int fd)
// {
//     struct files_struct *files = NULL;
//     struct fdtable *fdt = NULL;
//     struct file *f = NULL;
//     struct dentry *de = NULL;
//     struct qstr dn = {};
//     struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
//     bpf_probe_read(&files, sizeof(files), &curr->files);
//     bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
//     bpf_probe_read(&f, sizeof(f), &fdt[fd]);
//     bpf_probe_read(&de, sizeof(de), &f->f_path.dentry);
//     bpf_probe_read(&dn, sizeof(dn), &de->d_name);
//     bpf_trace_printk("fstat fd=%d file=%s\\n", fd, dn.name);
//     return 0;
// }