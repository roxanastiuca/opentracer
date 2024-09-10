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
const volatile uid_t targ_uid = 60004; /* TODO: set to 0, left to 501/1000 for testing */

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
        struct args_t args = {};
        args.fname = (const char *)ctx->filename;
        args.flags = (int)ctx->flags;

        bpf_map_update_elem(&start, &pid, &args, 0);
    }

    return 0;
}


struct sys_exit_open_common_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct sys_exit_open_common_args* ctx)
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

    if (event->ret > 0 && event->fname[0] != '/') {
        struct path path;

        {
            // current->files->fdt->fd[fd]->f.path
            int fd;
            struct task_struct* t;
            struct files_struct* f;
            struct fdtable* fdt;
            struct file** fdd;
            struct file* file;

            fd = event->ret;
            t = (struct task_struct*)bpf_get_current_task(); // current

            bpf_probe_read(&f, sizeof(f), (void*)&t->files); // current->files
            bpf_probe_read(&fdt, sizeof(fdt), (void*)&f->fdt); // current->files->fdt
            bpf_probe_read(&fdd, sizeof(fdd), (void*)&fdt->fd);
            bpf_probe_read(&file, sizeof(file), (void*)&fdd[fd]);
            bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);
        }

        // path.dentry->d_name.name
        struct vfsmount *curr_vfsmount_ptr = path.mnt;
        struct dentry *curr_dentry_ptr = path.dentry;
        
        struct vfsmount curr_vfsmount;
        bpf_probe_read(&curr_vfsmount, sizeof(struct vfsmount), curr_vfsmount_ptr);

        for (int i = 0; i < PATH_MAX_COUNT; i++) {
            struct dentry curr_dentry;
            bpf_probe_read(&curr_dentry, sizeof(struct dentry), curr_dentry_ptr);

            if (curr_dentry_ptr == curr_vfsmount.mnt_root) {
                struct mount *curr_mount_ptr =
                    (struct mount *)(((u8 *)curr_vfsmount_ptr) -
                        offsetof(struct mount, mnt));
                // struct mount curr_mount;
                // bpf_probe_read(&curr_mount, sizeof(struct mount), curr_mount_ptr);
                
                // struct dentry *mount_point_dentry_ptr = curr_mount.mnt_mountpoint;
                struct dentry *mount_point_dentry_ptr;
                bpf_probe_read(&mount_point_dentry_ptr, sizeof(struct dentry *),
                                &curr_mount_ptr->mnt_mountpoint);

                if (curr_dentry_ptr == mount_point_dentry_ptr) {
                    break;
                }

                curr_dentry_ptr = mount_point_dentry_ptr;

                // struct mount *parent_mount_ptr = curr_mount.mnt_parent;
                struct mount *parent_mount_ptr;
                bpf_probe_read(&parent_mount_ptr, sizeof(struct mount *),
                                &curr_mount_ptr->mnt_parent);

                struct vfsmount *parent_vfsmount_ptr =
                    (struct vfsmount *)(((u8 *)parent_mount_ptr) -
                                        offsetof(struct mount, mnt));
                
                if (curr_vfsmount_ptr == parent_vfsmount_ptr) {
                    break;
                }

                curr_vfsmount_ptr = parent_vfsmount_ptr;
                bpf_probe_read(&curr_vfsmount, sizeof(struct vfsmount), curr_vfsmount_ptr);
            } else {
                curr_dentry_ptr = curr_dentry.d_parent;

                bpf_probe_read_str(event->path[i], PATH_MAX_LEN, curr_dentry.d_name.name);
                (event->path_len)++;
            }
        }
    }

    bpf_get_stack(ctx, &stack, sizeof(stack), BPF_F_USER_STACK);
    event->callers[0] = stack[1];
    event->callers[1] = stack[2];

    /* emit event */
    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
