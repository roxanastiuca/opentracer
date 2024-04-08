#ifndef __OPENTRACER_H
#define __OPENTRACER_H

#define INVALID_UID ((uid_t)-1)

// Relevant fields from syscall_enter to be passed to syscall_exit:
struct open_args {
    const char *fname;
    int dfd;
    int flags;
};

struct execve_args {
    const char *fname;
    // const char *const *argv; // unused
    // const char *const *envp; // unused
};

struct chdir_args {
    const char *path;
};

struct fchdir_args {
    int fd;
};

#endif /* __OPENTRACER_H */
