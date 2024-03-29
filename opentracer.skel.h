/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __OPENTRACER_BPF_SKEL_H__
#define __OPENTRACER_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct opentracer_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *start;
		struct bpf_map *events;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *tracepoint__syscalls__sys_enter_openat;
		struct bpf_program *tracepoint__syscalls__sys_exit_openat;
		struct bpf_program *tracepoint__syscalls__sys_enter_chdir;
	} progs;
	struct {
		struct bpf_link *tracepoint__syscalls__sys_enter_openat;
		struct bpf_link *tracepoint__syscalls__sys_exit_openat;
		struct bpf_link *tracepoint__syscalls__sys_enter_chdir;
	} links;
	struct opentracer_bpf__rodata {
		pid_t targ_pid;
		pid_t targ_tgid;
		uid_t targ_uid;
	} *rodata;

#ifdef __cplusplus
	static inline struct opentracer_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct opentracer_bpf *open_and_load();
	static inline int load(struct opentracer_bpf *skel);
	static inline int attach(struct opentracer_bpf *skel);
	static inline void detach(struct opentracer_bpf *skel);
	static inline void destroy(struct opentracer_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
opentracer_bpf__destroy(struct opentracer_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
opentracer_bpf__create_skeleton(struct opentracer_bpf *obj);

static inline struct opentracer_bpf *
opentracer_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct opentracer_bpf *obj;
	int err;

	obj = (struct opentracer_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = opentracer_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	opentracer_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct opentracer_bpf *
opentracer_bpf__open(void)
{
	return opentracer_bpf__open_opts(NULL);
}

static inline int
opentracer_bpf__load(struct opentracer_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct opentracer_bpf *
opentracer_bpf__open_and_load(void)
{
	struct opentracer_bpf *obj;
	int err;

	obj = opentracer_bpf__open();
	if (!obj)
		return NULL;
	err = opentracer_bpf__load(obj);
	if (err) {
		opentracer_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
opentracer_bpf__attach(struct opentracer_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
opentracer_bpf__detach(struct opentracer_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *opentracer_bpf__elf_bytes(size_t *sz);

static inline int
opentracer_bpf__create_skeleton(struct opentracer_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "opentracer_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 3;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "start";
	s->maps[0].map = &obj->maps.start;

	s->maps[1].name = "events";
	s->maps[1].map = &obj->maps.events;

	s->maps[2].name = "opentrac.rodata";
	s->maps[2].map = &obj->maps.rodata;
	s->maps[2].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 3;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "tracepoint__syscalls__sys_enter_openat";
	s->progs[0].prog = &obj->progs.tracepoint__syscalls__sys_enter_openat;
	s->progs[0].link = &obj->links.tracepoint__syscalls__sys_enter_openat;

	s->progs[1].name = "tracepoint__syscalls__sys_exit_openat";
	s->progs[1].prog = &obj->progs.tracepoint__syscalls__sys_exit_openat;
	s->progs[1].link = &obj->links.tracepoint__syscalls__sys_exit_openat;

	s->progs[2].name = "tracepoint__syscalls__sys_enter_chdir";
	s->progs[2].prog = &obj->progs.tracepoint__syscalls__sys_enter_chdir;
	s->progs[2].link = &obj->links.tracepoint__syscalls__sys_enter_chdir;

	s->data = opentracer_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *opentracer_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x68\x1f\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x12\0\
\x01\0\xbf\x16\0\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x63\x0a\xfc\xff\0\0\0\0\x18\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x12\0\0\0\0\0\0\x15\x02\x04\0\0\0\0\0\x61\x11\
\0\0\0\0\0\0\xbf\x02\0\0\0\0\0\0\x77\x02\0\0\x20\0\0\0\x5d\x21\x21\0\0\0\0\0\
\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x12\0\0\0\0\0\0\x15\x02\x04\0\0\0\0\0\
\x61\x11\0\0\0\0\0\0\x67\0\0\0\x20\0\0\0\x77\0\0\0\x20\0\0\0\x5d\x01\x19\0\0\0\
\0\0\x18\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x71\0\0\0\0\0\0\x18\x02\0\0\xff\
\xff\xff\xff\0\0\0\0\0\0\0\0\x1d\x21\x05\0\0\0\0\0\x85\0\0\0\x0f\0\0\0\x61\x71\
\0\0\0\0\0\0\x67\0\0\0\x20\0\0\0\x77\0\0\0\x20\0\0\0\x5d\x01\x0e\0\0\0\0\0\xb7\
\x01\0\0\0\0\0\0\x7b\x1a\xf0\xff\0\0\0\0\x79\x61\x18\0\0\0\0\0\x7b\x1a\xe8\xff\
\0\0\0\0\x79\x61\x20\0\0\0\0\0\x63\x1a\xf0\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\
\x02\0\0\xfc\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xe8\xff\xff\xff\x18\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x02\0\0\0\xb7\0\
\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\xbf\x16\0\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x63\x0a\
\xe4\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xe4\xff\xff\xff\x18\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\xbf\x08\0\0\0\0\0\0\x15\x08\x26\0\0\
\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x38\x01\0\0\xb7\x03\0\0\
\0\0\0\0\x85\0\0\0\x83\0\0\0\xbf\x07\0\0\0\0\0\0\x15\x07\x1f\0\0\0\0\0\x85\0\0\
\0\x0e\0\0\0\x77\0\0\0\x20\0\0\0\x63\x07\x08\0\0\0\0\0\x85\0\0\0\x0f\0\0\0\x63\
\x07\x0c\0\0\0\0\0\xbf\x71\0\0\0\0\0\0\x07\x01\0\0\x28\0\0\0\xb7\x02\0\0\x10\0\
\0\0\x85\0\0\0\x10\0\0\0\x79\x83\0\0\0\0\0\0\xbf\x71\0\0\0\0\0\0\x07\x01\0\0\
\x38\0\0\0\xb7\x02\0\0\xff\0\0\0\x85\0\0\0\x72\0\0\0\x61\x81\x08\0\0\0\0\0\x63\
\x17\x14\0\0\0\0\0\x79\x61\x10\0\0\0\0\0\x63\x17\x10\0\0\0\0\0\xbf\xa2\0\0\0\0\
\0\0\x07\x02\0\0\xe8\xff\xff\xff\xbf\x61\0\0\0\0\0\0\xb7\x03\0\0\x18\0\0\0\xb7\
\x04\0\0\0\x01\0\0\x85\0\0\0\x43\0\0\0\x79\xa1\xf0\xff\0\0\0\0\x7b\x17\x18\0\0\
\0\0\0\x79\xa1\xf8\xff\0\0\0\0\x7b\x17\x20\0\0\0\0\0\xbf\x71\0\0\0\0\0\0\xb7\
\x02\0\0\0\0\0\0\x85\0\0\0\x84\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x85\0\
\0\0\x0e\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x12\0\0\0\0\0\0\x15\x02\
\x04\0\0\0\0\0\x61\x11\0\0\0\0\0\0\xbf\x02\0\0\0\0\0\0\x77\x02\0\0\x20\0\0\0\
\x5d\x21\x10\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x12\0\0\0\0\0\0\
\x15\x02\x04\0\0\0\0\0\x61\x11\0\0\0\0\0\0\x67\0\0\0\x20\0\0\0\x77\0\0\0\x20\0\
\0\0\x5d\x01\x08\0\0\0\0\0\x18\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x61\0\0\0\0\
\0\0\x18\x02\0\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\x1d\x21\x02\0\0\0\0\0\x85\0\0\
\0\x0f\0\0\0\x61\x61\0\0\0\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xf5\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x42\x53\x44\
\x2f\x47\x50\x4c\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x7c\x04\0\0\x7c\x04\0\
\0\x9e\x07\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\
\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x01\0\0\0\x05\0\0\0\0\0\0\
\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x02\0\0\0\x04\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\x19\0\0\0\0\0\0\x08\
\x09\0\0\0\x1d\0\0\0\0\0\0\x08\x0a\0\0\0\x23\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\
\0\0\0\0\0\0\0\0\x02\x0c\0\0\0\x30\0\0\0\x02\0\0\x04\x10\0\0\0\x37\0\0\0\x0d\0\
\0\0\0\0\0\0\x3d\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x0e\0\0\0\0\0\0\0\
\0\0\0\x0a\x0f\0\0\0\x43\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\x04\0\0\
\x04\x20\0\0\0\x48\0\0\0\x01\0\0\0\0\0\0\0\x4d\0\0\0\x05\0\0\0\x40\0\0\0\x59\0\
\0\0\x07\0\0\0\x80\0\0\0\x5d\0\0\0\x0b\0\0\0\xc0\0\0\0\x63\0\0\0\0\0\0\x0e\x10\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x13\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\
\0\x04\0\0\0\x1b\0\0\0\0\0\0\0\0\0\0\x02\x15\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x02\0\0\0\x04\0\0\0\0\0\x04\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\x48\0\0\0\x12\0\0\
\0\0\0\0\0\x4d\0\0\0\x14\0\0\0\x40\0\0\0\x69\0\0\0\0\0\0\x0e\x16\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\x02\x19\0\0\0\x70\0\0\0\x04\0\0\x04\x40\0\0\0\x8a\0\0\0\x1a\0\
\0\0\0\0\0\0\x8e\0\0\0\x1d\0\0\0\x40\0\0\0\x91\0\0\0\x1f\0\0\0\x80\0\0\0\x96\0\
\0\0\x20\0\0\0\0\x02\0\0\x9d\0\0\0\x04\0\0\x04\x08\0\0\0\x48\0\0\0\x1b\0\0\0\0\
\0\0\0\x3d\0\0\0\x1c\0\0\0\x10\0\0\0\xa9\0\0\0\x1c\0\0\0\x18\0\0\0\xb7\0\0\0\
\x02\0\0\0\x20\0\0\0\xbb\0\0\0\0\0\0\x01\x02\0\0\0\x10\0\0\0\xca\0\0\0\0\0\0\
\x01\x01\0\0\0\x08\0\0\0\xd8\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\x01\xdd\0\0\0\0\
\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x1e\0\0\0\x04\0\0\0\x06\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0f\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\x0d\x02\0\0\0\xeb\0\0\0\x18\0\0\0\xef\0\0\0\x01\0\0\x0c\x21\0\0\0\0\0\0\0\0\0\
\0\x02\x24\0\0\0\xb4\x03\0\0\x04\0\0\x04\x18\0\0\0\x8a\0\0\0\x1a\0\0\0\0\0\0\0\
\x8e\0\0\0\x1d\0\0\0\x40\0\0\0\xcd\x03\0\0\x1d\0\0\0\x80\0\0\0\x96\0\0\0\x20\0\
\0\0\xc0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xeb\0\0\0\x23\0\0\0\xd1\x03\0\0\
\x01\0\0\x0c\x25\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xeb\0\0\0\x18\0\0\0\xee\
\x06\0\0\x01\0\0\x0c\x27\0\0\0\0\0\0\0\0\0\0\x0a\x2a\0\0\0\0\0\0\0\0\0\0\x09\
\x2b\0\0\0\x38\x07\0\0\0\0\0\x08\x2c\0\0\0\x3e\x07\0\0\0\0\0\x08\x02\0\0\0\x4d\
\x07\0\0\0\0\0\x0e\x29\0\0\0\x01\0\0\0\x56\x07\0\0\0\0\0\x0e\x29\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\x0a\x30\0\0\0\0\0\0\0\0\0\0\x09\x31\0\0\0\x60\x07\0\0\0\0\0\
\x08\x32\0\0\0\x66\x07\0\0\0\0\0\x08\x0a\0\0\0\x77\x07\0\0\0\0\0\x0e\x2f\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0f\0\0\0\x04\0\0\0\x0d\0\0\0\x80\x07\0\0\
\0\0\0\x0e\x34\0\0\0\x01\0\0\0\x88\x07\0\0\x02\0\0\x0f\0\0\0\0\x11\0\0\0\0\0\0\
\0\x20\0\0\0\x17\0\0\0\0\0\0\0\x10\0\0\0\x8e\x07\0\0\x03\0\0\x0f\0\0\0\0\x2d\0\
\0\0\0\0\0\0\x04\0\0\0\x2e\0\0\0\0\0\0\0\x04\0\0\0\x33\0\0\0\0\0\0\0\x04\0\0\0\
\x96\x07\0\0\x01\0\0\x0f\0\0\0\0\x35\0\0\0\0\0\0\0\x0d\0\0\0\0\x69\x6e\x74\0\
\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\
\x75\x33\x32\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x61\x72\x67\x73\x5f\x74\0\x66\x6e\x61\x6d\x65\0\x66\x6c\x61\x67\x73\
\0\x63\x68\x61\x72\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\
\x73\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x73\x74\x61\x72\x74\0\x65\x76\x65\
\x6e\x74\x73\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\
\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x65\x6e\x74\0\x69\x64\0\x61\x72\x67\x73\
\0\x5f\x5f\x64\x61\x74\x61\0\x74\x72\x61\x63\x65\x5f\x65\x6e\x74\x72\x79\0\x70\
\x72\x65\x65\x6d\x70\x74\x5f\x63\x6f\x75\x6e\x74\0\x70\x69\x64\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x63\x68\x61\x72\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\
\x6c\x6f\x6e\x67\0\x63\x74\x78\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\
\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\
\x72\x5f\x6f\x70\x65\x6e\x61\x74\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\
\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\
\x6f\x70\x65\x6e\x61\x74\0\x2f\x55\x73\x65\x72\x73\x2f\x72\x73\x74\x69\x75\x63\
\x61\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x75\x6e\x69\x2f\x74\x68\x65\x73\x69\
\x73\x2f\x65\x62\x70\x66\x2f\x6c\x65\x61\x72\x6e\x69\x6e\x67\x2d\x65\x62\x70\
\x66\x2f\x6f\x70\x65\x6e\x74\x72\x61\x63\x65\x72\x2f\x6f\x70\x65\x6e\x74\x72\
\x61\x63\x65\x72\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x74\x72\x61\x63\x65\
\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\
\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\x74\x28\x73\x74\x72\x75\
\x63\x74\x20\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\
\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x2a\x20\x63\x74\x78\x29\0\x20\x20\x20\x20\
\x75\x36\x34\x20\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\
\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\x29\x3b\0\x20\x20\
\x20\x20\x75\x33\x32\x20\x70\x69\x64\x20\x3d\x20\x69\x64\x3b\0\x20\x20\x20\x20\
\x69\x66\x20\x28\x74\x61\x72\x67\x5f\x74\x67\x69\x64\x20\x26\x26\x20\x74\x61\
\x72\x67\x5f\x74\x67\x69\x64\x20\x21\x3d\x20\x74\x67\x69\x64\x29\0\x20\x20\x20\
\x20\x75\x33\x32\x20\x74\x67\x69\x64\x20\x3d\x20\x69\x64\x20\x3e\x3e\x20\x33\
\x32\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x74\x61\x72\x67\x5f\x70\x69\x64\x20\
\x26\x26\x20\x74\x61\x72\x67\x5f\x70\x69\x64\x20\x21\x3d\x20\x70\x69\x64\x29\0\
\x20\x20\x20\x20\x69\x66\x20\x28\x76\x61\x6c\x69\x64\x5f\x75\x69\x64\x28\x74\
\x61\x72\x67\x5f\x75\x69\x64\x29\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\
\x75\x69\x64\x20\x3d\x20\x28\x75\x33\x32\x29\x62\x70\x66\x5f\x67\x65\x74\x5f\
\x63\x75\x72\x72\x65\x6e\x74\x5f\x75\x69\x64\x5f\x67\x69\x64\x28\x29\x3b\0\x20\
\x20\x20\x20\x20\x20\x20\x20\x69\x66\x20\x28\x74\x61\x72\x67\x5f\x75\x69\x64\
\x20\x21\x3d\x20\x75\x69\x64\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\x73\
\x74\x72\x75\x63\x74\x20\x61\x72\x67\x73\x5f\x74\x20\x61\x72\x67\x73\x20\x3d\
\x20\x7b\x7d\x3b\0\x30\x3a\x32\x3a\x31\0\x20\x20\x20\x20\x20\x20\x20\x20\x61\
\x72\x67\x73\x2e\x66\x6e\x61\x6d\x65\x20\x3d\x20\x28\x63\x6f\x6e\x73\x74\x20\
\x63\x68\x61\x72\x20\x2a\x29\x63\x74\x78\x2d\x3e\x61\x72\x67\x73\x5b\x31\x5d\
\x3b\0\x30\x3a\x32\x3a\x32\0\x20\x20\x20\x20\x20\x20\x20\x20\x61\x72\x67\x73\
\x2e\x66\x6c\x61\x67\x73\x20\x3d\x20\x28\x69\x6e\x74\x29\x63\x74\x78\x2d\x3e\
\x61\x72\x67\x73\x5b\x32\x5d\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\
\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\x28\x26\x73\
\x74\x61\x72\x74\x2c\x20\x26\x70\x69\x64\x2c\x20\x26\x61\x72\x67\x73\x2c\x20\
\x30\x29\x3b\0\x20\x20\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x30\x3b\0\x74\x72\
\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\
\x78\x69\x74\0\x72\x65\x74\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\
\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x78\x69\x74\x5f\
\x6f\x70\x65\x6e\x61\x74\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\
\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x78\x69\x74\x5f\x6f\x70\x65\
\x6e\x61\x74\0\x69\x6e\x74\x20\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\
\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x78\x69\x74\x5f\
\x6f\x70\x65\x6e\x61\x74\x28\x73\x74\x72\x75\x63\x74\x20\x74\x72\x61\x63\x65\
\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x78\x69\x74\
\x2a\x20\x63\x74\x78\x29\0\x20\x20\x20\x20\x75\x33\x32\x20\x70\x69\x64\x20\x3d\
\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\
\x64\x5f\x74\x67\x69\x64\x28\x29\x3b\0\x20\x20\x20\x20\x61\x70\x20\x3d\x20\x62\
\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\
\x26\x73\x74\x61\x72\x74\x2c\x20\x26\x70\x69\x64\x29\x3b\0\x20\x20\x20\x20\x69\
\x66\x20\x28\x21\x61\x70\x29\x20\x7b\0\x20\x20\x20\x20\x65\x76\x65\x6e\x74\x20\
\x3d\x20\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x72\x65\x73\x65\x72\
\x76\x65\x28\x26\x65\x76\x65\x6e\x74\x73\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\
\x2a\x65\x76\x65\x6e\x74\x29\x2c\x20\x30\x29\x3b\0\x20\x20\x20\x20\x69\x66\x20\
\x28\x21\x65\x76\x65\x6e\x74\x29\x20\x7b\0\x20\x20\x20\x20\x65\x76\x65\x6e\x74\
\x2d\x3e\x70\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\
\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\x29\x20\x3e\x3e\x20\
\x33\x32\x3b\0\x20\x20\x20\x20\x65\x76\x65\x6e\x74\x2d\x3e\x75\x69\x64\x20\x3d\
\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x75\x69\
\x64\x5f\x67\x69\x64\x28\x29\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x67\x65\x74\
\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x63\x6f\x6d\x6d\x28\x26\x65\x76\x65\x6e\
\x74\x2d\x3e\x63\x6f\x6d\x6d\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x65\x76\x65\
\x6e\x74\x2d\x3e\x63\x6f\x6d\x6d\x29\x29\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\
\x70\x72\x6f\x62\x65\x5f\x72\x65\x61\x64\x5f\x75\x73\x65\x72\x5f\x73\x74\x72\
\x28\x26\x65\x76\x65\x6e\x74\x2d\x3e\x66\x6e\x61\x6d\x65\x2c\x20\x73\x69\x7a\
\x65\x6f\x66\x28\x65\x76\x65\x6e\x74\x2d\x3e\x66\x6e\x61\x6d\x65\x29\x2c\x20\
\x61\x70\x2d\x3e\x66\x6e\x61\x6d\x65\x29\x3b\0\x20\x20\x20\x20\x65\x76\x65\x6e\
\x74\x2d\x3e\x66\x6c\x61\x67\x73\x20\x3d\x20\x61\x70\x2d\x3e\x66\x6c\x61\x67\
\x73\x3b\0\x30\x3a\x32\0\x20\x20\x20\x20\x65\x76\x65\x6e\x74\x2d\x3e\x72\x65\
\x74\x20\x3d\x20\x63\x74\x78\x2d\x3e\x72\x65\x74\x3b\0\x20\x20\x20\x20\x62\x70\
\x66\x5f\x67\x65\x74\x5f\x73\x74\x61\x63\x6b\x28\x63\x74\x78\x2c\x20\x26\x73\
\x74\x61\x63\x6b\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x73\x74\x61\x63\x6b\x29\
\x2c\x20\x42\x50\x46\x5f\x46\x5f\x55\x53\x45\x52\x5f\x53\x54\x41\x43\x4b\x29\
\x3b\0\x20\x20\x20\x20\x65\x76\x65\x6e\x74\x2d\x3e\x63\x61\x6c\x6c\x65\x72\x73\
\x5b\x30\x5d\x20\x3d\x20\x73\x74\x61\x63\x6b\x5b\x31\x5d\x3b\0\x20\x20\x20\x20\
\x65\x76\x65\x6e\x74\x2d\x3e\x63\x61\x6c\x6c\x65\x72\x73\x5b\x31\x5d\x20\x3d\
\x20\x73\x74\x61\x63\x6b\x5b\x32\x5d\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x72\
\x69\x6e\x67\x62\x75\x66\x5f\x73\x75\x62\x6d\x69\x74\x28\x65\x76\x65\x6e\x74\
\x2c\x20\x30\x29\x3b\0\x7d\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\
\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\
\x5f\x63\x68\x64\x69\x72\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\
\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x63\x68\
\x64\x69\x72\0\x70\x69\x64\x5f\x74\0\x5f\x5f\x6b\x65\x72\x6e\x65\x6c\x5f\x70\
\x69\x64\x5f\x74\0\x74\x61\x72\x67\x5f\x70\x69\x64\0\x74\x61\x72\x67\x5f\x74\
\x67\x69\x64\0\x75\x69\x64\x5f\x74\0\x5f\x5f\x6b\x65\x72\x6e\x65\x6c\x5f\x75\
\x69\x64\x33\x32\x5f\x74\0\x74\x61\x72\x67\x5f\x75\x69\x64\0\x4c\x49\x43\x45\
\x4e\x53\x45\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\
\x65\x6e\x73\x65\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x34\0\0\0\x34\0\0\0\xac\
\x04\0\0\xe0\x04\0\0\x44\0\0\0\x08\0\0\0\x16\x01\0\0\x01\0\0\0\0\0\0\0\x22\0\0\
\0\xf7\x03\0\0\x01\0\0\0\0\0\0\0\x26\0\0\0\x14\x07\0\0\x01\0\0\0\0\0\0\0\x28\0\
\0\0\x10\0\0\0\x16\x01\0\0\x1b\0\0\0\0\0\0\0\x3b\x01\0\0\x8c\x01\0\0\0\xd8\0\0\
\x08\0\0\0\x3b\x01\0\0\xde\x01\0\0\x0e\xe0\0\0\x10\0\0\0\x3b\x01\0\0\x07\x02\0\
\0\x09\xe8\0\0\x18\0\0\0\x3b\x01\0\0\x19\x02\0\0\x09\x8c\0\0\x30\0\0\0\x3b\x01\
\0\0\x19\x02\0\0\x13\x8c\0\0\x38\0\0\0\x3b\x01\0\0\x19\x02\0\0\x16\x8c\0\0\x40\
\0\0\0\x3b\x01\0\0\x41\x02\0\0\x13\xe4\0\0\x50\0\0\0\x3b\x01\0\0\x19\x02\0\0\
\x09\x8c\0\0\x58\0\0\0\x3b\x01\0\0\x5a\x02\0\0\x09\x94\0\0\x70\0\0\0\x3b\x01\0\
\0\x5a\x02\0\0\x12\x94\0\0\x78\0\0\0\x3b\x01\0\0\x5a\x02\0\0\x15\x94\0\0\x80\0\
\0\0\x3b\x01\0\0\x07\x02\0\0\x0f\xe8\0\0\x90\0\0\0\x3b\x01\0\0\x5a\x02\0\0\x09\
\x94\0\0\x98\0\0\0\x3b\x01\0\0\x7f\x02\0\0\x13\x9c\0\0\xc0\0\0\0\x3b\x01\0\0\
\x7f\x02\0\0\x09\x9c\0\0\xc8\0\0\0\x3b\x01\0\0\x9e\x02\0\0\x14\xa0\0\0\xd0\0\0\
\0\x3b\x01\0\0\xcc\x02\0\0\x0d\xa4\0\0\xd8\0\0\0\x3b\x01\0\0\x9e\x02\0\0\x0f\
\xa0\0\0\xe8\0\0\0\x3b\x01\0\0\xcc\x02\0\0\x0d\xa4\0\0\xf8\0\0\0\x3b\x01\0\0\
\xeb\x02\0\0\x17\xf4\0\0\0\x01\0\0\x3b\x01\0\0\x12\x03\0\0\x24\xf8\0\0\x08\x01\
\0\0\x3b\x01\0\0\x12\x03\0\0\x14\xf8\0\0\x10\x01\0\0\x3b\x01\0\0\x49\x03\0\0\
\x1b\xfc\0\0\x18\x01\0\0\x3b\x01\0\0\x49\x03\0\0\x14\xfc\0\0\x28\x01\0\0\x3b\
\x01\0\0\xeb\x02\0\0\x17\xf4\0\0\x40\x01\0\0\x3b\x01\0\0\x71\x03\0\0\x09\0\x01\
\0\x60\x01\0\0\x3b\x01\0\0\xa6\x03\0\0\x05\x0c\x01\0\xf7\x03\0\0\x1e\0\0\0\0\0\
\0\0\x3b\x01\0\0\x1b\x04\0\0\0\x1c\x01\0\x08\0\0\0\x3b\x01\0\0\x6b\x04\0\0\x0f\
\x30\x01\0\x10\0\0\0\x3b\x01\0\0\x6b\x04\0\0\x09\x30\x01\0\x20\0\0\0\x3b\x01\0\
\0\0\0\0\0\0\0\0\0\x28\0\0\0\x3b\x01\0\0\x95\x04\0\0\x0a\x38\x01\0\x48\0\0\0\
\x3b\x01\0\0\xc1\x04\0\0\x09\x3c\x01\0\x50\0\0\0\x3b\x01\0\0\xd0\x04\0\0\x0d\
\x50\x01\0\x80\0\0\0\x3b\x01\0\0\x0d\x05\0\0\x09\x54\x01\0\x88\0\0\0\x3b\x01\0\
\0\x1f\x05\0\0\x12\x68\x01\0\x90\0\0\0\x3b\x01\0\0\x1f\x05\0\0\x2d\x68\x01\0\
\x98\0\0\0\x3b\x01\0\0\x1f\x05\0\0\x10\x68\x01\0\xa0\0\0\0\x3b\x01\0\0\x52\x05\
\0\0\x12\x6c\x01\0\xa8\0\0\0\x3b\x01\0\0\x52\x05\0\0\x10\x6c\x01\0\xb0\0\0\0\
\x3b\x01\0\0\x7e\x05\0\0\x22\x70\x01\0\xc0\0\0\0\x3b\x01\0\0\x7e\x05\0\0\x05\
\x70\x01\0\xd0\0\0\0\x3b\x01\0\0\xbb\x05\0\0\x46\x74\x01\0\xd8\0\0\0\x3b\x01\0\
\0\xbb\x05\0\0\x25\x74\x01\0\xe8\0\0\0\x3b\x01\0\0\xbb\x05\0\0\x05\x74\x01\0\
\xf8\0\0\0\x3b\x01\0\0\x08\x06\0\0\x18\x78\x01\0\0\x01\0\0\x3b\x01\0\0\x08\x06\
\0\0\x12\x78\x01\0\x08\x01\0\0\x3b\x01\0\0\x2a\x06\0\0\x17\x7c\x01\0\x10\x01\0\
\0\x3b\x01\0\0\x2a\x06\0\0\x10\x7c\x01\0\x20\x01\0\0\x3b\x01\0\0\0\0\0\0\0\0\0\
\0\x28\x01\0\0\x3b\x01\0\0\x45\x06\0\0\x05\x84\x01\0\x48\x01\0\0\x3b\x01\0\0\
\x86\x06\0\0\x19\x88\x01\0\x50\x01\0\0\x3b\x01\0\0\x86\x06\0\0\x17\x88\x01\0\
\x58\x01\0\0\x3b\x01\0\0\xa8\x06\0\0\x19\x8c\x01\0\x60\x01\0\0\x3b\x01\0\0\xa8\
\x06\0\0\x17\x8c\x01\0\x68\x01\0\0\x3b\x01\0\0\xca\x06\0\0\x05\x98\x01\0\x80\
\x01\0\0\x3b\x01\0\0\xec\x06\0\0\x01\xac\x01\0\x14\x07\0\0\x10\0\0\0\0\0\0\0\
\x3b\x01\0\0\xde\x01\0\0\x0e\xc4\x01\0\x08\0\0\0\x3b\x01\0\0\x19\x02\0\0\x09\
\x8c\0\0\x20\0\0\0\x3b\x01\0\0\x19\x02\0\0\x13\x8c\0\0\x28\0\0\0\x3b\x01\0\0\
\x19\x02\0\0\x16\x8c\0\0\x30\0\0\0\x3b\x01\0\0\x41\x02\0\0\x13\xc8\x01\0\x40\0\
\0\0\x3b\x01\0\0\x19\x02\0\0\x09\x8c\0\0\x48\0\0\0\x3b\x01\0\0\x5a\x02\0\0\x09\
\x94\0\0\x60\0\0\0\x3b\x01\0\0\x5a\x02\0\0\x12\x94\0\0\x68\0\0\0\x3b\x01\0\0\
\x5a\x02\0\0\x15\x94\0\0\x70\0\0\0\x3b\x01\0\0\x07\x02\0\0\x0f\xcc\x01\0\x80\0\
\0\0\x3b\x01\0\0\x5a\x02\0\0\x09\x94\0\0\x88\0\0\0\x3b\x01\0\0\x7f\x02\0\0\x13\
\x9c\0\0\xb0\0\0\0\x3b\x01\0\0\x7f\x02\0\0\x09\x9c\0\0\xb8\0\0\0\x3b\x01\0\0\
\x9e\x02\0\0\x14\xa0\0\0\xc0\0\0\0\x3b\x01\0\0\xcc\x02\0\0\x0d\xa4\0\0\xc8\0\0\
\0\x3b\x01\0\0\xa6\x03\0\0\x05\xe4\x01\0\x10\0\0\0\x16\x01\0\0\x02\0\0\0\0\x01\
\0\0\x19\0\0\0\x0c\x03\0\0\0\0\0\0\x10\x01\0\0\x19\0\0\0\x43\x03\0\0\0\0\0\0\
\xf7\x03\0\0\x01\0\0\0\x08\x01\0\0\x24\0\0\0\x26\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x9f\x01\0\0\0\0\x03\0\x58\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6e\x01\0\0\0\
\0\x03\0\x60\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8a\x01\0\0\0\0\x03\0\x98\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x7c\x01\0\0\0\0\x03\0\xf0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x91\x01\0\0\0\0\x05\0\x80\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x98\x01\0\0\0\0\x07\0\x48\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x75\x01\0\0\0\0\
\x07\0\xc8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x83\x01\0\0\0\0\x07\0\x88\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x68\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x70\x01\0\0\0\0\0\0\
\x3b\x01\0\0\x11\0\x09\0\x04\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x32\x01\0\0\x11\0\
\x09\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x29\x01\0\0\x11\0\x09\0\x08\0\0\0\0\0\
\0\0\x04\0\0\0\0\0\0\0\x14\0\0\0\x11\0\x0a\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\
\x1a\0\0\0\x12\0\x05\0\0\0\0\0\0\0\0\0\x90\x01\0\0\0\0\0\0\xb8\0\0\0\x11\0\x0a\
\0\x20\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xc5\0\0\0\x12\0\x07\0\0\0\0\0\0\0\0\0\
\xd8\0\0\0\0\0\0\0\x66\x01\0\0\x11\0\x0b\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\
\x18\0\0\0\0\0\0\0\x01\0\0\0\x0d\0\0\0\x58\0\0\0\0\0\0\0\x01\0\0\0\x0e\0\0\0\
\x98\0\0\0\0\0\0\0\x01\0\0\0\x0f\0\0\0\x40\x01\0\0\0\0\0\0\x01\0\0\0\x10\0\0\0\
\x28\0\0\0\0\0\0\0\x01\0\0\0\x10\0\0\0\x50\0\0\0\0\0\0\0\x01\0\0\0\x12\0\0\0\
\x08\0\0\0\0\0\0\0\x01\0\0\0\x0d\0\0\0\x48\0\0\0\0\0\0\0\x01\0\0\0\x0e\0\0\0\
\x88\0\0\0\0\0\0\0\x01\0\0\0\x0f\0\0\0\x38\x04\0\0\0\0\0\0\x04\0\0\0\x10\0\0\0\
\x44\x04\0\0\0\0\0\0\x04\0\0\0\x12\0\0\0\x5c\x04\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\
\0\x68\x04\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x74\x04\0\0\0\0\0\0\x03\0\0\0\x0f\0\
\0\0\x8c\x04\0\0\0\0\0\0\x04\0\0\0\x14\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\
\0\0\x3c\0\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x4c\0\0\0\0\0\0\0\x04\0\0\0\x08\0\0\
\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x80\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xa0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xc0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xd0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xe0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xf0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\0\
\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x10\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x20\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x30\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\
\0\x40\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x50\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\
\0\0\x60\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x70\x01\0\0\0\0\0\0\x04\0\0\0\x01\
\0\0\0\x80\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x90\x01\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\xa0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xb0\x01\0\0\0\0\0\0\x04\0\0\
\0\x01\0\0\0\xc0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xd0\x01\0\0\0\0\0\0\x04\0\
\0\0\x01\0\0\0\xe0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xf0\x01\0\0\0\0\0\0\x04\
\0\0\0\x01\0\0\0\0\x02\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x18\x02\0\0\0\0\0\0\x04\
\0\0\0\x06\0\0\0\x28\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x38\x02\0\0\0\0\0\0\
\x04\0\0\0\x06\0\0\0\x48\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x58\x02\0\0\0\0\0\
\0\x04\0\0\0\x06\0\0\0\x68\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x78\x02\0\0\0\0\
\0\0\x04\0\0\0\x06\0\0\0\x88\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x98\x02\0\0\0\
\0\0\0\x04\0\0\0\x06\0\0\0\xa8\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\xb8\x02\0\0\
\0\0\0\0\x04\0\0\0\x06\0\0\0\xc8\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\xd8\x02\0\
\0\0\0\0\0\x04\0\0\0\x06\0\0\0\xe8\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\xf8\x02\
\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x08\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x18\
\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x28\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\
\x38\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x48\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\
\0\x58\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x68\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\
\0\0\x78\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x88\x03\0\0\0\0\0\0\x04\0\0\0\x06\
\0\0\0\x98\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\xa8\x03\0\0\0\0\0\0\x04\0\0\0\
\x06\0\0\0\xb8\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\xc8\x03\0\0\0\0\0\0\x04\0\0\
\0\x06\0\0\0\xd8\x03\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\xe8\x03\0\0\0\0\0\0\x04\0\
\0\0\x06\0\0\0\0\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\x10\x04\0\0\0\0\0\0\x04\0\
\0\0\x08\0\0\0\x20\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\x30\x04\0\0\0\0\0\0\x04\
\0\0\0\x08\0\0\0\x40\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\x50\x04\0\0\0\0\0\0\
\x04\0\0\0\x08\0\0\0\x60\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\x70\x04\0\0\0\0\0\
\0\x04\0\0\0\x08\0\0\0\x80\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\x90\x04\0\0\0\0\
\0\0\x04\0\0\0\x08\0\0\0\xa0\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\xb0\x04\0\0\0\
\0\0\0\x04\0\0\0\x08\0\0\0\xc0\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\xd0\x04\0\0\
\0\0\0\0\x04\0\0\0\x08\0\0\0\xe0\x04\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\xf0\x04\0\
\0\0\0\0\0\x04\0\0\0\x08\0\0\0\x0c\x05\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x1c\x05\
\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x34\x05\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x16\
\x1b\x1d\x18\x17\x19\x1a\x1c\x1e\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\
\x42\x54\x46\x2e\x65\x78\x74\0\x73\x74\x61\x72\x74\0\x74\x72\x61\x63\x65\x70\
\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\
\x5f\x65\x78\x69\x74\x5f\x6f\x70\x65\x6e\x61\x74\0\x2e\x72\x65\x6c\x74\x72\x61\
\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\
\x73\x5f\x65\x78\x69\x74\x5f\x6f\x70\x65\x6e\x61\x74\0\x74\x72\x61\x63\x65\x70\
\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\
\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\x74\0\x2e\x72\x65\x6c\x74\x72\
\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\
\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\x74\0\x65\x76\x65\x6e\
\x74\x73\0\x2e\x6d\x61\x70\x73\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\
\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\
\x72\x5f\x63\x68\x64\x69\x72\0\x2e\x72\x65\x6c\x74\x72\x61\x63\x65\x70\x6f\x69\
\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\
\x65\x72\x5f\x63\x68\x64\x69\x72\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\
\x69\x67\0\x6c\x69\x63\x65\x6e\x73\x65\0\x74\x61\x72\x67\x5f\x75\x69\x64\0\x74\
\x61\x72\x67\x5f\x70\x69\x64\0\x74\x61\x72\x67\x5f\x74\x67\x69\x64\0\x2e\x73\
\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\
\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x4c\x42\
\x42\x30\x5f\x37\0\x4c\x42\x42\x32\x5f\x36\0\x4c\x42\x42\x30\x5f\x36\0\x4c\x42\
\x42\x32\x5f\x34\0\x4c\x42\x42\x30\x5f\x34\0\x4c\x42\x42\x31\x5f\x33\0\x4c\x42\
\x42\x32\x5f\x32\0\x4c\x42\x42\x30\x5f\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x45\x01\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc1\
\x1d\0\0\0\0\0\0\xa6\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x93\0\0\0\
\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x70\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8f\0\0\0\x09\0\0\0\x40\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x17\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x11\0\0\0\
\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x44\0\0\0\x01\0\0\0\x06\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xb0\x01\0\0\0\0\0\0\x90\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x18\x18\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x11\0\0\0\x05\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\xef\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x40\x03\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xeb\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x18\0\0\
\0\0\0\0\x30\0\0\0\0\0\0\0\x11\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x55\x01\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x04\0\0\0\0\0\
\0\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbf\0\0\
\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x28\x04\0\0\0\0\0\0\x30\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x21\x01\0\0\x01\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x04\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x01\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x68\x04\0\0\0\0\0\0\x32\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5d\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x68\x18\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x11\0\0\0\x0c\0\0\0\x08\0\0\
\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x9c\x10\0\0\0\0\0\0\x44\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc8\x18\0\
\0\0\0\0\0\xf0\x04\0\0\0\0\0\0\x11\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\
\0\0\0\0\x13\x01\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xb8\x1d\
\0\0\0\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x4d\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\x15\0\0\0\0\0\0\
\xf8\x01\0\0\0\0\0\0\x01\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct opentracer_bpf *opentracer_bpf::open(const struct bpf_object_open_opts *opts) { return opentracer_bpf__open_opts(opts); }
struct opentracer_bpf *opentracer_bpf::open_and_load() { return opentracer_bpf__open_and_load(); }
int opentracer_bpf::load(struct opentracer_bpf *skel) { return opentracer_bpf__load(skel); }
int opentracer_bpf::attach(struct opentracer_bpf *skel) { return opentracer_bpf__attach(skel); }
void opentracer_bpf::detach(struct opentracer_bpf *skel) { opentracer_bpf__detach(skel); }
void opentracer_bpf::destroy(struct opentracer_bpf *skel) { opentracer_bpf__destroy(skel); }
const void *opentracer_bpf::elf_bytes(size_t *sz) { return opentracer_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
opentracer_bpf__assert(struct opentracer_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->rodata->targ_pid) == 4, "unexpected size of 'targ_pid'");
	_Static_assert(sizeof(s->rodata->targ_tgid) == 4, "unexpected size of 'targ_tgid'");
	_Static_assert(sizeof(s->rodata->targ_uid) == 4, "unexpected size of 'targ_uid'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __OPENTRACER_BPF_SKEL_H__ */
