# Opentracer - eBPF program for tracing open() syscalls

This repository contains the source code for **opentracer**, an eBPF-based program for tracing open() system calls.

## Components
- eBPF programs:
    - these are loaded in the kernel and attached to syscall tracepoints such that on entering and leaving the correspodent syscall, the implemented function is triggered;
    - data from the syscalls open() (and openat()), execve(), chdir() and fchdir() is pushed into 1 ring buffer;
- eBPF handler and ring buffer consumer:
    - this component runs in the userspace, handles the lifetime of the eBPF objects and polls data from the ringbuffer;
    - for each event polled, it saves it into a memory-mapped file.
- post-processor:
    - can be ran anytime and it checks if there are new events saved;
    - for new data, it processes it to extract the list of files opened and the strings from the binary file executed by the job, and saves it;
    - for storage, it can be configured to publish to a file or save to an SQLite database.

We offer 2 simple functions for starting the functionalities:
```
run_opentracer(); // starts the first 2 components (they will continue running until the userspace process is given a termination signal)

run_processor(); // runs the post-processing component
```

Through these 2 function, we can integrate the tool into a cluster. Ideally, you'd want the following steps:
- Job is submitted: `sbatch run.sh`
- In job prolog (resources are setup, but computation hasn't started): `run_opentracer()`
- Job is executing, the first 2 components are running alongside it and recording the syscall events.
- In job epilog (resources are still allocated, but the computation has finished): `kill -9 $OPENTRACER_PID; run_processor()`
- Post-processor finishes, data is saved (file/sqlite). Nodes become available for other jobs.

We provide the implementation for integrating the tool on a cluster running the [Slurm Workload Manager](https://slurm.schedmd.com/documentation.html) through the [SPANK plugin](https://slurm.schedmd.com/spank.html).


## Build
```
cd src/spank
make
```

### Dependencies:
- [bpftool](https://man.archlinux.org/man/bpftool.8.en)
- [libbpf](https://github.com/libbpf/libbpf)
- [libmagic](https://man7.org/linux/man-pages/man3/libmagic.3.html)
- [libsqlite3](https://cppget.org/libsqlite3)

```
sudo apt install bpftool
sudo apt install libmagic-dev sqlite-devel
git clone git@github.com:libbpf/libbpf.git
cd libbpf/src
make
make install
```



## Install on Slurm cluster
- Build shared library `libopentracer.so`.
- Setup SPANK Plugin.
- Copy shared library to `/etc/slurm/spanks.d/` on all nodes.
- Add line `required /etc/slurm/spanks.d/libopentracer.so` to the file `/etc/slurm/plugstack.conf.d/spank.conf` (or wherever your SPANK config file is).
- Restart `slurmd` and `slurmctld`.

This is my script which I run from the management node whenever I re-compile the shared library (nodes are login, cns1, cns2):
```
#!/bin/bash
sudo scontrol update NodeName=cns[1,2] State=RESUME
sudo cp ~/opentracer/src/spank/libopentracer.so /etc/slurm/spanks.d/libopentracer.so
pdsh -w login,cns1,cns2 sudo cp ~/opentracer/src/spank/libopentracer.so /etc/slurm/spanks.d/libopentracer.so
sudo systemctl restart slurmctld
pdsh -w cns1,cns2 sudo systemctl restart slurmd
```


## File Structure
- src/common: functions used between all three components and struct declarations;
    - mmf.h/.c: definitions and functions for memory-mapped files;
    - config.h/.c: definition for the config and functions to read and write the config file;
    - tracer_events.h: definition for the `event_t` through which we record kernel events in the ring buffer;
- src/ebpf: source code for eBPF program and userspace handler
    - opentracer.bpf.c: source code for eBPF programs, these are loaded in the kernel and attached to the specified tracepoint
    - opentracer.c: source code for user space application for managing eBPF and transfering data from ring buffer to memory-mapped file;
    - opentracer.h: declaration for `run_opentracer()`;
    - opentracer.skel.h: auto-generated from the eBPF object, provides helper functions;
    - Makefile: build the eBPF object, generates the necessary files (e.g. vmlinux.h);
- src/processor: source code for the post-processor component;
- src/spank: Slurm-based implementation for cluster integration;
- src/storage: storage options for the post-processor:
    - simple_storage.h/.cxx: prints to file;
    - database.h/.cxx: saves to SQLite database.


_Note:_ Some systems have a slightly different format for system calls or have different system calls. For example, not all systems have the open() syscall, some only have openat(). You should adjust the functions in src/ebpf/opentracer.bpf.c. Also, the format of the context received by the `tracepoint__syscalls__sys_enter[/exit]_SYSCALL` functions can be different. You should inspect them and adjust accordingly:
```
# sudo cat /sys/kernel/tracing/events/syscalls/sys_enter[/exit]_SYSCALL/format
```

## Project Purpose
This project was developed as part of my Master Thesis at ETH Zurich on the topic of "Uninvasive Collection of Supercomputer Usage Data".

## Contributions
The development was mostly driven by having a working prototype, and not on delivering the best-quality code, but I am open to improve this code base. You can contact me regarding clarifications, and are free to add issues and comments, or to create pull requests.
