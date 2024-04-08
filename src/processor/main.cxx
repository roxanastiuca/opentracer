#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

#include "../common/tracer_events.h"


int open_memory_mapped_file(std::string file_name, struct memory_mapped_file &mmf)
{
    int fd = open(file_name.c_str(), O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file %s\n", file_name.c_str());
        return -1;
    }

    void *addr = mmap(NULL, EVENTS_FILE_SIZE_LIMIT, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap file %s\n", file_name.c_str());
        return -1;
    }

    close(fd);

    mmf.addr = addr;
    mmf.read_offset = (size_t *)addr;
    mmf.write_offset = (size_t *)((char *)addr + sizeof(size_t));
    mmf.data = (char *)addr + 2 * sizeof(size_t);

    return 0;
}


int handle_event(struct event *e)
{
    struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    switch (e->event_type) {
        case EVENT_TYPE_OPEN:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "OPEN", e->dfd, e->ret, e->pid, e->comm, e->fname);
            // return handle_event_open(e);
            break;
        case EVENT_TYPE_CHDIR:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "CHDIR", e->dfd, e->ret, e->pid, e->comm, e->fname);
            // return handle_event_chdir(e);
            break;
        case EVENT_TYPE_FCHDIR:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "FCHDIR", e->dfd, e->ret, e->pid, e->comm, e->fname);
            // return handle_event_fchdir(e);
            break;
        case EVENT_TYPE_EXECVE:
            printf("%-8s %-7s %-5d %-5d %-7d %-16s %s\n", ts, "EXEC", e->dfd, e->ret, e->pid, e->comm, e->fname);
            // return handle_event_execve(e);
            break;
        default:
            printf("Unknown event type: %d\n", e->event_type);
    }

    return 0;
}


int main()
{
    std::string file_name = "../../events_save_dir/events_0";

    struct memory_mapped_file mmf;
    if (open_memory_mapped_file(file_name, mmf) < 0) {
        fprintf(stderr, "Failed to open memory-mapped file\n");
        return -1;
    }
    printf("Memory-mapped file opened, size: %ld\n", *(mmf.write_offset));

    // Read events from the memory-mapped file
    struct event *e;

    while (*(mmf.read_offset) + sizeof(struct event) < *(mmf.write_offset)) {
        e = (struct event *)((char *)mmf.data + *(mmf.read_offset));
        *(mmf.read_offset) += sizeof(struct event);
        handle_event(e);
    }

    munmap(mmf.addr, EVENTS_FILE_SIZE_LIMIT);
    return 0;
}