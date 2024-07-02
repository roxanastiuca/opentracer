#include "mmf.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>

int open_memory_mapped_file(const config_t *config, const char *file_path, memory_mapped_file_t *mmf)
{
    int fd = open(file_path, O_RDWR);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open file %s\n", file_path);
        return -1;
    }

    void *addr = mmap(NULL, config->events_file_size_limit, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        syslog(LOG_ERR, "Failed to mmap file %s\n", file_path);
        return -1;
    }

    close(fd);

    mmf->addr = addr;
    mmf->read_offset = (size_t *)addr;
    mmf->write_offset = (size_t *)((char *)addr + sizeof(size_t));
    mmf->data = (char *)addr + 2 * sizeof(size_t);

    // *(mmf->read_offset) = 0; // TODO: remove this line

    return 0;
}


int create_memory_mapped_file(const config_t *config, char *file_path, memory_mapped_file_t *mmf)
{
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%y-%m-%d-%H-%M-%S", tm);

    if (file_path == NULL) {
        syslog(LOG_ERR, "File path is NULL in create_memory_mapped_file\n");
        return -1;
    }
    snprintf(file_path, MAX_FILE_NAME, "%s/events_%s", config->events_save_path, ts);

    int fd = open(file_path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open file %s\n", file_path);
        return -1;
    }

    if (ftruncate(fd, config->events_file_size_limit) < 0) {
        syslog(LOG_ERR, "Failed to set memory-mapped file size %s\n", file_path);
        return -1;
    }

    void *addr = mmap(NULL, config->events_file_size_limit, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        syslog(LOG_ERR, "Failed to mmap file %s\n", file_path);
        return -1;
    }

    close(fd);

    mmf->addr = addr;
    mmf->read_offset = (size_t *)addr;
    mmf->write_offset = (size_t *)((char *)addr + sizeof(size_t));
    mmf->data = (char *)addr + 2 * sizeof(size_t);

    return 0;
}


int close_memory_mapped_file(const config_t *config, const char *file_path, memory_mapped_file_t *mmf)
{
    size_t size = *(mmf->write_offset) + 2 * sizeof(size_t);
    munmap(mmf->addr, config->events_file_size_limit);

    mmf->addr = NULL;
    mmf->read_offset = NULL;
    mmf->write_offset = NULL;
    mmf->data = NULL;

    int fd = open(file_path, O_RDWR);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open file %s\n", file_path);
        return -1;
    }

    if (ftruncate(fd, size) < 0) {
        syslog(LOG_ERR, "Failed to reset file size %s\n", file_path);
        return -1;
    }

    close(fd);

    return 0;
}