#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// C++ std
#include <algorithm>
#include <string>
#include <vector>
#include <utility>

#include "../common/tracer_events.h"


static char timestamp_file_name[] = "last_processed_timestamp.txt";

int get_last_processed_timestamp(time_t &ts)
{
    FILE *fin = fopen(timestamp_file_name, "rt");
    if (fin == NULL) {
        fprintf(stderr, "Error opening file %s", timestamp_file_name);
        return -1;
    }

    fscanf(fin, "%ld", &ts);
    fclose(fin);
    return 0;
}

int save_last_processed_timestamp(time_t ts)
{
    FILE *fout = fopen(timestamp_file_name, "wt");
    if (fout == NULL) {
        fprintf(stderr, "Error opening file %s", timestamp_file_name);
        return -1;
    }

    fprintf(fout, "%ld", ts);
    fclose(fout);
    return 0;
}

int get_list_of_files(
    time_t last_timestamp,
    std::vector<std::pair<time_t, std::string>> &files)
{
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;

    // Open events directory
    dir = opendir(EVENTS_SAVE_PATH);
    if (dir == NULL) {
        fprintf(stderr, "Error opening directory %s", EVENTS_SAVE_PATH);
        return -1;
    }

    // Iterate over all files in directory
    while ((entry = readdir(dir)) != NULL) {
        char file_path[NAME_MAX];
        snprintf(file_path, NAME_MAX, "%s/%s", EVENTS_SAVE_PATH, entry->d_name);

        // Check if entry is a regular file
        if (stat(file_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
            time_t last_modified = file_stat.st_mtime;

            if (last_modified > last_timestamp) {
                files.push_back(std::make_pair(last_modified, std::string(file_path)));
            } else {
                printf("File was last modified before the last run of processor."
                       " Skipping  %s\n", file_path);
            }
        }
    }

    closedir(dir);

    // Sort files ascending on last modified timestamp
    std::sort(files.begin(), files.end());

    return 0;
}


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
    char type[10];

    switch (e->event_type) {
        case EVENT_TYPE_OPEN:
            strcpy(type, "OPEN");
            // return handle_event_open(e);
            break;
        case EVENT_TYPE_CHDIR:
            strcpy(type, "CHDIR");
            // return handle_event_chdir(e);
            break;
        case EVENT_TYPE_FCHDIR:
            strcpy(type, "FCHDIR");
            // return handle_event_fchdir(e);
            break;
        case EVENT_TYPE_EXECVE:
            strcpy(type, "EXECVE");
            // return handle_event_execve(e);
            break;
        default:
            strcpy(type, "UNKNOWN");
    }

    struct tm *tm = localtime(&e->ts);
    char ts[20];
    strftime(ts, sizeof(ts), "%Y-%m-%d-%H:%M:%S", tm);

    printf("\t%-22s %-7s %-7d %-5d %-7d %-16s %s\n",
            ts, type, e->dfd, e->ret, e->pid, e->comm, e->fname);

    return 0;
}


int process_file(const std::string &file_path)
{
    struct memory_mapped_file mmf;
    if (open_memory_mapped_file(file_path, mmf) < 0) {
        fprintf(stderr, "Failed to open memory-mapped file\n");
        return -1;
    }
    printf("Memory-mapped file opened, events count: %ld\n",
           *(mmf.write_offset)/sizeof(struct event));

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


int main()
{
    time_t current_timestamp = time(NULL);
    int err;

    // Get last processed timestamp
    time_t last_timestamp;
    if (get_last_processed_timestamp(last_timestamp) < 0) {
        return -1;
    }

    std::vector<std::pair<time_t, std::string>> files;
    err = get_list_of_files(last_timestamp, files);

    for (const auto &file : files) {
        printf("Processing file %s\n", file.second.c_str());
        err = process_file(file.second);
    }

    if (!err) {
        // Save timestamp from when script started as last processed timestamp
        if (save_last_processed_timestamp(current_timestamp) < 0) {
            fprintf(stderr, "Error saving last processed timestamp %ld",
                    current_timestamp);
            return -1;
        }
    }

    return err;
}
