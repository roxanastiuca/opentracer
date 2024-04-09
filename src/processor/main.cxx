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
#include <unordered_map>
#include <utility>
#include <vector>

#include "../common/tracer_events.h"

struct processor {
    std::unordered_map<int, std::string> pid_to_cwd;
    std::unordered_map<int, std::vector<std::string>> pid_to_fds_paths;
};


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

////////////// EVENT HANDLING ///////////////
// Main logic to handle kernel events

int handle_event_open(const struct event *e, struct processor &p)
{
    if (e->ret < 0) { // TODO: record failed opens too
        return 0;
    }

    std::string abs_path;
    std::string slash_fname = "/" + std::string(e->fname);
    if (slash_fname == "/.") {
        // Don't stack /. on the path
        slash_fname = "";
    }

    if (e->fname[0] == '/') {
        // Absolute path
        abs_path = std::string(e->fname);
    } else if (e->dfd == AT_FDCWD) {
        // Relative path to CWD
        if (p.pid_to_cwd.find(e->pid) != p.pid_to_cwd.end()) {
            abs_path = p.pid_to_cwd[e->pid] + slash_fname;
        } else {
            abs_path = "?" + slash_fname;
        }
    } else {
        // Relative path to dfd
        if (p.pid_to_fds_paths.find(e->pid) != p.pid_to_fds_paths.end()) {
            auto &fds_to_paths = p.pid_to_fds_paths[e->pid];
            if (e->dfd < (int)fds_to_paths.size() && fds_to_paths[e->dfd] != "") {
                abs_path = fds_to_paths[e->dfd] + slash_fname;
            } else {
                abs_path = "?" + slash_fname;
            }
        } else {
            abs_path = "?" + slash_fname;
        }
    }

    if (p.pid_to_fds_paths.find(e->pid) == p.pid_to_fds_paths.end()) {
        p.pid_to_fds_paths[e->pid] = std::vector<std::string>(100);
    }
    p.pid_to_fds_paths[e->pid].insert(p.pid_to_fds_paths[e->pid].begin() + e->ret, abs_path);

    printf("OPEN: %d -> %d -> %s\n", e->pid, e->ret, abs_path.c_str());

    return 0;
}


int handle_event_chdir(const struct event *e, struct processor &p)
{
    if (e->ret < 0) {
        return 0;
    }    

    // TODO: handle relative paths

    p.pid_to_cwd[e->pid] = std::string(e->fname);
    printf("CHDIR: %d -> %s\n", e->pid, e->fname);

    return 0;
}

int handle_event_fchdir(const struct event *e, struct processor &p)
{
    if (e->ret < 0) {
        return 0;
    }

    // If not found, set to "?"
    p.pid_to_cwd[e->pid] = "?";

    if (p.pid_to_fds_paths.find(e->pid) != p.pid_to_fds_paths.end()) {
        auto &fds_to_paths = p.pid_to_fds_paths[e->pid];
        if (e->dfd < (int)fds_to_paths.size() && fds_to_paths[e->dfd] != "") {
            p.pid_to_cwd[e->pid] = fds_to_paths[e->dfd];
        }
    }

    printf("FCHDIR: %d -> %s\n", e->pid, p.pid_to_cwd[e->pid].c_str());

    return 0;
}

int handle_event_execve(const struct event *e, struct processor &p)
{
    // e->pid = PID of the new process
    // e->ret = PID of the parent process (or <0 if error)
    if (e->ret < 0) {
        return 0;
    }

    if (p.pid_to_cwd.find(e->ret) != p.pid_to_cwd.end()) {
        p.pid_to_cwd[e->pid] = p.pid_to_cwd[e->ret];
    } else {
        p.pid_to_cwd[e->pid] = "?";
    }
    
    printf("EXECVE: %d -> %s\n", e->pid, p.pid_to_cwd[e->pid].c_str());

    return 0;
}

int handle_event(struct event *e, struct processor &processor)
{
    char type[10];
    int err = 0;

    switch (e->event_type) {
        case EVENT_TYPE_OPEN:
            strcpy(type, "OPEN");
            err = handle_event_open(e, processor);
            break;
        case EVENT_TYPE_CHDIR:
            strcpy(type, "CHDIR");
            err = handle_event_chdir(e, processor);
            break;
        case EVENT_TYPE_FCHDIR:
            strcpy(type, "FCHDIR");
            err = handle_event_fchdir(e, processor);
            break;
        case EVENT_TYPE_EXECVE:
            strcpy(type, "EXECVE");
            err = handle_event_execve(e, processor);
            break;
        default:
            strcpy(type, "UNKNOWN");
    }

    struct tm *tm = localtime(&e->ts);
    char ts[20];
    strftime(ts, sizeof(ts), "%Y-%m-%d-%H:%M:%S", tm);

    printf("\t%-22s %-7s %-7d %-5d %-7d %-16s %s\n",
            ts, type, e->dfd, e->ret, e->pid, e->comm, e->fname);

    return err;
}


// Read kernel events from memory-mapped file:
int process_file(const std::string &file_path, struct processor &processor)
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
        handle_event(e, processor);
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

    // Main structure for rolling back events:
    struct processor processor;

    for (const auto &file : files) {
        printf("Processing file %s\n", file.second.c_str());
        err = process_file(file.second, processor);
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
