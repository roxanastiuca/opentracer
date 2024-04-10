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

#include "../common/config.h"
#include "../common/tracer_events.h"

typedef struct {
    std::unordered_map<int, std::string> pid_to_cwd;
    std::unordered_map<int, std::vector<std::string>> pid_to_fds_paths;
} processor_t;


int get_list_of_files(
    config_t &config,
    std::vector<std::pair<time_t, std::string>> &files)
{
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;

    // Open events directory
    dir = opendir(config.events_save_path);
    if (dir == NULL) {
        fprintf(stderr, "Error opening directory %s", config.events_save_path);
        return -1;
    }

    // Iterate over all files in directory
    while ((entry = readdir(dir)) != NULL) {
        char file_path[NAME_MAX];
        snprintf(file_path, NAME_MAX, "%s/%s", config.events_save_path, entry->d_name);

        // Check if entry is a regular file
        if (stat(file_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
            time_t last_modified = file_stat.st_mtime;

            if (last_modified > config.last_processed_timestamp) {
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


int open_memory_mapped_file(
    const config_t &config, std::string file_name, memory_mapped_file_t &mmf)
{
    int fd = open(file_name.c_str(), O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file %s\n", file_name.c_str());
        return -1;
    }

    void *addr = mmap(NULL, config.events_file_size_limit, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
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

int handle_event_open(processor_t &p, const event_t *e)
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


int handle_event_chdir(processor_t &p, const event_t *e)
{
    if (e->ret < 0) {
        return 0;
    }    

    // TODO: handle relative paths

    p.pid_to_cwd[e->pid] = std::string(e->fname);
    printf("CHDIR: %d -> %s\n", e->pid, e->fname);

    return 0;
}

int handle_event_fchdir(processor_t &p, const event_t *e)
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

int handle_event_execve(processor_t &p, const event_t *e)
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

int handle_event(processor_t &processor, event_t *e)
{
    char type[10];
    int err = 0;

    switch (e->event_type) {
        case EVENT_TYPE_OPEN:
            strcpy(type, "OPEN");
            err = handle_event_open(processor, e);
            break;
        case EVENT_TYPE_CHDIR:
            strcpy(type, "CHDIR");
            err = handle_event_chdir(processor, e);
            break;
        case EVENT_TYPE_FCHDIR:
            strcpy(type, "FCHDIR");
            err = handle_event_fchdir(processor, e);
            break;
        case EVENT_TYPE_EXECVE:
            strcpy(type, "EXECVE");
            err = handle_event_execve(processor, e);
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
int process_file(
    const config_t &config, processor_t &processor, const std::string &file_path)
{
    memory_mapped_file_t mmf;
    if (open_memory_mapped_file(config, file_path, mmf) < 0) {
        fprintf(stderr, "Failed to open memory-mapped file\n");
        return -1;
    }
    printf("Memory-mapped file opened, events count: %ld\n",
           *(mmf.write_offset)/sizeof(event_t));

    // Read events from the memory-mapped file
    event_t *e;

    while (*(mmf.read_offset) + sizeof(event_t) < *(mmf.write_offset)) {
        e = (event_t *)((char *)mmf.data + *(mmf.read_offset));
        *(mmf.read_offset) += sizeof(event_t);
        handle_event(processor, e);
    }

    munmap(mmf.addr, config.events_file_size_limit);

    return 0;
}


int main(int argc, char **argv)
{
    time_t current_timestamp = time(NULL);
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    config_t config;
    if (load_config(&config, argv[1]) < 0) {
        fprintf(stderr, "Failed to load config file %s\n", argv[1]);
        return 1;
    }

    std::vector<std::pair<time_t, std::string>> files;
    err = get_list_of_files(config, files);

    // Main structure for rolling back events:
    processor_t processor;

    for (const auto &file : files) {
        printf("Processing file %s\n", file.second.c_str());
        err = process_file(config, processor, file.second);
    }

    if (!err) {
        // Update config with new value for last processed timestamp
        config.last_processed_timestamp = current_timestamp;
        if (save_config(&config, argv[1]) < 0) {
            fprintf(stderr,
                    "Failed to save config file %s, last processed timestamp: %ld\n",
                    argv[1], current_timestamp);
            return -1;
        }
    }

    return err;
}
