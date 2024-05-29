#include "processor.h"

#include <dirent.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>

#include "../common/mmf.h"

#include "../storage/database.h"
#include "../storage/simple_storage.h"


int get_list_of_files(
    config_t &config,
    const time_t last_processed_timestamp,
    std::vector<std::pair<time_t, std::string>> &files)
{
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;

    // Open events directory
    dir = opendir(config.events_save_path);
    if (dir == NULL) {
        syslog(LOG_ERR, "get_list_of_files: Error opening directory %s", config.events_save_path);
        return -1;
    }

    // Iterate over all files in directory
    while ((entry = readdir(dir)) != NULL) {
        char file_path[MAX_FILE_NAME];
        snprintf(file_path, MAX_FILE_NAME, "%s/%s", config.events_save_path, entry->d_name);

        // Check if entry is a regular file
        if (stat(file_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
            time_t last_modified = file_stat.st_mtime;

            if (last_modified > last_processed_timestamp) {
                files.push_back(std::make_pair(last_modified, std::string(file_path)));
                // printf("File %s, last modified: %ld > %ld\n",
                //         file_path, last_modified, config.last_processed_timestamp);
            } else {
                // printf("File was last modified before the last run of processor."
                //        " Skipping  %s\n", file_path);
            }
        }
    }

    closedir(dir);

    // Sort files ascending on last modified timestamp
    std::sort(files.begin(), files.end());

    return 0;
}


int run_processor(uid_t uid, gid_t gid, uint32_t jobid)
{
    time_t current_timestamp = time(NULL);
    time_t last_processed_timestamp;
    int err;

    config_t config;
    if (load_config(&config) != 0) {
        syslog(LOG_ERR, "run_processor: Failed to load config");
        return 1;
    }

    if (load_last_processed_timestamp(&last_processed_timestamp) != 0) {
        syslog(LOG_WARNING, "run_processor: Failed to load last processed timestamp, using 0");
        last_processed_timestamp = 0;
    }

    std::vector<std::pair<time_t, std::string>> files;
    err = get_list_of_files(config, last_processed_timestamp, files);
    if (err < 0) {
        syslog(LOG_ERR, "run_processor: Failed to get list of files");
        return -1;
    }

    Database storage(uid, gid, jobid);
    storage.save_job();
    storage.start_transaction();
    Processor processor(config, storage);

    for (const auto &file : files) {
        syslog(LOG_INFO, "run_processor: Processing file %s", file.second.c_str());
        err = processor.process_file(file.second);
    }
    
    storage.end_transaction();

    if (!err) {
        // Update config with new value for last processed timestamp
        last_processed_timestamp = current_timestamp;
        if (save_last_processed_timestamp(&last_processed_timestamp) < 0) {
            syslog(LOG_ERR,
                   "run_processor: Failed to save config file %s, last processed timestamp: %ld",
                   CONFIG_FILE_PATH, current_timestamp);
            return -1;
        }
    }

    return err;
}

template <typename Storage>
Processor<Storage>::Processor(const config_t &config, Storage &storage)
    : config(config), storage(storage)
{
    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL) {
        syslog(LOG_ERR, "Processor: Failed to initialize libmagic");
        exit(1);
    }

    if (magic_load(magic_cookie, NULL) != 0) {
        syslog(LOG_ERR, "Processor: Failed to load magic database");
        magic_close(magic_cookie);
        exit(1);
    }
}

template <typename Storage>
Processor<Storage>::~Processor()
{
    if (magic_cookie != NULL) {
        magic_close(magic_cookie);
    }
}

template <typename Storage>
int Processor<Storage>::process_file(const std::string &file_path)
{
    memory_mapped_file_t mmf;
    if (open_memory_mapped_file(&config, file_path.c_str(), &mmf) < 0) {
        syslog(LOG_ERR, "process_file: Failed to open memory-mapped file %s", file_path.c_str());
        return -1;
    }

    // *(mmf.read_offset) = 0; // TODO: remove

    // Read events from the memory-mapped file
    event_t *e;

    while (*(mmf.read_offset) + sizeof(event_t) < *(mmf.write_offset)) {
        e = (event_t *)((char *)mmf.data + *(mmf.read_offset));
        *(mmf.read_offset) += sizeof(event_t);
        process_event(e);
    }

    munmap(mmf.addr, config.events_file_size_limit);

    return 0;
}

template <typename Storage>
int Processor<Storage>::process_event(const event_t *e)
{
    char type[10];
    int err = 0;

    switch (e->event_type) {
        case EVENT_TYPE_OPEN:
            strcpy(type, "OPEN");
            err = process_event_open(e);
            break;
        case EVENT_TYPE_CHDIR:
            strcpy(type, "CHDIR");
            err = process_event_chdir(e);
            break;
        case EVENT_TYPE_FCHDIR:
            strcpy(type, "FCHDIR");
            err = process_event_fchdir(e);
            break;
        case EVENT_TYPE_EXECVE:
            strcpy(type, "EXECVE");
            err = process_event_execve(e);
            break;
        default:
            strcpy(type, "UNKNOWN");
    }

    // struct tm *tm = localtime(&e->ts);
    // char ts[20];
    // strftime(ts, sizeof(ts), "%Y-%m-%d-%H:%M:%S", tm);

    // printf("\t%-22s %-7s %-7d %-5d %-7d %-16s %s\n",
            // ts, type, e->dfd, e->ret, e->pid, e->comm, e->fname);

    return err;
}

////////////// EVENT HANDLING ///////////////
// Main logic to handle kernel events

template <typename Storage>
int Processor<Storage>::process_event_open(const event_t *e)
{
    fs::path abs_path;

    if (e->fname[0] == '/') {
        // Absolute path
        abs_path = fs::path(e->fname);
    } else if (e->dfd == AT_FDCWD) {
        // Relative path to CWD
        if (pid_to_cwd.find(e->pid) != pid_to_cwd.end()) {
            abs_path = (pid_to_cwd[e->pid] / fs::path(e->fname)).lexically_normal();
        } else {
            abs_path = "UNK" / fs::path(e->fname);
        }
    } else {
        // Relative path to dfd
        if (pid_to_fds_paths.find(e->pid) != pid_to_fds_paths.end()) {
            auto &fds_to_paths = pid_to_fds_paths[e->pid];
            if (e->dfd < (int)fds_to_paths.size() && fds_to_paths[e->dfd] != "") {
                abs_path = (fds_to_paths[e->dfd] / fs::path(e->fname)).lexically_normal();
            } else {
                abs_path = "UNK" / fs::path(e->fname);
            }
        } else {
            abs_path = "UNK" / fs::path(e->fname);
        }
    }

    if (e->ret >= 0) {
        if (pid_to_fds_paths.find(e->pid) == pid_to_fds_paths.end()) {
            pid_to_fds_paths[e->pid] = std::vector<fs::path>(100);
        }

        if (e->ret >= (int)pid_to_fds_paths[e->pid].size()) {
            pid_to_fds_paths[e->pid].resize(e->ret + 1);
        }
        pid_to_fds_paths[e->pid][e->ret] = abs_path;
    }

    // syslog(LOG_INFO, "OPEN: %d -> %d -> %s", e->pid, e->ret, abs_path.c_str());
    save_event_open(e, abs_path);

    return 0;
}

template <typename Storage>
int Processor<Storage>::process_event_chdir(const event_t *e)
{
    if (e->ret < 0) {
        return 0;
    }    

    if (e->fname[0] == '/') {
        // Absolute path
        pid_to_cwd[e->pid] = fs::path(e->fname);
    } else {
        // Relative path
        if (pid_to_cwd.find(e->pid) != pid_to_cwd.end()) {
            pid_to_cwd[e->pid] = (pid_to_cwd[e->pid] / fs::path(e->fname)).lexically_normal();
        } else {
            pid_to_cwd[e->pid] = fs::path(e->fname);
        }
    }

    // syslog(LOG_DEBUG, "CHDIR: %d -> %s\n", e->pid, pid_to_cwd[e->pid].c_str());

    return 0;
}

template <typename Storage>
int Processor<Storage>::process_event_fchdir(const event_t *e)
{
    if (e->ret < 0) {
        return 0;
    }

    // If not found, set to "UNK"
    pid_to_cwd[e->pid] = "UNK";

    if (pid_to_fds_paths.find(e->pid) != pid_to_fds_paths.end()) {
        auto &fds_to_paths = pid_to_fds_paths[e->pid];
        if (e->dfd < (int)fds_to_paths.size() && fds_to_paths[e->dfd] != "") {
            pid_to_cwd[e->pid] = fds_to_paths[e->dfd];
        }
    }

    // syslog(LOG_DEBUG, "FCHDIR: %d -> %s\n", e->pid, pid_to_cwd[e->pid].c_str());

    return 0;
}

template <typename Storage>
int Processor<Storage>::process_event_execve(const event_t *e)
{
    // e->pid = PID of the new process
    // e->ret = PID of the parent process (or <0 if error)
    if (e->ret < 0) {
        return 0;
    }

    if (pid_to_cwd.find(e->ret) != pid_to_cwd.end()) {
        pid_to_cwd[e->pid] = pid_to_cwd[e->ret];
    } else {
        pid_to_cwd[e->pid] = "UNK";
    }
    
    // syslog(LOG_DEBUG, "EXECVE: %d -> %s\n", e->pid, pid_to_cwd[e->pid].c_str());

    return 0;
}

////////////// OPENED FILE HANDLING ///////////////
// Logic to save information about opened files: filtering, processing etc.

template <typename Storage>
int Processor<Storage>::save_event_open(const event_t *e, const fs::path &path)
{
    // Skip /proc and /sys
    if (path.string().rfind("/proc", 0) == 0 || path.string().rfind("/sys", 0) == 0) {
        return 0;
    }

    // Skip slurm processes & others
    if (strncmp(e->comm, "slurm", 5) == 0 || strncmp(e->comm, "sleep", 5) == 0) {
        return 0;
    }

    fs::path link_path;
    fs::file_type file_type = fs::status(path).type();
    const char *mime_type = magic_file(magic_cookie, path.c_str());

    if (file_type == fs::file_type::symlink
            || (mime_type != NULL && strcmp(mime_type, "inode/symlink") == 0)) {
        // Symbolic link
        link_path = fs::read_symlink(path);
        if (link_path.is_absolute()) {
            link_path = link_path.lexically_normal();
        } else {
            link_path = (path.parent_path() / link_path).lexically_normal();
        }

        file_type = fs::status(link_path).type();
        mime_type = magic_file(magic_cookie, link_path.c_str());
        if (!is_accepted_file(link_path, file_type, mime_type)) {
            return 0;
        }
    }

    bool is_accepted = is_accepted_file(path, file_type, mime_type);

    storage.save_event(e, is_accepted,
                       ((int)file_type > 0) ? mime_type : "?",
                       path.c_str(), link_path.c_str());

    return 0;
}

template <typename Storage>
bool Processor<Storage>::is_accepted_file(
    const fs::path &path, const fs::file_type &file_type, const char *mime_type)
{
    // Accept unknown file types and not found
    if (file_type == fs::file_type::not_found || file_type == fs::file_type::unknown) {
        return true;
    }

    // Exclude anything other than regular files or symbolic links
    if (file_type != fs::file_type::regular && file_type != fs::file_type::symlink) {
        return false;
    }

    // Accept if unknown mime type or none set in config
    if (mime_type == NULL) {
        return true;
    }

    // Accept if mime type includes "executable" or "script"
    if (strstr(mime_type, "executable") != NULL || strstr(mime_type, "script") != NULL
            || strstr(mime_type, "application") != NULL) {
        return true;
    }

    return false;
}
