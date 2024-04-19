#include "processor.h"

#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>


#include "../common/mmf.h"


Processor::Processor(const config_t &config, FILE *output_file)
    : config(config), output_file(output_file)
{
    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL) {
        fprintf(stderr, "Failed to initialize libmagic\n");
        exit(1);
    }

    if (magic_load(magic_cookie, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database\n");
        magic_close(magic_cookie);
        exit(1);
    }
}

Processor::~Processor()
{
    if (magic_cookie != NULL) {
        magic_close(magic_cookie);
    }
    // output_file is closed in the main function
}

int Processor::process_file(const std::string &file_path)
{
    memory_mapped_file_t mmf;
    if (open_memory_mapped_file(&config, file_path.c_str(), &mmf) < 0) {
        fprintf(stderr, "Failed to open memory-mapped file %s\n", file_path.c_str());
        return -1;
    }

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

int Processor::process_event(const event_t *e)
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

    struct tm *tm = localtime(&e->ts);
    char ts[20];
    strftime(ts, sizeof(ts), "%Y-%m-%d-%H:%M:%S", tm);

    printf("\t%-22s %-7s %-7d %-5d %-7d %-16s %s\n",
            ts, type, e->dfd, e->ret, e->pid, e->comm, e->fname);

    return err;
}

////////////// EVENT HANDLING ///////////////
// Main logic to handle kernel events

int Processor::process_event_open(const event_t *e)
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

    printf("OPEN: %d -> %d -> %s\n", e->pid, e->ret, abs_path.c_str());

    save_event_open(e, abs_path);
    // // TODO: remove this, use a different storage option
    // fprintf(output_file, "%-12ld %-7d %-7d %-5d %-7d %-16s %s\n",
    //         e->ts, e->pid, e->uid, e->ret, e->flags, e->comm, abs_path.c_str());

    return 0;
}

int Processor::process_event_chdir(const event_t *e)
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

    printf("CHDIR: %d -> %s\n", e->pid, pid_to_cwd[e->pid].c_str());

    return 0;
}

int Processor::process_event_fchdir(const event_t *e)
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

    printf("FCHDIR: %d -> %s\n", e->pid, pid_to_cwd[e->pid].c_str());

    return 0;
}

int Processor::process_event_execve(const event_t *e)
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
    
    printf("EXECVE: %d -> %s\n", e->pid, pid_to_cwd[e->pid].c_str());

    return 0;
}

////////////// OPENED FILE HANDLING ///////////////
// Logic to save information about opened files: filtering, processing etc.

int Processor::save_event_open(const event_t *e, const fs::path &path)
{
    // Skip /proc and /sys
    if (path.string().rfind("/proc", 0) == 0 || path.string().rfind("/sys", 0) == 0) {
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

    if (!is_accepted_file(path, file_type, mime_type)) {
        return 0;
    }

    // TODO: remove this, use a different storage option
    fprintf(output_file, "%-12ld %-7d %-7d %-5d %-7d %-16s %-32s %s %s %d\n",
            e->ts, e->pid, e->uid, e->ret, e->flags, e->comm,
            ((int)file_type > 0 && mime_type != NULL) ? mime_type : "UNK",
            path.c_str(),
            link_path.c_str(),
            (int)file_type);

    return 0;
}

bool Processor::is_accepted_file(
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
    if (config.accepted_mime_types.empty() || mime_type == NULL) {
        return true;
    }

    // Accept if mime type includes "executable" or "script"
    if (strstr(mime_type, "executable") != NULL || strstr(mime_type, "script") != NULL) {
        return true;
    }

    return config.accepted_mime_types.find(std::string(mime_type)) != config.accepted_mime_types.end();
}
