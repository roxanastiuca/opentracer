#ifndef __PROCESSOR_H__
#define __PROCESSOR_H__

#include <magic.h>

#include "../common/config.h"
#include "../common/tracer_events.h"

// C++ headers
#include <algorithm>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fs = std::filesystem;


class Processor {
public:
    Processor(const config_t &config, FILE *output_file /* TODO: change this */);
    ~Processor();
    int process_file(const std::string &file_path);

private:
    int process_event(const event_t *event);
    int process_event_open(const event_t *event);
    int process_event_execve(const event_t *event);
    int process_event_chdir(const event_t *event);
    int process_event_fchdir(const event_t *event);

    int save_event_open(const event_t *event, const fs::path &path);
    bool is_accepted_file(
        const fs::path &path, const fs::file_type &type, const char *mime_type);

    const config_t &config;
    FILE *output_file; // TODO: remove this, use a different storage option
    magic_t magic_cookie;

    std::unordered_map<int, fs::path> pid_to_cwd;
    std::unordered_map<int, std::vector<fs::path>> pid_to_fds_paths;
};

int run_processor(uid_t uid, gid_t gid, uint32_t jobid);


#endif /* __PROCESSOR_H__ */