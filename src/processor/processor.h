#ifndef __PROCESSOR_H__
#define __PROCESSOR_H__

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
    int process_file(const std::string &file_path);

private:
    int process_event(const event_t *event);
    int process_event_open(const event_t *event);
    int process_event_execve(const event_t *event);
    int process_event_chdir(const event_t *event);
    int process_event_fchdir(const event_t *event);

    int save_event_open(const event_t *event, const fs::path &path);

    const config_t &config;
    FILE *output_file; // TODO: remove this, use a different storage option

    std::unordered_map<int, fs::path> pid_to_cwd;
    std::unordered_map<int, std::vector<fs::path>> pid_to_fds_paths;
};

#endif /* __PROCESSOR_H__ */