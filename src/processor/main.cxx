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
#include <filesystem>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "processor.h"
#include "../common/config.h"
#include "../common/mmf.h"
#include "../common/tracer_events.h"


namespace fs = std::filesystem;


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
        char file_path[MAX_FILE_NAME];
        snprintf(file_path, MAX_FILE_NAME, "%s/%s", config.events_save_path, entry->d_name);

        // Check if entry is a regular file
        if (stat(file_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
            time_t last_modified = file_stat.st_mtime;

            if (last_modified > config.last_processed_timestamp) {
                files.push_back(std::make_pair(last_modified, std::string(file_path)));
                printf("File %s, last modified: %ld > %ld\n",
                        file_path, last_modified, config.last_processed_timestamp);
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

    
    // TODO: remove this, use a different storage option
    char output_file_path[NAME_MAX];
    sprintf(output_file_path, "../../runs/open_%ld.txt", current_timestamp);
    FILE *output_file = fopen(output_file_path, "wt");
    fprintf(output_file, "%-12s %-7s %-7s %-5s %-7s %-16s %-32s %s\n",
            "TS", "PID", "UID", "RET", "FLAGS", "COMM", "MIME-TYPE", "FNAME");

    Processor processor(config, output_file);

    for (const auto &file : files) {
        printf("Processing file %s\n", file.second.c_str());
        err = processor.process_file(file.second);
    }

    fclose(output_file); // TODO: remove this, use a different storage option

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
