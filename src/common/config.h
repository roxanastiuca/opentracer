#ifndef __CONFIG_H
#define __CONFIG_H

#include <time.h>

#define MAX_LINE_LENGTH 255

typedef struct {
    char events_save_path[255];                             // path to save events
    unsigned long events_file_size_limit;                   // max size of events file
    time_t last_processed_timestamp;                        // last processed timestamp
} config_t;

/**
 * Configuration file in ini (simplified) format:
 * key = value
*/
int load_config(config_t *config, const char *config_file_path);
int save_config(config_t *config, const char *config_file_path);


#endif /* __CONFIG_H */