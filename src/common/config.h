#ifndef __CONFIG_H
#define __CONFIG_H

#include <time.h>

#define MAX_LINE_LENGTH 255
#define CONFIG_FILE_PATH "/etc/yalt/opentracer_config.ini"
#define LAST_PROCESSED_TIMESTAMP_FILE_PATH "/etc/yalt/last_processed_timestamp.txt"

typedef struct {
    char events_save_path[255];                             // path to save events
    unsigned long events_file_size_limit;                   // max size of events file
    long int events_limit;                                  // max number of events to process
    pid_t targ_pid;                                         // target process id
    pid_t targ_tgid;                                        // target thread group id
    int targ_uid;                                         // target user id
    int targ_uid_min;                                     // target min user id
} config_t;

/**
 * Configuration file in ini (simplified) format:
 * key = value
*/
int load_config(config_t *config);
int save_config(const config_t *config);

/**
 * Load last processed timestamp.
*/
int load_last_processed_timestamp(time_t *last_processed_timestamp);
int save_last_processed_timestamp(const time_t *last_processed_timestamp);


#endif /* __CONFIG_H */