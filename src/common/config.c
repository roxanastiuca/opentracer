#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

int load_config(config_t *config)
{
    FILE *fin = fopen(CONFIG_FILE_PATH, "rt");
    if (fin == NULL)
    {
        fprintf(stderr, "Error: Cannot open config file %s\n", CONFIG_FILE_PATH);
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int err = 0;

    // Set everything to 0
    memset(config, 0, sizeof(config_t));

    while (fgets(line, MAX_LINE_LENGTH, fin) && !err) {
        // Remove trailing newline character
        line[strcspn(line, "\n")] = '\0';

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == ';')
            continue;

        char key[MAX_LINE_LENGTH];
        char value[MAX_LINE_LENGTH];
        if (sscanf(line, "%s = %s", key, value) != 2)
        {
            fprintf(stderr, "Error: Invalid line in config file: %s\n", line);
            err = -1;
            break;
        }

        if (strcmp(key, "events_save_path") == 0) {
            strcpy(config->events_save_path, value);
        } else if (strcmp(key, "events_file_size_limit") == 0) {
            if (sscanf(value, "%lu", &config->events_file_size_limit) != 1) {
                fprintf(stderr, "Error: Invalid value for events_file_size_limit: %s\n", value);
                err = -1;
            }
        } else if (strcmp(key, "events_limit") == 0) {
            if (sscanf(value, "%ld", &config->events_limit) != 1) {
                fprintf(stderr, "Error: Invalid value for events_limit: %s\n", value);
                err = -1;
            }
        } else if (strcmp(key, "targ_pid") == 0) {
            if (sscanf(value, "%d", &config->targ_pid) != 1) {
                fprintf(stderr, "Error: Invalid value for targ_pid: %s\n", value);
                err = -1;
            }
        } else if (strcmp(key, "targ_tgid") == 0) {
            if (sscanf(value, "%d", &config->targ_tgid) != 1) {
                fprintf(stderr, "Error: Invalid value for targ_tgid: %s\n", value);
                err = -1;
            }
        } else if (strcmp(key, "targ_uid") == 0) {
            if (sscanf(value, "%d", &config->targ_uid) != 1) {
                fprintf(stderr, "Error: Invalid value for targ_uid: %s\n", value);
                err = -1;
            }
        } else if (strcmp(key, "targ_uid_min") == 0) {
            if (sscanf(value, "%d", &config->targ_uid_min) != 1) {
                fprintf(stderr, "Error: Invalid value for targ_uid_min: %s\n", value);
                err = -1;
            }
        } else {
            fprintf(stderr, "Error: Unknown key in config file: %s\n", key);
            err = -1;
        }
    }

    fclose(fin);
    return err;
}

int save_config(const config_t *config)
{
    FILE *fout = fopen(CONFIG_FILE_PATH, "wt");
    if (fout == NULL)
    {
        fprintf(stderr, "Error: Cannot open config file %s\n", CONFIG_FILE_PATH);
        return -1;
    }

    fprintf(fout, "events_save_path = %s\n", config->events_save_path);
    fprintf(fout, "events_file_size_limit = %lu\n", config->events_file_size_limit);
    fprintf(fout, "events_limit = %ld\n", config->events_limit);
    fprintf(fout, "targ_pid = %d\n", config->targ_pid);
    fprintf(fout, "targ_tgid = %d\n", config->targ_tgid);
    fprintf(fout, "targ_uid = %d\n", config->targ_uid);
    fprintf(fout, "targ_uid_min = %d\n", config->targ_uid_min);

    fclose(fout);
    return 0;
}

int load_last_processed_timestamp(time_t *last_processed_timestamp)
{
    FILE *fin = fopen(LAST_PROCESSED_TIMESTAMP_FILE_PATH, "rt");
    if (fin == NULL)
    {
        fprintf(stderr, "Error: Cannot open last processed timestamp file %s\n",
                LAST_PROCESSED_TIMESTAMP_FILE_PATH);
        return -1;
    }

    if (fscanf(fin, "%ld", last_processed_timestamp) != 1)
    {
        fprintf(stderr, "Error: Invalid last processed timestamp file\n");
        fclose(fin);
        return -1;
    }

    fclose(fin);
    return 0;
}

int save_last_processed_timestamp(const time_t *last_processed_timestamp)
{
    FILE *fout = fopen(LAST_PROCESSED_TIMESTAMP_FILE_PATH, "wt");
    if (fout == NULL)
    {
        fprintf(stderr, "Error: Cannot open last processed timestamp file %s\n",
                LAST_PROCESSED_TIMESTAMP_FILE_PATH);
        return -1;
    }

    fprintf(fout, "%ld", *last_processed_timestamp);

    fclose(fout);
    return 0;
}
