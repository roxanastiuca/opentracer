#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

int load_config(config_t *config, const char *config_file_path)
{
    FILE *fin = fopen(config_file_path, "rt");
    if (fin == NULL)
    {
        fprintf(stderr, "Error: Cannot open config file %s\n", config_file_path);
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int err = 0;

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
        } else if (strcmp(key, "last_processed_timestamp") == 0) {
            if (sscanf(value, "%lu", &config->last_processed_timestamp) != 1) {
                fprintf(stderr, "Error: Invalid value for last_processed_timestamp: %s\n", value);
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

int save_config(config_t *config, const char *config_file_path)
{
    FILE *fout = fopen(config_file_path, "wt");
    if (fout == NULL)
    {
        fprintf(stderr, "Error: Cannot open config file %s\n", config_file_path);
        return -1;
    }

    fprintf(fout, "events_save_path = %s\n", config->events_save_path);
    fprintf(fout, "events_file_size_limit = %lu\n", config->events_file_size_limit);
    fprintf(fout, "last_processed_timestamp = %lu\n", config->last_processed_timestamp);

    fclose(fout);
    return 0;
}
