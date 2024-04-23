#ifndef __MMF_H__
#define __MMF_H__

#include "config.h"

#define MAX_FILE_NAME 296

/**
 * Memory-mapped file structure:
 * - first 8 bytes: read offset
 * - next 8 bytes: write offset
 * - rest of the file: events
*/
typedef struct {
    void *addr;             /* start address of memory-mapped file */
    size_t *read_offset;    /* pointer to mapped memory of read offset */
    size_t *write_offset;   /* pointer to mapped memory of write offset */
    void *data;             /* start address of data (events) */
} memory_mapped_file_t;

int open_memory_mapped_file(const config_t *config, const char *file_path, memory_mapped_file_t *mmf);
int create_memory_mapped_file(const config_t *config, char *file_path, memory_mapped_file_t *mmf);
int close_memory_mapped_file(const config_t *config, const char *file_path, memory_mapped_file_t *mmf);


#endif /* __MMF_H__ */