#ifndef __SIMPLE_STORAGE_H__
#define __SIMPLE_STORAGE_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "../common/tracer_events.h"


class SimpleStorage {
public:
    SimpleStorage(uid_t uid, gid_t gid, uint32_t jobid);
    ~SimpleStorage();
    int save_event(
        const event_t *event,
        bool is_accepted,
        const char *mime_type,
        const char *file_path,
        const char *link_path);

private:
    FILE *fout;
};


#endif /* __SIMPLE_STORAGE_H__ */