#ifndef __SIMPLE_STORAGE_H__
#define __SIMPLE_STORAGE_H__

#include "storage.h"

#include <stdio.h>


class SimpleStorage : public Storage {
public:
    SimpleStorage(uid_t uid, gid_t gid, uint32_t jobid, const char* label);
    ~SimpleStorage();

    int save_job();
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