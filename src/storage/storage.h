#ifndef __STORAGE_H__
#define __STORAGE_H__

#include "../common/tracer_events.h"

class Storage {
public:
    Storage(uid_t uid, gid_t gid, uint32_t jobid, const char* label)
        : uid(uid), gid(gid), jobid(jobid), label(label) {}
    virtual ~Storage() {}

    virtual int save_job() = 0;
    virtual int save_event(
        const event_t *event,
        bool is_accepted,
        const char *mime_type,
        const char *file_path,
        const char *link_path) = 0;

protected:
    uid_t uid;
    gid_t gid;
    uint32_t jobid;
    const char* label;
};


#endif /* __STORAGE_H__ */