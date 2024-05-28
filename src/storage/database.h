#ifndef __DATABASE_H__
#define __DATABASE_H__

#include <sqlite3.h>

#include "../common/tracer_events.h"


class Database {
public:
    Database();
    ~Database();
    int save_job(uid_t uid, gid_t gid, uint32_t jobid);
    int save_event(
        const event_t *event,
        bool is_accepted,
        const char *mime_type,
        const char *file_path,
        const char *link_path);

private:
    sqlite3 *db;
};


#endif /* __DATABASE_H__ */