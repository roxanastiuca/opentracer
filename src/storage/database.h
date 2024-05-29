#ifndef __DATABASE_H__
#define __DATABASE_H__

#include <sqlite3.h>
#include <stdint.h>
#include <sys/types.h>

#include "../common/tracer_events.h"


class Database {
public:
    Database(uid_t uid, gid_t gid, uint32_t jobid);
    ~Database();

    int start_transaction();
    int end_transaction();

    int save_job();
    int save_event(
        const event_t *event,
        bool is_accepted,
        const char *mime_type,
        const char *file_path,
        const char *link_path);

private:
    int execute(const char *sql);
    int prepare_statements();

    sqlite3 *db;
    sqlite3_stmt *insert_event_stmt;

    uid_t uid;
    gid_t gid;
    uint32_t jobid;
};


#endif /* __DATABASE_H__ */