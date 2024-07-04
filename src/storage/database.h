#ifndef __DATABASE_H__
#define __DATABASE_H__

#include "storage.h"

#include <sqlite3.h>
#include <stdint.h>
#include <sys/types.h>

class Database : public Storage {
public:
    Database(uid_t uid, gid_t gid, uint32_t jobid, const char* label);
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
    int save_exec(
        const event_t *event,
        const char *comm_path,
        const char *nm,
        const char *strings);

private:
    int execute(const char *sql);
    int prepare_statements();

    sqlite3 *db;
    sqlite3_stmt *insert_event_stmt;
    sqlite3_stmt *insert_exec_stmt;
};


#endif /* __DATABASE_H__ */