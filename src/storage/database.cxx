#include "database.h"

#include <stdio.h>
#include <string.h>
#include <syslog.h>


static const char *YALT_DB_PATH = "/etc/yalt/yalt.db";

Database::Database()
{
    int rc = sqlite3_open(YALT_DB_PATH, &db);
    if (rc) {
        syslog(LOG_ERR, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        db = NULL;
    }
}

Database::~Database()
{
    if (db) {
        sqlite3_close(db);
    }
}

int Database::save_job(uid_t uid, gid_t gid, uint32_t jobid)
{
    if (!db) {
        return -1;
    }

    char *err_msg = NULL;
    char sql[256];
    sprintf(sql, "INSERT INTO jobs (jobid, uid, gid) VALUES (%d, %d, %d);",
            jobid, uid, gid);

    int rc = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

int Database::save_event(
    const event_t *event,
    bool is_accepted,
    const char *mime_type,
    const char *file_path,
    const char *link_path)
{
    if (!db) {
        return -1;
    }

    char *err_msg = NULL;
    char sql[512];
    sprintf(sql, "INSERT INTO events (ts, pid, uid, ret, flags, comm, mime_type, file_path, link_path, keep) "
                 "VALUES (%ld, %d, %d, %d, %d, '%s', '%s', '%s', '%s', '%s');",
            event->ts, event->pid, event->uid, event->ret, event->flags, event->comm,
            (mime_type != NULL) ? mime_type : "?",
            (file_path != NULL) ? file_path : "",
            (link_path != NULL) ? link_path : "",
            (is_accepted) ? "true" : "false");

    int rc = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}
