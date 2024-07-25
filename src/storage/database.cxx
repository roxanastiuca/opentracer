#include "database.h"

#include <stdio.h>
#include <string.h>
#include <syslog.h>


static const char *YALT_DB_PATH = "/etc/yalt/yalt.db";


Database::Database(uid_t uid, gid_t gid, uint32_t jobid, const char* label)
    : Storage(uid, gid, jobid, label), db(NULL)
{
    int rc = sqlite3_open(YALT_DB_PATH, &db);
    if (rc) {
        syslog(LOG_ERR, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        db = NULL;
    }
    rc = start_transaction();
    if (rc != 0) {
        syslog(LOG_ERR, "Can't start transaction\n");
        db = NULL;
    }
}

Database::~Database()
{
    end_transaction();
    if (db) {
        sqlite3_close(db);
    }
}

int Database::start_transaction()
{
    if (execute("BEGIN TRANSACTION;") != 0) {
        return -1;
    }
    if (prepare_statements() != 0) {
        return -1;
    }

    return 0;
}

int Database::end_transaction()
{
    if (execute("END TRANSACTION;") != 0) {
        return -1;
    }
    if (sqlite3_finalize(insert_event_stmt) != SQLITE_OK) {
        return -1;
    }
    if (sqlite3_finalize(insert_exec_stmt) != SQLITE_OK) {
        return -1;
    }

    return 0;
}

int Database::execute(const char *sql)
{
    if (!db) {
        return -1;
    }

    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, 0, &err_msg);
    if (rc != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

int Database::prepare_statements()
{
    if (!db) {
        return -1;
    }

    const char *sql = "INSERT INTO events (jobid, ts, pid, uid, ret, flags, comm, mime_type, file_path, link_path, keep) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, strlen(sql), &insert_event_stmt, NULL) != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    const char *sql2 = "INSERT INTO binaries (jobid, pid, comm, comm_path, nm, strings) "
                       "VALUES (?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql2, strlen(sql2), &insert_exec_stmt, NULL) != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    return 0;
}

int Database::save_job()
{
    if (!db) {
        return -1;
    }

    char *err_msg = NULL;
    char sql[256];

    if (label) {
        sprintf(sql, "INSERT INTO jobs (jobid, uid, gid, label) VALUES (%d, %d, %d, '%s');",
                jobid, uid, gid, label);
    } else {
        sprintf(sql, "INSERT INTO jobs (jobid, uid, gid) VALUES (%d, %d, %d);",
                jobid, uid, gid);
    }
    
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

    if (sqlite3_reset(insert_event_stmt) != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    if (sqlite3_clear_bindings(insert_event_stmt) != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(insert_event_stmt, 1, jobid);
    sqlite3_bind_int64(insert_event_stmt, 2, event->ts);
    sqlite3_bind_int(insert_event_stmt, 3, event->pid);
    sqlite3_bind_int(insert_event_stmt, 4, event->uid);
    sqlite3_bind_int(insert_event_stmt, 5, event->ret);
    sqlite3_bind_int(insert_event_stmt, 6, event->flags);
    sqlite3_bind_text(insert_event_stmt, 7, event->comm, -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt, 8, (mime_type != NULL) ? mime_type : "?", -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt, 9, (file_path != NULL) ? file_path : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt, 10, (link_path != NULL) ? link_path : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt, 11, (is_accepted) ? "true" : "false", -1, SQLITE_STATIC);

    if (sqlite3_step(insert_event_stmt) != SQLITE_DONE) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    return 0;
}

int Database::save_exec(
    const event_t *event,
    const char *comm_path,
    const char *nm,
    const char *strings)
{
    if (!db) {
        return -1;
    }

    if (sqlite3_reset(insert_exec_stmt) != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    if (sqlite3_clear_bindings(insert_exec_stmt) != SQLITE_OK) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(insert_exec_stmt, 1, jobid);
    sqlite3_bind_int(insert_exec_stmt, 2, event->pid);
    sqlite3_bind_text(insert_exec_stmt, 3, event->comm, -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_exec_stmt, 4, comm_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_exec_stmt, 5, nm, -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_exec_stmt, 6, strings, -1, SQLITE_STATIC);

    if (sqlite3_step(insert_exec_stmt) != SQLITE_DONE) {
        syslog(LOG_ERR, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    return 0;
}
