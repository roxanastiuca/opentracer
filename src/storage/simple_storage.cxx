#include "simple_storage.h"

#include <time.h>


SimpleStorage::SimpleStorage(uid_t uid, gid_t gid, uint32_t jobid, const char* label)
    : Storage(uid, gid, jobid, label)
{
    time_t current_timestamp = time(NULL);
    char output_file_path[NAME_MAX];
    sprintf(output_file_path, "/etc/yalt/runs/open_%ld.txt", current_timestamp);

    fout = fopen(output_file_path, "a");
}

SimpleStorage::~SimpleStorage()
{
    fclose(fout);
}

int SimpleStorage::save_job()
{
    fprintf(fout, "UID: %d, GID: %d, JOBID: %d", uid, gid, jobid);
    if (label != NULL)
        fprintf(fout, ", LABEL: %s", label);
    fprintf(fout, "\n");
    fprintf(fout, "%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
            "KEEP", "TS", "PID", "UID", "RET", "FLAGS", "COMM", "MIME-TYPE", "FNAME");
    return 0;
}

int SimpleStorage::save_event(
    const event_t *e,
    bool is_accepted,
    const char *mime_type,
    const char *file_path,
    const char *link_path)
{
    fprintf(fout, "%s,%ld,%d,%d,%d,%d,%s,%s,%s,%s\n",
            is_accepted ? "KEEP" : "SKIP",
            e->ts, e->pid, e->uid, e->ret, e->flags, e->comm,
            (mime_type != NULL) ? mime_type : "?",
            (file_path != NULL) ? file_path : "",
            (link_path != NULL) ? link_path : "");

    return 0;
}