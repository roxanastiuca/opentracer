
#include <slurm/spank.h>
#include <slurm/slurm.h>

#include <string.h>
#include <unistd.h>

#include "../ebpf/opentracer.h"

/* 
 * All spank plugins must define this macro for the SLURM plugin loader.
 */
SPANK_PLUGIN(opentracer, 1)

int slurm_spank_job_prolog(spank_t sp, int ac, char **av)
{

    FILE *flog = fopen("/home/roxanas/opentracer/test.log", "a"); // TODO: replace with syslog
    if (flog == NULL) {
        fprintf(stderr, "Error: Cannot open log file\n");
        return -1;
    }
    
    // Get hostname
    char hostname[1024];
    gethostname(hostname, 1024);

    // Get current time
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    fprintf(flog, "OPENTRACER: slurm_spank_job_prolog: %d-%02d-%02d %02d:%02d:%02d %s\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
            hostname); // TODO: replace with syslog

    // Run opentracer in a new process to avoid blocking the job
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        if (run_opentracer(flog) != 0) {
            fprintf(flog, "Error: Failed to run opentracer\n");
            return -1;
        }
    } else if (pid < 0) {
        // Error
        fprintf(flog, "Error: Failed to fork\n");
        return -1;
    }

    fclose(flog); // TODO: replace with syslog
    return 0;
}

int slurm_spank_job_epilog(spank_t sp, int ac, char **av)
{
    FILE *flog = fopen("/home/roxanas/opentracer/test.log", "a"); // TODO: replace with syslog
    if (flog == NULL) {
        fprintf(stderr, "Error: Cannot open log file\n");
        return -1;
    }

    // Get current time
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    // Get hostname
    char hostname[1024];
    gethostname(hostname, 1024);

    fprintf(flog, "OPENTRACER: slurm_spank_job_epilog: %d-%02d-%02d %02d:%02d:%02d %s\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
            hostname); // TODO: replace with syslog

    fclose(flog); // TODO: replace with syslog
    return 0;
}

int main() {
    run_opentracer(stdout);
}