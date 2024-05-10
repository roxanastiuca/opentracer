#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "../ebpf/opentracer.h"

#define PID_SAVE_FILE "/tmp/opentracer.pid"

extern "C" {
#include <slurm/spank.h>
#include <slurm/slurm.h>

/**
 * All spank plugins must define this macro for the SLURM plugin loader.
 * However, g++ does name mangling and spank can't find the symbols, so I
 * define them manually as extern and with asm(symbol).
*/
extern const char plugin_name [] asm("plugin_name") = "opentracer";
extern const char plugin_type [] asm("plugin_type") = "spank";
extern const unsigned int plugin_version asm("plugin_version") = SLURM_VERSION_NUMBER;
extern const unsigned int spank_plugin_version asm("spank_plugin_version") = 1;

int slurm_spank_job_prolog(spank_t sp, int ac, char **av)
{
    openlog("opentracer", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "slurm_spank_job_prolog: Started");
    
    // Run opentracer in a new process to avoid blocking the job
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        if (run_opentracer() != 0) {
            syslog(LOG_ERR, "slurm_spank_job_prolog: Failed to run eBPF program");
            return -1;
        }
    } else if (pid < 0) {
        // Error
        return -1;
    } else {
        // Parent process
        syslog(LOG_INFO, "slurm_spank_job_prolog: Created eBPF process with PID %d", pid);

        // Save PID in temporary file:
        FILE *pid_file = fopen(PID_SAVE_FILE, "w");
        if (pid_file == NULL) {
            syslog(LOG_ERR, "slurm_spank_job_prolog: Cannot open PID file %s", PID_SAVE_FILE);
            return -1;
        }
        fprintf(pid_file, "%d", pid);
        fclose(pid_file);

        // Set process group ID to PID to avoid killing the parent process
        if (setpgid(pid, pid) != 0) {
            syslog(LOG_ERR, "slurm_spank_job_prolog: Failed to set process group ID");
            return -1;
        }

        syslog(LOG_INFO, "slurm_spank_job_prolog: Finished");
        closelog();
    }

    return 0;
}

int slurm_spank_job_epilog(spank_t sp, int ac, char **av)
{
    openlog("opentracer", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "slurm_spank_job_epilog: Started");

    // Get PID
    FILE *pid_file = fopen(PID_SAVE_FILE, "r");
    if (pid_file == NULL) {
        syslog(LOG_ERR, "slurm_spank_job_epilog: Cannot open PID file");
        return -1;
    }
    int pid;
    fscanf(pid_file, "%d", &pid);
    fclose(pid_file);

    // Kill opentracer process
    if (kill(pid, SIGINT) != 0) {
        syslog(LOG_ERR, "slurm_spank_job_epilog: Failed to kill process with PID %d", pid);
        return -1;
    }

    syslog(LOG_INFO, "slurm_spank_job_epilog: Finished");
    closelog();
    return 0;
}
} // extern "C"
