#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/resource.h>
#include "trace.h"

void handle_subprocess_exit(int signal)
{
    printf("clean subprocess.\n");
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0)
        ;
}

void trace_openat()
{
    pid_t pid = fork();
    if (pid == 0)
    {
        load_tp_openat();
    }
}

void trace_execve()
{
    pid_t pid = fork();
    if (pid == 0)
    {
        load_tp_execve();
    }
}

void trace_tcp()
{
    pid_t pid = fork();
    if (pid == 0)
    {
        load_tcp_connect();
    }
}

// WSL kernel install libbpf-dev 1.0.5 not set rlimit.
// can remove after 1.1.0
int bump_rlimit_memlock(void)
{
    struct rlimit rlim;

    rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        return -1;

    return 0;
}

int main(int argc, char **argv)
{
    signal(SIGCHLD, handle_subprocess_exit);

    if (bump_rlimit_memlock() == -1)
    {
        fprintf(stderr, "set rlimit failed\n");
        return 1;
    }

    // printf("%-8s %-10s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME");

    // trace_openat();

    // trace_execve();

    trace_tcp();

    while (1)
    {
        sleep(1);
    }
}