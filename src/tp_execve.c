#include <stdio.h>
#include <argp.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "help.h"
#include "tp_execve.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void handle_args(struct sys_execve_event *e, char *p_args)
{
    for (int i = 0; i < e->buf_off - 1; i++)
    {
        char c = e->args[i];
        if (c == '\0')
        {
            p_args[i] = ' ';
        }
        else
        {
            p_args[i] = c;
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct sys_execve_event *e = data;

    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    char p_args[e->buf_off - 1];
    handle_args(e, p_args);

    printf("%-8s %-5s %-16s %-7d %-7d %s %s\n",
           ts, "EXECVE", e->comm, e->pid, e->ppid, e->filename, p_args);

    return 0;
}

int load_tp_execve()
{
    struct ring_buffer *rb = NULL;
    struct tp_execve_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = tp_execve_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = tp_execve_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = tp_execve_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.sys_enter_execve_events), handle_event, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // printf("%-8s %-10s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME");

    while (true)
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    tp_execve_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}