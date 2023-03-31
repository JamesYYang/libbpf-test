#include <stdio.h>
#include <argp.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include "help.h"
#include "tcp_connect.skel.h"

static const char *tcp_event[] = {
    [1] = "CONNECT",
    [2] = "ACCEPT",
    [3] = "CLOSE",
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct net_tcp_event *e = data;

    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    char saddr[26], daddr[26];
    inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));
    // data->saddr

    printf("%-8s %-10s %-16s %-20s %-5d %-20s %-5d\n",
           ts, tcp_event[e->event], e->comm, saddr, e->sport, daddr, e->dport);

    return 0;
}

int load_tcp_connect()
{
    struct ring_buffer *rb = NULL;
    struct tcp_connect_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = tcp_connect_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = tcp_connect_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = tcp_connect_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.sys_tcp_connect_events), handle_event, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("%-8s %-10s %-16s %-20s %-5s %-20s %-5s\n", "TIME", "EVENT", "COMM", "SADDR", "SPORT", "DADDR", "DPORT");

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
    tcp_connect_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}