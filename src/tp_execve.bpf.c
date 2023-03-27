#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "help.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} sys_enter_execve_events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct sys_execve_event *e;
    e = bpf_ringbuf_reserve(&sys_enter_execve_events, sizeof(*e), 0);
    if (!e)
    {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->tgid = BPF_CORE_READ(task, tgid);
    e->ppid = BPF_CORE_READ(task, real_parent, pid);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)(ctx->args[0]));

    char **args = (char **)(ctx->args[1]);
    e->buf_off = 0;

    for (int i = 1; i < MAX_STR_ARR_ELEM; i++)
    {
        char *argp = READ_USER(args[i]);
        if (!argp)
            break;

        if (e->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
            // not enough space - return
            break;

        // Read into buffer
        int sz = bpf_probe_read_user_str(&(e->args[e->buf_off]), MAX_STRING_SIZE, argp);
        if (sz > 0)
        {
            e->buf_off += sz;
        }
        else
        {
            break;
        }
    }

    bpf_printk("length: %d, args: %s", e->buf_off, e->args);

    bpf_ringbuf_submit(e, 0);

    return 0;
}