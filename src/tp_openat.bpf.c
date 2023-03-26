#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct sys_openat_event
{
    u32 pid;
    u32 tgid;
    u32 ppid;
    char comm[16];
    char filename[256];
};

SEC("tp/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{

    struct sys_openat_event t = {};
    struct sys_openat_event *e = &t;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->tgid = BPF_CORE_READ(task, tgid);
    e->ppid = BPF_CORE_READ(task, real_parent, pid);

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)(ctx->args[1]));

    bpf_printk("BPF triggered from PID: %d, COMM: %s, filename: %s\n", e->pid, e->comm, e->filename);

    return 0;
}