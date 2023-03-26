#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_printk("BPF triggered from PID %d and myid %d and COMM %s.\n", pid, my_pid, comm);

    return 0;
}