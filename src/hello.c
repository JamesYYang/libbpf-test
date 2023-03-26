#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    obj = bpf_object__open_file("output/hello.bpf.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = bpf_object__load(obj);
    if (err < 0)
    {
        fprintf(stderr, "Failed to load and verify BPF obj\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "handle_tp");

    /* Attach tracepoint handler */
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    for (;;)
    {
        fprintf(stderr, ".");
        sleep(5);
    }

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return -err;
}