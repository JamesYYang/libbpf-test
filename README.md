# libbpf test
Research libbpf.

## Build Env in WSL 2

try to upgrade kernel above `5.10.102.1-microsoft-standard-WSL2`


install dependency

```bash

apt-get install libbpf-dev make clang llvm libelf-dev

```

build bptfool from kernel. download kernel code from https://github.com/microsoft/WSL2-Linux-Kernel/releases

```bash

cd cd tools/bpf/bpftool

make

make install

```

generate vmlinux.h

```bash

bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/headers/vmlinux.h

```


## How to run

```bash

cd src

make

```

## Reference

- https://nakryiko.com/posts/libbpf-bootstrap/ [中文](https://zhuanlan.zhihu.com/p/486585330)
