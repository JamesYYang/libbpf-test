all: bpf skeleton exe 

bpf:
	mkdir -p output
	clang -g -O2 -c -target bpf -D__TARGET_ARCH_x86_64 -I./headers -o output/tp_openat.bpf.o tp_openat.bpf.c
	clang -g -O2 -c -target bpf -D__TARGET_ARCH_x86_64 -I./headers -o output/tp_execve.bpf.o tp_execve.bpf.c
	clang -g -O2 -c -target bpf -D__TARGET_ARCH_x86_64 -I./headers -o output/tcp_connect.bpf.o tcp_connect.bpf.c

skeleton:
	bpftool gen skeleton output/tp_openat.bpf.o > output/tp_openat.skel.h
	bpftool gen skeleton output/tp_execve.bpf.o > output/tp_execve.skel.h
	bpftool gen skeleton output/tcp_connect.bpf.o > output/tcp_connect.skel.h

exe:
	clang -Wall -O2 -g -I./output -I./headers -lbpf -lelf -lz -o output/my_libbpf main.c tp_execve.c tp_openat.c

clean:
	rm -f output/*