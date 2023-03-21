all: bpf skeleton exe 

bpf:
	mkdir -p output
	clang -g -O2 -c -target bpf -D__TARGET_ARCH_x86_64 -I./headers -o output/hello.bpf.o hello.bpf.c

skeleton:
	bpftool gen skeleton output/hello.bpf.o > output/hello.skel.h

exe:
	clang -g -O2 -Wall -I./output -c hello.c -o output/hello.o
	clang -Wall -O2 -g output/hello.o -static -lbpf -lelf -lz -o output/hello

clean:
	rm -f output/*