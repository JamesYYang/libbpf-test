APP := hello

all: bpf exe 

bpf:
	mkdir -p output
	clang -g -O2 -c -target bpf -D__TARGET_ARCH_x86_64 -I./headers -o output/$(APP).bpf.o $(APP).bpf.c

skeleton:
	bpftool gen skeleton output/$(APP).bpf.o > output/$(APP).skel.h

exe:
	clang -g -O2 -Wall -I./output -c $(APP).c -o output/$(APP).o
	clang -Wall -O2 -g output/$(APP).o -static -lbpf -lelf -lz -o output/$(APP)

clean:
	rm -f output/*