CFLAGS=-Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Werror
CC=clang

.PHONY: all
all: xdpfrer

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdpfrer.bpf.o: xdpfrer.bpf.c vmlinux.h common.h
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_X86 -c $< -o $@

xdpfrer.skel.h: xdpfrer.bpf.o
	sudo bpftool gen skeleton $^ > $@

xdpfrer.o: xdpfrer.c xdpfrer.skel.h common.h
	$(CC) -g -O2 $(CFLAGS) -c $< -o $@

xdpfrer: xdpfrer.o
	$(CC) -g -O2 $< -lbpf -o $@

install: xdpfrer
	cp xdpfrer /usr/local/bin/
	cp interface_switcher /usr/local/bin

clean:
	rm *.o *.skel.h vmlinux.h xdpfrer
