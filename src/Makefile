CFLAGS=-Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Werror
CC=clang
TARGET_ARCH ?= x86

.PHONY: all install clean
all: xdpfrer xdpfrer-ctl

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdpfrer.bpf.o: xdpfrer.bpf.c vmlinux.h common.h bpf_common.h
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_$(shell echo $(TARGET_ARCH) | tr a-z A-Z) -c $< -o $@

xdppref.bpf.o: xdppref.bpf.c vmlinux.h common.h bpf_common.h
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_$(shell echo $(TARGET_ARCH) | tr a-z A-Z) -c $< -o $@

xdpfrer.skel.h: xdpfrer.bpf.o
	sudo bpftool gen skeleton $^ > $@

xdppref.skel.h: xdppref.bpf.o
	sudo bpftool gen skeleton $^ > $@

xdpfrer.o: xdpfrer.c xdpfrer.skel.h xdppref.skel.h common.h
	$(CC) -g -O2 $(CFLAGS) -c $< -o $@

xdpfrer: xdpfrer.o
	$(CC) -g -O2 $< -lbpf -o $@

xdpfrer-ctl.o: xdpfrer-ctl.c common.h
	$(CC) -g -O2 $(CFLAGS) -c $< -o $@

xdpfrer-ctl: xdpfrer-ctl.o
	$(CC) -g -O2 $< -lbpf -o $@

install: xdpfrer xdpfrer-ctl
	cp xdpfrer /usr/local/bin/
	cp xdpfrer-ctl /usr/local/bin/

clean:
	rm -f *.o *.skel.h vmlinux.h xdpfrer xdpfrer-ctl
