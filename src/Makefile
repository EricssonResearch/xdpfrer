CFLAGS=-Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Werror
CC=clang

ifeq ($(MAKECMDGOALS),static)
  STATIC = -static
  EXTRA_FLAGS = -lelf -lz -lzstd
  TARGET = -D__TARGET_ARCH_X64
else
  TARGET = -D__TARGET_ARCH_X86
endif

.PHONY: all install clean static
all: xdpfrer
static: xdpfrer

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdpfrer.bpf.o: xdpfrer.bpf.c vmlinux.h common.h
	$(CC) -g -O2 -target bpf $(TARGET) -c $< -o $@

xdpfrer.skel.h: xdpfrer.bpf.o
	sudo bpftool gen skeleton $^ > $@

xdpfrer.o: xdpfrer.c xdpfrer.skel.h common.h
	$(CC) $(STATIC) -g -O2 $(CFLAGS) -c $< -o $@

xdpfrer: xdpfrer.o
	$(CC) $(STATIC) -g -O2 $< -lbpf $(EXTRA_FLAGS) -o $@

install: xdpfrer
	cp xdpfrer /usr/local/bin/

clean:
	rm *.o *.skel.h vmlinux.h xdpfrer
