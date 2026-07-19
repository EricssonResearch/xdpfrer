CFLAGS=-Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Werror
CC=clang
TARGET_ARCH ?= x86

BPFTOOL=$(shell which bpftool 2>/dev/null)
ifeq (, $(BPFTOOL))
        BPFTOOL=$(wildcard /usr/sbin/bpftool)
        ifeq (, $(BPFTOOL))
                $(error "bpftool not found (apt install linux-tools-common)")
        endif
endif

.PHONY: all install clean
all: xdpfrer xdppref-ctl

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdpfrer.bpf.o: xdpfrer.bpf.c vmlinux.h common.h bpf_common.h
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_$(shell echo $(TARGET_ARCH) | tr a-z A-Z) -c $< -o $@

xdppref.bpf.o: xdppref.bpf.c vmlinux.h common.h bpf_common.h
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_$(shell echo $(TARGET_ARCH) | tr a-z A-Z) -c $< -o $@

xdpfrer.skel.h: xdpfrer.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

xdppref.skel.h: xdppref.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

xdpfrer.o: xdpfrer.c xdpfrer.skel.h xdppref.skel.h common.h pcap_util.h
	$(CC) -g -O2 $(CFLAGS) -c $< -o $@

xdpfrer: xdpfrer.o pcap_util.o
	$(CC) -g -O2 $^ -lbpf -lpcap -o $@

xdppref-ctl.o: xdppref-ctl.c common.h pcap_util.h
	$(CC) -g -O2 $(CFLAGS) -c $< -o $@

pcap_util.o: pcap_util.c pcap_util.h common.h
	$(CC) -g -O2 $(CFLAGS) -c $< -o $@

xdppref-ctl: xdppref-ctl.o pcap_util.o
	$(CC) -g -O2 $^ -lbpf -lpcap -o $@

install: xdpfrer xdppref-ctl
	cp xdpfrer /bin/
	cp xdppref-ctl /bin/

clean:
	rm -f *.o *.skel.h vmlinux.h xdpfrer xdppref-ctl
