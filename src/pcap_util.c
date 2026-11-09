// pcap filter compilation, isolated in its own translation unit.
//
// This file includes <pcap.h> but NOT libbpf's <bpf/bpf.h>. Both headers define
// a `struct bpf_insn` (pcap's classic-BPF layout vs. the kernel's eBPF layout),
// so they cannot be included together. Keeping libpcap here and libbpf in
// xdppref-ctl.c avoids that conflict; the two sides communicate only through
// struct pcap_filter / struct cbpf_insn from common.h.

#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include "pcap_util.h"

#define PCAP_SNAPLEN 262144

int compile_pcap_filter(const char *expr, struct pcap_filter *out)
{
    // Link-layer type EN10MB => offsets assume a leading Ethernet header, which
    // matches the start of the packet as seen by XDP.
    pcap_t *pc = pcap_open_dead(DLT_EN10MB, PCAP_SNAPLEN);
    if (!pc) {
        fprintf(stderr, "pcap_open_dead failed\n");
        return -1;
    }

    struct bpf_program prog;
    if (pcap_compile(pc, &prog, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "pcap_compile('%s') failed: %s\n", expr, pcap_geterr(pc));
        pcap_close(pc);
        return -1;
    }

    if (prog.bf_len == 0 || prog.bf_len > MAX_CBPF_INSNS) {
        fprintf(stderr, "filter '%s' has %u instructions (max %d)\n",
                expr, prog.bf_len, MAX_CBPF_INSNS);
        pcap_freecode(&prog);
        pcap_close(pc);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->len = prog.bf_len;
    for (unsigned int i = 0; i < prog.bf_len; i++) {
        out->insns[i].code = prog.bf_insns[i].code;
        out->insns[i].jt   = prog.bf_insns[i].jt;
        out->insns[i].jf   = prog.bf_insns[i].jf;
        out->insns[i].k    = prog.bf_insns[i].k;
    }

    pcap_freecode(&prog);
    pcap_close(pc);
    return 0;
}
