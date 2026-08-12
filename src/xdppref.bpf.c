#include "bpf_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct pref_sid {
    uint64_t loc;           // 64 bits - Locator
    uint16_t funct;         // 16 bits - Function
    uint8_t args[6];        // 48 bits: flow_id(20) | seq(16) | reserved(12), network byte order
} __attribute__((packed));

// PREF destination address: (egress ifindex, match_id) -> IPv6 locator address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(struct tx_key));
    __uint(value_size, sizeof(struct in6_addr));
} dst_addr_map SEC(".maps");

const size_t ethhdr_sz = sizeof(struct ethhdr);
const size_t ipv6hdr_sz = sizeof(struct ipv6hdr);

volatile unsigned char dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

/**
 * @brief Extract the 20-bit flow ID from the PREF SID args field.
 */
static inline uint32_t get_pref_flow_id(const struct pref_sid *p)
{
    return ((uint32_t)p->args[0] << 12) | ((uint32_t)p->args[1] << 4) | (p->args[2] >> 4);
}

/**
 * @brief Extract the 16-bit sequence number from the PREF SID args field.
 */
static inline uint16_t get_pref_seq(const struct pref_sid *p)
{
    return ((uint16_t)(p->args[2] & 0xF) << 12) | ((uint16_t)p->args[3] << 4) | (p->args[4] >> 4);
}

/**
 * @brief Set the 20-bit flow ID in the PREF SID args field.
 */
static inline void set_pref_flow_id(struct pref_sid *p, uint32_t flow_id)
{
    p->args[0] = (flow_id >> 12) & 0xFF;
    p->args[1] = (flow_id >> 4) & 0xFF;
    p->args[2] = ((flow_id & 0xF) << 4) | (p->args[2] & 0x0F);
}

/**
 * @brief Set the 16-bit sequence number in the PREF SID args field.
 */
static inline void set_pref_seq(struct pref_sid *p, uint16_t seq)
{
    p->args[2] = (p->args[2] & 0xF0) | ((seq >> 12) & 0xF);
    p->args[3] = (seq >> 4) & 0xFF;
    p->args[4] = ((seq & 0xF) << 4) | (p->args[4] & 0x0F);
}

/**
 * @brief Get the 20-bit flow label from the IPv6 header.
 * @param pkt The packet with headers.
 * @return The flow label, or -1 on error.
 */
static int get_flow_label(const struct xdp_md *pkt)
{
    const void *data = (void *)(long) pkt->data;
    const void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    const struct ipv6hdr *ip6 = data + ethhdr_sz;
    return ((ip6->flow_lbl[0] & 0x0f) << 16) |
           (ip6->flow_lbl[1] << 8) |
            ip6->flow_lbl[2];
}

/**
 * @brief Extract the flow ID and sequence number from the PREF SID which is the outer IPv6 destination address.
 * @param pkt The packet with headers.
 * @param flow_id Pointer to store the extracted 20-bit flow ID.
 * @param seq Pointer to store the extracted 16-bit sequence number.
 * @param funct Pointer to store the extracted 16-bit function.
 * @return 0 if successful, -1 if the packet is too short.
 */
static inline int read_pref_sid(struct xdp_md *pkt, uint32_t *flow_id, uint32_t *seq, uint16_t *funct)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    struct ipv6hdr *outer = data + ethhdr_sz;
    struct pref_sid *psid = (struct pref_sid *)&outer->daddr;
    *flow_id = get_pref_flow_id(psid);
    *seq = get_pref_seq(psid);
    *funct = bpf_ntohs(psid->funct);

    return 0;
}

/**
 * @brief Remove the SRH from the packet, keeping the Ethernet and outer IPv6 headers.
 * Updates the outer IPv6 nexthdr and payload_len fields accordingly. If no SRH is present, nothing happens.
 * @param pkt The packet with headers.
 * @return 0 if successful, -1 if the packet is invalid.
 */
static inline int rm_srh(struct xdp_md *pkt)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    struct ipv6hdr *outer = data + ethhdr_sz;
    if (outer->nexthdr != 43)
        return 0;

    uint8_t *srh_start = (uint8_t *)outer + ipv6hdr_sz;
    if ((void *)srh_start + 2 > data_end)
        return -1;

    uint8_t inner_nexthdr = srh_start[0];
    uint8_t hdrlen = srh_start[1];

    int srh_sz;
    switch (hdrlen) {
        case 2:  srh_sz = 24;  break;
        case 4:  srh_sz = 40;  break;
        case 6:  srh_sz = 56;  break;
        case 8:  srh_sz = 72;  break;
        case 10: srh_sz = 88;  break;
        case 12: srh_sz = 104; break;
        default: return -1;
    }

    int keep_sz = ethhdr_sz + ipv6hdr_sz;
    if (data + keep_sz + srh_sz > data_end)
        return -1;

    __builtin_memmove(data + srh_sz, data, keep_sz);
    if (bpf_xdp_adjust_head(pkt, srh_sz))
        return -1;

    data = (void *)(long) pkt->data;
    data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    outer = data + ethhdr_sz;
    outer->nexthdr = inner_nexthdr;
    outer->payload_len = bpf_htons(bpf_ntohs(outer->payload_len) - srh_sz);

    return 0;
}

/**
 * @brief Remove the outer IPv6 header (and SRH if present) from the packet, preserving the
 * Ethernet header. Restores the EtherType based on the inner next header value.
 * @param pkt The packet with headers.
 * @return 0 if successful, -1 if the packet is invalid or the header removal failed.
 */
static inline int rm_outer_ipv6(struct xdp_md *pkt)
{
    if (rm_srh(pkt) < 0)
        return -1;

    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    struct ipv6hdr *outer = data + ethhdr_sz;
    uint8_t inner_nexthdr = outer->nexthdr;

    if (data + ethhdr_sz + ipv6hdr_sz + ethhdr_sz > data_end)
        return -1;
    __builtin_memmove(data + ipv6hdr_sz, data, ethhdr_sz);
    if (bpf_xdp_adjust_head(pkt, (int)ipv6hdr_sz))
        return -1;

    data = (void *)(long) pkt->data;
    data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz > data_end)
        return -1;

    struct ethhdr *eth = data;
    if (inner_nexthdr == 41)
        eth->h_proto = bpf_htons(0x86dd);
    else if (inner_nexthdr == 4)
        eth->h_proto = bpf_htons(0x0800);
    else
        eth->h_proto = bpf_htons(0x86dd);

    return 0;
}

/**
 * @brief Rewrite the outer IPv6 header. Rewrites the destination address with the address
 * from dst_addr_map and remove the SRH if present. Used when no_encap is set.
 * @param pkt The packet with headers.
 * @param match_id The match ID (flow label or RSID) used to look up the rewrite address.
 * @return 0 if successful, -1 if the packet is too short or the address is not found.
 */
static inline int rewrite_outer_ipv6(struct xdp_md *pkt, int64_t match_id)
{
    int *tx_ifindex = bpf_map_lookup_elem(&eliminate_tx_map, &match_id);
    if (!tx_ifindex)
        return -1;

    struct tx_key k = { .ifidx = *tx_ifindex, .match_id = match_id };
    struct in6_addr *addr = bpf_map_lookup_elem(&dst_addr_map, &k);
    if (!addr)
        return -1;

    if (rm_srh(pkt) < 0)
        return -1;

    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    struct ipv6hdr *outer = data + ethhdr_sz;
    struct pref_sid *psid = (struct pref_sid *)&outer->daddr;
    struct pref_sid *src = (struct pref_sid *)addr;
    psid->loc = src->loc;
    psid->funct = src->funct;
    
    // Copy flow_id from configured address, preserve seq
    uint16_t seq = get_pref_seq(psid);
    __builtin_memcpy(psid->args, src->args, 6);
    set_pref_seq(psid, seq);

    return 0;
}

/**
 * @brief Set the destination MAC address in the Ethernet header from the dst_mac global variable.
 * @param pkt The packet with headers.
 * @return 0 if successful, -1 if the packet is too short.
 */
static inline int set_dst_mac(struct xdp_md *pkt)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz > data_end)
        return -1;

    struct ethhdr *eth = data;
    __builtin_memcpy(eth->h_dest, (const void *)dst_mac, 6);
    return 0;
}


/**
 * @brief Add an outer IPv6 header with a PREF SID between the Ethernet header and the
 * original IPv6 header. The locator field is left empty for postprocessing to fill in.
 * Incoming: ETH | IPv6 | payload
 * Outgoing: ETH | outer IPv6 (nexthdr=41) | original IPv6 | payload
 * @param pkt The packet with headers.
 * @param flow_label The flow label from the original IPv6 header (outer header field).
 * @param match_id The flow's match ID; its low 36 bits are stamped into the SID as
 *        funct (bits 20..35) and flow_id (bits 0..19) so replicate_postprocessing()
 *        can reconstruct the key for dst_addr_map. For fl flows match_id == flow_label
 *        (funct 0), so this is identical to the previous behavior.
 * @param seq The sequence number to encode in the PREF SID.
 * @return 0 if successful, -1 if the packet is invalid or there is no space for the header.
 */
static inline int add_outer_ipv6(struct xdp_md *pkt, int flow_label, int64_t match_id, uint16_t seq)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    struct ipv6hdr *orig_ip6 = data + ethhdr_sz;
    uint16_t inner_total = bpf_ntohs(orig_ip6->payload_len) + ipv6hdr_sz;
    struct in6_addr orig_saddr = orig_ip6->saddr;
    struct in6_addr orig_daddr = orig_ip6->daddr;

    // Make room for the outer IPv6 header
    if (bpf_xdp_adjust_head(pkt, 0 - (int)ipv6hdr_sz))
        return -1;

    data = (void *)(long) pkt->data;
    data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz + ipv6hdr_sz > data_end)
        return -1;

    // Move Ethernet header to the new front
    __builtin_memmove(data, data + ipv6hdr_sz, ethhdr_sz);

    // Fill in the outer IPv6 header
    struct ipv6hdr *outer = data + ethhdr_sz;
    __builtin_memset(outer, 0, ipv6hdr_sz);
    outer->version = 6;
    outer->flow_lbl[0] = (flow_label >> 16) & 0x0f;
    outer->flow_lbl[1] = (flow_label >> 8) & 0xff;
    outer->flow_lbl[2] = flow_label & 0xff;
    outer->nexthdr = 41; // IPv6-in-IPv6
    outer->hop_limit = 64;
    outer->payload_len = bpf_htons(inner_total);
    outer->saddr = orig_saddr;

    // Build PREF SID as destination address. Stamp funct + flow_id from match_id
    // as a transient lookup key: replicate_postprocessing() reads them back to key
    // dst_addr_map, then overwrites both with the configured locator's values.
    // psid->loc and the final psid->funct are set in postprocessing.
    struct pref_sid *psid = (struct pref_sid *)&outer->daddr;
    __builtin_memset(psid->args, 0, 6);
    psid->funct = bpf_htons((uint16_t)((match_id >> 20) & 0xFFFF));
    set_pref_flow_id(psid, (uint32_t)(match_id & 0xFFFFF));
    set_pref_seq(psid, seq);

    return 0;
}

/* ------------------------------------------------------------------------- *
 * Classic BPF (cBPF) interpreter for libpcap-compiled filters.
 *
 * libpcap (in xdppref-ctl) compiles a tcpdump expression to classic BPF using
 * DLT_EN10MB, so the generated bytecode already contains all the Ethernet /
 * IPv4 / IPv6 / L4 offset logic - we do NOT hand-parse any protocol here. This
 * interpreter just executes the generic cBPF opcodes against the packet.
 * A nonzero return value (the snap length) means "match".
 * ------------------------------------------------------------------------- */

// Filter slot -> compiled pcap (cBPF) filter, iterated at ingress in replicate().
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PCAP_FILTERS);
    __type(key, int);
    __type(value, struct pcap_filter);
} pcap_filter_map SEC(".maps");

// Classic BPF opcode decoding (see linux/filter.h / pcap-bpf.h). Prefixed to
// avoid clashing with any eBPF BPF_* macros from vmlinux.h.
#define CBPF_CLASS(c) ((c) & 0x07)
#define CBPF_LD   0x00
#define CBPF_LDX  0x01
#define CBPF_ST   0x02
#define CBPF_STX  0x03
#define CBPF_ALU  0x04
#define CBPF_JMP  0x05
#define CBPF_RET  0x06
#define CBPF_MISC 0x07

#define CBPF_SIZE(c) ((c) & 0x18)
#define CBPF_W 0x00
#define CBPF_H 0x08
#define CBPF_B 0x10

#define CBPF_MODE(c) ((c) & 0xe0)
#define CBPF_IMM 0x00
#define CBPF_ABS 0x20
#define CBPF_IND 0x40
#define CBPF_MEM 0x60
#define CBPF_LEN 0x80
#define CBPF_MSH 0xa0

#define CBPF_OP(c) ((c) & 0xf0)
#define CBPF_ADD 0x00
#define CBPF_SUB 0x10
#define CBPF_MUL 0x20
#define CBPF_DIV 0x30
#define CBPF_OR  0x40
#define CBPF_AND 0x50
#define CBPF_LSH 0x60
#define CBPF_RSH 0x70
#define CBPF_NEG 0x80
#define CBPF_MOD 0x90
#define CBPF_XOR 0xa0
#define CBPF_JA   0x00
#define CBPF_JEQ  0x10
#define CBPF_JGT  0x20
#define CBPF_JGE  0x30
#define CBPF_JSET 0x40

#define CBPF_SRC(c) ((c) & 0x08)
#define CBPF_K 0x00
#define CBPF_X 0x08

#define CBPF_RVAL(c) ((c) & 0x18)
#define CBPF_A 0x10

#define CBPF_MISCOP(c) ((c) & 0xf8)
#define CBPF_TAX 0x00
#define CBPF_TXA 0x80

#define CBPF_MEM_SLOTS 16

/*
 * Packet header snapshot size for filter evaluation. Copied once into a stack
 * buffer per filter run; the interpreter reads packet bytes from this buffer
 * instead of doing per-instruction packet access. 64 bytes covers Ethernet +
 * IPv6 + L4 ports, which is enough for src/dst host and port matching. Accesses
 * beyond this are treated as out-of-bounds (filter fails on them).
 */
#define CBPF_SNAP 64

/*
 * Interpreter state, also the bpf_loop() callback context. Contains only scalars
 * and inline arrays (no packet/map pointers), so it is safe to pass across the
 * bpf_loop callback boundary. The cBPF program is re-looked-up by slot inside the
 * callback rather than carried as a pointer.
 */
struct cbpf_state {
    uint32_t A, X, pc, len;
    uint32_t plen;                        // real packet length (for the LEN opcode)
    uint32_t caplen;                      // bytes actually captured in buf (<= CBPF_SNAP)
    int slot;                             // pcap_filter_map slot being evaluated
    int result;                           // verdict once a RET is reached
    int done;                             // set when a RET is reached
    uint32_t mem[CBPF_MEM_SLOTS];         // cBPF scratch memory M[]
    unsigned char buf[CBPF_SNAP + 4];     // packet snapshot (+4 padding for word reads)
};

// Per-CPU scratch for cbpf_state. Kept off the BPF stack (the struct is ~150 bytes,
// which would blow the 512-byte combined stack limit of the replicate -> cbpf_step
// call chain). XDP runs non-preemptibly per-CPU and run_cbpf finishes with the
// scratch before returning, so a single-entry per-CPU array is safe to reuse.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct cbpf_state);
} cbpf_scratch SEC(".maps");

// bpf_loop() requires its callback context to be a stack pointer, so we pass a
// tiny stack wrapper that just holds a pointer to the per-CPU cbpf_state. This
// keeps the large state in the map (off the stack) while satisfying the verifier.
struct cbpf_loop_ctx {
    struct cbpf_state *s;
};

/**
 * @brief Load W/H/B from the packet snapshot at absolute offset `off`, big-endian.
 * @return 0 and writes *out on success, -1 if the access is outside the packet.
 */
static __always_inline int cbpf_load(struct cbpf_state *s, uint32_t off, uint16_t size, uint32_t *out)
{
    uint32_t n = (size == CBPF_W) ? 4 : (size == CBPF_H) ? 2 : 1;

    if (off + n > s->caplen)              // outside the real (captured) packet
        return -1;
    uint32_t o = off & (CBPF_SNAP - 1);   // bound the index for the verifier

    if (n == 4)
        *out = ((uint32_t)s->buf[o] << 24) | ((uint32_t)s->buf[o + 1] << 16) |
               ((uint32_t)s->buf[o + 2] << 8) | (uint32_t)s->buf[o + 3];
    else if (n == 2)
        *out = ((uint32_t)s->buf[o] << 8) | (uint32_t)s->buf[o + 1];
    else
        *out = (uint32_t)s->buf[o];
    return 0;
}

/**
 * @brief bpf_loop() callback: execute a single cBPF instruction at s->pc.
 * @return 1 to stop the loop (RET reached, pc past the end, or lookup failure),
 *         0 to continue with the next iteration.
 */
static long cbpf_step(__u32 index, void *vctx)
{
    struct cbpf_loop_ctx *lc = vctx;
    struct cbpf_state *s = lc->s;
    (void)index;

    if (!s || s->pc >= s->len)
        return 1;

    int slot = s->slot;
    struct pcap_filter *f = bpf_map_lookup_elem(&pcap_filter_map, &slot);
    if (!f)
        return 1;

    struct cbpf_insn insn = f->insns[s->pc & (MAX_CBPF_INSNS - 1)];
    uint16_t code = insn.code;
    uint32_t k = insn.k;
    uint32_t v;

    switch (CBPF_CLASS(code)) {
    case CBPF_LD:
        switch (CBPF_MODE(code)) {
        case CBPF_IMM: s->A = k; break;
        case CBPF_ABS:
            if (cbpf_load(s, k, CBPF_SIZE(code), &s->A) < 0) { s->done = 1; s->result = 0; return 1; }
            break;
        case CBPF_IND:
            if (cbpf_load(s, k + s->X, CBPF_SIZE(code), &s->A) < 0) { s->done = 1; s->result = 0; return 1; }
            break;
        case CBPF_MEM: s->A = s->mem[k & (CBPF_MEM_SLOTS - 1)]; break;
        case CBPF_LEN: s->A = s->plen; break;
        default: s->done = 1; s->result = 0; return 1;
        }
        break;
    case CBPF_LDX:
        switch (CBPF_MODE(code)) {
        case CBPF_IMM: s->X = k; break;
        case CBPF_MEM: s->X = s->mem[k & (CBPF_MEM_SLOTS - 1)]; break;
        case CBPF_LEN: s->X = s->plen; break;
        case CBPF_MSH: // X = 4 * (P[k] & 0xf) - IPv4 header length
            if (cbpf_load(s, k, CBPF_B, &v) < 0) { s->done = 1; s->result = 0; return 1; }
            s->X = 4 * (v & 0xf);
            break;
        default: s->done = 1; s->result = 0; return 1;
        }
        break;
    case CBPF_ST:  s->mem[k & (CBPF_MEM_SLOTS - 1)] = s->A; break;
    case CBPF_STX: s->mem[k & (CBPF_MEM_SLOTS - 1)] = s->X; break;
    case CBPF_ALU: {
        uint32_t op = (CBPF_SRC(code) == CBPF_X) ? s->X : k;
        switch (CBPF_OP(code)) {
        case CBPF_ADD: s->A += op; break;
        case CBPF_SUB: s->A -= op; break;
        case CBPF_MUL: s->A *= op; break;
        case CBPF_DIV: if (op == 0) { s->done = 1; s->result = 0; return 1; } s->A /= op; break;
        case CBPF_MOD: if (op == 0) { s->done = 1; s->result = 0; return 1; } s->A %= op; break;
        case CBPF_AND: s->A &= op; break;
        case CBPF_OR:  s->A |= op; break;
        case CBPF_XOR: s->A ^= op; break;
        case CBPF_LSH: s->A <<= (op & 31); break;
        case CBPF_RSH: s->A >>= (op & 31); break;
        case CBPF_NEG: s->A = -s->A; break;
        default: s->done = 1; s->result = 0; return 1;
        }
        break;
    }
    case CBPF_JMP: {
        if (CBPF_OP(code) == CBPF_JA) {
            s->pc += 1 + k;
            return 0;
        }
        uint32_t op = (CBPF_SRC(code) == CBPF_X) ? s->X : k;
        int taken;
        switch (CBPF_OP(code)) {
        case CBPF_JEQ:  taken = (s->A == op); break;
        case CBPF_JGT:  taken = (s->A > op);  break;
        case CBPF_JGE:  taken = (s->A >= op); break;
        case CBPF_JSET: taken = (s->A & op);  break;
        default: s->done = 1; s->result = 0; return 1;
        }
        s->pc += 1 + (taken ? insn.jt : insn.jf);
        return 0;
    }
    case CBPF_RET: {
        uint32_t rv = (CBPF_RVAL(code) == CBPF_A) ? s->A : k;
        s->result = (rv != 0);
        s->done = 1;
        return 1;
    }
    case CBPF_MISC:
        if (CBPF_MISCOP(code) == CBPF_TAX) s->X = s->A; // TAX
        else                               s->A = s->X; // TXA
        break;
    default:
        s->done = 1; s->result = 0; return 1;
    }

    s->pc += 1;
    return 0;
}

/**
 * @brief Execute the compiled cBPF filter in slot `slot` against the packet.
 * Uses bpf_loop() so the interpreter body is verified once regardless of the
 * instruction count, keeping verifier complexity bounded.
 * @return 1 if the filter matches, 0 otherwise.
 */
static __always_inline int run_cbpf(struct xdp_md *ctx, int slot, uint32_t len)
{
    int zero = 0;
    struct cbpf_state *s = bpf_map_lookup_elem(&cbpf_scratch, &zero);
    if (!s)
        return 0;

    uint32_t plen = (uint32_t)((long)ctx->data_end - (long)ctx->data);
    uint32_t caplen;

    // Bound caplen with a mask so the verifier sees a clean 0..CBPF_SNAP value
    // (a pointer-difference scalar has unknown upper bits; a plain min() leaves
    // the length's 64-bit range unbounded and bpf_xdp_load_bytes is rejected).
    if (plen >= CBPF_SNAP)
        caplen = CBPF_SNAP;
    else
        caplen = plen & (CBPF_SNAP - 1);

    // Reset per-run state (the per-CPU scratch persists across invocations).
    s->A = 0;
    s->X = 0;
    s->pc = 0;
    s->result = 0;
    s->done = 0;
    __builtin_memset(s->mem, 0, sizeof(s->mem));
    s->slot = slot;
    s->plen = plen;
    s->caplen = caplen;
    s->len = len > MAX_CBPF_INSNS ? MAX_CBPF_INSNS : len;

    if (caplen > 0 && bpf_xdp_load_bytes(ctx, 0, s->buf, caplen) < 0)
        return 0;

    struct cbpf_loop_ctx lc = { .s = s };
    bpf_loop(MAX_CBPF_INSNS, cbpf_step, &lc, 0);
    return s->done ? s->result : 0;
}

/**
 * @brief Run every installed pcap filter against the packet.
 * @return the match_id of the first matching filter, or -1 if none match.
 */
static __always_inline int64_t run_pcap_filters(struct xdp_md *pkt)
{
    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_PCAP_FILTERS; i++) {
        int key = i;
        struct pcap_filter *f = bpf_map_lookup_elem(&pcap_filter_map, &key);
        if (!f || f->len == 0)
            continue;
        uint32_t len = f->len;
        int64_t mid = f->match_id;
        if (run_cbpf(pkt, i, len))
            return mid;
    }
    return -1;
}

// Periodically invoked to reset timed-out sequence recovery entries.
SEC("xdp")
int check_reset(char *dummy) // unused param to satisfy verifier
{
    bpf_for_each_map_elem(&seqrcvy_map, sequence_recovery_reset, NULL, 0);
    return 1;
}

// PREF replication: match IPv6 flow label or RSID, generate sequence number,
// add outer IPv6 with PREF SID, set destination MAC, broadcast to egress interfaces.
SEC("xdp")
int replicate(struct xdp_md *pkt)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        goto not_for_us;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(0x86dd)) {
        bpf_printk("[Repl] not ipv6 packet");
        goto not_for_us;
    }

    uint32_t flow_id;
    uint32_t seq_dummy;
    uint16_t funct;
    int64_t match_id;
    int flow_label = get_flow_label(pkt);
    struct seq_gen *gen = NULL;

    // Try rsid match (combined funct+flow_id from PREF SID), then fl match (IPv6
    // flow label), then any installed pcap filter (ingress-only, additional match).
    if (read_pref_sid(pkt, &flow_id, &seq_dummy, &funct) == 0) {
        match_id = ((int64_t)funct << 20) | (flow_id & 0xFFFFF);
        gen = bpf_map_lookup_elem(&seqgen_map, &match_id);
    }
    if (!gen && flow_label >= 0) {
        match_id = flow_label;
        gen = bpf_map_lookup_elem(&seqgen_map, &match_id);
    }
    if (!gen) {
        int64_t fmid = run_pcap_filters(pkt);
        if (fmid >= 0) {
            match_id = fmid;
            gen = bpf_map_lookup_elem(&seqgen_map, &match_id);
        }
    }
    if (!gen) {
        bpf_printk("[Repl] no match (rsid/fl/filter)");
        goto not_for_us;
    }

    // Packet matched our criteria, count it as received
    __sync_fetch_and_add(&received, 1);

    int ret = 0;
    if (gen->no_encap) {
        // Remove the SRH but keep the outer IPv6 header with the PREF SID (preserving flow_id and seq).
        // The destination locator and function are rewritten per egress interface in replicate_postprocessing.
        ret = rm_srh(pkt);
        if (ret < 0) {
            bpf_printk("[Repl] Unable to remove SRH");
            goto drop;
        }
    } else {
        uint16_t seq = gen_seq(gen);
        bpf_printk("[Repl] generated seq %d", seq);
        
        ret = add_outer_ipv6(pkt, flow_label, match_id, seq); // stamp match_id into the SID key
        if (ret < 0) {
            bpf_printk("[Repl] add_outer_ipv6 failed");
            goto drop;
        }
    }

    struct tx_ifaces *tx = bpf_map_lookup_elem(&replicate_tx_map, &match_id);
    if (!tx) {
        bpf_printk("[Repl] drop");
        goto drop;
    }

    ret = set_dst_mac(pkt);
    if (ret < 0) {
        bpf_printk("[Repl] set MAC failed");
        goto drop;
    }

pass:
    bpf_printk("[Repl] redirect");
    return bpf_redirect_map(tx, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
not_for_us:
    __sync_fetch_and_add(&unmatched, 1); // prevent race condition when increment the counter
    return XDP_PASS;
drop:
    return XDP_DROP;
}

// Per-egress devmap callback: fill in the locator portion of the PREF SID from dst_addr_map.
SEC("xdp/devmap")
int replicate_postprocessing(struct xdp_md *pkt)
{
    // Compute the same key used by replicate: try rsid first, then fl
    uint32_t flow_id;
    uint32_t seq_dummy;
    uint16_t funct;
    int64_t match_id;

    if (read_pref_sid(pkt, &flow_id, &seq_dummy, &funct) == 0) {
        match_id = ((int64_t)funct << 20) | (flow_id & 0xFFFFF);
    } else {
        match_id = (int64_t)get_flow_label(pkt);
    }

    struct tx_key k = { .ifidx = pkt->egress_ifindex, .match_id = match_id };
    struct in6_addr *addr = bpf_map_lookup_elem(&dst_addr_map, &k);
    if (!addr) {
        // Fallback to flow label match
        match_id = (int64_t)get_flow_label(pkt);
        k.match_id = match_id;
        addr = bpf_map_lookup_elem(&dst_addr_map, &k);
        if (!addr)
            return XDP_PASS;
    }

    void *data = (void *)(long)pkt->data;
    void *data_end = (void *)(long)pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return XDP_DROP;

    struct ipv6hdr *outer = data + ethhdr_sz;
    struct pref_sid *psid = (struct pref_sid *)&outer->daddr;
    struct pref_sid *src = (struct pref_sid *)addr;
    psid->loc = src->loc;
    psid->funct = src->funct;
    
    // Copy flow_id from the configured address (needed for SRv6 route matching),
    // preserve the seq already set by add_outer_ipv6.
    uint16_t seq = get_pref_seq(psid);
    __builtin_memcpy(psid->args, src->args, 6);
    set_pref_seq(psid, seq);

    bpf_printk("[Repl postprocessing] pass");
    return XDP_PASS;
}

// PREF elimination: read PREF SID, strip outer IPv6, run recovery algorithm, redirect or drop.
SEC("xdp")
int eliminate(struct xdp_md *pkt)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz + ipv6hdr_sz > data_end) {
        bpf_printk("[Elim] Not a good packet for us, pass");
        goto not_for_us;
    }

    uint32_t flow_id;
    uint32_t seq;
    uint16_t funct;
    int ret = read_pref_sid(pkt, &flow_id, &seq, &funct);
    if (ret < 0) {
        bpf_printk("[Elim] Unable to read PREF SID");
        goto not_for_us;
    }

    bpf_printk("[Elim] funct: %d flow_id: %d, seq: %d", funct, flow_id, seq);

    // Try combined key (rsid mode) first, then flow_id only (fl mode)
    int64_t match_id = ((int64_t)funct << 20) | (flow_id & 0xFFFFF);
    int *rcvy_idx = bpf_map_lookup_elem(&seqrcvy_idx_map, &match_id);
    if (!rcvy_idx) {
        match_id = (int64_t)flow_id;
        rcvy_idx = bpf_map_lookup_elem(&seqrcvy_idx_map, &match_id);
        if (!rcvy_idx) {
            bpf_printk("[Elim] drop wrong rsid or flow_id %d", flow_id);
            goto not_for_us;
        }
    }

    bpf_printk("[Elim] rcvy_idx for history window %d", rcvy_idx);

    struct seq_rcvy_and_hist *rec = bpf_map_lookup_elem(&seqrcvy_map, rcvy_idx);
    if (!rec) {
        bpf_printk("[Elim] No history window found for idx %d", *rcvy_idx);
        goto not_for_us;
    }

    if (rec->no_encap) {
        ret = rewrite_outer_ipv6(pkt, match_id);
        if (ret < 0) {
            bpf_printk("[Elim] Unable to rewrite outer IPv6 destination");
            goto drop;
        }
    } else {
        ret = rm_outer_ipv6(pkt);
        if (ret < 0) {
            bpf_printk("[Elim] Unable to remove outer IPv6 header");
            goto drop;
        }
    }

    int *tx_ifindex = bpf_map_lookup_elem(&eliminate_tx_map, &match_id);
    if (!tx_ifindex) {
        bpf_printk("[Elim] Drop, wrong key %ld for tx_map", match_id);
        goto drop;
    }

    bpf_spin_lock(&(rec->lock)); // lock
    bool pass = recover(rec, seq); 
    bpf_spin_unlock(&(rec->lock)); // unlock
    if (pass == false) {
        bpf_printk("[Elim] Drop, not the first instance");
        goto drop;
    }

    ret = set_dst_mac(pkt);
    if (ret < 0) {
        bpf_printk("[Elim] Failed to set destination MAC address");
        goto drop;
    }

pass:
    __sync_fetch_and_add(&passed, 1); // prevent race condition when increment the counter
    rec->last_packet_ns = bpf_ktime_get_ns();
    return bpf_redirect(*tx_ifindex, 0);
not_for_us:
    __sync_fetch_and_add(&unmatched, 1); // prevent race condition when increment the counter
    return XDP_PASS;
drop:
    __sync_fetch_and_add(&dropped, 1); // prevent race condition when increment the counter
    return XDP_DROP;
}
