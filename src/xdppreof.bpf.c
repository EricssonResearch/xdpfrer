#include "bpf_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct preof_sid {
    uint64_t loc;           // 64 bits - Locator
    uint16_t funct;         // 16 bits - Function
    uint32_t flow_id : 20;  // 20 bits - Flow-ID
    uint32_t seq : 16;      // 16 bits - Sequence Number
    uint32_t reserved : 12; // 12 bits - padding (zeros)
} __attribute__((packed));

// PREOF destination address: (egress ifindex, flow label) -> IPv6 locator address
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
 * @brief Extract the flow ID and sequence number from the PREOF SID which is the outer IPv6 destination address.
 * @param pkt The packet with headers.
 * @param flow_id Pointer to store the extracted 20-bit flow ID.
 * @param seq Pointer to store the extracted 16-bit sequence number.
 * @return 0 if successful, -1 if the packet is too short.
 */
static inline int read_preof_sid(struct xdp_md *pkt, uint32_t *flow_id, uint32_t *seq)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return -1;

    struct ipv6hdr *outer = data + ethhdr_sz;
    struct preof_sid *psid = (struct preof_sid *)&outer->daddr;
    *flow_id = psid->flow_id;
    *seq = psid->seq;

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
 * @param flow_label The flow label used to look up the rewrite address.
 * @return 0 if successful, -1 if the packet is too short or the address is not found.
 */
static inline int rewrite_outer_ipv6(struct xdp_md *pkt, uint32_t flow_label)
{
    int *tx_ifindex = bpf_map_lookup_elem(&eliminate_tx_map, &flow_label);
    if (!tx_ifindex)
        return -1;

    struct tx_key k = { .ifidx = *tx_ifindex, .flow_label = flow_label };
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
    struct preof_sid *psid = (struct preof_sid *)&outer->daddr;
    struct preof_sid *src = (struct preof_sid *)addr;
    psid->loc = src->loc;
    psid->funct = src->funct;

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
 * @brief Add an outer IPv6 header with a PREOF SID between the Ethernet header and the
 * original IPv6 header. The locator field is left empty for postprocessing to fill in.
 * Incoming: ETH | IPv6 | payload
 * Outgoing: ETH | outer IPv6 (nexthdr=41) | original IPv6 | payload
 * @param pkt The packet with headers.
 * @param flow_label The flow label from the original IPv6 header.
 * @param seq The sequence number to encode in the PREOF SID.
 * @return 0 if successful, -1 if the packet is invalid or there is no space for the header.
 */
static inline int add_outer_ipv6(struct xdp_md *pkt, int flow_label, uint16_t seq)
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

    // Build PREOF SID as destination address
    // psid->loc and psid->funct are set in postprocessing
    struct preof_sid *psid = (struct preof_sid *)&outer->daddr;
    psid->flow_id = flow_label;
    psid->seq = seq;
    psid->reserved = 0;

    return 0;
}

// Periodically invoked to reset timed-out sequence recovery entries.
SEC("xdp")
int check_reset(char *dummy) // unused param to satisfy verifier
{
    bpf_for_each_map_elem(&seqrcvy_map, sequence_recovery_reset, NULL, 0);
    return 1;
}

// PREOF replication: match IPv6 flow label, generate sequence number, add outer IPv6 with
// PREOF SID, set destination MAC, broadcast to egress interfaces.
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

    int flow_label = get_flow_label(pkt);
    if (flow_label < 0) {
        bpf_printk("[Repl] flow_label is not set");
        goto not_for_us;
    }

    bpf_printk("[Repl] flow_label: %d", flow_label);

    struct seq_gen *gen = bpf_map_lookup_elem(&seqgen_map, &flow_label);
    if (!gen) {
        bpf_printk("[Repl] seqgen_map lookup failed");
        goto not_for_us;
    }

    // Packet matched our criteria, count it as received
    __sync_fetch_and_add(&received, 1);

    int ret = 0;
    if (no_encap) {
        // Remove the SRH but keep the outer IPv6 header with the PREOF SID (preserving flow_id and seq).
        // The destination locator and function are rewritten per egress interface in replicate_postprocessing.
        ret = rm_srh(pkt);
        if (ret < 0) {
            bpf_printk("[Repl] Unable to remove SRH");
            goto drop;
        }
    } else {
        uint16_t seq = gen_seq(gen);
        bpf_printk("[Repl] generated seq %d", seq);
        
        ret = add_outer_ipv6(pkt, flow_label, seq);
        if (ret < 0) {
            bpf_printk("[Repl] add_outer_ipv6 failed");
            goto drop;
        }
    }

    struct tx_ifaces *tx = bpf_map_lookup_elem(&replicate_tx_map, &flow_label);
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
    bpf_printk("[Repl] pass");
    return bpf_redirect_map(tx, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
not_for_us:
    __sync_fetch_and_add(&unmatched, 1); // prevent race condition when increment the counter
    return XDP_PASS;
drop:
    return XDP_DROP;
}

// Per-egress devmap callback: fill in the locator portion of the PREOF SID from dst_addr_map.
SEC("xdp/devmap")
int replicate_postprocessing(struct xdp_md *pkt)
{
    struct tx_key k = { .ifidx = pkt->egress_ifindex, .flow_label = get_flow_label(pkt) };
    bpf_printk("[Repl postprocessing] key: ifidx %d, fl %d", k.ifidx, k.flow_label);
    struct in6_addr *addr = bpf_map_lookup_elem(&dst_addr_map, &k);
    if (!addr)
        return XDP_PASS;

    void *data = (void *)(long)pkt->data;
    void *data_end = (void *)(long)pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz > data_end)
        return XDP_DROP;

    struct ipv6hdr *outer = data + ethhdr_sz;
    struct preof_sid *psid = (struct preof_sid *)&outer->daddr;
    struct preof_sid *src = (struct preof_sid *)addr;
    psid->loc = src->loc;
    psid->funct = src->funct;

    bpf_printk("[Repl postprocessing] pass");
    return XDP_PASS;
}

// PREOF elimination: read PREOF SID, strip outer IPv6, run recovery algorithm, redirect or drop.
SEC("xdp")
int eliminate(struct xdp_md *pkt)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + ipv6hdr_sz + ipv6hdr_sz > data_end) {
        bpf_printk("[Elim] Not a good packet for us, pass");
        goto not_for_us;
    }

    uint32_t flow_label;
    uint32_t seq;
    int ret = read_preof_sid(pkt, &flow_label, &seq);
    if (ret < 0) {
        bpf_printk("[Elim] Unable to read PREOF SID");
        goto not_for_us;
    }

    bpf_printk("[Elim] flow_id: %d, seq: %d", flow_label, seq);

    struct seq_rcvy_and_hist *rec = bpf_map_lookup_elem(&seqrcvy_map, &flow_label);
    if (!rec) {
        bpf_printk("[Elim] drop wrong flow_label %d", flow_label);
        goto not_for_us;
    }

    if (no_encap) {
        ret = rewrite_outer_ipv6(pkt, flow_label);
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

    int *tx_ifindex = bpf_map_lookup_elem(&eliminate_tx_map, &flow_label);
    if (!tx_ifindex) {
        bpf_printk("[Elim] drop wrong flow_label %d", flow_label);
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
