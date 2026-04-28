#include "bpf_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct rtaghdr {
    uint16_t reserved;  // 16 bits - Reserved
    uint16_t seq;       // 16 bits - Sequence number
    uint16_t nexthdr;   // 16 bits - Next header
} __attribute__((packed));

// Replication VLAN translation: egress ifindex -> VLAN ID mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct vlan_translation_entry));
} rvt SEC(".maps");

// Elimination VLAN translation: ingress ifindex -> VLAN ID mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct vlan_translation_entry));
} evt SEC(".maps");

const size_t ethhdr_sz = sizeof(struct ethhdr);
const size_t vlanhdr_sz = sizeof(struct vlan_hdr);
const size_t rtaghdr_sz = sizeof(struct rtaghdr);
const size_t iphdr_sz = sizeof(struct iphdr);

/**
 * @brief Get the VLAN ID of the packet from the header.
 * @param pkt The packet with headers.
 * @return The VLAN ID, or -1 if the packet is too short or not VLAN-tagged.
 */
static int get_vlan_id(const struct xdp_md *pkt)
{
    // Error bound check for the sake of the verifier
    const void *data = (void *)(long) pkt->data;
    const void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz > data_end)
        return -1;

    // Check the EtherType, because VLAN uses 0x8100 EtherType value
    // The h_proto is a big-endian 16-bit integer therefore it needs to process with htons
    const struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(0x8100))
        return -1;

    // The last 12 bits of the TCI are the VLAN ID
    const struct vlan_hdr *vhdr = data + ethhdr_sz;
    return bpf_ntohs(vhdr->h_vlan_TCI) & 0x0fff;
}

/**
 * @brief Put an R-tag into the packet's Ethernet header. R-tag should be placed after the VLAN
 * tag based on the standard.
 * @param pkt The packet with headers.
 * @param seq The sequence number that will appear in the R-tag.
 * @return 0 if successful, -1 if the packet is invalid or there is no space for the R-tag.
 */
static inline int add_rtag(struct xdp_md *pkt, ushort *seq)
{
    // Make room for the R-tag at the beginning of the packet
    if (bpf_xdp_adjust_head(pkt, 0 - (int)rtaghdr_sz))
        return -1;

    // Error bound check for the sake of the verifier
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if(data + rtaghdr_sz + ethhdr_sz + vlanhdr_sz > data_end)
        return -1;

    // Move Ethernet and VLAN headers to the front of the buffer
    __builtin_memmove(data, data + rtaghdr_sz, ethhdr_sz + vlanhdr_sz);
    struct vlan_hdr *vhdr = data + ethhdr_sz;
    struct rtaghdr *rtag = data + ethhdr_sz + vlanhdr_sz;

    // Prepare the R-tag
    __builtin_memset(rtag, 0, rtaghdr_sz);
    rtag->nexthdr = vhdr->h_vlan_encapsulated_proto;
    vhdr->h_vlan_encapsulated_proto = bpf_htons(0xf1c1);
    rtag->seq = bpf_htons(*seq);

    return 0;
}

/**
 * @brief Remove the R-tag from the packet's header. R-tag can be found after the VLAN ID.
 * @param pkt The packet with headers.
 * @param seq A pointer that will store the sequence number from the packet's R-tag.
 * @return 0 if successful, -1 if the packet is invalid or the R-tag removal failed.
 */
static inline int rm_rtag(struct xdp_md *pkt, ushort *seq)
{
    // Error bound check for the sake of the verifier
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz + rtaghdr_sz > data_end)
        return -1;

    // Find the R-tag
    struct vlan_hdr *vhdr = data + ethhdr_sz;
    struct rtaghdr *rtag = data + ethhdr_sz + vlanhdr_sz;
    vhdr->h_vlan_encapsulated_proto = rtag->nexthdr;

    // Get the seq number from R-tag
    *seq = bpf_ntohs(rtag->seq);

    // Remove the R-tag
    if (!no_encap) {
        __builtin_memmove(data + rtaghdr_sz, data, ethhdr_sz + vlanhdr_sz);
        if (bpf_xdp_adjust_head(pkt, (int)rtaghdr_sz))
            return -1;
    }

    return 0;
}

/**
 * @brief Change the VLAN ID in the packet's VLAN header.
 * @param pkt The packet with headers.
 * @param ifindex The interface index used to look up the VLAN translation entry.
 * @param replication True to use the replication (rvt) table, false for elimination (evt).
 * @return 0 if VLAN changing was successful, -1 if the packet was invalid or the VLAN entry was not
 * found or the VLAN ID was not matched with the old one.
 */
static inline int change_vlan(const struct xdp_md *pkt, int ifindex, bool replication)
{
    // Error bound check for the sake of the verifier
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz > data_end)
        return -1;

    // Get the VLAN ID
    struct ethhdr *const eth = data;
    struct vlan_hdr *const vhdr = data + ethhdr_sz;
    int old_vid = get_vlan_id(pkt);
    if (old_vid < 0)
        return -1;

    // Change the VLAN ID
    struct vlan_translation_entry *vte;
    if (replication) {
        vte = bpf_map_lookup_elem(&rvt, &ifindex);
    } else {
        vte = bpf_map_lookup_elem(&evt, &ifindex);
    }
    
    if (!vte)
        return 0;

    if (old_vid == vte->from) {
        vhdr->h_vlan_TCI = bpf_htons(vte->to);
    } else {
        return -1;
    }
    return 0;
}

// Periodically invoked to reset timed-out sequence recovery entries.
SEC("xdp")
int check_reset(char *dummy) // unused param to satisfy verifier
{
    bpf_for_each_map_elem(&seqrcvy_map, sequence_recovery_reset, NULL, 0);
    return 1;
}

// FRER replication: match VLAN, generate sequence number, add R-tag, broadcast to egress interfaces.
SEC("xdp")
int replicate(struct xdp_md *pkt)
{
    __sync_fetch_and_add(&received, 1); // prevent race condition when increment the counter
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz > data_end)
        return XDP_DROP;

    int vid = get_vlan_id(pkt);
    if (vid < 0)
        return XDP_DROP;

    struct seq_gen *gen = bpf_map_lookup_elem(&seqgen_map, &vid);
    if (!gen)
        return XDP_DROP;

    if (!no_encap) {
        uint16_t seq = gen_seq(gen);
        int ret = add_rtag(pkt, &seq);
        if (ret < 0)
            return XDP_DROP;
    }

    struct tx_ifaces *tx = bpf_map_lookup_elem(&replicate_tx_map, &vid);
    if (!tx)
        return XDP_DROP;

    return bpf_redirect_map(tx, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

// Per-egress devmap callback: translate VLAN ID after replication.
SEC("xdp/devmap")
int replicate_postprocessing(struct xdp_md *pkt)
{
    int ret = change_vlan(pkt, pkt->egress_ifindex, true);
    if (ret < 0)
        return XDP_DROP;

    return XDP_PASS;
}

// FRER elimination: translate VLAN, extract sequence from R-tag, run recovery, redirect or drop.
SEC("xdp")
int eliminate(struct xdp_md *pkt)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz + rtaghdr_sz > data_end)
        goto drop;

    int ret = change_vlan(pkt, pkt->ingress_ifindex, false);
    if (ret < 0)
        goto drop;

    int vid = get_vlan_id(pkt);
    if (vid < 0)
        goto drop;

    struct seq_rcvy_and_hist *rec = bpf_map_lookup_elem(&seqrcvy_map, &vid);
    if (!rec)
        goto drop;

    ushort seq;
    ret = rm_rtag(pkt, &seq);
    if (ret < 0)
        goto drop;

    int *tx_ifindex = bpf_map_lookup_elem(&eliminate_tx_map, &vid);
    if (!tx_ifindex)
        goto drop;

    bpf_spin_lock(&(rec->lock)); // lock
    bool pass = recover(rec, seq); 
    bpf_spin_unlock(&(rec->lock)); // unlock
    if (pass == false)
        goto drop;

pass:
    __sync_fetch_and_add(&passed, 1); // prevent race condition when increment the counter
    rec->last_packet_ns = bpf_ktime_get_ns();
    return bpf_redirect(*tx_ifindex, 0);
drop:
    __sync_fetch_and_add(&dropped, 1); // prevent race condition when increment the counter
    return XDP_DROP;
}
