#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

static inline int genseq(struct seq_gen *gen)
{
    int seq = gen->gen_seq_num;
    if (gen->gen_seq_num >= FRER_RCVY_SEQ_SPACE - 1)
        gen->gen_seq_num = 0;
    else
        gen->gen_seq_num += 1;
    return seq;
}

struct rtaghdr {
    uint16_t reserved;
    uint16_t seq;
    uint16_t nexthdr;
} __attribute__((packed));

/* const size_t udphdr_sz = sizeof(struct udphdr); */
const size_t ethhdr_sz = sizeof(struct ethhdr);
const size_t vlanhdr_sz = sizeof(struct vlan_hdr);
const size_t rtaghdr_sz = sizeof(struct rtaghdr);
const size_t iphdr_sz = sizeof(struct iphdr);

// UNI VLAN ---> Seq generator
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct seq_gen));
} seqgen_map SEC(".maps");

// UNI VLAN ---> Replication TX interfaces (devmap)
struct tx_ifaces { //helper for the verifier
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct bpf_devmap_val));
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    /* __uint(value_size, sizeof(int)); */
    __array(values, struct tx_ifaces);
} replicate_tx_map SEC(".maps");

// NNI VLAN ---> Seq recovery
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, struct seq_rcvy_and_hist);
} seqrcvy_map SEC(".maps");

// NNI VLAN ---> Elimination TX interface (ifindex)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} eliminate_tx_map SEC(".maps");

// VLAN translation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct vlan_translation_entry));
} rvt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct vlan_translation_entry));
} evt SEC(".maps");


// History window maps
/*struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, HISTORY_WINDOW_TYPE);
} history_maps SEC(".maps");*/

// Timer map
/* struct timer { */
/*     __uint(type, BPF_MAP_TYPE_HASH); */
/*     __uint(max_entries, 8); */
/*     __uint(key_size, sizeof(int)); */
/*     __uint(value_size, sizeof(struct timer_map_elem)); */
/* } timer_map SEC(".maps"); */

volatile int packets_seen = 0;
volatile int dropped = 0;
volatile int passed = 0;

static inline long reset_recovery_cb(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct seq_rcvy_and_hist *rec = value;
    if (rec && ((rec->hist_recvseq_takeany >> TAKE_ANY) & 1LU) == true)
        goto end;

    if (bpf_ktime_get_ns() - rec->last_packet_ns < FRER_RCVY_TIMEOUT_NS)
        goto end;

    // Reset history window
    rec->hist_recvseq_takeany = 0;

    rec->hist_recvseq_takeany ^= (-(true) ^ rec->hist_recvseq_takeany) & (1UL << TAKE_ANY); // set take any true
    rec->latent_error_resets += 1;
    //bpf_printk("Seq recovery reset for VLAN %d", *((int *) key));
end:
    return 0;
}

static void timer_cb()
{
    /* bpf_printk("Run timer callback!"); */
    bpf_for_each_map_elem(&seqrcvy_map, reset_recovery_cb, NULL, 0);
    /* int key = 0; */
    /* struct timer_map_elem *te = bpf_map_lookup_elem(&timer_map, &key); */
    /* if (!te) { */
    /*     return; */
    /* } */
    /* struct bpf_timer *recovery_timer = &te->t; */
    /* bpf_timer_start(recovery_timer, FRER_TIMEOUT_CHECK_PERIOD_NS, 0); */
}

static inline ulong bit_range(HST value, int from, int to) {
    HST waste = sizeof(HST) * 8 - to - 1;
    return (value << waste) >> (waste + from);
}

static inline bool recover(struct seq_rcvy_and_hist *rec, ushort seq)
{
    HST hst = rec->hist_recvseq_takeany;
    uint64_t history_window = bit_range(hst, 0, SEQ_START_BIT - 1);
    bool take_any = (hst >> TAKE_ANY) & 1LU;
    ushort recv_seq = bit_range(hst, SEQ_START_BIT, TAKE_ANY - 1);

    int delta = calc_delta(seq, recv_seq);
    if (take_any) {
        history_window |= (1UL << (FRER_DEFAULT_HIST_LEN - 1)); // set first bit to 1
        take_any = false;
        recv_seq = seq;
        rec->passed_packets += 1;
        reset_ticks(rec);
        //return true;
        goto pass;
    } else if (delta >= FRER_DEFAULT_HIST_LEN || delta <= -FRER_DEFAULT_HIST_LEN) {
        rec->rogue_packets += 1;
        rec->discarded_packets += 1;

        if (rec->individual_recovery)
            reset_ticks(rec);
    } else if (delta <= 0) {
        if (-delta != FRER_DEFAULT_HIST_LEN) { // error check for verifier
            //return false;
            goto drop;
        }

        if (((history_window >> -delta) & 1LU) == 0) { // checking -deltath bit
            history_window |= (1UL << -delta); // set deltath bit to 1
            rec->out_of_order_packets += 1;
            rec->passed_packets += 1;
            reset_ticks(rec);
            //return true;
            goto pass;
        } else {
            rec->discarded_packets += 1;
            if(rec->individual_recovery)
               reset_ticks(rec);
        }
    } else {
        if (delta != 1) {
            rec->out_of_order_packets += 1;
        }
        history_window = (history_window >> delta); // shift every bit to right
        history_window |= (1UL << (FRER_DEFAULT_HIST_LEN - 1)); // set first bit to 1
        recv_seq = seq;
        rec->passed_packets += 1;
        reset_ticks(rec);
        //return true;
        goto pass;
    }
    //return false;
    goto drop;
drop:
    // Copy history window to hst.
    for (int i = 0; i < SEQ_START_BIT; i++)
        hst ^= (-((history_window >> i) & 1LU) ^ hst) & (1UL << i);

    // Copy seqence number to hst.
    for (int i = SEQ_START_BIT; i < TAKE_ANY; i++)
        hst ^= ((-((recv_seq >> (i - SEQ_START_BIT)) & 1LU)) ^ hst) & (1UL << i);

    // Set take any.
    hst ^= (-(take_any) ^ hst) & (1UL << TAKE_ANY);

    rec->hist_recvseq_takeany = hst;
    return false;
pass:
    // Copy history window to hst.
    for (int i = 0; i < SEQ_START_BIT; i++)
        hst ^= (-((history_window >> i) & 1LU) ^ hst) & (1UL << i);

    // Copy seqence number to hst.
    for (int i = SEQ_START_BIT; i < TAKE_ANY; i++)
        hst ^= ((-((recv_seq >> (i - SEQ_START_BIT)) & 1LU)) ^ hst) & (1UL << i);

    // Set take any.
    hst ^= (-(take_any) ^ hst) & (1UL << TAKE_ANY);

    rec->hist_recvseq_takeany = hst;
    return true;
}

static int get_vlan_id(const struct xdp_md *pkt)
{
    const void *data = (void *)(long) pkt->data;
    const void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz > data_end)
        return -1;

    const struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(0x8100))
        return -1;

    const struct vlan_hdr *vhdr = data + ethhdr_sz;
    return bpf_ntohs(vhdr->h_vlan_TCI) & 0x0fff;
}

static inline int add_rtag(struct xdp_md *pkt, ushort *seq)
{
    // Make room for R-tag
    if (bpf_xdp_adjust_head(pkt, 0 - (int)rtaghdr_sz))
        return -1;

    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if(data + rtaghdr_sz + ethhdr_sz + vlanhdr_sz > data_end) // bound check for verifier
        return -1;

    // Move Ethernet+VLAN headers to the front of the buffer
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

static inline int rm_rtag(struct xdp_md *pkt, ushort *seq)
{
    // Find the R-tag in the header
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz + rtaghdr_sz > data_end)
        return -1;

    struct vlan_hdr *vhdr = data + ethhdr_sz;
    struct rtaghdr *rtag = data + ethhdr_sz + vlanhdr_sz;

    //TODO: restore next proto header after R-tag
    vhdr->h_vlan_encapsulated_proto = rtag->nexthdr;

    // Get the seq number from R-tag
    *seq = bpf_ntohs(rtag->seq);

    // Remove the R-tag
    __builtin_memmove(data + rtaghdr_sz, data, ethhdr_sz + vlanhdr_sz);
    if (bpf_xdp_adjust_head(pkt, (int)rtaghdr_sz))
        return -1;

    return 0;
}

static inline int change_vlan(const struct xdp_md *pkt, int ifindex, bool replication)
{
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz > data_end)
        return -1;

    struct ethhdr *const eth = data;
    struct vlan_hdr *const vhdr = data + ethhdr_sz;
    int old_vid = get_vlan_id(pkt);
    if (old_vid < 0)
        return -1;

    //bpf_printk("Old VID valid: %d ifinex: %d replication: %d", old_vid, ifindex, replication);
    struct vlan_translation_entry *vte;
    if (replication) {
        vte = bpf_map_lookup_elem(&rvt, &ifindex);
    } else {
        vte = bpf_map_lookup_elem(&evt, &ifindex);
    }
    
    if (!vte)
        return 0;

    if (old_vid == vte->from) {
        // dropping PCP and DCE
        vhdr->h_vlan_TCI = bpf_htons(vte->to);
    } else {
        //bpf_printk("Invalid VTE, drop packet (from %d, to %d, %s)", vte->from, vte->to, ingress ? "ingress" : "egress");
        return -1;
    }
    return 0;
}

/* SEC("xdp") */
/* __attribute__((noinline)) */
/* int init_timer(void) */
/* { */
/*     bpf_printk("RUN PROG!!!"); */
/*     int key = 0; */
/*     struct timer_map_elem init = { }; */
/*     bpf_map_update_elem(&timer_map, &key, &init, 0); */
/*     struct timer_map_elem *te = bpf_map_lookup_elem(&timer_map, &key); */
/*     if (te) { */
/*         struct bpf_timer *timer = &te->t; */
/*         bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC); */
/*         bpf_timer_set_callback(timer, timer_cb); */
/*         bpf_timer_start(timer, FRER_TIMEOUT_CHECK_PERIOD_NS, 0); */
/*     } */
/*     return 0; */
/* } */

SEC("xdp")
int check_reset(void)
{
    timer_cb();
    return 1;
}


SEC("xdp")
int replicate(struct xdp_md *pkt)
{
    //bpf_printk("\n\n---- Replicate XDP prog run");
    __sync_fetch_and_add(&packets_seen, 1); // prevent race condition when increment counters
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
    //bpf_printk("Generator for %d VID found", vid);

    uint16_t seq = genseq(gen);
    int ret = add_rtag(pkt, &seq);
    if (ret < 0)
        return XDP_DROP;

    struct tx_ifaces *tx = bpf_map_lookup_elem(&replicate_tx_map, &vid);
    if (!tx)
        return XDP_DROP;

    //bpf_printk("Broadcast the packet");

    return bpf_redirect_map(tx, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

SEC("xdp/devmap")
int replicate_postprocessing(struct xdp_md *pkt)
{
    int ret = change_vlan(pkt, pkt->egress_ifindex, true);
    if (ret < 0)
        return XDP_DROP;

    return XDP_PASS;
}

SEC("xdp")
int eliminate(struct xdp_md *pkt)
{
    //bpf_printk("\n\n---- Eliminate XDP prog run");
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

    bpf_spin_lock(&(rec->lock));
    bool pass = recover(rec, seq); 
    bpf_spin_unlock(&(rec->lock));
    if (pass == false)
        goto drop;

pass:
    __sync_fetch_and_add(&passed, 1); // prevent race condition when increment counters
    //bpf_printk("Passed!");
    rec->last_packet_ns = bpf_ktime_get_ns();
    return bpf_redirect(*tx_ifindex, 0);
drop:
    __sync_fetch_and_add(&dropped, 1); // prevent race condition when increment counters
    return XDP_DROP;
}
