#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

struct rtaghdr {
    uint16_t reserved;
    uint16_t seq;
    uint16_t nexthdr;
} __attribute__((packed)); // avoid to add paddings (spaces without actual data) by the compiler

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

// Replication VLAN match/translation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct vlan_translation_entry));
} rvt SEC(".maps");

// Elimination VLAN match/translation
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

volatile int packets_seen = 0;
volatile int dropped = 0;
volatile int passed = 0;
volatile bool add_or_rm_rtag = true;

/**
 * @brief Generates a sequence number between 0 and 65535. If it reaches 65535 then start from 0 again.
 * @param gen is a struct pointer where `gen->gen_seq_num` is the sequence number
 * @return the generated sequence number
 */
static inline short gen_seq(struct seq_gen *gen)
{
    int seq = gen->gen_seq_num;
    if (gen->gen_seq_num >= FRER_RCVY_SEQ_SPACE - 1)
        gen->gen_seq_num = 0;
    else
        gen->gen_seq_num += 1;
    return seq;
}

/**
 * @brief (7.4.3.3 SequenceRecoveryReset)
 * SequenceRecoveryReset is called whenever the BEGIN event or the RECOVERY_TIMEOUT event occurs.
 * It resets the RecovSeqNum and SequenceHistory variables to their initial states, increments
 * frerCpsSeqRcvyResets, and sets TakeAny. Note that RecovSeqNum and SequenceHistory are reset only
 * if the VectorRecoveryAlgorithm is configured.
 * This function is a callback function in `bpf_for_each_map_elem` that means this function is going
 * to be called for every item in the bpf map.
 * @param map is a bpf hashmap
 * @param key is a key in the hashmap
 * @param value is a value in the hashmap
 * @param ctx can provide additional input and allow to write to caller stack for output
 * @return If the callback function returns 0, the helper will iterate through next element if available.
 * If the callback function returns 1, the helper will stop iterating and returns to the bpf program.
 * Other return values are not used for now.
 */
static inline short sequence_recovery_reset(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct seq_rcvy_and_hist *rec = (struct seq_rcvy_and_hist *)value;
    if (rec && ((rec->hist_recvseq_takeany >> TAKE_ANY) & 1LU) == true)
        return 1;
        //goto end;

    if (bpf_ktime_get_ns() - rec->last_packet_ns < FRER_RECOVERY_TIMEOUT_NS)
        return 1;
        //goto end;

    rec->hist_recvseq_takeany = 0; // reset the history window
    rec->hist_recvseq_takeany ^= (-(true) ^ rec->hist_recvseq_takeany) & (1UL << TAKE_ANY); // set take_any to true
    rec->latent_error_resets += 1;
end:
    return 0;
}

/**
 * @brief When SequenceRecoveryReset is called, it resets RecovSeqNum and SequenceHistory variables to their initial
 * states and sets TakeAny. These 3 variables are stored in HST which is a 64 bits long variable. 0th-46th bits store
 * the SequenceHistory so-called history window, 47th-62nd bits store the RecovSeqNum, and 63rd bit is the TakeAny.
 * This function selects bits from a given bit to a given bit.
 * @param value is the 64-bit variable that stores the RecovSeqNum, SequenceHistory, and TakeAny
 * @param from is the first bit
 * @param to is the last bit
 * @return the selected part of the 64-bit variable
 */
static inline ulong bit_range(HST value, int from, int to) {
    HST waste = sizeof(HST) * 8 - to - 1;
    return (value << waste) >> (waste + from);
}

/**
 * @brief Sets bits of the 64-bit variable that stores the RecovSeqNum, SequenceHistory, and TakeAny.
 * @param hst is the 64-bit variable that stores the RecovSeqNum, SequenceHistory, and TakeAny
 * @param history_window is the SequenceHistory
 * @param recv_seq is the RecovSeqNum so-called sequence number
 * @param take_any is the TakeAny
 * @param rec is the sequence recovery struct that stores the SequenceHistory
 */
static inline void set_hst(HST hst, uint64_t history_window, ushort recv_seq, bool take_any, struct seq_rcvy_and_hist *rec)
{
    // Copy the history window into the hst
    for (int i = 0; i < SEQ_START_BIT; i++)
        hst ^= (-((history_window >> i) & 1LU) ^ hst) & (1UL << i);

    // Copy the seqence number into the hst
    for (int i = SEQ_START_BIT; i < TAKE_ANY; i++)
        hst ^= ((-((recv_seq >> (i - SEQ_START_BIT)) & 1LU)) ^ hst) & (1UL << i);

    // Set the take any
    hst ^= (-(take_any) ^ hst) & (1UL << TAKE_ANY);

    rec->hist_recvseq_takeany = hst;
}

/**
 * @brief (7.4.3.4) VectorRecoveryAlgorithm
 * Immediately after SequenceRecoveryReset (7.4.3.3) is called, the VectorRecoveryAlgorithm accepts the first packet received
 * as valid. After the first packet has been accepted, all subsequent packets that are in the window last packet number
 * accepted ± frerSeqRcvyHistoryLength are accepted, and those packets with sequence number values outside that range are discarded.
 * If the sequence number occurred before that means the deltath bit is 1 in the SequenceHistory so-called history window and this
 * packet will not be accepted.
 * NOTE: In this function, you can not call any functions, because function calls are not possible while holding lock.
 * @param rec is the sequence recovery struct that stores the SequenceHistory
 * @param seq is the packet sequence number
 * @return true if the packet is going to be accepted or false if the packet is going to be dropped
 */
static inline bool recover(struct seq_rcvy_and_hist *rec, ushort seq)
{
    HST hst = rec->hist_recvseq_takeany;
    uint64_t history_window = bit_range(hst, 0, SEQ_START_BIT - 1);
    bool take_any = (hst >> TAKE_ANY) & 1LU;
    ushort recv_seq = bit_range(hst, SEQ_START_BIT, TAKE_ANY - 1);
    int delta = calc_delta(seq, recv_seq);

    // After the reset, accept the first incoming packet
    if (take_any) {
        history_window |= (1UL << (FRER_DEFAULT_HIST_LEN - 1)); // set the first bit to 1
        take_any = false;
        recv_seq = seq;
        rec->passed_packets += 1;
        goto pass;
    } else if (delta >= FRER_DEFAULT_HIST_LEN || delta <= -FRER_DEFAULT_HIST_LEN) {
        rec->rogue_packets += 1;
        rec->discarded_packets += 1;
    } else if (delta <= 0) {
        if (-delta != FRER_DEFAULT_HIST_LEN) // error check for the sake of the verifier
            goto drop;

        if (((history_window >> -delta) & 1LU) == 0) { // checking -deltath bit
            history_window |= (1UL << -delta); // set the deltath bit to 1
            rec->out_of_order_packets += 1;
            rec->passed_packets += 1;
            goto pass;
        } else {
            rec->discarded_packets += 1;
        }
    } else {
        // Packet has not been seen before, we can accept it
        if (delta != 1) {
            rec->out_of_order_packets += 1;
        }
        history_window = (history_window >> delta); // shift every bit to the right
        history_window |= (1UL << (FRER_DEFAULT_HIST_LEN - 1)); // set the first bit to 1
        recv_seq = seq;
        rec->passed_packets += 1;
        goto pass;
    }
    goto drop;

drop:
    set_hst(hst, history_window, recv_seq, take_any, rec);
    return false;
pass:
    set_hst(hst, history_window, recv_seq, take_any, rec);
    return true;
}

/**
 * @brief Gets the VLAN ID of the packet from the header.
 * @param pkt is the packet with headers
 * @return the VLAN number
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
 * @brief Puts an R-tag into the packet's ethernet header. R-tag should be placed after the VLAN tag based on the standard.
 * @param pkt is the packet with headers
 * @param seq is the sequence number that will appear in the R-tag
 * @return -1 if we can't make space for the R-tag or the packet is invalid, 0 if it was successful
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
 * @brief Removes the R-tag from the packet's header. R-tag can be found in the ethernet header, after the VLAN ID based on the standard.
 * @param pkt is the packet with headers
 * @param seq is a pointer that will store the sequence number from the packet's R-tag
 * @return -1 if the packet is invalid or the R-tag removal was unsuccessful, 0 if the removal was successful
 */
static inline int rm_rtag(struct xdp_md *pkt, ushort *seq)
{
    // Error bound check for the sake of the verifier
    void *data = (void *)(long) pkt->data;
    void *data_end = (void *)(long) pkt->data_end;
    if (data + ethhdr_sz + vlanhdr_sz + rtaghdr_sz > data_end)
        return -1;

    // Find the R-tag in the header
    struct vlan_hdr *vhdr = data + ethhdr_sz;
    struct rtaghdr *rtag = data + ethhdr_sz + vlanhdr_sz;
    vhdr->h_vlan_encapsulated_proto = rtag->nexthdr;

    // Get the seq number from R-tag
    *seq = bpf_ntohs(rtag->seq);

    // Remove the R-tag
    if (add_or_rm_rtag) {
        __builtin_memmove(data + rtaghdr_sz, data, ethhdr_sz + vlanhdr_sz);
        if (bpf_xdp_adjust_head(pkt, (int)rtaghdr_sz))
            return -1;
    }

    return 0;
}

/**
 * @brief Changes the VLAN ID in the packet's ethernet header.
 * @param pkt is the packet with headers
 * @param ingress is true if the interface is an ingress interface
 * @return -1 if the packet was invalid or the VLAN entry was not found or the VLAN ID was not matched with the
 * old one, 0 if VLAN changing was successful
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

SEC("xdp")
int check_reset(char *dummy) // unused param to satisfy verifier
{
    bpf_for_each_map_elem(&seqrcvy_map, sequence_recovery_reset, NULL, 0);
    return 1;
}


SEC("xdp")
int replicate(struct xdp_md *pkt)
{
    __sync_fetch_and_add(&packets_seen, 1); // prevent race condition when increment the counter
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

    if (add_or_rm_rtag) {
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
