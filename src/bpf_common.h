#ifndef _H_BPF_COMMON
#define _H_BPF_COMMON

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

// Match ID (VLAN ID or flow label) -> sequence number generator
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct seq_gen));
} seqgen_map SEC(".maps");

// Match ID (VLAN ID or flow label) -> replication TX interfaces (devmap)
struct tx_ifaces { //helper for the verifier
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct bpf_devmap_val));
};

// Match ID -> devmap of replication TX interfaces
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __array(values, struct tx_ifaces);
} replicate_tx_map SEC(".maps");

// Match ID -> sequence recovery state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, int);
    __type(value, struct seq_rcvy_and_hist);
} seqrcvy_map SEC(".maps");

// Match ID -> elimination TX interface (ifindex)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} eliminate_tx_map SEC(".maps");

volatile int received = 0;
volatile int dropped = 0;
volatile int passed = 0;
volatile int unmatched = 0;
volatile bool add_or_rm_rtag = true;

/**
 * @brief Generate a sequence number between 0 and 65535. If it reaches 65535 then start from 0 again.
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
 * @param map A bpf hashmap.
 * @param key A key in the hashmap.
 * @param value A value in the hashmap.
 * @param ctx Provide additional input and allow to write to caller stack for output.
 * @return If the callback function returns 0, the helper will iterate through next element if available.
 * If the callback function returns 1, the helper will stop iterating and returns to the bpf program.
 * Other return values are not used for now.
 */
static inline short sequence_recovery_reset(struct bpf_map *map, const void *key, void *value, void *ctx)
{
    struct seq_rcvy_and_hist *rec = (struct seq_rcvy_and_hist *)value;
    if (rec && ((rec->hist_recvseq_takeany >> TAKE_ANY) & 1LU) == true)
        return 1;

    if (bpf_ktime_get_ns() - rec->last_packet_ns < FRER_RECOVERY_TIMEOUT_NS)
        return 1;

    rec->hist_recvseq_takeany = 0; // reset the history window
    rec->hist_recvseq_takeany ^= (-(true) ^ rec->hist_recvseq_takeany) & (1UL << TAKE_ANY); // set take_any to true
    rec->latent_error_resets += 1;

    return 0;
}

/**
 * @brief Extract a range of bits from the HST bit-packed variable.
 * @param value The 64-bit HST variable.
 * @param from The starting bit position (inclusive).
 * @param to The ending bit position (inclusive).
 * @return The extracted bits as an unsigned long.
 */
static inline ulong bit_range(HST value, int from, int to) {
    HST waste = sizeof(HST) * 8 - to - 1;
    return (value << waste) >> (waste + from);
}

/**
 * @brief Set bits of the 64-bit variable that stores the RecovSeqNum, SequenceHistory, and TakeAny.
 * @param hst The 64-bit variable that stores the RecovSeqNum, SequenceHistory, and TakeAny.
 * @param history_window The SequenceHistory.
 * @param recv_seq The RecovSeqNum so-called sequence number.
 * @param take_any The TakeAny.
 * @param rec The sequence recovery struct that stores the SequenceHistory.
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
 * @param rec The sequence recovery struct that stores the SequenceHistory.
 * @param seq The packet sequence number.
 * @return True if the packet is going to be accepted or false if the packet is going to be dropped.
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

#endif // _H_BPF_COMMON
