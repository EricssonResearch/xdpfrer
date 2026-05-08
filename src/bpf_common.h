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

// Match ID -> sequence number generator
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __uint(key_size, sizeof(int64_t));
    __uint(value_size, sizeof(struct seq_gen));
} seqgen_map SEC(".maps");

// Match ID -> replication TX interfaces (devmap)
struct tx_ifaces { //helper for the verifier
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct bpf_devmap_val));
};

// Match ID -> devmap of replication TX interfaces
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FLOWS);
    __uint(key_size, sizeof(int64_t));
    __array(values, struct tx_ifaces);
} replicate_tx_map SEC(".maps");

// Match ID -> History window index (indirection for shared history window)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __uint(key_size, sizeof(int64_t));
    __uint(value_size, sizeof(int));
} seqrcvy_idx_map SEC(".maps");

// History window index -> History window
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FLOWS);
    __type(key, int);
    __type(value, struct seq_rcvy_and_hist);
} seqrcvy_map SEC(".maps");

// Match ID -> elimination TX interface (ifindex)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __uint(key_size, sizeof(int64_t));
    __uint(value_size, sizeof(int));
} eliminate_tx_map SEC(".maps");

volatile int received = 0;
volatile int dropped = 0;
volatile int passed = 0;
volatile int unmatched = 0;

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
 * frerCpsSeqRcvyResets, and sets TakeAny.
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
    if (rec && rec->take_any)
        return 1;

    if (bpf_ktime_get_ns() - rec->last_packet_ns < FRER_RECOVERY_TIMEOUT_NS)
        return 1;

    rec->history_window = 0;
    rec->recv_seq = 0;
    rec->take_any = true;
    rec->latent_error_resets += 1;

    return 0;
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
static inline bool recover(struct seq_rcvy_and_hist *rec, uint16_t seq)
{
    int delta = calc_delta(seq, rec->recv_seq);

    // After the reset, accept the first incoming packet
    if (rec->take_any) {
        rec->history_window |= (1ULL << (FRER_DEFAULT_HIST_LEN - 1)); // set the first bit to 1
        rec->take_any = false;
        rec->recv_seq = seq;
        rec->passed_packets += 1;
        return true;
    } else if (delta >= FRER_DEFAULT_HIST_LEN || delta <= -FRER_DEFAULT_HIST_LEN) {
        rec->rogue_packets += 1;
        rec->discarded_packets += 1;
    } else if (delta <= 0) {
        if (-delta >= FRER_DEFAULT_HIST_LEN) // error check for the sake of the verifier
            return false;

        if (((rec->history_window >> (FRER_DEFAULT_HIST_LEN - 1 + delta)) & 1ULL) == 0) { // check bit for this seq
            rec->history_window |= (1ULL << (FRER_DEFAULT_HIST_LEN - 1 + delta)); // set the bit
            rec->out_of_order_packets += 1;
            rec->passed_packets += 1;
            return true;
        } else {
            rec->discarded_packets += 1;
        }
    } else {
        // Packet has not been seen before, we can accept it
        if (delta != 1) {
            rec->out_of_order_packets += 1;
        }
        rec->history_window = (rec->history_window >> delta); // shift every bit to the right
        rec->history_window |= (1ULL << (FRER_DEFAULT_HIST_LEN - 1)); // set the first bit to 1
        rec->recv_seq = seq;
        rec->passed_packets += 1;
        return true;
    }

    return false;
}

#endif // _H_BPF_COMMON
