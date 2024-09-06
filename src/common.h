#ifndef _H_COMMON
#define _H_COMMON

// HST = history window, sequence number, take any
// 0th-46th bit means the history window
// 47th-62nd bit means the sequence number
// 63rd means the take any
typedef uint64_t HST;
#define TAKE_ANY 63
#define SEQ_START_BIT 47
#define FRER_DEFAULT_HIST_LEN 47
#define FRER_RCVY_SEQ_SPACE (1 << 16) // 65536
#define FRER_RECOVERY_TIMEOUT_NS ((1000*1000*1000)*2) // 2 seconds
#define FRER_TIMEOUT_CHECK_PERIOD_NS ((1000*1000*1000) / 100) //every 10ms

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

struct vlan_translation_entry {
    int from;
    int to;
};

struct seq_rcvy_and_hist {
    unsigned reset_msec;
    bool individual_recovery;

    HST hist_recvseq_takeany;

    int lost_packets;
    int out_of_order_packets;
    int passed_packets;
    int rogue_packets;
    int discarded_packets;
    int remaining_ticks;
    int seq_recovery_resets;
    int latent_errors;
    int latent_reset_counter;
    int latent_error_counter;
    int latent_error_resets;

    unsigned long last_packet_ns;
    struct bpf_spin_lock lock;
};

struct seq_gen {
    int gen_seq_num;
    int resets;
};

/**
 * @brief Calculates the distance between `seq1` and `seq2`. Sequence numbers can be between 0 to 65535. This function
 * can calculate the difference at the end of a cycle.
 * @param seq1 is a sequence number
 * @param seq2 is a sequence number
 * @return the distance between the two sequence numbers
 */
static inline int calc_delta(ushort seq1, ushort seq2)
{
    int delta = (seq1 - seq2) & (FRER_RCVY_SEQ_SPACE - 1);
    if((delta & (FRER_RCVY_SEQ_SPACE / 2)) != 0)
        delta = delta - FRER_RCVY_SEQ_SPACE;
    return delta;
}

#endif //_H_COMMON
