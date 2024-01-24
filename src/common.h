#ifndef _H_COMMON
#define _H_COMMON

#include <stdbool.h>
#include <string.h>

// HST = history window, sequence number, take any
// 0th-46th bit means the history window
// 47th-62nd bit means the sequence number
// 63rd means the take any
typedef uint64_t HST;
#define TAKE_ANY 63
#define SEQ_START_BIT 47
#define FRER_DEFAULT_HIST_LEN 47
#define FRER_RCVY_SEQ_SPACE (1 << 16)
#define FRER_RCVY_TIMEOUT_NS ((1000*1000*1000)*2)
#define FRER_TIMEOUT_CHECK_PERIOD_NS ((1000*1000*1000) / 100) //every 10ms

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

// Per-ifindex ingress VLAN translation table
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

static inline int calc_delta(ushort seq1, ushort seq2)
{
    int delta = (seq1 - seq2) & (FRER_RCVY_SEQ_SPACE - 1);
    if((delta & (FRER_RCVY_SEQ_SPACE / 2)) != 0)
        delta = delta - FRER_RCVY_SEQ_SPACE;
    return delta;
}

static inline void reset_ticks(struct seq_rcvy_and_hist *rec)
{
    (void) rec;
}

#endif //_H_COMMON
