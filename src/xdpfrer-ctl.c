#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "common.h"

#define PIN_DIR "/sys/fs/bpf/xdpfrer"
#define MAX_IFACES 16
#define MAX_IFNAME_LEN 16

enum program_mode {
    FRER_ELIM,
    FRER_REPL,
    PREF_ELIM,
    PREF_REPL
};

enum match_type {
    MATCH_FL,
    MATCH_RSID
};

struct ingress_entry {
    char ifname[MAX_IFNAME_LEN];
    enum match_type mtype;
    int64_t match_id; // flow_label or rsid
};

/**
 * @brief Print usage information.
 */
static void usage(void)
{
    fprintf(stderr,
        "Usage: xdpfrer-ctl <command> [options]\n"
        "\n"
        "Commands:\n"
        "  list                          List active flows\n"
        "  add  -m <mode> -i ... -e ...  Add a flow\n"
        "  del  -m <mode> -i ...         Delete a flow\n"
        "\n"
        "Modes: prf (replication), pef (elimination)\n"
        "\n"
        "Examples:\n"
        "  xdpfrer-ctl add -m prf -i eth0:fl:10 -e veth0:5f00::1 [-e ...] [-n]\n"
        "  xdpfrer-ctl add -m pef -i eth0:rsid:f:10110 [-i ...] -e veth0::: [-n]\n"
        "  xdpfrer-ctl del -m prf -i eth0:fl:10\n"
        "  xdpfrer-ctl del -m pef -i eth0:rsid:f:10110 [-i ...]\n"
        "  xdpfrer-ctl list\n"
        "\n"
        "Options:\n"
        "  -m <mode>   Mode: prf or pef\n"
        "  -i <iface>  Ingress: IFNAME:fl:FLOW_LABEL or IFNAME:rsid:FUNCT:FLOW_ID\n"
        "  -e <iface>  Egress: IFNAME:ADDR (IPv6 locator)\n"
        "  -n          Don't encapsulate/decapsulate (rewrite outer header)\n");
}

/**
 * @brief Parse a string as a non-negative number with validation.
 * @param str The string to parse.
 * @param base The numeric base (10 for decimal, 16 for hex).
 * @param max Maximum allowed value.
 * @param result Pointer to store the parsed value.
 * @return 0 on success, -1 on failure.
 */
static int parse_number(const char *str, int base, long max, long *result)
{
    char *endptr;
    long val = strtol(str, &endptr, base);
    if (*endptr != '\0' || endptr == str || val < 0 || val > max)
        return -1;
    *result = val;
    return 0;
}

/**
 * @brief Print a match ID in decimal if it fits in 20 bits, otherwise in hex.
 * @param match_id The match ID to print.
 */
static void print_match_id(int64_t match_id)
{
    if (match_id <= 0xFFFFF)
        printf("%ld", match_id);
    else
        printf("0x%lx", match_id);
}

/**
 * @brief Open a pinned BPF map or program by name from PIN_DIR.
 * @param name The object name in PIN_DIR.
 * @param quiet If true, suppress error output when the object is not found.
 * @return File descriptor on success, -1 on failure.
 */
static int open_pinned_opt(const char *name, bool quiet)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", PIN_DIR, name);
    
    int fd = bpf_obj_get(path);
    if (fd < 0 && !quiet)
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
    
    return fd;
}

/**
 * @brief Open a pinned BPF object by name, printing an error on failure.
 * @param name The object name in PIN_DIR.
 * @return File descriptor on success, -1 on failure.
 */
static int open_pinned(const char *name)
{
    return open_pinned_opt(name, false);
}

/**
 * @brief Find the next available recovery index by scanning the seqrcvy_idx_map.
 */
static int find_next_rcvy_idx(int idx_fd)
{
    int64_t key, next;
    int max_idx = -1;
    if (bpf_map_get_next_key(idx_fd, NULL, &next) != 0)
        return 0;
    do {
        key = next;
        int idx;
        if (bpf_map_lookup_elem(idx_fd, &key, &idx) == 0 && idx > max_idx)
            max_idx = idx;
    } while (bpf_map_get_next_key(idx_fd, &key, &next) == 0);
    return max_idx + 1;
}

/**
 * @brief Add a PREF replication flow. Creates a devmap with egress interfaces, populates
 * dst_addr_map with per-egress locator addresses, and initializes the sequence generator.
 * @param match_id The match ID (flow label or combined funct+flow_id).
 * @param egress Array of egress interface names.
 * @param addrs Array of IPv6 destination addresses corresponding to each egress interface.
 * @param n Number of egress interfaces.
 * @param no_encap If true, skip encapsulation.
 * @return 0 on success, 1 on failure.
 */
static int cmd_add_prf(int64_t match_id, char egress[][MAX_IFNAME_LEN], struct in6_addr *addrs, int n, bool no_encap)
{
    int seqgen_fd = open_pinned("seqgen_map");
    int repl_fd = open_pinned("replicate_tx_map");
    int dst_fd = open_pinned("dst_addr_map");
    int pp_fd = open_pinned("postprocessing_prog");
    if (seqgen_fd < 0 || repl_fd < 0 || dst_fd < 0 || pp_fd < 0)
        return 1;

    char mapname[BPF_OBJ_NAME_LEN];
    snprintf(mapname, sizeof(mapname), "id%ld_txifs", match_id);
    int tx_fd = bpf_map_create(BPF_MAP_TYPE_DEVMAP_HASH, mapname,
                                sizeof(int), sizeof(struct bpf_devmap_val), 8, 0);
    if (tx_fd < 0) {
        fprintf(stderr, "Failed to create devmap: %s\n", strerror(errno));
        return 1;
    }

    for (int i = 0; i < n; i++) {
        int ifidx = if_nametoindex(egress[i]);
        if (!ifidx) {
            fprintf(stderr, "Interface '%s' not found\n", egress[i]);
            close(tx_fd);
            return 1;
        }
        struct bpf_devmap_val val = { .ifindex = ifidx, .bpf_prog = { pp_fd } };
        if (bpf_map_update_elem(tx_fd, &i, &val, 0) < 0) {
            fprintf(stderr, "Failed to add to devmap: %s\n", strerror(errno));
            close(tx_fd);
            return 1;
        }
        struct tx_key k = { .ifidx = ifidx, .match_id = match_id };
        bpf_map_update_elem(dst_fd, &k, &addrs[i], 0);
    }

    if (bpf_map_update_elem(repl_fd, &match_id, &tx_fd, 0) < 0) {
        fprintf(stderr, "Failed to update replicate_tx_map: %s\n", strerror(errno));
        close(tx_fd);
        return 1;
    }
    close(tx_fd);

    struct seq_gen gen = { .no_encap = no_encap };
    bpf_map_update_elem(seqgen_fd, &match_id, &gen, BPF_NOEXIST);

    printf("Added replication flow key=%ld (%d egress%s)\n", match_id, n, no_encap ? ", no_encap" : "");
    close(seqgen_fd); close(repl_fd); close(dst_fd);
    return 0;
}

/**
 * @brief Add a PREF elimination flow. Maps each ingress match ID to a shared recovery index
 * and configures the egress interface for forwarding recovered packets.
 * @param ingress Array of ingress entries (interface + match ID).
 * @param num_ingress Number of ingress entries.
 * @param egress_ifname The egress interface name for recovered packets.
 * @param egress_addr The IPv6 address for rewrite (used when no_encap is set).
 * @param no_encap If true, rewrite outer header instead of decapsulating.
 * @return 0 on success, 1 on failure.
 */
static int cmd_add_pef(struct ingress_entry *ingress, int num_ingress,
                       const char *egress_ifname, struct in6_addr *egress_addr,
                       bool no_encap)
{
    int idx_fd = open_pinned("seqrcvy_idx_map");
    int rcvy_fd = open_pinned("seqrcvy_map");
    int elim_fd = open_pinned("eliminate_tx_map");
    int dst_fd = open_pinned_opt("dst_addr_map", true);
    if (idx_fd < 0 || rcvy_fd < 0 || elim_fd < 0)
        return 1;

    int egress_ifidx = if_nametoindex(egress_ifname);
    if (!egress_ifidx) {
        fprintf(stderr, "Interface '%s' not found\n", egress_ifname);
        return 1;
    }

    int rcvy_idx = find_next_rcvy_idx(idx_fd);

    for (int i = 0; i < num_ingress; i++) {
        int64_t key = ingress[i].match_id;
        bpf_map_update_elem(elim_fd, &key, &egress_ifidx, 0);
        bpf_map_update_elem(idx_fd, &key, &rcvy_idx, 0);

        if (no_encap && dst_fd >= 0) {
            struct tx_key k = { .ifidx = egress_ifidx, .match_id = key };
            bpf_map_update_elem(dst_fd, &k, egress_addr, 0);
        }
    }

    struct seq_rcvy_and_hist rec = {};
    rec.hist_recvseq_takeany = 1UL << TAKE_ANY;
    rec.no_encap = no_encap;
    bpf_map_update_elem(rcvy_fd, &rcvy_idx, &rec, BPF_ANY);

    printf("Added elimination flow rcvy_idx=%d (%d ingress%s)\n", rcvy_idx, num_ingress, no_encap ? ", no_encap" : "");
    close(idx_fd); close(rcvy_fd); close(elim_fd);
    if (dst_fd >= 0) close(dst_fd);
    return 0;
}

/**
 * @brief Delete a PREF replication flow. Removes entries from seqgen_map, replicate_tx_map,
 * and dst_addr_map for the given match ID.
 * @param match_id The match ID identifying the flow to delete.
 * @return 0 on success, 1 if the maps cannot be opened.
 */
static int cmd_del_prf(int64_t match_id)
{
    int seqgen_fd = open_pinned("seqgen_map");
    int repl_fd = open_pinned("replicate_tx_map");
    int dst_fd = open_pinned("dst_addr_map");
    if (seqgen_fd < 0 || repl_fd < 0 || dst_fd < 0)
        return 1;

    bpf_map_delete_elem(seqgen_fd, &match_id);
    bpf_map_delete_elem(repl_fd, &match_id);

    struct tx_key tk = {}, tnext;
    struct tx_key to_delete[MAX_IFACES];
    int del_count = 0;

    while (bpf_map_get_next_key(dst_fd, &tk, &tnext) == 0) {
        if (tnext.match_id == match_id && del_count < MAX_IFACES)
            to_delete[del_count++] = tnext;
        tk = tnext;
    }
    for (int i = 0; i < del_count; i++)
        bpf_map_delete_elem(dst_fd, &to_delete[i]);

    printf("Deleted replication match id=%ld\n", match_id);
    close(seqgen_fd); close(repl_fd); close(dst_fd);
    return 0;
}

/**
 * @brief Delete a PREF elimination flow. Removes entries from seqrcvy_idx_map and
 * eliminate_tx_map for each ingress match ID.
 * @param ingress Array of ingress entries to delete.
 * @param num_ingress Number of ingress entries.
 * @return 0 on success, 1 if the maps cannot be opened.
 */
static int cmd_del_pef(struct ingress_entry *ingress, int num_ingress)
{
    int idx_fd = open_pinned("seqrcvy_idx_map");
    int elim_fd = open_pinned("eliminate_tx_map");
    if (idx_fd < 0 || elim_fd < 0)
        return 1;

    for (int i = 0; i < num_ingress; i++) {
        int64_t key = ingress[i].match_id;
        bpf_map_delete_elem(idx_fd, &key);
        bpf_map_delete_elem(elim_fd, &key);
    }
    // Note: seqrcvy_map is an array, entries are not deleted (reused)

    printf("Deleted elimination flow (%d ingress keys)\n", num_ingress);
    close(idx_fd); close(elim_fd);
    return 0;
}

/**
 * @brief Print seqgen_map entries. Each entry maps a match ID (VLAN ID or flow label)
 * to its current sequence number and reset count.
 */
static int print_seqgen_map(void)
{
    int64_t key = 0, next;
    int fd = open_pinned("seqgen_map");
    if (fd < 0)
        return -1;

    bool has_entries = false;
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        if (!has_entries) { printf("- seqgen_map:\n"); has_entries = true; }
        struct seq_gen gen;
        if (bpf_map_lookup_elem(fd, &next, &gen) == 0) {
            printf("    key="); print_match_id(next);
            printf(", seq=%d resets=%d%s\n", gen.gen_seq_num, gen.resets,
                   gen.no_encap ? " no_encap" : " encap");
        }
        key = next;
    }
    close(fd);

    return 0;
}

/**
 * @brief Print replicate_tx_map entries. Each entry contains a match ID (VLAN ID or flow label)
 * that keys into a per-flow devmap of egress interfaces.
 */
static int print_replicate_tx_map(void)
{
    int64_t key = 0, next;
    int fd = open_pinned("replicate_tx_map");
    if (fd < 0)
        return -1;

    bool has_entries = false;
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        if (!has_entries) { printf("- replicate_tx_map:\n"); has_entries = true; }
        printf("    key="); print_match_id(next);

        int inner_id;
        if (bpf_map_lookup_elem(fd, &next, &inner_id) == 0) {
            int inner_fd = bpf_map_get_fd_by_id(inner_id);
            if (inner_fd >= 0) {
                int ikey = -1, inext;
                printf(" -> [");
                bool first = true;
                while (bpf_map_get_next_key(inner_fd, &ikey, &inext) == 0) {
                    struct bpf_devmap_val val;
                    if (bpf_map_lookup_elem(inner_fd, &inext, &val) == 0) {
                        char ifname[MAX_IFNAME_LEN] = "?";
                        if_indextoname(val.ifindex, ifname);
                        printf("%s%s", first ? "" : ", ", ifname);
                        first = false;
                    }
                    ikey = inext;
                }
                printf("]");
                close(inner_fd);
            }
        }
        printf("\n");
        key = next;
    }
    close(fd);
    return 0;
}

/**
 * @brief Print seqrcvy_idx_map entries. Each entry maps a match ID to a shared
 * recovery index in seqrcvy_map.
 */
static int print_seqrcvy_idx_map(void)
{
    int64_t key = 0, next;
    int fd = open_pinned_opt("seqrcvy_idx_map", true);
    if (fd < 0)
        return 0;

    bool has_entries = false;
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        if (!has_entries) { printf("- seqrcvy_idx_map:\n"); has_entries = true; }
        int idx;
        if (bpf_map_lookup_elem(fd, &next, &idx) == 0) {
            printf("    key="); print_match_id(next);
            printf(" -> rcvy_idx=%d\n", idx);
        }
        key = next;
    }
    close(fd);
    return 0;
}

/**
 * @brief Print seqrcvy_map entries that are in use. Shows recovery statistics
 * (passed, discarded, rogue packets) for each active recovery index.
 */
static int print_seqrcvy_map(void)
{
    int idx_fd = open_pinned_opt("seqrcvy_idx_map", true);
    int fd = open_pinned_opt("seqrcvy_map", true);
    if (fd < 0)
        return 0;

    // Collect which indices are actually in use
    bool used[MAX_FLOWS] = {};
    if (idx_fd >= 0) {
        int64_t key = 0, next;
        while (bpf_map_get_next_key(idx_fd, &key, &next) == 0) {
            int idx;
            if (bpf_map_lookup_elem(idx_fd, &next, &idx) == 0 && idx >= 0 && idx < MAX_FLOWS)
                used[idx] = true;
            key = next;
        }
        close(idx_fd);
    }

    bool has_entries = false;
    for (int i = 0; i < MAX_FLOWS; i++) {
        if (!used[i])
            continue;
        struct seq_rcvy_and_hist rec;
        if (bpf_map_lookup_elem(fd, &i, &rec) == 0) {
            if (!has_entries) { printf("- seqrcvy_map:\n"); has_entries = true; }
            printf("    rcvy_idx=%d passed=%d discarded=%d rogue=%d%s\n",
                   i, rec.passed_packets, rec.discarded_packets, rec.rogue_packets,
                   rec.no_encap ? " no_encap" : " encap");
        }
    }
    close(fd);
    return 0;
}

/**
 * @brief Print eliminate_tx_map entries. Each entry maps a match ID (VLAN ID or flow label)
 * to the egress interface index where recovered packets are forwarded.
 */
static int print_eliminate_tx_map(void)
{
    int64_t key = 0, next;
    int fd = open_pinned("eliminate_tx_map");
    if (fd < 0)
        return -1;

    bool has_entries = false;
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        if (!has_entries) { printf("- eliminate_tx_map:\n"); has_entries = true; }
        int ifidx;
        if (bpf_map_lookup_elem(fd, &next, &ifidx) == 0) {
            char ifname[MAX_IFNAME_LEN] = "?";
            if_indextoname(ifidx, ifname);
            printf("    key="); print_match_id(next);
            printf(" -> %s (ifindex=%d)\n", ifname, ifidx);
        }
        key = next;
    }
    close(fd);
    return 0;
}

/**
 * @brief Print dst_addr_map entries. Each entry maps (egress ifindex, match ID) to
 * the IPv6 destination address used for the outer header.
 */
static int print_dst_addr_map(void)
{
    int fd = open_pinned_opt("dst_addr_map", true);
    if (fd < 0)
        return 0;

    bool has_entries = false;
    struct tx_key tk = {}, tnext;
    while (bpf_map_get_next_key(fd, &tk, &tnext) == 0) {
        struct in6_addr addr;
        if (bpf_map_lookup_elem(fd, &tnext, &addr) == 0) {
            if (!has_entries) { printf("- dst_addr_map:\n"); has_entries = true; }
            char buf[INET6_ADDRSTRLEN];
            char ifname[MAX_IFNAME_LEN] = "?";
            inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
            if_indextoname(tnext.ifidx, ifname);
            printf("    %s (ifindex=%d), key=", ifname, tnext.ifidx);
            print_match_id(tnext.match_id);
            printf(" -> %s\n", buf);
        }
        tk = tnext;
    }
    close(fd);

    return 0;
}

/**
 * @brief List all active flows by printing all pinned BPF map contents.
 * @return 0 on success.
 */
static int cmd_list(void)
{
    print_seqgen_map();
    print_replicate_tx_map();
    print_dst_addr_map();
    print_seqrcvy_idx_map();
    print_seqrcvy_map();
    print_eliminate_tx_map();

    return 0;
}

/**
 * @brief Parse PREF ingress argument. Format: IFNAME:fl:NUM or IFNAME:rsid:FUNCT:FLOW_ID
 */
static int parse_pref_ingress(char *arg, struct ingress_entry *entry)
{
    char *tok = strtok(arg, ":");
    if (!tok) return -1;
    strncpy(entry->ifname, tok, MAX_IFNAME_LEN - 1);

    tok = strtok(NULL, ":");
    if (!tok) return -1;

    if (strcmp(tok, "fl") == 0) {
        tok = strtok(NULL, ":");
        if (!tok) return -1;
        long val;
        if (parse_number(tok, 10, 0xFFFFF, &val) < 0) return -1;
        entry->mtype = MATCH_FL;
        entry->match_id = (int64_t)val;
    } else if (strcmp(tok, "rsid") == 0) {
        tok = strtok(NULL, ":");
        if (!tok) return -1;
        long fval;
        if (parse_number(tok, 16, 0xFFFF, &fval) < 0) return -1;

        tok = strtok(NULL, ":");
        if (!tok) return -1;
        long fidval;
        if (parse_number(tok, 16, 0xFFFFF, &fidval) < 0) return -1;

        entry->mtype = MATCH_RSID;
        entry->match_id = ((int64_t)fval << 20) | (fidval & 0xFFFFF);
    } else {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    if (argc < 2) {
        usage();
        return EXIT_FAILURE;
    }

    if (access(PIN_DIR, F_OK) != 0) {
        fprintf(stderr, "No pinned maps found at %s. Is xdpfrer running?\n", PIN_DIR);
        return EXIT_FAILURE;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "list") == 0)
        return cmd_list() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    char *mode_str = NULL;
    enum program_mode mode;
    struct ingress_entry ingress[MAX_IFACES];
    int num_ingress = 0;
    char egress_ifnames[MAX_IFACES][MAX_IFNAME_LEN];
    struct in6_addr egress_addrs[MAX_IFACES];
    int egress_vids[MAX_IFACES];
    int num_egress = 0;
    bool no_encap = false;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0) {
            no_encap = true;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            mode_str = argv[++i];
            if (strcmp(mode_str, "repl") == 0) mode = FRER_REPL;
            else if (strcmp(mode_str, "elim") == 0) mode = FRER_ELIM;
            else if (strcmp(mode_str, "prf") == 0) mode = PREF_REPL;
            else if (strcmp(mode_str, "pef") == 0) mode = PREF_ELIM;
            else { fprintf(stderr, "Unknown mode\n"); usage(); return EXIT_FAILURE; }
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            if (!mode_str) { fprintf(stderr, "-m must come before -i\n"); return EXIT_FAILURE; }
            if (num_ingress >= MAX_IFACES) { fprintf(stderr, "Too many ingress\n"); return EXIT_FAILURE; }
            i++;
            if (mode == PREF_REPL || mode == PREF_ELIM) {
                if (parse_pref_ingress(argv[i], &ingress[num_ingress]) < 0) {
                    fprintf(stderr, "Invalid ingress format. Use IFNAME:fl:NUM or IFNAME:rsid:FUNCT:FLOW_ID\n");
                    return EXIT_FAILURE;
                }
            } else {
                char *colon = strchr(argv[i], ':');
                if (!colon) { fprintf(stderr, "Invalid ingress format\n"); return EXIT_FAILURE; }
                *colon = '\0';
                strncpy(ingress[num_ingress].ifname, argv[i], MAX_IFNAME_LEN - 1);
                ingress[num_ingress].match_id = (int64_t)atoi(colon + 1);
                *colon = ':';
            }
            num_ingress++;
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            if (!mode_str) { fprintf(stderr, "-m must come before -e\n"); return EXIT_FAILURE; }
            if (num_egress >= MAX_IFACES) { fprintf(stderr, "Too many egress\n"); return EXIT_FAILURE; }
            i++;
            char *colon = strchr(argv[i], ':');
            if (!colon) { fprintf(stderr, "Invalid egress format\n"); return EXIT_FAILURE; }
            *colon = '\0';
            strncpy(egress_ifnames[num_egress], argv[i], MAX_IFNAME_LEN - 1);
            if (mode == FRER_REPL || mode == FRER_ELIM)
                egress_vids[num_egress] = atoi(colon + 1);
            else
                inet_pton(AF_INET6, colon + 1, &egress_addrs[num_egress]);
            *colon = ':';
            num_egress++;
        }
    }

    if (!mode_str || num_ingress == 0) {
        fprintf(stderr, "-m and -i are required\n");
        usage();
        return EXIT_FAILURE;
    }

    if (strcmp(cmd, "add") == 0) {
        if (num_egress == 0) { fprintf(stderr, "At least one -e required\n"); return EXIT_FAILURE; }
        switch (mode) {
            case FRER_REPL:
            case FRER_ELIM:
                fprintf(stderr, "FRER ctl not yet updated for new map format\n");
                return EXIT_FAILURE;
            case PREF_REPL:
                return cmd_add_prf(ingress[0].match_id, egress_ifnames, egress_addrs, num_egress, no_encap);
            case PREF_ELIM:
                return cmd_add_pef(ingress, num_ingress, egress_ifnames[0], &egress_addrs[0], no_encap);
        }
    } else if (strcmp(cmd, "del") == 0) {
        switch (mode) {
            case FRER_REPL:
            case FRER_ELIM:
                fprintf(stderr, "FRER ctl not yet updated for new map format\n");
                return EXIT_FAILURE;
            case PREF_REPL:
                return cmd_del_prf(ingress[0].match_id);
            case PREF_ELIM:
                return cmd_del_pef(ingress, num_ingress);
        }
    } else {
        fprintf(stderr, "Unknown command\n");
        usage();
        return EXIT_FAILURE;
    }

    return ret;
}
