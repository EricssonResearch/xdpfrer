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
    PREOF_ELIM,
    PREOF_REPL
};

/**
 * @brief Print usage information.
 */
static void usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "  xdpfrer-ctl add -m repl -i IFNAME:VID -e IFNAME:VID [-e ...]\n"
        "  xdpfrer-ctl add -m elim -i IFNAME:VID [-i ...] -e IFNAME:VID\n"
        "  xdpfrer-ctl del -m repl -i IFNAME:VID\n"
        "  xdpfrer-ctl del -m elim -i IFNAME:VID\n"
        "  xdpfrer-ctl add -m prf -i IFNAME:FLOW_ID -e IFNAME:ADDR [-e ...]\n"
        "  xdpfrer-ctl add -m pef -i IFNAME:FLOW_ID -e IFNAME:::\n"
        "  xdpfrer-ctl del -m prf -i IFNAME:FLOW_ID\n"
        "  xdpfrer-ctl del -m pef -i IFNAME:FLOW_ID\n"
        "  xdpfrer-ctl list\n");
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
 * @brief Add a FRER replication flow. Creates a devmap for egress interfaces, populates the
 * replication VLAN translation table, and initializes the sequence number generator.
 * @param ingress_vid The ingress VLAN ID used as match ID.
 * @param ingress_ifname The ingress interface name (for logging).
 * @param egress_ifnames Array of egress interface names.
 * @param egress_vids Array of egress VLAN IDs corresponding to each egress interface.
 * @param n Number of egress interfaces.
 * @return 0 on success, 1 on failure.
 */
static int cmd_add_repl(int ingress_vid, const char *ingress_ifname,
                             char egress_ifnames[][MAX_IFNAME_LEN], int *egress_vids, int n)
{
    int seqgen_fd = open_pinned("seqgen_map");
    int repl_fd = open_pinned("replicate_tx_map");
    int rvt_fd = open_pinned("rvt");
    int pp_fd = open_pinned("postprocessing_prog");
    if (seqgen_fd < 0 || repl_fd < 0 || rvt_fd < 0 || pp_fd < 0)
        return 1;

    char mapname[16];
    snprintf(mapname, sizeof(mapname), "id%d_txifs", ingress_vid);
    int tx_fd = bpf_map_create(BPF_MAP_TYPE_DEVMAP_HASH, mapname,
                                sizeof(int), sizeof(struct bpf_devmap_val), 8, 0);
    if (tx_fd < 0) {
        fprintf(stderr, "Failed to create devmap: %s\n", strerror(errno));
        return 1;
    }

    for (int i = 0; i < n; i++) {
        int ifidx = if_nametoindex(egress_ifnames[i]);
        if (!ifidx) {
            fprintf(stderr, "Interface '%s' not found\n", egress_ifnames[i]);
            close(tx_fd);
            return 1;
        }
        struct bpf_devmap_val val = { .ifindex = ifidx, .bpf_prog = { pp_fd } };
        if (bpf_map_update_elem(tx_fd, &i, &val, 0) < 0) {
            fprintf(stderr, "Failed to add to devmap: %s\n", strerror(errno));
            close(tx_fd);
            return 1;
        }
        struct vlan_translation_entry vte = { .from = ingress_vid, .to = egress_vids[i] };
        bpf_map_update_elem(rvt_fd, &ifidx, &vte, BPF_ANY);
    }

    if (bpf_map_update_elem(repl_fd, &ingress_vid, &tx_fd, 0) < 0) {
        fprintf(stderr, "Failed to update replicate_tx_map: %s\n", strerror(errno));
        close(tx_fd);
        return 1;
    }
    close(tx_fd);

    struct seq_gen gen = {};
    bpf_map_update_elem(seqgen_fd, &ingress_vid, &gen, BPF_NOEXIST);

    printf("Added FRER replication: VID %d on %s -> %d egress\n", ingress_vid, ingress_ifname, n);
    close(seqgen_fd); close(repl_fd); close(rvt_fd);
    return 0;
}

/**
 * @brief Add a FRER elimination flow. Sets the egress interface in the eliminate map, populates
 * the elimination VLAN translation table, and initializes the sequence recovery state.
 * @param egress_vid The egress VLAN ID used as match ID.
 * @param egress_ifname The egress interface name.
 * @param ingress_ifnames Array of ingress interface names.
 * @param ingress_vids Array of ingress VLAN IDs corresponding to each ingress interface.
 * @param n Number of ingress interfaces.
 * @return 0 on success, 1 on failure.
 */
static int cmd_add_elim(int egress_vid, const char *egress_ifname,
                             char ingress_ifnames[][MAX_IFNAME_LEN], int *ingress_vids, int n)
{
    int rcvy_fd = open_pinned("seqrcvy_map");
    int elim_fd = open_pinned("eliminate_tx_map");
    int evt_fd = open_pinned("evt");
    if (rcvy_fd < 0 || elim_fd < 0 || evt_fd < 0)
        return 1;

    int egress_ifidx = if_nametoindex(egress_ifname);
    if (!egress_ifidx) {
        fprintf(stderr, "Interface '%s' not found\n", egress_ifname);
        return 1;
    }

    bpf_map_update_elem(elim_fd, &egress_vid, &egress_ifidx, 0);

    struct seq_rcvy_and_hist rec = {};
    rec.hist_recvseq_takeany = 1UL << TAKE_ANY;
    bpf_map_update_elem(rcvy_fd, &egress_vid, &rec, BPF_NOEXIST);

    for (int i = 0; i < n; i++) {
        int ifidx = if_nametoindex(ingress_ifnames[i]);
        if (!ifidx) {
            fprintf(stderr, "Interface '%s' not found\n", ingress_ifnames[i]);
            return 1;
        }
        struct vlan_translation_entry vte = { .from = ingress_vids[i], .to = egress_vid };
        bpf_map_update_elem(evt_fd, &ifidx, &vte, BPF_ANY);
    }

    printf("Added FRER elimination: %d ingress -> VID %d on %s\n", n, egress_vid, egress_ifname);
    close(rcvy_fd); close(elim_fd); close(evt_fd);
    return 0;
}

/**
 * @brief Delete a FRER replication flow by removing its seqgen and replicate_tx_map entries.
 * @param vid The VLAN ID identifying the flow.
 * @return 0 on success, 1 if the pinned maps cannot be opened.
 */
static int cmd_del_repl(int vid)
{
    int seqgen_fd = open_pinned("seqgen_map");
    int repl_fd = open_pinned("replicate_tx_map");
    if (seqgen_fd < 0 || repl_fd < 0)
        return 1;

    bpf_map_delete_elem(seqgen_fd, &vid);
    bpf_map_delete_elem(repl_fd, &vid);

    printf("Deleted FRER replication flow VID %d\n", vid);
    close(seqgen_fd); close(repl_fd);
    return 0;
}

/**
 * @brief Delete a FRER elimination flow by removing its seqrcvy and eliminate_tx_map entries.
 * @param vid The VLAN ID identifying the flow.
 * @return 0 on success, 1 if the pinned maps cannot be opened.
 */
static int cmd_del_elim(int vid)
{
    int rcvy_fd = open_pinned("seqrcvy_map");
    int elim_fd = open_pinned("eliminate_tx_map");
    if (rcvy_fd < 0 || elim_fd < 0)
        return 1;

    bpf_map_delete_elem(rcvy_fd, &vid);
    bpf_map_delete_elem(elim_fd, &vid);

    printf("Deleted FRER elimination flow VID %d\n", vid);
    close(rcvy_fd); close(elim_fd);
    return 0;
}

/**
 * @brief Add a PREOF replication flow. Creates a devmap for egress interfaces, populates the
 * destination address map, and initializes the sequence number generator.
 * @param flow_id The IPv6 flow label used as match ID.
 * @param egress Array of egress interface names.
 * @param addrs Array of destination IPv6 addresses corresponding to each egress interface.
 * @param n Number of egress interfaces.
 * @return 0 on success, 1 on failure.
 */
static int cmd_add_prf(int flow_id, char egress[][MAX_IFNAME_LEN], struct in6_addr *addrs, int n)
{
    int seqgen_fd = open_pinned("seqgen_map");
    int repl_fd = open_pinned("replicate_tx_map");
    int dst_fd = open_pinned("dst_addr_map");
    int pp_fd = open_pinned("postprocessing_prog");
    if (seqgen_fd < 0 || repl_fd < 0 || dst_fd < 0 || pp_fd < 0)
        return 1;

    char mapname[16];
    snprintf(mapname, sizeof(mapname), "id%d_txifs", flow_id);
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
        struct tx_key k = { .ifidx = ifidx, .flow_label = flow_id };
        bpf_map_update_elem(dst_fd, &k, &addrs[i], 0);
    }

    if (bpf_map_update_elem(repl_fd, &flow_id, &tx_fd, 0) < 0) {
        fprintf(stderr, "Failed to update replicate_tx_map: %s\n", strerror(errno));
        close(tx_fd);
        return 1;
    }
    close(tx_fd);

    struct seq_gen gen = {};
    bpf_map_update_elem(seqgen_fd, &flow_id, &gen, BPF_NOEXIST);

    printf("Added replication flow %d (%d egress)\n", flow_id, n);
    close(seqgen_fd); close(repl_fd); close(dst_fd);
    return 0;
}

/**
 * @brief Add a PREOF elimination flow. Sets the egress interface in the eliminate map
 * and initializes the sequence recovery state.
 * @param flow_id The flow label used as match ID.
 * @param ifname The egress interface name.
 * @return 0 on success, 1 on failure.
 */
static int cmd_add_pef(int flow_id, const char *ifname)
{
    int rcvy_fd = open_pinned("seqrcvy_map");
    int elim_fd = open_pinned("eliminate_tx_map");
    if (rcvy_fd < 0 || elim_fd < 0)
        return 1;

    int ifidx = if_nametoindex(ifname);
    if (!ifidx) {
        fprintf(stderr, "Interface '%s' not found\n", ifname);
        return 1;
    }

    bpf_map_update_elem(elim_fd, &flow_id, &ifidx, 0);

    struct seq_rcvy_and_hist rec = {};
    rec.hist_recvseq_takeany = 1UL << TAKE_ANY;
    bpf_map_update_elem(rcvy_fd, &flow_id, &rec, BPF_NOEXIST);

    printf("Added elimination flow %d -> %s\n", flow_id, ifname);
    close(rcvy_fd); close(elim_fd);
    return 0;
}

/**
 * @brief Delete a PREOF replication flow from seqgen, replicate and dst_addr_map maps.
 * @param flow_id The flow label.
 * @return 0 on success, 1 if the maps cannot be opened.
 */
static int cmd_del_prf(int flow_id)
{
    int seqgen_fd = open_pinned("seqgen_map");
    int repl_fd = open_pinned("replicate_tx_map");
    int dst_fd = open_pinned("dst_addr_map");
    if (seqgen_fd < 0 || repl_fd < 0 || dst_fd < 0)
        return 1;

    bpf_map_delete_elem(seqgen_fd, &flow_id);
    bpf_map_delete_elem(repl_fd, &flow_id);

    struct tx_key tk = {}, tnext;
    struct tx_key to_delete[MAX_IFACES];
    int del_count = 0;

    while (bpf_map_get_next_key(dst_fd, &tk, &tnext) == 0) {
        if (tnext.flow_label == flow_id && del_count < MAX_IFACES)
            to_delete[del_count++] = tnext;
        tk = tnext;
    }
    for (int i = 0; i < del_count; i++)
        bpf_map_delete_elem(dst_fd, &to_delete[i]);

    printf("Deleted replication flow %d\n", flow_id);
    close(seqgen_fd); close(repl_fd); close(dst_fd);
    return 0;
}

/**
 * @brief Delete a PREOF elimination flow from seqrcvy and eliminate maps.
 * @param flow_id The flow label.
 * @return 0 on success, 1 if the maps cannot be opened.
 */
static int cmd_del_pef(int flow_id)
{
    int rcvy_fd = open_pinned("seqrcvy_map");
    int elim_fd = open_pinned("eliminate_tx_map");
    if (rcvy_fd < 0 || elim_fd < 0)
        return 1;

    bpf_map_delete_elem(rcvy_fd, &flow_id);
    bpf_map_delete_elem(elim_fd, &flow_id);

    printf("Deleted elimination flow %d\n", flow_id);
    close(rcvy_fd); close(elim_fd);
    return 0;
}

/**
 * @brief Print seqgen_map entries. Each entry maps a match ID (VLAN ID or flow label)
 * to its current sequence number and reset count.
 */
static int print_seqgen_map(void)
{
    int next;
    int key = 0;
    int fd = open_pinned("seqgen_map");
    if (fd < 0)
        return -1;
    
    printf("- seqgen_map:\n");
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        struct seq_gen gen;
        if (bpf_map_lookup_elem(fd, &next, &gen) == 0)
            printf("    match_id=%d, seq=%d resets=%d\n", next, gen.gen_seq_num, gen.resets);
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
    int next;
    int key = 0;
    int fd = open_pinned("replicate_tx_map");
    if (fd < 0)
        return -1;

    printf("- replicate_tx_map:\n");
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        printf("    match_id=%d\n", next);
        key = next;
    }
    close(fd);

    return 0;
}

/**
 * @brief Print seqrcvy_map entries. Each entry maps a match ID (VLAN ID or flow label)
 * to recovery statistics (passed, discarded, rogue packet counts).
 */
static int print_seqrcvy_map(void)
{
    int next;
    int key = 0;
    int fd = open_pinned("seqrcvy_map");
    if (fd < 0)
        return -1;

    printf("- seqrcvy_map:\n");
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        struct seq_rcvy_and_hist rec;
        if (bpf_map_lookup_elem(fd, &next, &rec) == 0)
            printf("    match_id=%d  passed=%d discarded=%d rogue=%d\n",
                   next, rec.passed_packets, rec.discarded_packets, rec.rogue_packets);
        key = next;
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
    int next;
    int key = 0;
    int fd = open_pinned("eliminate_tx_map");
    if (fd < 0)
        return -1;

    printf("- eliminate_tx_map:\n");
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        int ifidx;
        if (bpf_map_lookup_elem(fd, &next, &ifidx) == 0) {
            char ifname[MAX_IFNAME_LEN] = "?";
            if_indextoname(ifidx, ifname);
            printf("    match_id=%d -> %s (ifindex=%d)\n", next, ifname, ifidx);
        }
        key = next;
    }
    close(fd);
    
    return 0;
}

/**
 * @brief Print dst_addr_map entries. Each entry maps an (ifindex, flow label) key
 * to a destination IPv6 address.
 */
static int print_dst_addr_map(void)
{
    int fd = open_pinned_opt("dst_addr_map", true);
    if (fd < 0)
        return 0;

    printf("- dst_addr_map:\n");
    struct tx_key tk = {}, tnext;
    while (bpf_map_get_next_key(fd, &tk, &tnext) == 0) {
        struct in6_addr addr;
        if (bpf_map_lookup_elem(fd, &tnext, &addr) == 0) {
            char buf[INET6_ADDRSTRLEN];
            char ifname[MAX_IFNAME_LEN] = "?";
            inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
            if_indextoname(tnext.ifidx, ifname);
            printf("    %s (ifindex=%d), flow=%d -> %s\n", ifname, tnext.ifidx, tnext.flow_label, buf);
        }
        tk = tnext;
    }
    close(fd);

    return 0;
}

/**
 * @brief Print VLAN translation map entries. Silently skips if the map is not pinned.
 * @param name The pinned map name ("rvt" or "evt").
 * @return 0 always.
 */
static int print_vlan_translation(const char *name)
{
    int fd = open_pinned_opt(name, true);
    if (fd < 0)
        return 0;

    printf("- %s:\n", name);
    int key = 0, next;
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        struct vlan_translation_entry vte;
        if (bpf_map_lookup_elem(fd, &next, &vte) == 0) {
            char ifname[MAX_IFNAME_LEN] = "?";
            if_indextoname(next, ifname);
            printf("    %s (ifindex=%d): from=%d to=%d\n", ifname, next, vte.from, vte.to);
        }
        key = next;
    }
    close(fd);
    return 0;
}

/**
 * @brief List all pinned eBPF map contents, grouped by replication and elimination.
 * Mode-specific maps that are not pinned are silently skipped.
 */
static int cmd_list(void)
{
    int ret = 0;
    
    printf("Replication maps:\n");
    ret = print_seqgen_map();
    if (ret < 0)
        return ret;

    ret = print_replicate_tx_map();
    if (ret < 0)
        return ret;

    ret = print_dst_addr_map();
    if (ret < 0)
        return ret;

    ret = print_vlan_translation("rvt");
    if (ret < 0)
        return ret;

    printf("\nElimination maps:\n");
    ret = print_seqrcvy_map();
    if (ret < 0)
        return ret;

    ret = print_eliminate_tx_map();
    if (ret < 0)
        return ret;

    ret = print_vlan_translation("evt");
    if (ret < 0)
        return ret;

    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    if (argc < 2) {
        usage();
        ret = EXIT_FAILURE;
        goto end;
    }

    // Check whether the xdpfrer maps are pinned
    if (access(PIN_DIR, F_OK) != 0) {
        fprintf(stderr, "No pinned maps found at %s. Is xdpfrer running?\n", PIN_DIR);
        ret = EXIT_FAILURE;
        goto end;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "list") == 0) {
        ret = cmd_list() < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        goto end;
    }

    char *mode_str = NULL;
    enum program_mode mode;
    char ingress_ifnames[MAX_IFACES][MAX_IFNAME_LEN];
    int ingress_ids[MAX_IFACES];
    int num_ingress = 0;
    char egress_ifnames[MAX_IFACES][MAX_IFNAME_LEN];
    struct in6_addr egress_addrs[MAX_IFACES];
    int egress_vids[MAX_IFACES];
    int num_egress = 0;

    // Parse options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            mode_str = argv[++i];
            if (strcmp(mode_str, "repl") == 0) {
                mode = FRER_REPL;
            } else if (strcmp(mode_str, "elim") == 0) {
                mode = FRER_ELIM;
            } else if (strcmp(mode_str, "prf") == 0) {
                mode = PREOF_REPL;
            } else if (strcmp(mode_str, "pef") == 0) {
                mode = PREOF_ELIM;
            } else {
                fprintf(stderr, "Unknown mode\n");
                usage();
                ret = EXIT_FAILURE;
                goto end;
            }
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            if (!mode_str) {
                fprintf(stderr, "-m must be specified before -i and -e\n");
                ret = EXIT_FAILURE;
                goto end;
            }

            if (num_ingress >= MAX_IFACES) {
                fprintf(stderr, "Too many ingress interfaces\n");
                ret = EXIT_FAILURE;
                goto end;
            }
            i++;
            char *colon = strchr(argv[i], ':');
            if (!colon) {
                fprintf(stderr, "Invalid ingress format. Use IFNAME:ID\n");
                ret = EXIT_FAILURE;
                goto end;
            }
            *colon = '\0';
            strncpy(ingress_ifnames[num_ingress], argv[i], MAX_IFNAME_LEN - 1);
            ingress_ids[num_ingress] = atoi(colon + 1);
            *colon = ':';
            num_ingress++;
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            if (!mode_str) {
                fprintf(stderr, "-m must be specified before -i and -e\n");
                ret = EXIT_FAILURE;
                goto end;
            }

            if (num_egress >= MAX_IFACES) {
                fprintf(stderr, "Too many egress interfaces\n");
                ret = EXIT_FAILURE;
                goto end;
            }
            i++;
            char *colon = strchr(argv[i], ':');
            if (!colon) {
                fprintf(stderr, "Invalid egress format. Use IFNAME:VID or IFNAME:ADDR\n");
                ret = EXIT_FAILURE;
                goto end;
            }
            *colon = '\0';
            strncpy(egress_ifnames[num_egress], argv[i], MAX_IFNAME_LEN - 1);
            if (mode == FRER_REPL || mode == FRER_ELIM) {
                egress_vids[num_egress] = atoi(colon + 1);
            } else {
                inet_pton(AF_INET6, colon + 1, &egress_addrs[num_egress]);
            }
            *colon = ':';
            num_egress++;
        }
    }

    if (!mode_str || num_ingress == 0) {
        fprintf(stderr, "-m and -i are required\n");
        usage();
        ret = EXIT_FAILURE;
        goto end;
    }

    // Add or remove entries from the maps
    if (strcmp(cmd, "add") == 0) {
        if (num_egress == 0) {
            fprintf(stderr, "At least one -e is required for add\n");
            ret = EXIT_FAILURE;
            goto end;
        }
        switch (mode) {
            case FRER_REPL:
                return cmd_add_repl(ingress_ids[0], ingress_ifnames[0], egress_ifnames, egress_vids, num_egress);
            case FRER_ELIM:
                return cmd_add_elim(egress_vids[0], egress_ifnames[0], ingress_ifnames, ingress_ids, num_ingress);
            case PREOF_REPL:
                return cmd_add_prf(ingress_ids[0], egress_ifnames, egress_addrs, num_egress);
            case PREOF_ELIM:
                return cmd_add_pef(ingress_ids[0], egress_ifnames[0]);
        }   
    } else if (strcmp(cmd, "del") == 0) {
        switch (mode) {
            case FRER_REPL:
                return cmd_del_repl(ingress_ids[0]);
            case FRER_ELIM:
                return cmd_del_elim(ingress_ids[0]);
            case PREOF_REPL:
                return cmd_del_prf(ingress_ids[0]);
            case PREOF_ELIM:
                return cmd_del_pef(ingress_ids[0]);
        }
    } else {
        fprintf(stderr, "Unknown command or mode\n");
        usage();
        ret = EXIT_FAILURE;
        goto end;
    }

end:
    return ret;
}
