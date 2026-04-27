#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <net/if.h>
#include <unistd.h>
#include <argp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "common.h"
#include "xdpfrer.skel.h"
#include "xdppreof.skel.h"

#define MAX_IFACES 16
#define MAX_IFNAME_LEN 16
#define MAX_CFG_ENTRIES 16
#define PIN_DIR "/sys/fs/bpf/xdpfrer"

enum program_mode mode;
static bool run;
static bool is_mode_set = false;
static unsigned int rvt_size = 0;
static unsigned int evt_size = 0;
static unsigned int cfg_size = 0;
static unsigned int ingress_size = 0;
static unsigned int egress_size = 0;
static bool add_or_rm_rtag = true;
static bool quiet_output = false;
static unsigned char dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

// xdp_attach_mode from libxdp.h
// licensed under BSD-2

enum xdp_attach_mode {
	XDP_MODE_UNSPEC = 0,
	XDP_MODE_NATIVE,
	XDP_MODE_SKB,
	XDP_MODE_HW
};

enum xdp_attach_mode attach_mode = XDP_MODE_NATIVE;

enum program_mode {
    FRER_ELIM,
    FRER_REPL,
    PREOF_ELIM,
    PREOF_REPL
};

struct egress_info {
    char ifname[MAX_IFNAME_LEN];
    int ifidx;
    union {
        int vid;                   // for FRER
        struct in6_addr dst_addr;  // for PREOF
    };
};

struct ingress_info {
    char ifname[MAX_IFNAME_LEN];
    int ifidx;
    union {
        int vid;      // for FRER
        int flow_id;  // for PREOF
    };
};

struct vlan_translation_table {
    char ifname[MAX_IFNAME_LEN];
    struct vlan_translation_entry vte;
};

struct config_item {
    char rx_ifname[MAX_IFNAME_LEN];
    int match_id;
    enum program_mode mode;
    int num_tx_ifaces;
    char tx_ifname[MAX_IFACES][MAX_IFNAME_LEN];
    int prog_fd;
};

// Abstraction over skeleton types so config functions work with both FRER and PREOF
struct skel_fds {
    int seqgen_map;
    int replicate_tx_map;
    int seqrcvy_map;
    int eliminate_tx_map;
    int dst_addr_map;
    int rvt_map;
    int evt_map;
    int replicate_prog;
    int eliminate_prog;
    int postprocessing_prog;
    int check_reset_prog;
};

// Egress interfaces' informations
static struct egress_info egress_ifaces[MAX_IFACES];

// Ingress interfaces' informations
static struct ingress_info ingress_ifaces[MAX_IFACES];

// Replication VLAN translation table.
// Translation is made after replication function.
// Egress iface, VID from, VID to.
static struct vlan_translation_table rvt[MAX_CFG_ENTRIES];

// Elimination VLAN translation table.
// Translation is made before elimination function.
// Ingress iface, VID from, VID to.
static struct vlan_translation_table evt[MAX_CFG_ENTRIES];

// Configuration entries populated from CLI arguments.
// Each entry maps an ingress interface and match ID (VLAN ID or flow label)
// to one or more egress interfaces, along with the program type and fd.
static struct config_item global_config[MAX_CFG_ENTRIES];

/**
 * @brief Signal handler. When SIGINT or SIGTERM is sent to the program, set the run flag to false,
 * therefore the program will stop running.
 * @param sig The signal number.
 */
static void sighandler(int sig)
{
    (void) sig;
    run = false;
}

__attribute_maybe_unused__
static inline int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    (void) level;
	return vfprintf(stderr, format, args);
}

/**
 * @brief Attach the appropriate XDP program to the ingress interface. Selects the replication or
 * elimination program based on the configuration entry's mode.
 * @param fds Holds the file descriptors for BPF programs and maps.
 * @param cfg A configuration entry specifying the interface and program type.
 * @return 0 if successful, -EINVAL if the program fd is invalid, the interface is not found,
 * or the attach fails.
 */
static int config_xdp_prog(struct skel_fds *fds, struct config_item *cfg)
{
    int prog_fd = (cfg->mode == FRER_ELIM || cfg->mode == PREOF_ELIM)
        ? fds->eliminate_prog : fds->replicate_prog;
    if (prog_fd < 0) {
        fprintf(stderr, "Error while searching for BPF program\n");
        return -EINVAL;
    }

    int ifindex = if_nametoindex(cfg->rx_ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to convert %s interface name to an index\n", cfg->rx_ifname);
        return -EINVAL;
    }

    int ret = bpf_xdp_attach(ifindex, prog_fd, attach_mode, NULL);
    if (ret < 0) {
        fprintf(stderr, "Failed to attach XDP program to interface %s\n", cfg->rx_ifname);
        return -EINVAL;
    }
    cfg->prog_fd = prog_fd;

    return ret;
}

/**
 * @brief Configure replication for a given ingress interface. Creates a devmap with the egress
 * interfaces, inserts it into the replicate map keyed by match ID, attaches the XDP program,
 * and initializes the sequence number generator.
 * @param fds Holds the file descriptors for BPF programs and maps.
 * @param cfg A configuration entry specifying the ingress interface, match ID, and egress interfaces.
 * @return 0 if successful, -EINVAL if map creation, interface lookup, or map update fails.
 */
static int configure_replication(struct skel_fds *fds, struct config_item *cfg)
{
    int ret = EXIT_SUCCESS;

    if (fds->seqgen_map < 0 || fds->replicate_tx_map < 0) {
        fprintf(stderr, "eBPF maps for replication config not found\n");
        return -EINVAL;
    }
    printf("Config replication on interface %s (ifindex: %d) match id %d\n",
           cfg->rx_ifname, if_nametoindex(cfg->rx_ifname), cfg->match_id);

    const int max_tx_ifaces = 8;
    char mapname[BPF_OBJ_NAME_LEN] = { };
    snprintf(mapname, BPF_OBJ_NAME_LEN, "id%d_txifs", cfg->match_id);
    int tx_ifaces_map_fd = bpf_map_create(
        BPF_MAP_TYPE_DEVMAP_HASH,
        mapname, sizeof(int),
        sizeof(struct bpf_devmap_val),
        max_tx_ifaces, 0
    );
    if (tx_ifaces_map_fd < 0) {
        fprintf(stderr, "Failed to create replication devmap for match ID %d\n", cfg->match_id);
        return -EINVAL;
    }

    for (int i = 0; i < cfg->num_tx_ifaces; ++i) {
        int ifindex = if_nametoindex(cfg->tx_ifname[i]);
        if (!ifindex) {
            fprintf(stderr, "Failed to convert '%s' interface name to an index\n", cfg->tx_ifname[i]);
            return -EINVAL;
        }
        struct bpf_devmap_val replication_iface = {
            .ifindex = ifindex,
            .bpf_prog = {fds->postprocessing_prog}
        };
        ret = bpf_map_update_elem(tx_ifaces_map_fd, &i, &replication_iface, 0);
        if (ret < 0) {
            fprintf(stderr, "Failed to insert replication interface to devmap\n");
            return -EINVAL;
        }
    }

    ret = bpf_map_update_elem(fds->replicate_tx_map, &cfg->match_id, &tx_ifaces_map_fd, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert tx interfaces into replicate map. Maybe already exists?\n");
        return -EINVAL;
    }

    close(tx_ifaces_map_fd);
    config_xdp_prog(fds, cfg);

    struct seq_gen new_gen = {};
    ret = bpf_map_update_elem(fds->seqgen_map, &cfg->match_id, &new_gen, BPF_ADD);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert sequence generator into seqgen map. Maybe already exists?\n");
        return -EINVAL;
    }

    return EXIT_SUCCESS;
}

/**
 * @brief Configure elimination for a given ingress interface. Inserts the egress interface into
 * the eliminate map keyed by match ID, attaches the XDP program, and initializes the sequence
 * number, history window and TakeAny set to true.
 * @param fds Holds the file descriptors for BPF programs and maps.
 * @param cfg A configuration entry specifying the ingress interface, match ID, and egress interface.
 * @return 0 if successful, -EINVAL if interface lookup or map update fails.
 */
static int configure_elimination(struct skel_fds *fds, struct config_item *cfg)
{
    int ret = EXIT_SUCCESS;

    if (fds->seqrcvy_map < 0 || fds->eliminate_tx_map < 0) {
        fprintf(stderr, "eBPF maps for elimination config not found\n");
        return -EINVAL;
    }

    printf("Config recovery on iface %s (ifindex: %d) match id %d\n",
           cfg->rx_ifname, if_nametoindex(cfg->rx_ifname), cfg->match_id);
    int ifindex = if_nametoindex(cfg->tx_ifname[0]);
    if (!ifindex) {
        fprintf(stderr, "Failed to convert %s interface name to an index\n", cfg->tx_ifname[0]);
        return -EINVAL;
    }

    ret = bpf_map_update_elem(fds->eliminate_tx_map, &cfg->match_id, &ifindex, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert %s into eliminate map. Maybe already exists?\n", cfg->tx_ifname[0]);
        return -EINVAL;
    }

    config_xdp_prog(fds, cfg);

    struct seq_rcvy_and_hist new_rec = {}; // set sequence number and history window to 0
    new_rec.hist_recvseq_takeany ^= (-(true) ^ new_rec.hist_recvseq_takeany) & (1UL << TAKE_ANY); // set take_any true
    ret = bpf_map_update_elem(fds->seqrcvy_map, &cfg->match_id, &new_rec, BPF_ADD);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert sequence recovery to elimination map. Maybe already exists?\n");
        return -EINVAL;
    }

    return ret;
}

/**
 * @brief Iterate over all configuration entries and configure replication or elimination
 * for each one based on its mode.
 * @param fds Holds the file descriptors for BPF programs and maps.
 * @return 0 if successful, -EINVAL if any configuration entry fails.
 */
static int config_progs(struct skel_fds *fds)
{
    int ret = EXIT_SUCCESS;

    for (unsigned int i = 0; i < cfg_size; ++i) {
        struct config_item *frer_func = &global_config[i];
        if (frer_func->mode == FRER_REPL || frer_func->mode == PREOF_REPL) {
            ret = configure_replication(fds, frer_func);
            if (ret < 0) {
                fprintf(stderr, "Failed to configure replication (ID %d)\n", frer_func->match_id);
                return ret;
            }
        } else if (frer_func->mode == FRER_ELIM || frer_func->mode == PREOF_ELIM) {
            ret = configure_elimination(fds, frer_func);
            if (ret < 0) {
                fprintf(stderr, "Failed to configure elimination (ID %d)\n", frer_func->match_id);
                return ret;
            }
        } else {
            fprintf(stderr, "Invalid program type\n");
            return -EINVAL;
        }
    }

    return ret;
}

/**
 * @brief Detach XDP programs from all configured interfaces.
 */
static void cleanup(void)
{
    for (unsigned int i = 0; i < cfg_size; ++i) {
        struct config_item *frer_func = &global_config[i];
        int ifindex = if_nametoindex(frer_func->rx_ifname);
        if (!ifindex) {
            fprintf(stderr, "Failed to convert %s interface name to an index\n", frer_func->rx_ifname);
            continue;
        }

        if (frer_func->prog_fd) {
            int ret = bpf_xdp_detach(ifindex, attach_mode, NULL);
            if (ret < 0) {
                fprintf(stderr, "Failed to detach xdp program from %s\n", frer_func->rx_ifname);
            }
        }
    }
}

/**
 * @brief Pin a single BPF map to PIN_DIR.
 * @param map The BPF map to pin.
 * @param name The map name (used as filename).
 * @return 0 on success, -1 on failure.
 */
static int pin_map(struct bpf_map *map, const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", PIN_DIR, name);
    unlink(path);
    
    int ret = bpf_map__pin(map, path);
    if (ret < 0) {
        fprintf(stderr, "Failed to pin %s: %s\n", name, strerror(-ret));
        return -1;
    }
    
    return 0;
}

/**
 * @brief Pin a BPF program fd to PIN_DIR.
 */
static int pin_prog(int prog_fd, const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", PIN_DIR, name);
    unlink(path);

    int ret = bpf_obj_pin(prog_fd, path);
    if (ret < 0) {
        fprintf(stderr, "Failed to pin prog %s: %s\n", name, strerror(-ret));
        return -1;
    }

    return 0;
}

/**
 * @brief Unpin all known maps and remove the pin directory.
 */
static void unpin_maps(void)
{
    const char *names[] = { "seqgen_map", "replicate_tx_map", "seqrcvy_map",
                            "eliminate_tx_map", "rvt", "evt", "dst_addr_map",
                            "postprocessing_prog" };
    unsigned short names_size = sizeof(names)/sizeof(names[0]);

    for (unsigned short i = 0; i < names_size; i++) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s", PIN_DIR, names[i]);
        unlink(path);
    }
    rmdir(PIN_DIR);
}

/**
 * @brief Populate the `dst_addr_map` eBPF map with egress interface index and flow label to
 * IPv6 destination address mappings, used by the replication postprocessing program.
 * @param table_fd The file descriptor of the `dst_addr_map` eBPF map.
 * @param ifaces The array of egress interface info containing ifindex and destination address.
 * @param entries The number of entries to insert.
 * @param flow_label The flow label used as part of the map key.
 * @return 0 if successful, -EINVAL if any map update fails.
 */
static int setup_ip_translation(int table_fd, struct egress_info *ifaces, int entries, int flow_label)
{
    for (int i = 0; i < entries; ++i) {
        struct tx_key k = { .ifidx = ifaces[i].ifidx, .flow_label = flow_label };
        int ret = bpf_map_update_elem(table_fd, &k, &ifaces[i].dst_addr, 0);
        if (ret < 0) {
            fprintf(stderr, "Failed to insert IP for %s into dst_addr_map\n", ifaces[i].ifname);
            return -EINVAL;
        }
    }

    return 0;
}

/**
 * @brief Populate a VLAN translation eBPF map with interface-to-VLAN mappings. If an entry
 * already exists for an interface, it verifies the existing entry matches the new one. This way,
 * it is possible to send multiple replicas to a single interface.
 * @param table_fd The file descriptor of the rvt or evt eBPF map.
 * @param t The array of VLAN translation entries containing interface name and from/to VIDs.
 * @param entries The number of entries to insert.
 * @return 0 if successful, -EINVAL if interface lookup, map update, or conflict check fails.
 */
static int setup_vlan_translation(int table_fd, struct vlan_translation_table *t, int entries)
{
    int ret;
    for (int i = 0; i < entries; ++i) {
        struct vlan_translation_entry e;
        e.from = t[i].vte.from;
        e.to = t[i].vte.to;

        int ifindex = if_nametoindex(t[i].ifname);
        if (!ifindex) {
            fprintf(stderr, "Failed to convert %s interface name to an index\n", t[i].ifname);
            return -EINVAL;
        }

        ret = bpf_map_update_elem(table_fd, &ifindex, &e, BPF_NOEXIST);
        if (ret < 0) {
            // Already exists, check that the existing translation is consistent.
            // This allows sending multiple replicas for the same interface.
            struct vlan_translation_entry existing_entry;
            ret = bpf_map_lookup_elem(table_fd, &ifindex, &existing_entry);
            if (ret < 0) {
                fprintf(stderr, "Failed to get an already existing VLAN translation entry from the table.\n");
                return -EINVAL;
            }

            if (existing_entry.from != e.from || existing_entry.to != e.to) {
                fprintf(stderr, "VLAN translation conflict on %s: existing from=%d, new from=%d\n",
                        t[i].ifname, existing_entry.from, e.from);
                return -EINVAL;
            }
        }
    }
    return 0;
}

/**
 * @brief Populate global_config, rvt, and evt tables from the parsed CLI arguments.
 * For replication mode, creates one config entry with all egress interfaces and fills
 * the rvt table. For elimination mode, creates one config entry per ingress interface
 * and fills the evt table. VLAN translation tables are only filled in FRER mode.
 *
 * Example rvt entry:  { "enp3s0", { .from = 10, .to = 50 } }
 * Example evt entry:  { "enp7s0", { .from = 55, .to = 10 } }
 * Example config:     { "aeth0", 10, FRER_REPL, 2, { "enp3s0", "enp6s0" }, 0 }
 */
static void fill_config_tables(void)
{
    if (mode == FRER_REPL || mode == PREOF_REPL) {
        struct config_item cfg_item = {};
        strcpy(cfg_item.rx_ifname, ingress_ifaces[0].ifname);
        cfg_item.match_id = (mode == PREOF_REPL) ? ingress_ifaces[0].flow_id : ingress_ifaces[0].vid;
        cfg_item.mode = mode;
        cfg_item.num_tx_ifaces = egress_size;
        cfg_item.prog_fd = 0;
        for (unsigned int i = 0; i < egress_size; i++) {
            strcpy(cfg_item.tx_ifname[i], egress_ifaces[i].ifname);
        }
        global_config[cfg_size++] = cfg_item;

        // Populate VLAN transition tables
        if (mode == FRER_REPL) {
            for (unsigned int i = 0; i < egress_size; i++) {
                static struct vlan_translation_table rvt_item = {};
                strcpy(rvt_item.ifname, egress_ifaces[i].ifname);
                rvt_item.vte.from = ingress_ifaces[0].vid;
                rvt_item.vte.to = egress_ifaces[i].vid;
                rvt[rvt_size++] = rvt_item;
            }
        }
    } else {
        for (unsigned int i = 0; i < ingress_size; i++) {
            struct config_item cfg_item = {};
            strcpy(cfg_item.rx_ifname, ingress_ifaces[i].ifname);
            cfg_item.match_id = (mode == PREOF_ELIM) ? ingress_ifaces[i].flow_id : egress_ifaces[0].vid;
            cfg_item.mode = mode;
            cfg_item.num_tx_ifaces = 1;
            cfg_item.prog_fd = 0;
            strcpy(cfg_item.tx_ifname[0], egress_ifaces[0].ifname);
            global_config[cfg_size++] = cfg_item;

            // Populate VLAN transition tables
            if (mode == FRER_ELIM) {
                struct vlan_translation_table evt_item = {};
                strcpy(evt_item.ifname, ingress_ifaces[i].ifname);
                evt_item.vte.from = ingress_ifaces[i].vid;
                evt_item.vte.to = egress_ifaces[0].vid;
                evt[evt_size++] = evt_item;
            }
        }
    }
}

/**
 * @brief Callback for argp to parse a single CLI option. Validates required options (-m, -i, -e)
 * and populates mode, ingress/egress interface arrays, and flags accordingly.
 * @param key The option character.
 * @param arg The argument value following the option.
 * @param state The argp parser state.
 * @return 0 on success, exits the program on invalid input.
 */
static int parse_opt(int key, char *arg, struct argp_state *state) {    
    // Check if help option is present
    int k = 0;
    int help = 0;
    while (!help && k < state->argc) {
        if (!strcmp(state->argv[k], "--help") || !strcmp(state->argv[k], "-?") || !strcmp(state->argv[k], "--usage"))
            help = 1;
        k++;
    }
    
    // Check required options
    if (!help) {
        const char* required[] = { "-m" , "-i", "-e" };
        for (unsigned long i = 0; i < sizeof(required)/sizeof(required[0]); i++) {
            int j = 0;
            int isPresent = 0;
            while (!isPresent && j < state->argc) {
                if (!strcmp(state->argv[j], required[i]))
                    isPresent = 1;
                j++;
            }
            if (!isPresent) {
                fprintf(stderr, "Required: -m, -i, -e\n");
                exit(EXIT_FAILURE);
            }
        }
    }
    
    // Set variables based on given argp options
    char* token;
    switch (key) {
        case 'h':
            argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            break;
        case 'm':
            if (is_mode_set) {
                fprintf(stderr, "-m can only be specified once\n");
                exit(EXIT_FAILURE);
            }

            if (strcmp("repl", arg) == 0) {
                mode = FRER_REPL;
            } else if (strcmp("elim", arg) == 0) {
                mode = FRER_ELIM;
            } else if (strcmp("prf", arg) == 0) {
                mode = PREOF_REPL;
            } else if (strcmp("pef", arg) == 0) {
                mode = PREOF_ELIM;
            } else {
                fprintf(stderr, "There is no '%s' mode!\n", arg);
                exit(EXIT_FAILURE);
            }
            is_mode_set = true;
            break;
        case 'i':
            if (!is_mode_set) {
                fprintf(stderr, "-m must be specified before -i and -e\n");
                exit(EXIT_FAILURE);
            }

            if ((mode == FRER_REPL || mode == PREOF_REPL) && ingress_size >= 1) {
                fprintf(stderr, "Only one ingress interface can be in replication mode!\n");
                exit(EXIT_FAILURE);
            }

            token = strtok(arg, ":");
            if (token == NULL) {
                fprintf(stderr, "Invalid ingress format. Use IFNAME:NUM (e.g. eth0:10)\n");
                exit(EXIT_FAILURE);
            }
            strcpy(ingress_ifaces[ingress_size].ifname, token);
            ingress_ifaces[ingress_size].ifidx = if_nametoindex(token);
            if (!ingress_ifaces[ingress_size].ifidx) {
                fprintf(stderr, "Interface '%s' not found\n", token);
                exit(EXIT_FAILURE);
            }

            token = strtok(NULL, ":");
            if (token == NULL) {
                if (mode == FRER_REPL)
                    fprintf(stderr, "Missing VID for ingress interface. Use IFNAME:VID (e.g. eth0:10)\n");
                else if (mode == PREOF_REPL)
                    fprintf(stderr, "Missing Flow ID for ingress interface. Use IFNAME:FLOW_ID (e.g. eth0:10)\n");
                else
                    fprintf(stderr, "Wrong format for ingress interface. Use IFNAME:NUM (e.g. eth0:10)\n");
                exit(EXIT_FAILURE);
            }

            if (mode == PREOF_REPL || mode == PREOF_ELIM)
                ingress_ifaces[ingress_size].flow_id = atoi(token);
            else
                ingress_ifaces[ingress_size].vid = atoi(token);
            ingress_size++;
            break;
        case 'e':
            if (!is_mode_set) {
                fprintf(stderr, "-m must be specified before -i and -e\n");
                exit(EXIT_FAILURE);
            }

            if ((mode == FRER_ELIM || mode == PREOF_ELIM) && egress_size >= 1) {
                fprintf(stderr, "Only one egress interface can be in elimination mode!\n");
                exit(EXIT_FAILURE);
            }

            token = strchr(arg, ':');
            if (token == NULL) {
                fprintf(stderr, "Invalid egress format. Use IFNAME:VID or IFNAME:ADDR\n");
                exit(EXIT_FAILURE);
            }
            *token = '\0';
            token++;

            strcpy(egress_ifaces[egress_size].ifname, arg);
            egress_ifaces[egress_size].ifidx = if_nametoindex(arg);
            if (!egress_ifaces[egress_size].ifidx) {
                fprintf(stderr, "Interface '%s' not found\n", arg);
                exit(EXIT_FAILURE);
            }

            if (mode == PREOF_ELIM || mode == PREOF_REPL) {
                if (inet_pton(AF_INET6, token, &egress_ifaces[egress_size].dst_addr) != 1) {
                    fprintf(stderr, "Invalid IPv6 address '%s'\n", token);
                    exit(EXIT_FAILURE);
                }
            } else {
                if (*token == '\0') {
                    fprintf(stderr, "Missing VID for egress interface. Use IFNAME:VID (e.g. eth0:10)\n");
                    exit(EXIT_FAILURE);
                }
                egress_ifaces[egress_size].vid = atoi(token);
            }
            egress_size++;
            break;
        case 'n':
            add_or_rm_rtag = false;
            break;
        case 'q':
            quiet_output = true;
            break;
        case 'd':
            if (sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &dst_mac[0], &dst_mac[1], &dst_mac[2],
                        &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
                fprintf(stderr, "Invalid MAC address '%s'. Use format XX:XX:XX:XX:XX:XX\n", arg);
                exit(EXIT_FAILURE);
            }
            break;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    struct xdpfrer_bpf *frer_skel = NULL;
    struct xdppreof_bpf *preof_skel = NULL;
    struct skel_fds fds = {};
    volatile int *bss_received = NULL;
    volatile int *bss_passed = NULL;
    volatile int *bss_dropped = NULL;
    volatile int *bss_unmatched = NULL;

    struct timespec wait;
    int prog_fd;
    int ret;

    struct argp_option options[] =
    {
        { 0, 0, 0, 0, "Required options:", 1},
        { "mode", 'm', "WORD", 0, "Mode: repl/elim (FRER) or prf/pef (PREOF).", 1},
        { "ingress", 'i', "WORD", 0, "Ingress interface in IFNAME:VID (FRER) or IFNAME:FLOW_ID (PREOF) format.", 1},
        { "egress", 'e', "WORD", 0, "Egress interface in IFNAME:VID (FRER) or IFNAME:ADDR (PREOF) format.", 1},
        { 0, 0, 0, 0, "Optional:", 2},
        { "dmac", 'd', "MAC", 0, "Destination MAC address for PREOF mode (XX:XX:XX:XX:XX:XX). " \
          "Default value is 02:00:00:00:00:01.", 2},
        { "not", 'n', 0, 0, "Don't add or remove R-tag.", 2},
        { "quiet", 'q', 0, 0, "Quiet output.", 2},
        { "help", 'h', 0, 0, "Show this help message.", 3},
        { 0 }
    };
    struct argp argp = { options, parse_opt, 0, 0, 0, 0, 0 };
    argp_parse(&argp, argc, argv, ARGP_NO_HELP, 0, 0);

    fill_config_tables();

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    if (mode == FRER_REPL || mode == FRER_ELIM) {
        frer_skel = xdpfrer_bpf__open_and_load();
        if (!frer_skel) {
            perror("Error while open and load FRER skeleton");
            ret = EXIT_FAILURE;
            goto end;
        }
        frer_skel->data->add_or_rm_rtag = add_or_rm_rtag;

        fds.seqgen_map = bpf_map__fd(frer_skel->maps.seqgen_map);
        fds.replicate_tx_map = bpf_map__fd(frer_skel->maps.replicate_tx_map);
        fds.seqrcvy_map = bpf_map__fd(frer_skel->maps.seqrcvy_map);
        fds.eliminate_tx_map = bpf_map__fd(frer_skel->maps.eliminate_tx_map);
        fds.dst_addr_map = -1;
        fds.rvt_map = bpf_map__fd(frer_skel->maps.rvt);
        fds.evt_map = bpf_map__fd(frer_skel->maps.evt);
        fds.replicate_prog = bpf_program__fd(frer_skel->progs.replicate);
        fds.eliminate_prog = bpf_program__fd(frer_skel->progs.eliminate);
        fds.postprocessing_prog = bpf_program__fd(frer_skel->progs.replicate_postprocessing);
        fds.check_reset_prog = bpf_program__fd(frer_skel->progs.check_reset);

        bss_received = &frer_skel->bss->received;
        bss_passed = &frer_skel->bss->passed;
        bss_dropped = &frer_skel->bss->dropped;
        bss_unmatched = &frer_skel->bss->unmatched;

    } else {
        preof_skel = xdppreof_bpf__open_and_load();
        if (!preof_skel) {
            perror("Error while open and load PREOF skeleton");
            ret = EXIT_FAILURE;
            goto end;
        }
        __builtin_memcpy(preof_skel->data->dst_mac, dst_mac, 6);

        fds.seqgen_map = bpf_map__fd(preof_skel->maps.seqgen_map);
        fds.replicate_tx_map = bpf_map__fd(preof_skel->maps.replicate_tx_map);
        fds.seqrcvy_map = bpf_map__fd(preof_skel->maps.seqrcvy_map);
        fds.eliminate_tx_map = bpf_map__fd(preof_skel->maps.eliminate_tx_map);
        fds.dst_addr_map = bpf_map__fd(preof_skel->maps.dst_addr_map);
        fds.rvt_map = -1;
        fds.evt_map = -1;
        fds.replicate_prog = bpf_program__fd(preof_skel->progs.replicate);
        fds.eliminate_prog = bpf_program__fd(preof_skel->progs.eliminate);
        fds.postprocessing_prog = bpf_program__fd(preof_skel->progs.replicate_postprocessing);
        fds.check_reset_prog = bpf_program__fd(preof_skel->progs.check_reset);

        bss_received = &preof_skel->bss->received;
        bss_passed = &preof_skel->bss->passed;
        bss_dropped = &preof_skel->bss->dropped;
        bss_unmatched = &preof_skel->bss->unmatched;

        // Pinning maps
        if (mkdir(PIN_DIR, 0700) && errno != EEXIST) {
            fprintf(stderr, "Failed to mkdir %s: %s\n", PIN_DIR, strerror(errno));
            ret = EXIT_FAILURE;
            goto end;
        }

        pin_map(preof_skel->maps.seqgen_map, "seqgen_map");
        pin_map(preof_skel->maps.replicate_tx_map, "replicate_tx_map");
        pin_map(preof_skel->maps.seqrcvy_map, "seqrcvy_map");
        pin_map(preof_skel->maps.eliminate_tx_map, "eliminate_tx_map");
        pin_map(preof_skel->maps.dst_addr_map, "dst_addr_map");
        pin_prog(fds.postprocessing_prog, "postprocessing_prog");
    }

    ret = config_progs(&fds);
    if (ret < 0)
        goto end;

    if (mode == FRER_REPL || mode == FRER_ELIM) {
        ret = setup_vlan_translation(fds.rvt_map, rvt, rvt_size);
        if (ret < 0)
            goto end;

        ret = setup_vlan_translation(fds.evt_map, evt, evt_size);
        if (ret < 0)
            goto end;
    } else {
        if (mode == PREOF_REPL) {
            ret = setup_ip_translation(fds.dst_addr_map, egress_ifaces, egress_size, ingress_ifaces[0].flow_id);
            if (ret < 0)
                goto end;
        }
    }

    prog_fd = fds.check_reset_prog;
    if (prog_fd < 0) {
        perror("Error while search for check_reset BPF program");
        goto end;
    }

    run = true;
    wait = (struct timespec){ .tv_sec = 0, .tv_nsec = 100000000 };
    while (run) {
        if (!quiet_output) {
            if (mode == FRER_REPL)
                printf("Received: %d\n", *bss_received);
            else if (mode == PREOF_REPL)
                printf("Received: %d, Unmatched: %d\n", *bss_received, *bss_unmatched);
            else if (mode == FRER_ELIM)
                printf("Passed: %d, Dropped: %d\n", *bss_passed, *bss_dropped);
            else if (mode == PREOF_ELIM)
                printf("Passed: %d, Dropped: %d, Unmatched: %d\n", *bss_passed, *bss_dropped, *bss_unmatched);
        }

        for (int i = 0; i < 10; ++i) {
            clock_nanosleep(CLOCK_MONOTONIC, 0, &wait, NULL);
            struct bpf_test_run_opts opts;
            memset(&opts, 0, sizeof(opts));
            opts.sz = sizeof(opts);

            char data[64] = {};
            opts.data_in = data;
            opts.data_size_in = sizeof(data);

            // Periodically invoke check_reset
            ret = bpf_prog_test_run_opts(prog_fd, &opts);
            if (ret < 0) {
                perror("Error while running BPF program");
                goto end;
            }
        }
    }

end:
    printf("Exiting...\n");
    cleanup();
    if (preof_skel)
        unpin_maps();
    if (frer_skel)
        xdpfrer_bpf__destroy(frer_skel);
    if (preof_skel)
        xdppreof_bpf__destroy(preof_skel);
    return ret;
}
