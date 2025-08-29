#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <net/if.h>
#include <unistd.h>
#include <argp.h>

#include "common.h"
#include "xdpfrer.skel.h"

#define MAX_IFACES 16
#define MAX_IFNAME_LEN 16
#define MAX_CFG_ENTRIES 16

static bool run;
int evt_fd;
unsigned int rvt_size = 0;
unsigned int evt_size = 0;
unsigned int cfg_size = 0;
unsigned int ingress_size = 0;
unsigned int egress_size = 0;
bool repl_mode = false;
bool add_or_rm_rtag = true;
bool quiet_output = false;

// xdp_attach_mode from libxdp.h
// licensed under BSD-2

enum xdp_attach_mode {
	XDP_MODE_UNSPEC = 0,
	XDP_MODE_NATIVE,
	XDP_MODE_SKB,
	XDP_MODE_HW
};

enum xdp_attach_mode attach_mode = XDP_MODE_NATIVE;

enum FRER {
    FRER_RCVY, // elimination
    FRER_REPL // replication
};

struct egress_info {
    char ifname[MAX_IFNAME_LEN];
    int ifidx;
    int vid;
};

struct ingress_info {
    char ifname[MAX_IFNAME_LEN];
    int ifidx;
    int vid;
};

struct vlan_translation_table {
    char ifname[MAX_IFNAME_LEN];
    struct vlan_translation_entry vte;
};

struct frer_config_item {
    char rx_ifname[MAX_IFNAME_LEN];
    int match_vlan;
    enum FRER type;
    int num_tx_ifaces;
    char tx_ifname[MAX_IFACES][MAX_IFNAME_LEN];
    int prog_fd;
};

// Egress interfaces' informations
static struct egress_info egress_ifaces[MAX_IFACES];

// Ingress interfaces' informations
static struct ingress_info ingress_ifaces[MAX_IFACES];

// Replication VLAN translation table:
// Translation is made after replication function
// Egress iface, VID from, VID to
static struct vlan_translation_table rvt[MAX_CFG_ENTRIES];

// Elimination VLAN translation table
// Translation is made before elimination function
// Ingress iface, VID from, VID to
static struct vlan_translation_table evt[MAX_CFG_ENTRIES];

// talker interface
// matching VLAN ID
// Generator (replicate) / Recovery (eliminate)
// number of connected interfaces
// connected interface names
static struct frer_config_item global_config[MAX_CFG_ENTRIES];

/**
 * @brief Signal handler. When SIGINT or SIGTERM is sent to the program, set the run flag to false,
 * therefore the program will stop running.
 * @param sig is the signal number
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
 * @brief Attach the proper XDP program to the interface.
 * @param frer contains everything about the XDP FRER, for example, programs, counters, maps, and headers too
 * @param frer_func is an entry in the FRER config table, this contains the talker interface, matching VLAN ID,
 * Generator (replicate) / Recovery (eliminate), number of connected interfaces, connected interface names
 * @return EINVAL if something went wrong, 0 if it was successful
 */
static int config_xdp_prog(struct xdpfrer_bpf *frer, struct frer_config_item *frer_func)
{
    int prog_fd;
    int ret;

    if (frer_func->type == FRER_RCVY) {
        prog_fd = bpf_program__fd(frer->progs.eliminate);
    } else {
        prog_fd = bpf_program__fd(frer->progs.replicate);
    }

    if (prog_fd < 0) {
        fprintf(stderr, "Error while search for check_reset BPF program\n");
        return -EINVAL;
    }

    int ifindex = if_nametoindex(frer_func->rx_ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to convert %s interface name to an index\n", frer_func->rx_ifname);
        return -EINVAL;
    }

    ret = bpf_xdp_attach(ifindex, prog_fd, attach_mode, NULL);
    if (ret < 0) {
        fprintf(stderr, "Failed to attach XDP program to interface %s\n", frer_func->rx_ifname);
        return -EINVAL;
    }
    frer_func->prog_fd = prog_fd;

    return ret;
}

static int configure_replication(struct xdpfrer_bpf *frer, struct frer_config_item *cfg)
{
    int ret = EXIT_SUCCESS;
    int seqgen_map_fd = bpf_map__fd(frer->maps.seqgen_map);
    int replicate_txmap_fd = bpf_map__fd(frer->maps.replicate_tx_map);

    if (seqgen_map_fd < 0 || replicate_txmap_fd < 0) {
        fprintf(stderr, "FRER maps for replication config not found\n");
        return -EINVAL;
    }
    printf("Config replication on interface %s (ifindex: %d) match vlan %d\n",
           cfg->rx_ifname, if_nametoindex(cfg->rx_ifname), cfg->match_vlan);

    const int max_tx_ifaces = 8;
    char mapname[BPF_OBJ_NAME_LEN] = { };
    snprintf(mapname, BPF_OBJ_NAME_LEN, "vid%d_txifs", cfg->match_vlan);
    // Construct a map with all the replication egress interfaces
    int tx_ifaces_map_fd = bpf_map_create(
        BPF_MAP_TYPE_DEVMAP_HASH,
        mapname, sizeof(int),
        sizeof(struct bpf_devmap_val),
        max_tx_ifaces, 0
    );
    if (tx_ifaces_map_fd < 0) {
        fprintf(stderr, "Failed to create replication devamp for VID %d\n", cfg->match_vlan);
        return -EINVAL;
    }

    // Place the interfaces into that map
    for (int i = 0; i < cfg->num_tx_ifaces; ++i) {
        int ifindex = if_nametoindex(cfg->tx_ifname[i]);
        if (!ifindex) {
            fprintf(stderr, "Failed to convert %s interface name to an index\n", cfg->tx_ifname[i]);
            return -EINVAL;
        }
        struct bpf_devmap_val replication_iface = {
            .ifindex = ifindex,
            .bpf_prog = {bpf_program__fd(frer->progs.replicate_postprocessing)}
        };

        ret = bpf_map_update_elem(tx_ifaces_map_fd, &i, &replication_iface, 0);
        if (ret < 0) {
            fprintf(stderr, "Failed to insert replication interface to replicatio devmap\n");
            return -EINVAL;
        }
    }

    // Assign the constructed devmap to ingress VLAN, for example
    // if ingress VLAN ID = 10, replicate packet to iface1, iface2 and iface3 (all in the devmap)
    ret = bpf_map_update_elem(replicate_txmap_fd, &cfg->match_vlan, &tx_ifaces_map_fd, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert tx interfaces into replicate map. Maybe already exists?\n");
        return -EINVAL;
    }

    close(tx_ifaces_map_fd);
    config_xdp_prog(frer, cfg);

    struct seq_gen *new_gen = calloc(1, sizeof(struct seq_gen));
    ret = bpf_map_update_elem(seqgen_map_fd, &cfg->match_vlan, new_gen, BPF_ADD);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert sequence generator into seqgen map. Maybe already exists?\n");
        return -EINVAL;
    }

    return EXIT_SUCCESS;
}

static int configure_elimination(struct xdpfrer_bpf *frer, struct frer_config_item *cfg)
{
    int elim_tx_map_fd = bpf_map__fd(frer->maps.eliminate_tx_map);
    int rcvy_map_fd = bpf_map__fd(frer->maps.seqrcvy_map);
    int ret = EXIT_SUCCESS;

    if (rcvy_map_fd < 0 || elim_tx_map_fd < 0) {
        fprintf(stderr, "FRER maps for elimination config not found\n");
        return -EINVAL;
    }

    printf("Config recovery on iface %s (ifindex: %d) match vlan %d\n",
           cfg->rx_ifname, if_nametoindex(cfg->rx_ifname), cfg->match_vlan);
    int ifindex = if_nametoindex(cfg->tx_ifname[0]);
    if (!ifindex) {
        fprintf(stderr, "Failed to convert %s interface name to an index\n", cfg->tx_ifname[0]);
        return -EINVAL;
    }

    ret = bpf_map_update_elem(elim_tx_map_fd, &cfg->match_vlan, &ifindex, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert %s into eliminate map. Maybe already exists?\n", cfg->tx_ifname[0]);
        return -EINVAL;
    }

    config_xdp_prog(frer, cfg);

    struct seq_rcvy_and_hist *new_seq_rcvy_and_hist = calloc(1, sizeof(struct seq_rcvy_and_hist)); // set seq number and history window to 0
    new_seq_rcvy_and_hist->hist_recvseq_takeany ^= (-(true) ^ new_seq_rcvy_and_hist->hist_recvseq_takeany) & (1UL << TAKE_ANY); // set take any true
    ret = bpf_map_update_elem(rcvy_map_fd, &cfg->match_vlan, new_seq_rcvy_and_hist, BPF_ADD);
    if (ret < 0) {
        fprintf(stderr, "Failed to insert sequence recovery to elimination map. Maybe already exists?\n");
        return -EINVAL;
    }

    return ret;
}

/**
 * @brief Sets up every bpf map, configures VLANs on interfaces, and calls config_xdp_prog() that attaches the
 * proper XDP program to an interface.
 * @param frer contains everything about the XDP FRER, for example, programs, counters, maps, and headers too
 * @return EINVAL if something went wrong, 0 if it was successful
 */
static int config_frer(struct xdpfrer_bpf *frer)
{
    int ret = EXIT_SUCCESS;

    for (unsigned int i = 0; i < cfg_size; ++i) {
        struct frer_config_item *frer_func = &global_config[i];
        if (frer_func->type == FRER_REPL) {
            ret = configure_replication(frer, frer_func);
            if (ret < 0) {
                fprintf(stderr, "Failed to configure replication (VID %d)\n", frer_func->match_vlan);
                return ret;
            }
        } else if (frer_func->type == FRER_RCVY) {
            ret = configure_elimination(frer, frer_func);
            if (ret < 0) {
                fprintf(stderr, "Failed to configure elimination (VID %d)\n", frer_func->match_vlan);
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
 * @brief Cleans up XDP FRER. It detaches programs from interfaces.
 * @param frer contains everything about the XDP FRER, for example, programs, counters, maps, and headers too
 */
static void cleanup_frer(struct xdpfrer_bpf *frer)
{
    (void) frer;
    for (unsigned int i = 0; i < cfg_size; ++i) {
        struct frer_config_item *frer_func = &global_config[i];
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
 * @brief Sets up the VLAN translation in ingress or egress bpf VLAN maps.
 * @param table_fd is the file descriptor of the bpf map
 * @param t is the VLAN translation table
 * @param entries is the number of entries that will be updated in the bpf VLAN map
 * @return EINVAL if something went wrong, 0 if it was successful
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
            fprintf(stderr, "Failed to insert VLAN translation entry into the table. Already exists?\n");
            return -EINVAL;
        }
    }
    return 0;
}

/**
 * @brief Fill config, evt, rtv tables based on the given command prompt arguments.
 * An example for rvt: { "enp3s0", { 10, 50 } },
 * An example for evt: { "enp7s0", { 55, 10 } },
 * An example for global_config: { "aeth0", 10, FRER_REPL, 2, { "enp3s0", "enp6s0" }, 0 }
*/
static void fill_config_tables(void)
{
    if (repl_mode) {
        struct frer_config_item cfg_item = {};
        strcpy(cfg_item.rx_ifname, ingress_ifaces[0].ifname);
        cfg_item.match_vlan = ingress_ifaces[0].vid;
        cfg_item.type = FRER_REPL;
        cfg_item.num_tx_ifaces = egress_size;
        cfg_item.prog_fd = 0;
        for (unsigned int i = 0; i < egress_size; i++) {
            strcpy(cfg_item.tx_ifname[i], egress_ifaces[i].ifname);
        }
        global_config[cfg_size++] = cfg_item;

        for (unsigned int i = 0; i < egress_size; i++) {
            static struct vlan_translation_table rvt_item = {};
            strcpy(rvt_item.ifname, egress_ifaces[i].ifname);
            rvt_item.vte.from = ingress_ifaces[0].vid;
            rvt_item.vte.to = egress_ifaces[i].vid;
            rvt[rvt_size++] = rvt_item;
        }
    } else {
        for (unsigned int i = 0; i < ingress_size; i++) {
            struct frer_config_item cfg_item = {};
            strcpy(cfg_item.rx_ifname, ingress_ifaces[i].ifname);
            cfg_item.match_vlan = egress_ifaces[0].vid;
            cfg_item.type = FRER_RCVY;
            cfg_item.num_tx_ifaces = 1;
            cfg_item.prog_fd = 0;
            strcpy(cfg_item.tx_ifname[0], egress_ifaces[0].ifname);
            global_config[cfg_size++] = cfg_item;

            struct vlan_translation_table evt_item = {};
            strcpy(evt_item.ifname, ingress_ifaces[i].ifname);
            evt_item.vte.from = ingress_ifaces[i].vid;
            evt_item.vte.to = egress_ifaces[0].vid;
            evt[evt_size++] = evt_item;
        }
    }
}

/**
 * @brief Parse command prompt arguments.
 * @param key the option
 * @param arg argument value after the option
 * @param state argument parser state
 * @return 0 if everything is ok, otherwise the program exit with failure.
*/
static int parse_opt(int key, char *arg, struct argp_state *state) {    
    /* Check if help option is present */
    int k = 0;
    int help = 0;
    while (!help && k < state->argc) {
        if (!strcmp(state->argv[k], "--help") || !strcmp(state->argv[k], "-?") || !strcmp(state->argv[k], "--usage"))
            help = 1;
        k++;
    }
    
    /* Check required options */
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
    
    /* Set variables based on given argp options */
    char* token;
    switch (key) {
        case 'm':
            if (strcmp("repl", arg) == 0) {
                repl_mode = true;
            } else if (strcmp("elim", arg) == 0) {
                repl_mode = false;
            } else {
                fprintf(stderr, "There is no '%s' mode!\n", arg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'i':
            if (repl_mode && ingress_size >= 1) {
                fprintf(stderr, "Only one ingress interface can be in replication mode!\n");
                exit(EXIT_FAILURE);
            }

            token = strtok(arg, ":");
            if (token != NULL) {
                strcpy(ingress_ifaces[ingress_size].ifname, arg);
                ingress_ifaces[ingress_size].ifidx = if_nametoindex(arg);
                
                token = strtok(NULL, ":");
                if (token != NULL)
                    ingress_ifaces[ingress_size].vid = atoi(token);
            }
            ingress_size++;
            break;
        case 'e':
            if (!repl_mode && egress_size >= 1) {
                fprintf(stderr, "Only one egress interface can be in elimination mode!\n");
                exit(EXIT_FAILURE);
            }

            token = strtok(arg, ":");
            if (token != NULL) {
                strcpy(egress_ifaces[egress_size].ifname, arg);
                egress_ifaces[egress_size].ifidx = if_nametoindex(arg);
                
                token = strtok(NULL, ":");
                if (token != NULL)
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
    }
    return 0;
}

int main(int argc, char* argv[])
{
    struct xdpfrer_bpf *skel;
    struct timespec wait;
    int prog_fd;
    int ret;

    struct argp_option options[] =
    {
        { "mode", 'm', "WORD", 0, "Mode: repl or elim (Required)", 0},
        { "ingress", 'i', "WORD", 0, "Ingress interface in IFNAME:VID format (Required)", 0},
        { "egress", 'e', "WORD", 0, "Egress interface in IFNAME:VID format (Required)", 0},
        { "not", 'n', 0, 0, "Not adding or removing R-tag. (Optional)", 0},
        { "quiet", 'q', 0, 0, "Quiet output. (Optional)", 0},
        { 0 }
    };
    struct argp argp = { options, parse_opt, 0, 0, 0, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, 0);

    fill_config_tables();

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    skel = xdpfrer_bpf__open_and_load();
    if (!skel) {
        perror("Error while open and load skeleton");
        ret = EXIT_FAILURE;
        goto end;
    }
    skel->data->add_or_rm_rtag = add_or_rm_rtag;

    ret = config_frer(skel);
    if (ret < 0) {
        goto end;
    }

    ret = setup_vlan_translation(bpf_map__fd(skel->maps.rvt), rvt, rvt_size);
    if (ret < 0) {
        goto end;
    }

    ret = setup_vlan_translation(bpf_map__fd(skel->maps.evt), evt, evt_size);
    if (ret < 0) {
        goto end;
    }
    
    evt_fd = bpf_map__fd(skel->maps.evt);
    if (evt_fd < 0) {
        perror("Error while search for evt BPF map");
        goto end;
    }

    prog_fd = bpf_program__fd(skel->progs.check_reset);
    if (prog_fd < 0) {
        perror("Error while search for check_reset BPF program");
        goto end;
    }

    run = true;
    wait = (struct timespec){ .tv_sec = 0, .tv_nsec = 100000000 };
    while (run) {
         if (!quiet_output) {
            if (repl_mode)
                printf("Received packets: %d\n", skel->bss->packets_seen);
            else
                printf("Passed %d, Dropped %d\n", skel->bss->passed, skel->bss->dropped);
        }

        for (int i = 0; i < 10; ++i) {
            clock_nanosleep(CLOCK_MONOTONIC, 0, &wait, NULL);

            char dummy_ctx[] = "0000000000000";
            struct bpf_test_run_opts dummy_opts = {
                .sz = sizeof(struct bpf_test_run_opts),
                .data_in = &dummy_ctx,
                .data_size_in = sizeof(dummy_ctx),
                .repeat = 1
            };

            ret = bpf_prog_test_run_opts(prog_fd, &dummy_opts);
            if (ret < 0) {
                perror("Error while running BPF program");
                goto end;
            }
        }
    }

end:
    printf("Exiting...\n");
    cleanup_frer(skel);
    xdpfrer_bpf__destroy(skel);
    return ret;
}
