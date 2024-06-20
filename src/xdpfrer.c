#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/cdefs.h>
#include <time.h>
#include <net/if.h>
#include <argp.h>
#include <error.h>
#include <unistd.h>

#include "common.h"
#include "xdpfrer.skel.h"

#define DETNET

#ifdef VETH
#undef DETNET
#endif

#ifdef DETNET
#undef VETH
#endif

static bool run;
int evt_fd;

// xdp_attach_mode from libxdp.h
// licensed under BSD-2

enum xdp_attach_mode {
	XDP_MODE_UNSPEC = 0,
	XDP_MODE_NATIVE,
	XDP_MODE_SKB,
	XDP_MODE_HW
};

enum xdp_attach_mode attach_mode = XDP_MODE_NATIVE;

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


struct vlan_translation_table {
    const char ifname[16];
    struct vlan_translation_entry vte;
};

enum FRER {
    FRER_RCVY,
    FRER_GEN
};

struct frer_config_item {
    const char *rx_ifname;
    int match_vlan;
    enum FRER type;
    int num_tx_ifaces;
    const char *tx_ifname[16];
    /* struct xdp_program *prog; */
    int prog_fd;
};

////////////////Config part///////////////
// Everything is hardcoded. Proper control plane would be better.

// Replication VLAN translation table:
// Translation is made after replication function
// Egress iface, VID from, VID to
static struct vlan_translation_table rvt[] = {
    {"enp3s0", { 10, 50 }},
    {"enp6s0", { 10, 55 }},
    {"enp4s0", { 10, 60 }},
    {"enp7s0", { 10, 66 }},
};

// Elimination VLAN translation table
// Translation is made before elimination function
// Ingress iface, VID from, VID to
static struct vlan_translation_table evt[] = {
    {"enp4s0", { 50, 10 }},
    {"enp7s0", { 55, 10 }},
    {"enp3s0", { 60, 10 }},
    {"enp6s0", { 66, 10 }},
};

// FRER configuration table
// Interface, matching VID, Generator/Recovery, num of ifaces, iface names
static struct frer_config_item cfg[] = {
    { "aeth0", 10, FRER_GEN, 2, { "enp3s0", "enp6s0" }, 0 },
    { "beth0", 10, FRER_GEN, 2, { "enp4s0", "enp7s0" }, 0 },
    { "enp3s0", 10, FRER_RCVY, 1, { "aeth0" }, 0 },
    { "enp6s0", 10, FRER_RCVY, 1, { "aeth0" }, 0 },
    { "enp4s0", 10, FRER_RCVY, 1, { "beth0" }, 0 },
    { "enp7s0", 10, FRER_RCVY, 1, { "beth0" }, 0 },
};

const char route0[] = "enp4s0";
const char route1[] = "enp7s0";

static void handler(int signum, siginfo_t *info, void *ctx) {
    (void) signum;
    (void) ctx;

    int new_vlan = 22;
    int new_vlan2 = 33;
    int sig_ifindex = info->si_value.sival_int;
    int entries = sizeof(evt) / sizeof(struct vlan_translation_table);

    for (int i = 0; i < entries; ++i) {
        int ifindex = if_nametoindex(evt[i].ifname);
        if (!ifindex) {
            perror("if_nametoindex");
            return;
        }

        if (sig_ifindex == ifindex) {
            struct vlan_translation_entry e;
            e.to = evt[i].vte.to;
            if (evt[i].vte.from == new_vlan || evt[i].vte.from == new_vlan2) {
                if (strcmp(evt[i].ifname, route0) == 0 || strcmp(evt[i].ifname, route1) == 0) {
                    e.from = 55;
                    evt[i].vte.from = 55;
                } else {
                    e.from = 66;
                    evt[i].vte.from = 66;
                }
            } else {
                if (strcmp(evt[i].ifname, route0) == 0 || strcmp(evt[i].ifname, route1) == 0) {
                    e.from = new_vlan;
                    evt[i].vte.from = new_vlan;
                } else {
                    e.from = new_vlan2;
                    evt[i].vte.from = new_vlan2;
                }
            }

            int ret = bpf_map_update_elem(evt_fd, &ifindex, &e, BPF_EXIST);
            if (ret < 0) {
                fprintf(stderr, "\tFailed to update VLAN translation entry. Maybe not exists?\n");
                return;
            }

            printf("Successfully change VLAN on %s to %d\n", evt[i].ifname, evt[i].vte.from);
            break;
        }
    }

    for (int i = 0; i < entries; ++i) {
        printf("  %s %d %d\n", evt[i].ifname, evt[i].vte.from, evt[i].vte.to);
    }
}

static int config_xdp_prog(struct xdpfrer_bpf *frer, struct frer_config_item *frer_func)
{
    int prog_fd;
    int ret;

    if (frer_func->type == FRER_RCVY) {
        prog_fd = bpf_program__fd(frer->progs.eliminate);
    } else {
        prog_fd = bpf_program__fd(frer->progs.replicate);
    }

    int ifindex = if_nametoindex(frer_func->rx_ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return -EINVAL;
    }

    ret = bpf_xdp_attach(ifindex, prog_fd, attach_mode, NULL);
    if (ret < 0) {
        fprintf(stderr, "Failed to attach XDP program to iface %s\n", frer_func->rx_ifname);
        return -EINVAL;
    }
    frer_func->prog_fd = prog_fd;

    return ret;
}

static int config_frer(struct xdpfrer_bpf *frer)
{
    int elim_map_fd, eliminate_txmap_fd;
    int seqgen_map_fd, replicate_txmap_fd;
    int ret;

    seqgen_map_fd = bpf_map__fd(frer->maps.seqgen_map);
    replicate_txmap_fd = bpf_map__fd(frer->maps.replicate_tx_map);
    elim_map_fd = bpf_map__fd(frer->maps.seqrcvy_map);
    eliminate_txmap_fd = bpf_map__fd(frer->maps.eliminate_tx_map);
    if (seqgen_map_fd < 0 || replicate_txmap_fd < 0 ||
        eliminate_txmap_fd < 0 || elim_map_fd < 0) {
        fprintf(stderr, "FRER map(s) not found\n");
        return -EINVAL;
    }

    int num_frer_functions = sizeof(cfg) / sizeof(struct frer_config_item);
    for (int i = 0; i < num_frer_functions; ++i) {

        struct frer_config_item *frer_func = &cfg[i];

        switch (frer_func->type) {
            case FRER_GEN:
                printf("Config replication on iface %s match vlan %d\n", frer_func->rx_ifname, frer_func->match_vlan);
                int tx_ifaces_map_fd = bpf_map_create(BPF_MAP_TYPE_DEVMAP_HASH, NULL, sizeof(int), sizeof(struct bpf_devmap_val), 8, 0 );
                struct bpf_devmap_val iface = { };
                for (int j = 0; j < frer_func->num_tx_ifaces; ++j) {
                    int ifindex = if_nametoindex(frer_func->tx_ifname[j]);
                    if (!ifindex) {
                        perror("if_nametoindex");
                        return -EINVAL;
                    }
                    iface.ifindex = ifindex;

                    // Attach XDP prog to change VLAN ID after replication
                    iface.bpf_prog.fd = bpf_program__fd(frer->progs.replicate_postprocessing);

                    ret = bpf_map_update_elem(tx_ifaces_map_fd, &j, &iface, 0);
                    if (ret < 0) {
                        fprintf(stderr, "\tFailed to insert ifindex to replicate map\n");
                        return -EINVAL;
                    }
                }
                bpf_map_update_elem(replicate_txmap_fd, &frer_func->match_vlan, &tx_ifaces_map_fd, 0);
                close(tx_ifaces_map_fd);
                config_xdp_prog(frer, frer_func);
                struct seq_gen *new_gen = calloc(1, sizeof(struct seq_gen));
                ret = bpf_map_update_elem(seqgen_map_fd, &frer_func->match_vlan, new_gen, BPF_ADD);
                if (ret < 0) {
                    fprintf(stderr, "\tFailed to insert sequence generator to seqgen map. Maybe already exists?\n");
                    return -EINVAL;
                }
            break;

            case FRER_RCVY:
                printf("Config recovery on iface %s match vlan %d\n", frer_func->rx_ifname, frer_func->match_vlan);

                int ifindex = if_nametoindex(frer_func->tx_ifname[0]);
                if (!ifindex) {
                    perror("if_nametoindex");
                    return -EINVAL;
                }
                bpf_map_update_elem(eliminate_txmap_fd, &frer_func->match_vlan, &ifindex, 0);
                config_xdp_prog(frer, frer_func);

                struct seq_rcvy_and_hist *new_seq_rcvy_and_hist = calloc(1, sizeof(struct seq_rcvy_and_hist)); // set seq number and history window to 0
                new_seq_rcvy_and_hist->hist_recvseq_takeany ^= (-(true) ^ new_seq_rcvy_and_hist->hist_recvseq_takeany) & (1UL << TAKE_ANY); // set take any true
                ret = bpf_map_update_elem(elim_map_fd, &frer_func->match_vlan, new_seq_rcvy_and_hist, BPF_ADD);
                if (ret < 0) {
                    fprintf(stderr, "\tFailed to insert sequence recovery to elim map. Maybe already exists?\n");
                    return -EINVAL;
                }
            break;
        }
    }
    return 0;
}

static void cleanup_frer(struct xdpfrer_bpf *frer)
{
    (void) frer;
    int num_frer_functions = sizeof(cfg) / sizeof(struct frer_config_item);
    for (int i = 0; i < num_frer_functions; ++i) {
        struct frer_config_item *frer_func = &cfg[i];
        int ifindex = if_nametoindex(frer_func->rx_ifname);
        /* if (frer_func->prog) { */
        if (frer_func->prog_fd) {
            bpf_xdp_detach(ifindex, attach_mode, NULL);
        }
    }
}

static int setup_vlan_translation(int table_fd, struct vlan_translation_table *t, int entries)
{
    /* int evt_table_fd = bpf_map__fd(frer->maps.evt); */
    /* int entries = sizeof(rvt) / sizeof(struct vlan_translation_table); */
    for (int i = 0; i < entries; ++i) {
        struct vlan_translation_entry e;
        e.from = t[i].vte.from;
        e.to = t[i].vte.to;

        int ifindex = if_nametoindex(t[i].ifname);
        if (!ifindex) {
            perror("if_nametoindex");
            return -EINVAL;
        }

        int ret = bpf_map_update_elem(table_fd, &ifindex, &e, BPF_NOEXIST);
        if (ret < 0) {
            fprintf(stderr, "\tFailed to insert VLAN translation entry into the table. Already exists?\n");
            return -EINVAL;
        }
    }
    return 0;
}

int main(void)
{
    struct xdpfrer_bpf *skel;
    /* int timer_map_fd; */
    int prog_fd;
    int ret;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    struct sigaction s;
    s.sa_sigaction = handler;
    s.sa_flags = SA_SIGINFO;
    sigemptyset(&s.sa_mask);
    sigaction(SIGUSR1, &s, NULL);

    /* libbpf_set_print(libbpf_print_fn); */
    // libxdp_set_print(libxdp_print_fn);
    /* libbpf_set_memlock_rlim(RLIMIT_INFINITY); */

    skel = xdpfrer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "%s\n", strerror(errno));
        ret = EXIT_FAILURE;
        goto end;
    }

    ret = config_frer(skel);
    if (ret < 0)
        goto end;

    ret = setup_vlan_translation(bpf_map__fd(skel->maps.rvt), rvt, sizeof(rvt)/sizeof(struct vlan_translation_table));
    if (ret < 0)
        goto end;

    ret = setup_vlan_translation(bpf_map__fd(skel->maps.evt), evt, sizeof(evt)/sizeof(struct vlan_translation_table));
    if (ret < 0)
        goto end;
    evt_fd = bpf_map__fd(skel->maps.evt);

    /* timer_map_fd = bpf_map__fd(skel->maps.timer_map); */
    /* if (timer_map_fd < 0 || prog_fd < 0) { */
    prog_fd = bpf_program__fd(skel->progs.check_reset);
    if (prog_fd < 0) {
        goto end;
    }
    // Start the recovery timers
    /* bpf_progg_test_run_opts(prog_fd, NULL); */
    run = true;
    while (run) {
        printf("Received packets: %d, passed %d, dropped %d\n", skel->bss->packets_seen, skel->bss->passed, skel->bss->dropped);
        struct timespec wait = { 0, 100000000 };
        for (int i = 0; i < 10; ++i) {
            clock_nanosleep(CLOCK_MONOTONIC, 0, &wait, NULL);
            bpf_prog_test_run_opts(prog_fd, NULL);
        }
    }

end:
    cleanup_frer(skel);
    xdpfrer_bpf__destroy(skel);
    printf("Exiting...\n");
    return ret;
}
