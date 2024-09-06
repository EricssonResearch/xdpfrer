# XDP FRER

This software is an experimental partial implementation of the IEEE 802.1CB Frame Replication and Elimination for Reliability standard.
The implementation uses the XDP packet processing subsystem of the Linux kernel, which can be configured with BPF.

The details of the experiment are discussed in the following research paper:

__Lightweight Implementation of Per-packet Service Protection in eBPF/XDP__ ([pdf](https://netdevconf.info/0x17/docs/netdev-0x17-paper25-talk-paper.pdf) | [arxiv](https://arxiv.org/abs/2312.07152) | [slides](https://netdevconf.info/0x17/docs/netdev-0x17-paper25-talk-slides/netdev0x17_xdpfrer_slides.pdf))

Cite as:

```
@misc{fejes2023lightweight,
      title={Lightweight Implementation of Per-packet Service Protection in eBPF/XDP}, 
      author={Ferenc Fejes and Ferenc Orosi and Balázs Varga and János Farkas},
      booktitle={Netdev 0x17, THE Technical Conference on Linux Networking},
      year={2023},
      eprint={2312.07152},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://netdevconf.info/0x17/25}
}
```

## Requirements

Debian based GNU/Linux distribution is preferred.
Tested with Debian Bookworm and Ubuntu 23.04, 23.10.

```
sudo apt install build-essential gcc-multilib clang llvm linux-tools-common bpftool libbpf-dev
```

**Note: libbpf version must be at least 1.3.0 on Ubuntu 23.04.**

## Building

```
cd src
make
```

## Source

```
.
├── README.md
├── src
│   ├── common.h        // basic data structures and defines
│   ├── Makefile        // GNU make file
│   ├── xdpfrer.bpf.c   // XDP programs and BPF map definitions
│   └── xdpfrer.c       // configure and load the BPF part to the kernel
└── test
    ├── measurement.py  // All-in-one testing and plotting script
    ├── physical.env    // Network config/environment for real testbed
    └── veth.env        // Full network config for veth/namespace based testbed
```

## Environment:

`physical.env` and `veth.env` contains this environment. Obviously you can modify vlans when you start running xdpfrer instances.

```
                    ┌───────────────────────────────────────────────────┐                    
                    │                        nsx                        │                    
                    │                                                   │                    
                    │┌──────────┬────────┐         ┌────────┬──────────┐│                    
┌─────────────┐     ││          │ enp3s0 ├────55───▶ enp4s0 │          ││     ┌─────────────┐
│      tx     │     ││          │        ◀────66───┐        │          ││     │      lx     │
│    ┌────────┤     │├────────┐ └────────┤         ├────────┘ ┌────────┤│     ├────────┐    │
│    │  teth0 ◀━━10━┿▶  aeth0 │          │         │          │  beth0 ◀┿━20━━▶  leth0 │    │
│    │10.0.0.1│     │├────────┘ ┌────────┤         ├────────┐ └────────┤│     │10.0.0.2│    │
│    └────────┤     ││          │ enp6s0 ├────56───▶ enp7s0 │          ││     ├────────┘    │
└─────────────┘     ││          │        ◀────67───┐        │          ││     └─────────────┘
                    │└──────────┴────────┘         └────────┴──────────┘│                    
                    │                                                   │                    
                    └───────────────────────────────────────────────────┘                    
```

## Usage

For basic usage a GNU/Linux system required with BPF and XDP support.

1. Open some terminal and source the `env` file which configure the whole network: network namespaces acting as talker, switch and listener, including the virtual interfaces and links.
2. Run the `xdpfrer` instances inside the switch namespace (use the `nsx` alias)
3. Open up another root terminal, source the `env` file, and start a ping command from talker to listener
4. If everything OK, the ping successful and the XDP forwarding works properly
5. To cleanup, press `Ctrl+D` or type `exit` to exit from terminals. The last terminal cleanup the environment

The commands:

```
# 1.
cd test
sudo su
source veth.env
```

```
# 2.1 (tx -> lx)
nsx ../src/xdpfrer -m repl -i aeth0:10 -e enp3s0:55 -e enp6s0:56
nsx ../src/xdpfrer -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20

# 2.2 (lx -> tx)
nsx ../src/xdpfrer -m repl -i beth0:20 -e enp4s0:66 -e enp7s0:67
nsx ../src/xdpfrer -m elim -i enp3s0:66 -i enp6s0:67 -e aeth0:10
```

```
# 3.
cd test
sudo su
source veth.env

tx ping 10.0.0.2 -c 4
#  PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
#  64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.044 ms
#  64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.056 ms
#  64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.055 ms
#  64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=0.057 ms
```

```
# 4.
#  (veth.env) root:test# nsx ../src/xdpfrer -m repl -i aeth0:10 -e enp3s0:55 -e enp6s0:56
#  Config replication on interface aeth0 (ifindex: 2) match vlan 10
#  Received packets: 0
#  Received packets: 1
#  Received packets: 2
#  Received packets: 3
#  Received packets: 4
#  Received packets: 4
#  Received packets: 4

#  (veth.env) root:test# nsx ../src/xdpfrer -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20
#  Config recovery on iface enp4s0 (ifindex: 3) match vlan 20
#  Config recovery on iface enp7s0 (ifindex: 5) match vlan 20
#  Passed 0, Dropped 0
#  Passed 1, Dropped 1
#  Passed 2, Dropped 2
#  Passed 3, Dropped 3
#  Passed 4, Dropped 4
#  Passed 4, Dropped 4
```

```
# 5.
Ctrl+C # in xdpfrer terminal
Ctrl+D # in both terminal
```

## Measurements:

For advanced usage, take a look at the test/measurement.py script. It is possible to run XDP FRER on a real, physical testbed, just change the interface names and VLAN IDs and the script accordingly.

First, run common tests or error tests:
```
python3 measurement.py test
or
python3 measurement.py error
```

After that, generate `txt` files from `pcap` files:
```
python3 measurement.py data
```

Last but not least, generate plots:
```
python3 measurement.py plot
```

With questions regarding usage, bugs and evaluation, please contact [Ferenc Fejes \<ferenc.fejes@ericsson.com\>](mailto:ferenc.fejes@ericsson.com).
