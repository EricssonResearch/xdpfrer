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

## Usage

For basic usage a GNU/Linux system required with BPF and XDP support.

1. Open a root terminal and source the `env` file which configure the whole network: network namespaces acting as talker, switch and listener, including the virtual interfaces and links.
2. Run the `xdpfrer` inside the switch namespace (use the `nsx` alias)
3. Open up another root terminal, source the `env` file, and start a ping command from talker to listener
4. If everything OK, the ping successful and the XDP forwarding works properly
5. To cleanup, press `Ctrl+D` or type `exit` to exit from both terminal. The last terminal cleanup the environment

The commands:

```
# 1.
cd test
sudo su
source veth.env

# 2.
nsx ../src/xdpfrer

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

# 4.
#  (veth.env) root:test# nsx ../src/xdpfrer
#  Config replication on iface aeth0 match vlan 55
#  Config replication on iface beth0 match vlan 66
#  Config recovery on iface enp3s0 match vlan 66
#  Config recovery on iface enp6s0 match vlan 66
#  Config recovery on iface enp4s0 match vlan 55
#  Config recovery on iface enp7s0 match vlan 55
#  Received packets: 0, passed 0, dropped 0
#  Received packets: 0, passed 0, dropped 0
#  Received packets: 2, passed 2, dropped 2
#  Received packets: 4, passed 4, dropped 4
#  Received packets: 6, passed 6, dropped 6
#  Received packets: 8, passed 8, dropped 8
#  Received packets: 8, passed 8, dropped 8

# 5.
Ctrl+C # in xdpfrer terminal
Ctrl+D # in both terminal
```

For advanced usage, take a look to the `test/measurement.py` script.
It is possible to run XDP FRER on a real, physical testbed, just change the interface names and VLAN IDs in the code and the script accordingly.
With questions regarding usage, bugs and evaluation, please contact [Ferenc Fejes \<ferenc.fejes@ericsson.com\>](mailto:ferenc.fejes@ericsson.com).
