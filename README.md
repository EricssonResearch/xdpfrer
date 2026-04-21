# XDP FRER / XDP PREF

This software is an experimental partial implementation of the IEEE 802.1CB FRER [standard](https://standards.ieee.org/ieee/802.1CB/5703/).
It can replicate multiple copies of a packet over redundant network paths,
in order to protect them from network failures.
This function is called replication.
There must be a receiver side, called elimination.
The purpose of this is to accept the first copy received and drop the extra copies.

* Replication and elimination with vector recovery algorithm (defined in IEEE 802.1CB)
* Layer 2 TSN dataplane encapsulation with R-tag (IEEE 802.1CB)
* Layer 3 DetNet dataplane encapsulation with [SRv6 Redundancy SID](https://datatracker.ietf.org/doc/draft-ietf-spring-sr-redundancy-protection/)

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
Tested with Debian Bookworm and Ubuntu 23.10 and above.

```
sudo apt install build-essential gcc-multilib clang llvm linux-tools-common bpftool libbpf-dev
```

**Note: libbpf version must be at least 1.3.0 on Ubuntu 23.04.**

## Building

```
cd src
make
```

To build for aarch64, build the Docker image and run it.
The binary xdpfrer is presented in the /tmp folder.
We can copy the binary file back to host filesystem from the running Docker container.

```
docker build -f aarch64.Dockerfile -t xdpfrer .
docker run -it --name xdpfrer xdpfrer /bin/bash
docker cp xdpfrer:/tmp/src/xdpfrer .
```

## Argument list

```
Usage: xdpfrer [OPTION...]

 Required options:
  -e, --egress=WORD          Egress interface in IFNAME:VID (FRER) or
                             IFNAME:ADDR (PREOF) format.
  -i, --ingress=WORD         Ingress interface in IFNAME:VID (FRER) or
                             IFNAME:FLOW_ID (PREOF) format.
  -m, --mode=WORD            Mode: repl/elim (FRER) or prf/pef (PREOF).

 Optional:
  -d, --dmac=MAC             Destination MAC address for PREOF mode
                             (XX:XX:XX:XX:XX:XX). Default value is
                             02:00:00:00:00:01.
  -n, --not                  Don't add or remove R-tag.
  -q, --quiet                Quiet output.

  -h, --help                 Show this help message.
```

__Important:__ 

* In replication modes `repl` and `prf` one or more `--egress` and only one `--ingress` interface can be used
* In elimination modes `elim` and `pef` one or more `--ingress` and only one `--egress` interface can be used
* More replication and elimination instances can be added runtime with the `xdpfrer-ctl` helper tool.
The format of the command line arguments are the same as the `xdpfrer` case.

## Examples

### FRER (Layer 2)

`xdpfrer -m repl -i beth0:20 -e enp4s0:66 -e enp7s0:67` means:
Packets with VLAN ID 20 arriving on `beth0` are replicated to `enp4s0` with VLAN ID 66 and `enp7s0` with VLAN ID 67.

And `xdpfrer -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20` means:
Packets with VLAN ID 55 on `enp4s0` and VLAN ID 56 on `enp7s0` are received, duplicates are eliminated,
and only the first copy is forwarded to `beth0` with VLAN ID 20.

Using different VLAN IDs on the redundant paths is recommended.
With that, per-VLAN STP instances can be used.
Without that the egress interfaces of the redundant path(s) might be disabled by the STP,
which would make the replication unreliable.

### PREF (Layer 3)

`xdpfrer -m prf -i ethBA:10 -e veth0:5f00:0:0:e:: -e veth0:5f00:0:0:e:: -d 02:00:00:00:00:01` means:
IPv6 packets with flow label 10 arriving on `ethBA7` are encapsulated with an outer IPv6 header carrying a Redundancy SID
and two replicas are sent out through `veth0`, each with the same destination locator (`5f00:0:0:e::`).

And `xdpfrer -m pef -i ethED:10 -e veth0::: -d 02:00:00:00:00:01` means:
Encapsulated packets with flow ID 10 on `ethED` are decapsulated, duplicates are eliminated,
and only the first instance is forwarded to `veth0` with destination MAC 02:00:00:00:00:01.

In this implementation of the Layer 3 case the `xdpfrer` nodes should be the
SRv6 tunnel endpoints.
This achieved by configuring Linux with veth interfaces with MAC addresses and
`xdpfrer` set the destination MAC addresses of the ingress packets (with matching flow labels) to that address.
With that the node accept the packet for further Layer 3 processing e.g.: routing, SRv6 operations or
perform ARP or ND if needed.

## Source

```
.
├── README.md
├── src
│   ├── aarch64.Dockerfile // Dockerfile for cross-compilation on aarch64
│   ├── bpf_common.h       // BPF map definitions and shared structures
│   ├── common.h           // Shared data structures and defines
│   ├── Makefile           // GNU make file
│   ├── xdpfrer.bpf.c      // XDP programs for FRER (replication/elimination)
│   ├── xdpfrer.c          // Configure and load the BPF part to the kernel
│   └── xdppreof.bpf.c     // XDP programs for PREOF (SRv6-based)
└── test
    ├── measurement.py     // All-in-one testing and plotting script
    ├── env.py             // Mininet-based test environment setup for SRV6-PREOF
    ├── physical.env       // Network config/environment for real testbed
    └── veth.env           // Full network config for veth/namespace based testbed
```

## Test environment:

### FRER: veth-based environment

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

### PREOF: Mininet-based environment

`env.py` sets up a Mininet-based environment with IPv6/SRv6 addressing for PREF testing.

```
                    ┌───────────────────────────────────────┐                                                                      ┌───────────────────────────────────────┐                    
                    │                  nb                   │                                                                      │                  ne                   │                    
                    │            ┌────────────┐             │                                                                      │            ┌────────────┐             │                    
                    │            │     lo     │             │                                                                      │            │     lo     │             │                    
                    │            │5f00:0:0:b::│             │                                                                      │            │5f00:0:0:e::│             │                    
┌────────────────┐  │            └────────────┘             │  ┌──────────────────────────────┐  ┌──────────────────────────────┐  │            └────────────┘             │  ┌────────────────┐
│       na       │  │┌─────────────────┐ ┌─────────────────┐│  │              nc              │  │              nd              │  │┌─────────────────┐ ┌─────────────────┐│  │       nf       │
│ ┌────────────┐ │  ││      veth0      │ │      veth1      ││  │        ┌────────────┐        │  │        ┌────────────┐        │  ││      veth0      │ │      veth1      ││  │ ┌────────────┐ │
│ │     lo     │ │  ││02:00:00:00:00:00├─┤02:00:00:00:00:01││  │        │     lo     │        │  │        │     lo     │        │  ││02:00:00:00:00:00├─┤02:00:00:00:00:01││  │ │     lo     │ │
│ │5f00:0:0:a::│ │  │└────────────────▲┘ └─────────────────┘│  │        │5f00:0:0:c::│        │  │        │5f00:0:0:d::│        │  │└────────────────▲┘ └─────────────────┘│  │ │5f00:0:0:f::│ │
│ └────────────┘ │  │                 │                     │  │        └────────────┘        │  │        └────────────┘        │  │                 │                     │  │ └────────────┘ │
│ ┌──────────────┤  ├──────────────┐ xdpfrer ┌──────────────┤  ├──────────────┐┌──────────────┤  ├──────────────┐┌──────────────┤  ├──────────────┐ xdpfrer ┌──────────────┤  ├──────────────┐ │
│ │    ethAB     │  │    ethBA     │  repl   │     ethBC    │  │    ethCB     ││     ethCD    │  │     ethDC    ││     ethDE    │  │     ethED    │  elim   │     ethEF    │  │     ethFE    │ │
│ │5f00:0:0:ab::a├──┤5f00:0:0:ab::b├──┘      │5f00:0:0:bc::b├──┤5f00:0:0:bc::c││5f00:0:0:cd::c├──┤5f00:0:0:cd::d││5f00:0:0:de::d├──┤5f00:0:0:de::e├──┘      │5f00:0:0:ef::e├──┤5f00:0:0:ef::f│ │
│ └──────────────┤  ├──────────────┘         └──────────────┤  ├──────────────┘└──────────────┤  ├──────────────┘└──────────────┤  ├──────────────┘         └──────────────┤  ├──────────────┘ │
└────────────────┘  └───────────────────────────────────────┘  └──────────────────────────────┘  └──────────────────────────────┘  └───────────────────────────────────────┘  └────────────────┘
```

## Usage

### FRER mode (veth-based)

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
#  Config replication on interface aeth0 (ifindex: 2) match id 10
#  Received: 0
#  Received: 1
#  Received: 2
#  Received: 3
#  Received: 4
#  Received: 4
#  Received: 4

#  (veth.env) root:test# nsx ../src/xdpfrer -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20
#  Config recovery on iface enp4s0 (ifindex: 3) match id 20
#  Config recovery on iface enp7s0 (ifindex: 5) match id 20
#  Passed: 0, Dropped: 0
#  Passed: 1, Dropped: 1
#  Passed: 2, Dropped: 2
#  Passed: 3, Dropped: 3
#  Passed: 4, Dropped: 4
#  Passed: 4, Dropped: 4
```

```
# 5.
Ctrl+C # in xdpfrer terminal
Ctrl+D # in both terminal
```

### PREOF mode (Mininet-based)

1. Start the Mininet environment:

This starts a Mininet CLI with the 6-node topology.
Run `xdpfrer` replication on `nb` and elimination on `ne` from within the Mininet CLI or by attaching to the node namespaces.

```
cd test
sudo python3 env.py
```

Optionally use `-t` to enable `tcpdump` tracing on all interfaces:

```
sudo python3 env.py -t
```

2. From the Mininet CLI, start `xdpfrer` replication on `nb` and elimination on `ne`:

```
nb ../src/xdpfrer -m prf -i ethBA:10 -e veth0:5f00:0:0:e:: -e veth0:5f00:0:0:e:: -d 02:00:00:00:00:01
ne ../src/xdpfrer -m pef -i ethED:10 -e veth0::: -d 02:00:00:00:00:01
```

3. Send a ping from `na` to `nf` with flow label 10:

```
na ping 5f00:0:0:ef::f -F 10
```

## Measurements:

For advanced usage, take a look at the `test/measurement.py` script.
It is possible to run XDP FRER/PREF on a real, physical testbed, just change the interface names and VLAN IDs and the script accordingly.

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
