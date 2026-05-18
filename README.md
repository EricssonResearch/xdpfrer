# XDP FRER / XDP PREF

This software is an experimental implementation of the [IEEE 802.1CB](https://standards.ieee.org/ieee/802.1CB/5703/) FRER standard
and [SRv6 Redundancy SID](https://datatracker.ietf.org/doc/draft-ietf-spring-sr-redundancy-protection/).
It replicates packets over redundant network paths to protect against network failures.
On the sender side, this is called *replication*. On the receiver side, *elimination* accepts the first copy and drops the duplicates.

**Provided functions:**
* Replication and elimination functionality:
   * Vector recovery algorithm (defined in IEEE 802.1CB)

* Encapsulation:
   * Layer 2 TSN dataplane encapsulation with R-tag (IEEE 802.1CB)
   * Layer 3 DetNet dataplane encapsulation with SRv6 Redundancy SID

The implementation uses XDP, a high-performance packet processing framework in the Linux kernel based on eBPF.

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

## Table of Contents

- [Prerequisites](#prerequisites)
- [Source](#source)
- [Building](#building)
- [Argument list](#argument-list)
- [Packet Format and Examples](#packet-format-and-examples)
   - [Layer 2 (FRER)](#layer-2-frer)
   - [Layer 3 (PREF)](#layer-3-pref)
- [Test environments and usage](#test-environments-and-usage)
   - [Layer 2 (FRER): bash-based environment](#layer-2-frer-bash-based-environment)
   - [Layer 3 (PREF): basic bash-based environment](#layer-3-pref-basic-bash-based-environment)
   - [Layer 3 (PREF): multiple replication](#layer-3-pref-multiple-replication)
   - [Layer 3 (PREF): multiple elimination](#layer-3-pref-multiple-elimination)
- [Limitations](#limitations)
- [Wireshark Plugin](#wireshark-plugin)
- [Measurements](#measurements)

## Prerequisites

Debian based GNU/Linux distribution is preferred.
Tested with Debian Bookworm and Ubuntu 23.10 and above.

```
sudo apt install build-essential gcc-multilib clang llvm linux-tools-common bpftool libbpf-dev
```

**Note: libbpf version must be at least 1.3.0 on Ubuntu 23.04.**

## Source

```
.
├── README.md
├── src
│   ├── aarch64.Dockerfile // Dockerfile for cross-compilation on aarch64
│   ├── bpf_common.h       // eBPF map definitions, elimination algorithm and shared structures
│   ├── common.h           // Shared data structures and defines
│   ├── Makefile           // GNU Makefile
│   ├── xdppref-ctl.c      // Runtime flow management tool for PREF mode
│   ├── xdpfrer.c          // Main program that configures and loads the eBPF programs
│   ├── xdpfrer.bpf.c      // XDP programs for Layer 2 VLAN-based (FRER)
│   └── xdppref.bpf.c      // XDP programs for Layer 3 SRv6 (PREF)
└── test
    ├── pref_sid.lua       // Wireshark plugin for Redundancy SID
    ├── measurement.py     // All-in-one testing and plotting script
    ├── frer_physical.env  // 3-node FRER topology for physical performance testbed (bash)
    ├── frer.env           // 3-node FRER topology using veth pairs and namespaces (bash)
    ├── srv6.env           // 9-node SRv6 PREF topology (bash)
    ├── srv6_multi_prf.env // 9-node SRv6 PREF topology with multiple replication (bash)
    └── srv6_multi_pef.env // 7-node SRv6 PREF topology with multiple elimination (bash)
```

## Building

```
cd src
make
make install
```

To build for aarch64, build the Docker image from the root folder and run it.
The binary `xdpfrer` is presented in the `/tmp` folder.
We can copy the binary file back to host filesystem from the running Docker container.

```
docker build -f src/aarch64.Dockerfile -t xdpfrer .
docker cp xdpfrer:/tmp/src/xdpfrer .
```

## Argument list

```
Usage: xdpfrer [OPTION...]

 Required options:
  -e, --egress=WORD          Egress interface in IFNAME:VID (Ethernet/FRER) or
                             IFNAME:ADDR (SRv6/PREF) format.
  -i, --ingress=WORD         Ingress interface in IFNAME:VID (Ethernet/FRER) or
                             IFNAME:fl:FLOW_LABEL or IFNAME:rsid:FUNCT:FLOW_ID
                             (SRv6/PREF) format.
  -m, --mode=WORD            Mode: repl/elim (FRER) or prf/pef (PREF).

 Optional:
  -n, --not                  Don't add/remove R-tag (Ethernet/FRER) or don't
                             encapsulate/decapsulate (SRv6/PREF).
  -q, --quiet                Quiet output.

  -h, --help                 Show this help message.
```

__Important:__ 

* In replication modes `repl` and `prf` one or more `--egress` and only one `--ingress` interface can be used.
* In elimination modes `elim` and `pef` one or more `--ingress` and only one `--egress` interface can be used.
* In PREF modes (`prf`/`pef`), flows can be added or removed at runtime using the `xdppref-ctl` helper tool,
which accepts the same command-line argument format as `xdpfrer`.
The `xdppref-ctl` tool relies on pinned BPF maps (at `/sys/fs/bpf/xdpfrer`),
which are only created when running in PREF mode.
* In FRER mode (`repl`/`elim`), VLAN IDs cannot be modified at runtime. To change the configuration, stop and restart `xdpfrer`.

## Packet Format and Examples

This section describes the packet headers used in Layer 2 (FRER) and Layer 3 (PREF),
how they are modified during replication and elimination, and provides command-line examples for each mode.
In Layer 2 (FRER), packets that do not match the configured flow are dropped,
while in Layer 3 (PREF), unmatched packets are passed to the Linux Network Stack for normal processing.

### Layer 2 (FRER)

In FRER mode, during replication, the incoming packet MUST have a VLAN tag matching the configured ingress VLAN ID —
packets without a VLAN tag or with a different VLAN ID are dropped.
An R-tag is inserted after the VLAN tag and copies of the packet are sent out on each given egress interface.
During elimination, packets MUST arrive with a VLAN tag and R-tag. The R-tag is processed and the VLAN ID is changed to
the configured egress value.

In the command-line arguments we can set which VLAN ID will be accepted on ingress and what VLAN ID will be
set on the egress interface, both in replication and elimination.

On the replication side, `xdpfrer -m repl -i beth0:20 -e enp4s0:66 -e enp7s0:67` means:
Packets with VLAN ID 20 (decimal) arriving on `beth0` are replicated to `enp4s0` with VLAN ID 66 (decimal) and `enp7s0` with VLAN ID 67 (decimal).

For the command-line argument above, the valid incoming packet looks like this:
```
beth0:
┌─────────┬──────────┬─────────────────┐
│         │          │                 │
│   ETH   │   VLAN   │Payload (e.g. IP)│
│         │  VID 20  │                 │
└─────────┴──────────┴─────────────────┘
```

After the replication, packets look like this:
```
enp4s0:
┌─────────┬──────────┬─────────┬─────────────────┐
│         │          │         │                 │
│   ETH   │   VLAN   │  R-TAG  │Payload (e.g. IP)│
│         │  VID 66  │  SEQ 1  │                 │
└─────────┴──────────┴─────────┴─────────────────┘

enp7s0:
┌─────────┬──────────┬─────────┬─────────────────┐
│         │          │         │                 │
│   ETH   │   VLAN   │  R-TAG  │Payload (e.g. IP)│
│         │  VID 67  │  SEQ 1  │                 │
└─────────┴──────────┴─────────┴─────────────────┘
```

On the elimination side, `xdpfrer -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:10` means:
Packets with VLAN ID 55 (decimal) on `enp4s0` and VLAN ID 56 (decimal) on `enp7s0` are received, duplicates are eliminated,
and only the first copy is forwarded to `beth0` with VLAN ID 10 (decimal).

The valid incoming packets look like this:
```
enp4s0:
┌─────────┬──────────┬─────────┬─────────────────┐
│         │          │         │                 │
│   ETH   │   VLAN   │  R-TAG  │Payload (e.g. IP)│
│         │  VID 55  │  SEQ 1  │                 │
└─────────┴──────────┴─────────┴─────────────────┘

enp7s0:
┌─────────┬──────────┬─────────┬─────────────────┐
│         │          │         │                 │
│   ETH   │   VLAN   │  R-TAG  │Payload (e.g. IP)│
│         │  VID 56  │  SEQ 1  │                 │
└─────────┴──────────┴─────────┴─────────────────┘
```

After the elimination, the R-tag is processed (and removed) and the packet looks like this:
```
beth0:
┌─────────┬──────────┬─────────────────┐
│         │          │                 │
│   ETH   │   VLAN   │Payload (e.g. IP)│
│         │  VID 10  │                 │
└─────────┴──────────┴─────────────────┘
```

Using different VLAN IDs on the redundant paths is strongly recommended.
With that, traffic engineering of the redundant paths becomes easier.
Without that, the egress interfaces of the redundant path(s) might be disabled by the STP,
which would make the replication unreliable.

### Layer 3 (PREF)

During replication, `xdpfrer` encapsulates and replicates incoming packets,
then sends them to a PREF-specific internal veth interface.
A postprocessing XDP program on the PREF-specific internal veth interface is used to add
the Redundancy SID, thus encoding the sequence number in the destination address.
The packet is processed on the other side of the veth pair, where it enters the Linux Network Stack.

Once the packet is in the Linux Network Stack, an SRv6 inline routing rule adds an SRH header if needed,
and Linux forwards the packet.
For multiple redundant paths, multiple veth pairs are needed.

Background traffic (packets not matching any configured flow label) also passes through the eBPF code
but is forwarded directly to the Linux Network Stack without replication or elimination.

On the replication side, `xdpfrer -m prf -i eth21:fl:10 -e veth0:5f00:0:0:8:f:1011:: -e veth2:5f00:0:0:8:f:2012::` means:
IPv6 packets with flow label 10 arriving on `eth21` are encapsulated with an outer IPv6 header carrying a Redundancy SID
as the destination address and two replicas are sent out through `veth0` and `veth2`.

Below is the Redundancy SID structure of the address from above `5f00:0:0:8:f:1011::` in its expanded form (`5f00:0000:0000:0008:000f:1011:0000:0000`). The sequence number field should be left as zero in the configuration — it is automatically filled and incremented by the program for each packet. Only 16 bits are supported for the sequence number. Only the Locator, Function, and Flow ID fields need to be set:

```
┌────────────────────────┐ 5f00:0000:0000:0008: 000f: 1011:0 XXX:X 000 
│    Locator (64 bit)    │           │            │     │      │    │  
│  5f00:0000:0000:0008   ◀───────────┘            │     │      │    │  
├────────────────────────┤                        │     │      │    │  
│   Function (16 bit)    │                        │     │      │    │  
│          000f          ◀────────────────────────┘     │      │    │  
├────────────────────────┤                              │      │    │  
│    Flow ID (20 bit)    │                              │      │    │  
│         10110          ◀──────────────────────────────┘      │    │  
├────────────────────────┤                                     │    │  
│Sequence number (16 bit)│                                     │    │  
│          XXXX          ◀─────────────────────────────────────┘    │  
├────────────────────────┤                                          │  
│   Reserved (12 bit)    │                                          │  
│          000           ◀──────────────────────────────────────────┘  
└────────────────────────┘                                             
```

The incoming packet:
```
eth21:
┌─────────┬───────────────────┐
│   ETH   │        IPv6       │
│         │     (original)    │
│         │                   │
│         │   flow label 10   │
└─────────┴───────────────────┘
```

After replication, packets look like this:
(The Redundancy SID encodes the sequence number — so the address differs
from what was configured.)
```
veth0:
┌─────────┬─────────────────────┬─────────────────────┐
│   ETH   │        IPv6         │         IPv6        │
│         │       (outer)       │      (original)     │
│         │         dst         │                     │
│         │5f00::8:f:1011:1:5000│    flow label 10    │
└─────────┴─────────────────────┴─────────────────────┘

veth2:
┌─────────┬─────────────────────┬─────────────────────┐
│   ETH   │        IPv6         │         IPv6        │
│         │       (outer)       │      (original)     │
│         │         dst         │                     │
│         │5f00::8:f:2012:1:5000│    flow label 10    │
└─────────┴─────────────────────┴─────────────────────┘
```

```
┌────────────────────────┐ 5f00:0000:0000:0008: 000f: 1011:0 001:5 000 
│    Locator (64 bit)    │           │            │     │      │    │  
│  5f00:0000:0000:0008   ◀───────────┘            │     │      │    │  
├────────────────────────┤                        │     │      │    │  
│   Function (16 bit)    │                        │     │      │    │  
│          000f          ◀────────────────────────┘     │      │    │  
├────────────────────────┤                              │      │    │  
│    Flow ID (20 bit)    │                              │      │    │  
│         10110          ◀──────────────────────────────┘      │    │  
├────────────────────────┤                                     │    │  
│Sequence number (16 bit)│                                     │    │  
│          0015          ◀─────────────────────────────────────┘    │  
├────────────────────────┤                                          │  
│   Reserved (12 bit)    │                                          │  
│          000           ◀──────────────────────────────────────────┘  
└────────────────────────┘                                             
```

Once the packet enters the Linux Network Stack, an SRv6 inline routing rule can add an SRH header. For example:
`ip -6 route add 5f00:0:0:8:f:1000::/84 encap seg6 mode inline segs 5f00:0:0:3::,5f00:0:0:4:: dev eth23`
```
eth23 (egress interface):
┌─────────┬─────────────────────┬───────────────────────────────┬─────────────────────┐
│   ETH   │        IPv6         │              SRH              │         IPv6        │
│         │       (outer)       ├────┬────┬─────────────────────┤      (original)     │
│         │                     │SIDy│... │ [0] Redundancy SID: │                     │
│         │      dst SIDy       │    │    │5f00::8:f:1011:1:5000│    flow label 10    │
└─────────┴─────────────────────┴────┴────┴─────────────────────┴─────────────────────┘

eth24 (egress interface):
┌─────────┬─────────────────────┬───────────────────────────────┬─────────────────────┐
│   ETH   │        IPv6         │              SRH              │         IPv6        │
│         │       (outer)       ├────┬────┬─────────────────────┤      (original)     │
│         │                     │SIDy│... │ [0] Redundancy SID: │                     │
│         │      dst SIDy       │    │    │5f00::8:f:2012:1:5000│    flow label 10    │
└─────────┴─────────────────────┴────┴────┴─────────────────────┴─────────────────────┘
```

On the elimination side, `xdpfrer -m pef -i eth84:rsid:f:10110 -i eth87:rsid:f:20120 -e veth0:::` means:
Encapsulated packets with Redundancy SID `f:10110` (Function + Flow ID) on `eth84` and `f:20120` (Function + Flow ID) on `eth87` are decapsulated,
duplicates are eliminated, and only the first instance is forwarded to `veth0`.

The incoming packet:
```
eth84:
┌─────────┬─────────────────────┬───────────────────────────────┬─────────────────────┐
│   ETH   │        IPv6         │              SRH              │         IPv6        │
│         │       (outer)       ├────┬────┬─────────────────────┤      (original)     │
│         │                     │SIDy│... │ [0] Redundancy SID: │                     │
│         │ dst Redundancy SID  │    │    │5f00::8:f:1011:1:5000│    flow label 10    │
└─────────┴─────────────────────┴────┴────┴─────────────────────┴─────────────────────┘

eth87:
┌─────────┬─────────────────────┬───────────────────────────────┬─────────────────────┐
│   ETH   │        IPv6         │              SRH              │         IPv6        │
│         │       (outer)       ├────┬────┬─────────────────────┤      (original)     │
│         │                     │SIDy│... │ [0] Redundancy SID: │                     │
│         │ dst Redundancy SID  │    │    │5f00::8:f:2012:1:5000│    flow label 10    │
└─────────┴─────────────────────┴────┴────┴─────────────────────┴─────────────────────┘
```

The outgoing packet after the elimination:
```
veth0:
┌─────────┬───────────────────┐
│   ETH   │        IPv6       │
│         │     (original)    │
│         │                   │
│         │   flow label 10   │
└─────────┴───────────────────┘
```

In this implementation of the Layer 3 case, the `xdpfrer` nodes are SRv6 tunnel endpoints.
At the edge nodes, flows are identified by their IPv6 flow label;
at the tunnel endpoints, they are identified by the Redundancy SID (Flow ID).

**Note:** Packets with matching flow labels are sent to a PREF-specific internal veth interface,
so `xdpfrer` rewrites the destination MAC address to match the PREF-specific internal veth interface's MAC address (`02:00:00:00:00:01`),
allowing the node to accept the packet at the veth interface for further Layer 3 processing (e.g., routing, SRv6 operations, ARP/ND).

## Test environments and usage

### Layer 2 (FRER): bash-based environment

`frer_physical.env` and `frer.env` contain this environment. Obviously you can modify VLANs
when you start running `xdpfrer` instances. In FRER mode, only one VLAN ID can be matched per ingress interface,
so only a single stream is supported per direction.

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

1. **Set up the test environment:**

   Open a terminal and source the environment file. This creates network namespaces for the talker, switch, and listener, along with all virtual interfaces and links.

   ```
   cd test
   sudo su
   source frer.env
   ```

2. **Start `xdpfrer` inside the switch namespace:**

   Use the `nsx` alias to run replication and elimination instances in both directions:

   ```
   # tx -> lx
   nsx xdpfrer -m repl -i aeth0:10 -e enp3s0:55 -e enp6s0:56
   nsx xdpfrer -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20

   # lx -> tx
   nsx xdpfrer -m repl -i beth0:20 -e enp4s0:66 -e enp7s0:67
   nsx xdpfrer -m elim -i enp3s0:66 -i enp6s0:67 -e aeth0:10
   ```

3. **Test connectivity:**

   Ping from the talker to the listener:

   ```
   tx ping 10.0.0.2 -c 4
   ```

4. **Verify the output:**

   If everything works, the ping succeeds and the `xdpfrer` terminals show replication and elimination activity:

   ```
   # Replicator output:
   #  Config replication on interface aeth0 (ifindex: 2) match id 10
   #  Received: 0
   #  Received: 1
   #  ...

   # Eliminator output:
   #  Config recovery on iface enp4s0 (ifindex: 3) match id 20 rcvy_idx 0
   #  Config recovery on iface enp7s0 (ifindex: 5) match id 20 rcvy_idx 0
   #  Passed: 1, Dropped: 1
   #  Passed: 2, Dropped: 2
   #  ...
   ```

5. **Clean up:**

   Press `Ctrl+C` to stop `xdpfrer`, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

### Layer 3 (PREF): basic bash-based environment

`srv6.env` contains this 9-node topology with two redundant paths: `1` (n3-n4) and `2` (n5-n6-n7).
`n2` replicates packets to both paths; `n8` eliminates duplicates. Normal (non-replicated) traffic is forwarded via path `1`.
IPv6 loopback addresses follow the node name (e.g., `n3` has `5f00:0:0:3::`).
Link addresses encode both endpoints: `5f00:0:0:23::2` is the `n2` side of the `n2`–`n3` link.

```
                                         "1" path                                         
                                                                                          
                                5f00:0:0:3::  5f00:0:0:4::                                
                                 ┌────────┐    ┌────────┐                                 
                                 │        │    │        │                                 
                            ┌────┤   n3   ├────┤   n4   ├────┐                            
                            │    │        │    │        │    │                            
                            │    └────────┘    └────────┘    │                            
  ┌────────┐   ┌────────┐   │                                │    ┌────────┐   ┌────────┐ 
  │        │   │        ├───┘                                └────┤        │   │        │ 
  │   n1   ├───┤   n2   │                                         │   n8   ├───┤   n9   │ 
  │        │   │   prf  ├─┐                                    ┌──┤   pef  │   │        │ 
  └────────┘   └────────┘ │                                    │  └────────┘   └────────┘ 
5f00:0:0:1::  5f00:0:0:2::│ ┌────────┐  ┌────────┐  ┌────────┐ │5f00:0:0:8::  5f00:0:0:9::
                          │ │        │  │        │  │        │ │                          
                          └─┤   n5   ├──┤   n6   ├──┤   n7   ├─┘                          
                            │        │  │        │  │        │                            
                            └────────┘  └────────┘  └────────┘                            
                          5f00:0:0:5:: 5f00:0:0:6:: 5f00:0:0:7::                          
                                                                                          
                                         "2" path                                         
```

1. **Start the environment:**

   Open a terminal and source the environment file. This creates the 9-node topology with network namespaces, veth pairs, IPv6 addressing, and SRv6 routing.

   ```
   cd test
   sudo su
   source srv6.env
   ```

2. **Start `xdpfrer` on the replication and elimination nodes:**

   Configure `n2` for replication and `n8` for elimination:

   ```
   n2 xdpfrer -m prf -i eth21:fl:10 -e veth0:5f00:0:0:8:f:1011:: -e veth2:5f00:0:0:8:f:2012::
   n8 xdpfrer -m pef -i eth84:rsid:f:10110 -i eth87:rsid:f:20120 -e veth0:::
   ```

   **SRv6 routing (configured by the env script):**

   The env script already sets up SRv6 inline encapsulation routes on `n2` so that replicated packets are forwarded through the correct paths:

   ```
   n2 ip -6 route add 5f00:0:0:8:f:1000::/84 encap seg6 mode inline segs 5f00:0:0:3::,5f00:0:0:4:: dev eth23
   n2 ip -6 route add 5f00:0:0:8:f:2000::/84 encap seg6 mode inline segs 5f00:0:0:5::,5f00:0:0:6::,5f00:0:0:7:: dev eth25
   ```

3. **Test connectivity:**

   Ping from `n1` to `n9`. Use flow label 10 to test the replication/elimination path, or omit it to verify normal forwarding:

   ```
   n1 ping 5f00:0:0:89::9 -F 10  # replicated and eliminated
   n1 ping 5f00:0:0:89::9        # normal forwarding
   ```

   Normal forwarding means the packet enters the eBPF code but is passed directly to the Linux Network Stack without replication or elimination.

4. **Manage flows at runtime:**

   Once `xdpfrer` is running, you can dynamically manage flows using `xdppref-ctl` without restarting `xdpfrer`.

   **List active flows** on a node:
   ```
   n2 xdppref-ctl list
   ```

   **Add a new flow** — for example, replicating a second flow (flow ID 20) on `n2` and eliminating it on `n8`:
   ```
   n2 xdppref-ctl add -m prf -i eth21:fl:20 -e veth0:5f00:0:0:8:f:1021:: -e veth2:5f00:0:0:8:f:2022::
   n8 xdppref-ctl add -m pef -i eth84:rsid:f:10210 -i eth87:rsid:f:20220 -e veth0:::
   ```

   **Remove a flow** when it is no longer needed:
   ```
   n2 xdppref-ctl del -m prf -i eth21:fl:20
   n8 xdppref-ctl del -m pef -i eth84:rsid:f:10210 -i eth87:rsid:f:20220
   ```

5. **Clean up:**

   Press `Ctrl+C` to stop `xdpfrer`, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

### Layer 3 (PREF): multiple replication

`srv6_multi_prf.env` contains a 9-node topology with three redundant paths: `3` (n4–n5–n8), `4` (n4–n6–n8), and `2` (n2–n7–n8).
`n2` replicates packets onto path `1` (via n3 to n4) and path `2` (via n7). `n4` further replicates path `1` into `3` (via n5) and `4` (via n6). As a result, `n8` receives three copies of the same packet and performs elimination.
The `-n` flag on `n4` removes the SRH while preserving the Redundancy SID (flow_id and sequence number) in the outer IPv6 header. The destination locator is rewritten per egress interface.

```
                                                     ┌────────┐                           
                                            "3" path │        │                           
                                                  ┌──┤   n5   ├──┐                        
                          ┌────────┐  ┌────────┐  │  │        │  │                        
                 "1" path │        │  │        ├──┘  └────────┘  │                        
                        ┌─┤   n3   ├──┤   n4   │     ┌────────┐  │                        
┌────────┐   ┌────────┐ │ │        │  │   prf  ├──┐  │        │  │ ┌────────┐   ┌────────┐
│        │   │        ├─┘ └────────┘  └────────┘  └──┤   n6   │  └─┤        │   │        │
│   n1   ├───┤   n2   │   ┌────────┐        "4" path │        ├────┤   n8   ├───┤   n9   │
│        │   │   prf  ├─┐ │        │                 └────────┘  ┌─┤   pef  │   │        │
└────────┘   └────────┘ └─┤   n7   ├─────────────────────────────┘ └────────┘   └────────┘
                          │        │                                                      
                 "2" path └────────┘                                                      
```

1. **Start the environment:**

   ```
   cd test
   sudo su
   source srv6_multi_prf.env
   ```

2. **Start `xdpfrer` on the replication and elimination nodes:**

   Configure `n2` for replication, `n4` for intermediate replication (with `-n`), and `n8` for elimination:

   ```
   n2 xdpfrer -m prf -i eth21:fl:10 -e veth0:5f00:0:0:4:f:1011:: -e veth2:5f00:0:0:8:f:2012::
   n4 xdpfrer -m prf -i eth43:rsid:f:10110 -e veth0:5f00:0:0:8:f:3013:: -e veth2:5f00:0:0:8:f:4014:: -n
   n8 xdpfrer -m pef -i eth85:rsid:f:30130 -i eth86:rsid:f:40140 -i eth87:rsid:f:20120 -e veth0:::
   ```

   **SRv6 routing (configured by the env script):**

   The env script already sets up SRv6 inline encapsulation routes so that replicated packets are forwarded through the correct paths:

   ```
   n2 ip -6 route add 5f00:0:0:4:f:1000::/84 encap seg6 mode inline segs 5f00:0:0:3:: dev eth23
   n2 ip -6 route add 5f00:0:0:8:f:2000::/84 encap seg6 mode inline segs 5f00:0:0:7:: dev eth27
   n4 ip -6 route add 5f00:0:0:8:f:3000::/84 encap seg6 mode inline segs 5f00:0:0:5:: dev eth45
   n4 ip -6 route add 5f00:0:0:8:f:4000::/84 encap seg6 mode inline segs 5f00:0:0:6:: dev eth46
   ```

3. **Test connectivity:**

   Normal forwarding means the packet enters the eBPF code but is passed directly to the Linux Network Stack without replication or elimination.

   ```
   n1 ping 5f00:0:0:89::9 -F 10  # replicated and eliminated
   n1 ping 5f00:0:0:89::9        # normal forwarding
   ```

4. **Manage flows at runtime:**

   In this example, we add flow label 20 using only path `1`, replicating packets to paths `3` and `4`. On `n2`, we need a command to redirect the packets to path `1` because the default route is path `2`.

   ```
   n2 xdppref-ctl add -m prf -i eth21:fl:20 -e veth0:5f00:0:0:4:f:1021::
   n4 xdppref-ctl add -m prf -i eth43:rsid:f:10210 -e veth0:5f00:0:0:8:f:3023:: -e veth2:5f00:0:0:8:f:4024:: -n
   n8 xdppref-ctl add -m pef -i eth85:rsid:f:30230 -i eth86:rsid:f:40240 -e veth0:::
   ```

5. **Clean up:**

   Press `Ctrl+C` to stop `xdpfrer`, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

### Layer 3 (PREF): multiple elimination

`srv6_multi_pef.env` contains this 7-node topology with three redundant paths: `1` (n3-n5), `2` (n4-n5), and `3` (direct n2-n6).
`n2` replicates packets to all three paths; `n5` performs intermediate elimination, `n6` performs final elimination.
The `-n` flag on `n5` removes SRH and rewrites the outer IPv6 destination address.
The default path is path `3`.

```
                               ┌────────┐                                       
                     "1" path  │        │                                       
                   ┌───────────┤   n3   ├─┐ ┌────────┐                          
                   │           │        │ │ │        │                          
                   │           └────────┘ └─┤   n5   │                          
                   │           ┌────────┐ ┌─┤   pef  ├─┐                        
                   │  "2" path │        │ │ └────────┘ │ "1" path               
                   │ ┌─────────┤   n4   ├─┘            │                        
┌────────┐   ┌─────┴─┴┐        │        │              │ ┌────────┐   ┌────────┐
│        │   │        │        └────────┘              │ │        │   │        │
│   n1   ├───┤   n2   │                                └─┤   n6   ├───┤   n7   │
│        │   │   prf  ├──────────────────────────────────┤   pef  │   │        │
└────────┘   └────────┘             "3" path             └────────┘   └────────┘
```

1. **Start the environment:**

   ```
   cd test
   sudo su
   source srv6_multi_pef.env
   ```

2. **Start `xdpfrer` on the replication and elimination nodes:**

   Configure `n2` for replication, `n5` for intermediate elimination (with `-n`), and `n6` for final elimination:

   ```
   n2 xdpfrer -m prf -i eth21:fl:10 -e veth0:5f00:0:0:5:f:1011:: -e veth2:5f00:0:0:5:f:2012:: -e veth4:5f00:0:0:6:f:3013::
   n5 xdpfrer -m pef -i eth53:rsid:f:10110 -i eth54:rsid:f:20120 -e veth0:5f00:0:0:6:f:1014:: -n
   n6 xdpfrer -m pef -i eth65:rsid:f:10140 -i eth62:rsid:f:30130 -e veth0:::
   ```

   **SRv6 routing (configured by the env script):**

   The env script already sets up SRv6 inline encapsulation routes on `n2` so that replicated packets are forwarded through the correct paths:

   ```
   n2 ip -6 route add 5f00:0:0:5:f:1000::/84 encap seg6 mode inline segs 5f00:0:0:3:: dev eth23
   n2 ip -6 route add 5f00:0:0:5:f:2000::/84 encap seg6 mode inline segs 5f00:0:0:4:: dev eth24
   ```

   Path `3` (n2→n6) does not need an SRH because the packet is forwarded directly to `n6` without intermediate hops.

3. **Test connectivity:**

   Normal forwarding means the packet enters the eBPF code but is passed directly to the Linux Network Stack without replication or elimination.

   ```
   n1 ping 5f00:0:0:67::7 -F 10  # replicated and eliminated
   n1 ping 5f00:0:0:67::7        # normal forwarding
   ```

4. **Manage flows at runtime:**

   In this example, we replicate flow 20 to path `1` and path `2`. On `n5`, elimination removes the duplicates and decapsulates the packets, so on `n6` these packets are unmatched.

   ```
   n2 xdppref-ctl add -m prf -i eth21:fl:20 -e veth0:5f00:0:0:5:f:1021:: -e veth2:5f00:0:0:5:f:2022::
   n5 xdppref-ctl add -m pef -i eth53:rsid:f:10210 -i eth54:rsid:f:20220 -e veth0:::
   ```

5. **Clean up:**

   Press `Ctrl+C` to stop `xdpfrer`, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

## Limitations

**Generic:**

- The number of concurrent flows is limited to 128 (both sequence number generators and recovery instances). Increasing this requires changing the BPF map sizes.
- `xdppref-ctl` only works in Layer 3 PREF mode.
- Each `xdpfrer` or `xdppref-ctl` command adds one flow at a time, as each invocation creates a single sequence number generator or history window.
- XDP allows only one program per interface. An interface can only be used as ingress once, but can appear as egress in multiple instances.

**Replication/Elimination:**

- The history window size is 64 bits. For details, see [IEEE 802.1CB](https://standards.ieee.org/ieee/802.1CB/5703/) section 7.4.3.2.2 and 7.4.3.4.
- Replication supports up to 8 egress interfaces per flow.

**Encapsulation:**

- Flows are identified by VLAN ID (Layer 2) and Flow Label (Layer 3).
- In FRER mode (repl/elim), VLAN IDs cannot be modified at runtime. To change the configuration, stop and restart `xdpfrer`.
- In PREF mode, a PREF-specific internal veth pair is required for each redundant path.
- The Maximum SID Depth (MSD) is 6. During elimination, the SRH must be removed, which requires knowing its exact size. Since the eBPF verifier does not allow computing the size dynamically, a fixed set of allowed sizes is used. This could be increased by adding more switch cases.

## Wireshark Plugin

A Lua dissector plugin (`test/pref_sid.lua`) is provided for decoding the PREF Redundancy SID fields in Wireshark.
It parses the Locator, Function, Flow ID, Sequence number, and Reserved fields from the SID.

The plugin handles two cases:
- **IPv6-in-IPv6 (nexthdr=41):** The Redundancy SID is the outer IPv6 destination address (on veth interfaces after replication).
- **SRH (nexthdr=43):** The Redundancy SID is the last segment in the SRH segment list (on egress interfaces after Linux adds the SRH).

The plugin recognizes a Redundancy SID by checking that the first two bytes of the address are `0x5f00`
and that the Function field is non-zero. Additionally, if all bits after the Function field are zero,
the address is treated as a regular SRv6 SID rather than a Redundancy SID.

**Installation:**

Copy the plugin to the global Wireshark Lua plugins directory:

```
sudo cp test/pref_sid.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/pref_sid.lua
```

Restart Wireshark. Verify it is loaded under `Help → About Wireshark → Plugins`.

## Measurements

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
