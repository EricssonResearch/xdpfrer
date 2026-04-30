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
make install
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
  -n, --not                  Don't add/remove R-tag (FRER) or don't
                             encapsulate/decapsulate (PREOF).
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
IPv6 packets with flow label 10 arriving on `ethBA` are encapsulated with an outer IPv6 header carrying a Redundancy SID
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
│   ├── xdpfrer-ctl.c      // Runtime flow management tool for PREF mode
│   ├── xdpfrer.bpf.c      // XDP programs for FRER (replication/elimination)
│   ├── xdpfrer.c          // Configure and load the BPF part to the kernel
│   └── xdppreof.bpf.c     // XDP programs for PREOF (SRv6-based)
└── test
    ├── development
    │   ├── srv6_test.py   // 6-node SRv6 PREF topology (Mininet)
    │   ├── srv6_test.env  // 6-node SRv6 PREF topology (bash)
    │   └── README.md      // Detailed SRv6 PREF internals
    ├── measurement.py     // All-in-one testing and plotting script
    ├── srv6.env           // 9-node SRv6 PREF topology (bash)
    ├── srv6_multi_pef.env // 7-node SRv6 PREF topology with multiple elimination (bash)
    ├── physical.env       // FRER environment for physical testbed
    └── veth.env           // FRER environment using veth pairs and namespaces
```

## Test environments and usage

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

1. **Set up the test environment:**

   Open a terminal and source the environment file. This creates network namespaces for the talker, switch, and listener, along with all virtual interfaces and links.

   ```
   cd test
   sudo su
   source veth.env
   ```

2. **Start xdpfrer inside the switch namespace:**

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

   If everything works, the ping succeeds and the xdpfrer terminals show replication and elimination activity:

   ```
   # Replicator output:
   #  Config replication on interface aeth0 (ifindex: 2) match id 10
   #  Received: 0
   #  Received: 1
   #  ...

   # Eliminator output:
   #  Config recovery on iface enp4s0 (ifindex: 3) match id 20
   #  Passed: 1, Dropped: 1
   #  Passed: 2, Dropped: 2
   #  ...
   ```

5. **Clean up:**

   Press `Ctrl+C` to stop xdpfrer, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

### PREF: basic veth-based environment

`srv6.env` contains this 9-node topology with two redundant paths: `a` (n3-n4) and `b` (n5-n6-n7).
`n2` replicates packets to both paths; `n8` eliminates duplicates. Normal (non-replicated) traffic is forwarded via path `a`.
IPv6 loopback addresses follow the node name (e.g., `n3` has `5f00:0:0:3::`).
Link addresses encode both endpoints: `5f00:0:0:23::2` is the `n2` side of the `n2`–`n3` link.

```
                                         "a" path                                         
                                                                                          
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
                                                                                          
                                         "b" path                                         
```

1. **Start the environment:**

   Open a terminal and source the environment file. This creates the 9-node topology with network namespaces, veth pairs, IPv6 addressing, and SRv6 routing.

   ```
   cd test
   sudo su
   source srv6.env
   ```

2. **Start xdpfrer on the replication and elimination nodes:**

   Configure `n2` for replication and `n8` for elimination:

   ```
   n2 xdpfrer -m prf -i eth21:10 -e veth0:5f00:0:0:8:a:: -e veth2:5f00:0:0:8:b:: -d 02:00:00:00:00:01
   n8 xdpfrer -m pef -i eth84:10 -i eth87:10 -e veth0::: -d 02:00:00:00:00:01
   ```

3. **Test connectivity:**

   Ping from `n1` to `n9`. Use flow label 10 to test the replication/elimination path, or omit it to verify normal forwarding:

   ```
   n1 ping 5f00:0:0:89::9 -F 10  # replicated and eliminated
   n1 ping 5f00:0:0:89::9        # normal forwarding
   ```

4. **Manage flows at runtime:**

   Once `xdpfrer` is running, you can dynamically manage flows using `xdpfrer-ctl` without restarting `xdpfrer`.

   **List active flows** on a node:
   ```
   n2 xdpfrer-ctl list
   ```

   **Add a new flow** — for example, replicating a second flow (flow ID 11) on `n2` and eliminating it on `n8`:
   ```
   n2 xdpfrer-ctl add -m prf -i eth21:11 -e veth0:5f00:0:0:8:a:: -e veth2:5f00:0:0:8:b::
   n8 xdpfrer-ctl add -m pef -i eth84:11 -i eth87:11 -e veth0:::
   ```

   **Remove a flow** when it is no longer needed:
   ```
   n2 xdpfrer-ctl del -m prf -i eth21:11
   n8 xdpfrer-ctl del -m pef -i eth84:11
   ```

5. **Clean up:**

   Press `Ctrl+C` to stop xdpfrer, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

### PREF: multiple replication

`srv6_multi_prf.env` contains a 9-node topology with three redundant paths: `a1` (n4–n5), `a2` (n4–n6), and `b` (n2–n7).
`n2` replicates packets onto path `a` (via n3 to n4) and path `b` (via n7). `n4` further replicates path `a` into `a1` (via n5) and `a2` (via n6). As a result, `n8` receives three copies of the same packet and performs elimination.
The `-n` flag on `n4` removes the SRH while preserving the PREOF SID (flow_id and sequence number) in the outer IPv6 header. The destination locator is rewritten per egress interface.

```
                                                     ┌────────┐                           
                                            "a1" path│        │                           
                                                  ┌──┤   n5   ├──┐                        
                          ┌────────┐  ┌────────┐  │  │        │  │                        
                 "a" path │        │  │        ├──┘  └────────┘  │                        
                        ┌─┤   n3   ├──┤   n4   │     ┌────────┐  │                        
┌────────┐   ┌────────┐ │ │        │  │   prf  ├──┐  │        │  │ ┌────────┐   ┌────────┐
│        │   │        ├─┘ └────────┘  └────────┘  └──┤   n6   │  └─┤        │   │        │
│   n1   ├───┤   n2   │   ┌────────┐        "a2" path│        ├────┤   n8   ├───┤   n9   │
│        │   │   prf  ├─┐ │        │                 └────────┘  ┌─┤   pef  │   │        │
└────────┘   └────────┘ └─┤   n7   ├─────────────────────────────┘ └────────┘   └────────┘
                          │        │                                                      
                 "b" path └────────┘                                                      
```

1. **Start the environment:**

   ```
   cd test
   sudo su
   source srv6_multi_prf.env
   ```

2. **Start xdpfrer on the replication and elimination nodes:**

   Configure `n2` for replication, `n4` for intermediate replication (with `-n`), and `n8` for elimination:

   ```
   n2 xdpfrer -m prf -i eth21:10 -e veth0:5f00:0:0:4:a:: -e veth2:5f00:0:0:8:b::
   n4 xdpfrer -m prf -i eth43:10 -e veth0:5f00:0:0:8:a1:: -e veth2:5f00:0:0:8:a2:: -n
   n8 xdpfrer -m pef -i eth85:10 -i eth86:10 -i eth87:10 -e veth0:::
   ```

3. **Test connectivity:**

   ```
   n1 ping 5f00:0:0:89::9 -F 10  # replicated and eliminated
   n1 ping 5f00:0:0:89::9        # normal forwarding
   ```

4. **Clean up:**

   Press `Ctrl+C` to stop xdpfrer, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

### PREF: multiple elimination

`srv6_multi_pef.env` contains this 7-node topology with three redundant paths: `a` (n3-n5), `b` (n4-n5), and `c` (direct n2-n6).
`n2` replicates packets to all three paths; `n5` performs intermediate elimination, `n6` performs final elimination.
The `-n` flag on `n5` removes SRH and rewrites the outer IPv6 destination address.

```
                               ┌────────┐                                       
                     "a" path  │        │                                       
                   ┌───────────┤   n3   ├─┐ ┌────────┐                          
                   │           │        │ │ │        │                          
                   │           └────────┘ └─┤   n5   │                          
                   │           ┌────────┐ ┌─┤   pef  ├─┐                        
                   │  "b" path │        │ │ └────────┘ │                        
                   │ ┌─────────┤   n4   ├─┘            │                        
┌────────┐   ┌─────┴─┴┐        │        │              │ ┌────────┐   ┌────────┐
│        │   │        │        └────────┘              │ │        │   │        │
│   n1   ├───┤   n2   │                                └─┤   n6   ├───┤   n7   │
│        │   │   prf  ├──────────────────────────────────┤   pef  │   │        │
└────────┘   └────────┘             "c" path             └────────┘   └────────┘
```

1. **Start the environment:**

   ```
   cd test
   sudo su
   source srv6_multi_pef.env
   ```

2. **Start xdpfrer on the replication and elimination nodes:**

   Configure `n2` for replication, `n5` for intermediate elimination (with `-n`), and `n6` for final elimination:

   ```
   n2 xdpfrer -m prf -i eth21:10 -e veth0:5f00:0:0:5:a:: -e veth2:5f00:0:0:5:b:: -e veth4:5f00:0:0:6:c::
   n5 xdpfrer -m pef -i eth53:10 -i eth54:10 -e veth0:5f00:0:0:6:: -n
   n6 xdpfrer -m pef -i eth65:10 -i eth62:10 -e veth0:::
   ```

3. **Test connectivity:**

   ```
   n1 ping 5f00:0:0:67::7 -F 10  # replicated and eliminated
   n1 ping 5f00:0:0:67::7        # normal forwarding
   ```

4. **Clean up:**

   Press `Ctrl+C` to stop xdpfrer, then `Ctrl+D` or type `exit` in both terminals. The last terminal to exit tears down the environment.

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
