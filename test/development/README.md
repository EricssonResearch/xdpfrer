# Development details

This document describes how SRv6-based PREF works internally.

This folder contains two environment scripts that create the same 6-node test topology:
- `srv6_test.py` — Mininet-based (manages namespaces via Mininet nodes)
- `srv6_test.env` — bash-based (uses `ip netns` and `unshare --mount` with a persistent `sleep infinity` process per
namespace to keep bpffs mounted; PID files are stored in `/tmp/xdpfrer-srv6-mntns`)

The commands below work in both environments.

## How SRv6 PREF works

The replication XDP program is attached to the ingress interface. It encapsulates and replicates incoming packets,
then sends them to a veth interface. A postprocessing XDP program on the veth replaces the IPv6 destination address
with the PREOF SID, encoding the sequence number in the destination address. The packet then crosses to the other side
of the veth pair, where it enters the Linux network stack. An SRv6 inline routing rule adds an SRH header, and Linux
forwards the packet. For multiple redundant paths, multiple veth pairs are needed.

The elimination XDP program is attached to the ingress interface on the receiving side. It parses all incoming packets
(including replicas), reads the sequence number, and decapsulates the packet. Based on the sequence number, it either
eliminates the duplicate or forwards the packet to a veth interface so it can reach the network stack.

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

1. **Start the environment:**

   Launch the 6-node topology using the Mininet script:
   ```
   sudo python3 srv6_test.py
   ```

   To enable tcpdump tracing on all interfaces, add the `-t` flag:
   ```
   sudo python3 srv6_test.py -t
   ```

   Or start the bash-based environment:
   ```
   source srv6_test.env
   ```

2. **Start xdpfrer on the replication and elimination nodes:**

   Configure `nb` for replication and `ne` for elimination:

   ```
   nb xdpfrer -m prf -i ethBA:10 -e veth0:5f00:0:0:e:: -e veth0:5f00:0:0:e:: -d 02:00:00:00:00:01
   ne xdpfrer -m pef -i ethED:10 -e veth0::: -d 02:00:00:00:00:01
   ```

3. **Test connectivity:**

   Send a ping from `na` to `nf`. Use flow label 10 to test the replication/elimination path, or omit it to verify normal forwarding:

   ```
   na ping 5f00:0:0:ef::f -F 10  # replicated and eliminated
   na ping 5f00:0:0:ef::f        # normal forwarding
   ```

4. **Manage flows at runtime:**

   Once `xdpfrer` is running, you can dynamically manage flows using `xdpfrer-ctl` without restarting `xdpfrer`.

   **List active flows** on a node:
   ```
   nb xdpfrer-ctl list
   ```

   **Add a new flow** — for example, replicating a second flow (flow ID 11) on `nb` and eliminating it on `ne`:
   ```
   nb xdpfrer-ctl add -m prf -i ethBA:11 -e veth0:5f00:0:0:e:: -e veth0:5f00:0:0:e::
   ne xdpfrer-ctl add -m pef -i ethED:11 -e veth0:::
   ```

   **Remove a flow** when it is no longer needed:
   ```
   nb xdpfrer-ctl del -m prf -i ethBA:11
   ne xdpfrer-ctl del -m pef -i ethED:11
   ```
