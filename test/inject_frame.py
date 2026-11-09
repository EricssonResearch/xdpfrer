#!/usr/bin/python3
# ============================================================================
# inject_frame.py - raw AF_PACKET frame injector for the pcap-filter self-test.
#
# Builds hand-crafted Ethernet + IPv6 (+ L4 / IPv4) frames from named templates
# and injects <count> copies out of a given interface. Used to drive xdpfrer's
# replication-ingress pcap filter with deterministic packets; only whether the
# filter matches is relevant, so the frames need not be routable or answered.
#
# Usage:
#   inject_frame.py <ifname> <case> [count]
#
# Exit status: 0 on success, non-zero on error (bad case / socket failure).
# Pure Python 3 standard library (no scapy).
# ============================================================================

import socket
import struct
import sys

ETH_P_ALL = 0x0003

# Fixed test MAC addresses (delivery is irrelevant; replicate only checks the
# IPv6 ethertype, not the destination MAC).
SRC_MAC = bytes.fromhex("02aaaaaaaa01")
DST_MAC = bytes.fromhex("02bbbbbbbb02")

# IPv6 test addresses. HOST_A / HOST_B are the two sources used for the
# per-filter attribution cases; DST_MATCH / DST_OTHER for dst-host cases.
HOST_A    = "5f00:0:0:1::111"
HOST_B    = "5f00:0:0:1::222"
HOST_C    = "5f00:0:0:1::333"
DST_MATCH = "5f00:0:0:89::9"
DST_OTHER = "5f00:0:0:89::99"

NEXTHDR_TCP    = 6
NEXTHDR_UDP    = 17
NEXTHDR_ICMPV6 = 58


def ip6(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


def eth_hdr(ethertype):
    return DST_MAC + SRC_MAC + struct.pack("!H", ethertype)


def ipv6_hdr(src, dst, nexthdr, payload_len, flow_label=0):
    # version(4)=6, traffic class(8)=0, flow label(20)
    ver_tc_fl = (6 << 28) | (flow_label & 0xFFFFF)
    return (
        struct.pack("!I", ver_tc_fl)
        + struct.pack("!H", payload_len)
        + struct.pack("!B", nexthdr)
        + struct.pack("!B", 64)          # hop limit
        + ip6(src)
        + ip6(dst)
    )


def l4_ports(sport, dport):
    # Minimal 4-byte L4 header prefix: source + destination port. Enough for
    # libpcap "port" matching, which reads the first two 16-bit words after the
    # IPv6 header. The rest of the L4 header is zero-padded by the caller.
    return struct.pack("!HH", sport, dport)


def tcp_frame(src=HOST_A, dst=DST_MATCH, sport=12345, dport=80, extra=b""):
    # 20-byte TCP header (ports + zero padding) so port offsets are valid.
    l4 = l4_ports(sport, dport) + b"\x00" * 16 + extra
    return eth_hdr(0x86DD) + ipv6_hdr(src, dst, NEXTHDR_TCP, len(l4)) + l4


def udp_frame(src=HOST_A, dst=DST_MATCH, sport=12345, dport=53, extra=b""):
    # 8-byte UDP header (ports + len + csum) + optional payload.
    payload = extra
    l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return eth_hdr(0x86DD) + ipv6_hdr(src, dst, NEXTHDR_UDP, len(l4)) + l4


def icmp6_frame(src=HOST_A, dst=DST_MATCH):
    # ICMPv6 echo request (type 128), minimal.
    l4 = struct.pack("!BBHHH", 128, 0, 0, 0x1234, 1)
    return eth_hdr(0x86DD) + ipv6_hdr(src, dst, NEXTHDR_ICMPV6, len(l4)) + l4


def ipv4_frame(src="10.0.0.1", dst="10.0.0.2"):
    # Minimal IPv4/ICMP frame (ethertype 0x0800). Used to prove an IPv4 pcap
    # filter is inert: replicate drops non-IPv6 before the filter runs.
    ihl_ver = (4 << 4) | 5
    ip = struct.pack("!BBHHHBBH", ihl_ver, 0, 20 + 8, 0, 0, 64, 1, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1)
    return eth_hdr(0x0800) + ip + icmp


def oversize_frame(src=HOST_A, dst=DST_MATCH):
    # A large UDP frame whose distinguishing byte sits *past* the 64-byte cBPF
    # snapshot. Used for the boundary case: a filter referencing a deep byte
    # must not match because the interpreter cannot see it.
    marker = b"\xde\xad\xbe\xef"
    padding = b"\x00" * 60          # push the marker well beyond byte 64
    return udp_frame(src=src, dst=dst, sport=1111, dport=2222, extra=padding + marker)


# Named frame templates. Each maps a case name to a builder producing one frame.
CASES = {
    # source-host based
    "src_a":       lambda: tcp_frame(src=HOST_A),
    "src_b":       lambda: tcp_frame(src=HOST_B),
    "src_c":       lambda: tcp_frame(src=HOST_C),
    # dst-host based
    "dst_match":   lambda: tcp_frame(dst=DST_MATCH),
    "dst_other":   lambda: tcp_frame(dst=DST_OTHER),
    # any IPv6
    "ip6_any":     lambda: udp_frame(src=HOST_C, dst=DST_OTHER),
    # L4 ports
    "tcp80":       lambda: tcp_frame(sport=40000, dport=80),
    "tcp81":       lambda: tcp_frame(sport=40000, dport=81),
    "udp53":       lambda: udp_frame(sport=40000, dport=53),
    "udp54":       lambda: udp_frame(sport=40000, dport=54),
    "icmp6":       lambda: icmp6_frame(),
    # combined: src A and tcp port 80
    "a_tcp80":     lambda: tcp_frame(src=HOST_A, dport=80),
    "a_tcp81":     lambda: tcp_frame(src=HOST_A, dport=81),
    "b_tcp80":     lambda: tcp_frame(src=HOST_B, dport=80),
    # byte-offset: next-header field (ip6[6]) == 58 (ICMPv6)
    "nh_icmp6":    lambda: icmp6_frame(),
    "nh_tcp":      lambda: tcp_frame(),
    # length based (small vs large). small ~ 74 bytes, large padded.
    "small":       lambda: udp_frame(extra=b""),
    "large":       lambda: udp_frame(extra=b"\x00" * 120),
    # IPv4 (inert - must not reach the filter)
    "ipv4":        lambda: ipv4_frame(),
    # boundary: distinguishing bytes beyond the 64-byte snapshot
    "oversize":    lambda: oversize_frame(),
}


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: inject_frame.py <ifname> <case> [count]\n")
        sys.stderr.write("cases: " + ", ".join(sorted(CASES)) + "\n")
        return 2

    ifname = argv[1]
    case = argv[2]
    count = int(argv[3]) if len(argv) > 3 else 1

    if case not in CASES:
        sys.stderr.write("unknown case: %s\n" % case)
        sys.stderr.write("cases: " + ", ".join(sorted(CASES)) + "\n")
        return 2

    frame = CASES[case]()

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((ifname, 0))
    except OSError as e:
        sys.stderr.write("socket/bind failed on %s: %s\n" % (ifname, e))
        return 1

    try:
        for _ in range(count):
            s.send(frame)
    except OSError as e:
        sys.stderr.write("send failed: %s\n" % e)
        return 1
    finally:
        s.close()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
