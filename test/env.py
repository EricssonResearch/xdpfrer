#!/bin/env python3

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from datetime import datetime
import os
import argparse
import sys

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def start_tcpdump(net: Mininet, output_dir: str):
    for host in net.hosts:
        intfs = host.cmd("ip -o link show up | awk -F': ' '{print $2}' | grep -v lo").strip().split('\n')
        for intf in intfs:
            ifname = intf.split("@")[0]
            print(ifname)
            host.cmd(f'tcpdump -i {ifname} -w {output_dir}/{host.name}_{ifname}.pcap &')

def stop_tcpdump(net: Mininet):
    for host in net.hosts:
        host.cmd('killall tcpdump 2>/dev/null; wait 2>/dev/null')

def run_cmd(host, cmd: str):
    ret = host.cmd(cmd)
    if ret:
        return f'[{host.name}] {cmd}\n  {ret.strip()}\n'
    return ""

def cleanup_after_fail(net: Mininet):
    net.stop()
    sys.exit(1)

def print_ok(label: str):
    info(f'\r{GREEN}{label}✔{RESET}\n')

def print_fail(label: str):
    info(f'\r{RED}{label}✘{RESET}\n\n')

def check_ret(net: Mininet, ret: str, section_label: str):
    if ret != "":
        print_fail(section_label)
        print(ret)
        cleanup_after_fail(net)
    print_ok(section_label)

def start_network():
    ret = ""
    net = Mininet()

    # create nodes
    section_label = '*** Creating nodes... '
    info(section_label)
    na = net.addHost('na', ip=None)
    nb = net.addHost('nb', ip=None)
    nc = net.addHost('nc', ip=None)
    nd = net.addHost('nd', ip=None)
    ne = net.addHost('ne', ip=None)
    nf = net.addHost('nf', ip=None)
    check_ret(net, ret, section_label)

    # link them in a chain
    section_label = '*** Adding links... '
    info(section_label)
    net.addLink(na, nb, intfName1='ethAB', intfName2='ethBA')
    net.addLink(nb, nc, intfName1='ethBC', intfName2='ethCB')
    net.addLink(nc, nd, intfName1='ethCD', intfName2='ethDC')
    net.addLink(nd, ne, intfName1='ethDE', intfName2='ethED')
    net.addLink(ne, nf, intfName1='ethEF', intfName2='ethFE')
    check_ret(net, ret, section_label)

    setLogLevel('error') # avoid unnecessary prints
    net.build()
    setLogLevel('info')

    # we need IPv6 for SRv6
    section_label = '*** Adding IP addresses... '
    info(section_label)

    # loopback addresses
    ret += run_cmd(na, "ip a a 5f00:0:0:a::/128 dev lo")
    ret += run_cmd(nb, "ip a a 5f00:0:0:b::/128 dev lo")
    ret += run_cmd(nc, "ip a a 5f00:0:0:c::/128 dev lo")
    ret += run_cmd(nd, "ip a a 5f00:0:0:d::/128 dev lo")
    ret += run_cmd(ne, "ip a a 5f00:0:0:e::/128 dev lo")
    ret += run_cmd(nf, "ip a a 5f00:0:0:f::/128 dev lo")

    # link addresses
    ret += run_cmd(na, "ip a a 5f00:0:0:ab::a/64 dev ethAB")
    ret += run_cmd(nb, "ip a a 5f00:0:0:ab::b/64 dev ethBA")
    ret += run_cmd(nb, "ip a a 5f00:0:0:bc::b/64 dev ethBC")
    ret += run_cmd(nc, "ip a a 5f00:0:0:bc::c/64 dev ethCB")
    ret += run_cmd(nc, "ip a a 5f00:0:0:cd::c/64 dev ethCD")
    ret += run_cmd(nd, "ip a a 5f00:0:0:cd::d/64 dev ethDC")
    ret += run_cmd(nd, "ip a a 5f00:0:0:de::d/64 dev ethDE")
    ret += run_cmd(ne, "ip a a 5f00:0:0:de::e/64 dev ethED")
    ret += run_cmd(ne, "ip a a 5f00:0:0:ef::e/64 dev ethEF")
    ret += run_cmd(nf, "ip a a 5f00:0:0:ef::f/64 dev ethFE")

    check_ret(net, ret, section_label)

    section_label = '*** Enabling seg6... '
    info(section_label)
    for n in [na, nb, nc, nd, ne, nf]:
        ret += run_cmd(n, "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")
        ret += run_cmd(n, "echo 1 > /proc/sys/net/ipv6/conf/all/seg6_enabled")

    ret += run_cmd(nb, "echo 1 > /proc/sys/net/ipv6/conf/ethBA/seg6_enabled")
    ret += run_cmd(nc, "echo 1 > /proc/sys/net/ipv6/conf/ethCB/seg6_enabled")
    ret += run_cmd(nd, "echo 1 > /proc/sys/net/ipv6/conf/ethDC/seg6_enabled")
    ret += run_cmd(ne, "echo 1 > /proc/sys/net/ipv6/conf/ethED/seg6_enabled")
    ret += run_cmd(nf, "echo 1 > /proc/sys/net/ipv6/conf/ethFE/seg6_enabled")

    check_ret(net, ret, section_label)

    section_label = '*** Adding routing... '
    info(section_label)
    ret += run_cmd(na, "ip -6 r a default via 5f00:0:0:ab::b dev ethAB")
    ret += run_cmd(nf, "ip -6 r a default via 5f00:0:0:ef::e dev ethFE")

    # nb forward (via nc)
    ret += run_cmd(nb, "ip -6 r a 5f00:0:0:cd::/64 via 5f00:0:0:bc::c dev ethBC")
    ret += run_cmd(nb, "ip -6 r a 5f00:0:0:de::/64 via 5f00:0:0:bc::c dev ethBC")
    ##################ret += run_cmd(nb, "ip -6 r a 5f00:0:0:ef::/64 via 5f00:0:0:bc::c dev ethBC")
    ret += run_cmd(nb, "ip -6 r a 5f00:0:0:c::/64 via 5f00:0:0:bc::c dev ethBC")
    ret += run_cmd(nb, "ip -6 r a 5f00:0:0:d::/64 via 5f00:0:0:bc::c dev ethBC")
    ret += run_cmd(nb, "ip -6 r a 5f00:0:0:f::/64 via 5f00:0:0:bc::c dev ethBC")
    # nb reverse (via na)
    ret += run_cmd(nb, "ip -6 r a 5f00:0:0:a::/64 via 5f00:0:0:ab::a dev ethBA")

    # nc forward (via nd)
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:de::/64 via 5f00:0:0:cd::d dev ethCD")
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:ef::/64 via 5f00:0:0:cd::d dev ethCD")
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:d::/64 via 5f00:0:0:cd::d dev ethCD")
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:e::/64 via 5f00:0:0:cd::d dev ethCD")
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:f::/64 via 5f00:0:0:cd::d dev ethCD")
    # nc reverse (via nb)
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:ab::/64 via 5f00:0:0:bc::b dev ethCB")
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:a::/64 via 5f00:0:0:bc::b dev ethCB")
    ret += run_cmd(nc, "ip -6 r a 5f00:0:0:b::/64 via 5f00:0:0:bc::b dev ethCB")

    # nd forward (via ne)
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:ef::/64 via 5f00:0:0:de::e dev ethDE")
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:e::/64 via 5f00:0:0:de::e dev ethDE")
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:f::/64 via 5f00:0:0:de::e dev ethDE")
    # nd reverse (via nc)
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:bc::/64 via 5f00:0:0:cd::c dev ethDC")
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:ab::/64 via 5f00:0:0:cd::c dev ethDC")
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:a::/64 via 5f00:0:0:cd::c dev ethDC")
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:b::/64 via 5f00:0:0:cd::c dev ethDC")
    ret += run_cmd(nd, "ip -6 r a 5f00:0:0:c::/64 via 5f00:0:0:cd::c dev ethDC")

    # ne forward (via nf)
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:f::/64 via 5f00:0:0:ef::f dev ethEF")
    # ne reverse (via nd)
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:cd::/64 via 5f00:0:0:de::d dev ethED")
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:bc::/64 via 5f00:0:0:de::d dev ethED")
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:ab::/64 via 5f00:0:0:de::d dev ethED")
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:a::/64 via 5f00:0:0:de::d dev ethED")
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:b::/64 via 5f00:0:0:de::d dev ethED")
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:c::/64 via 5f00:0:0:de::d dev ethED")
    ret += run_cmd(ne, "ip -6 r a 5f00:0:0:d::/64 via 5f00:0:0:de::d dev ethED")

    check_ret(net, ret, section_label)

    section_label = '*** Setting SRv6... '
    info(section_label)
    ret += run_cmd(nb, "ip -6 r a 5f00:0:0:e::/64 encap seg6 mode inline segs 5f00:0:0:c::,5f00:0:0:d:: dev ethBC")
    
    check_ret(net, ret, section_label)

    # veth pair on nb for replication
    section_label = '*** Adding veths... '
    info(section_label)
    ret += run_cmd(nb, "ip link add veth0 type veth peer name veth1")
    ret += run_cmd(nb, "ip link set veth0 up")
    ret += run_cmd(nb, "ip link set veth1 up")
    ret += run_cmd(nb, "echo 1 > /proc/sys/net/ipv6/conf/veth0/seg6_enabled")
    ret += run_cmd(nb, "echo 1 > /proc/sys/net/ipv6/conf/veth1/seg6_enabled")
    ret += run_cmd(nb, "ethtool -K veth0 gro on")
    ret += run_cmd(nb, "ethtool -K veth1 gro on")
    ret += run_cmd(nb, "ip link set veth0 address 02:00:00:00:00:00")
    ret += run_cmd(nb, "ip link set veth1 address 02:00:00:00:00:01")

    # veth pair on ne for elimination
    ret += run_cmd(ne, "ip link add veth0 type veth peer name veth1")
    ret += run_cmd(ne, "ip link set veth0 up")
    ret += run_cmd(ne, "ip link set veth1 up")
    ret += run_cmd(ne, "echo 1 > /proc/sys/net/ipv6/conf/veth0/seg6_enabled")
    ret += run_cmd(ne, "echo 1 > /proc/sys/net/ipv6/conf/veth1/seg6_enabled")
    ret += run_cmd(ne, "ethtool -K veth0 gro on")
    ret += run_cmd(ne, "ethtool -K veth1 gro on")
    ret += run_cmd(ne, "ip link set veth0 address 02:00:00:00:00:00")
    ret += run_cmd(ne, "ip link set veth1 address 02:00:00:00:00:01")

    check_ret(net, ret, section_label)

    return net

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--trace", action="store_true", help="Trace each node.")
    args = parser.parse_args()

    setLogLevel('info')
    net = start_network()

    if args.trace:
        output_dir = f'/tmp/xdpfrer_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        os.makedirs(output_dir)

        start_tcpdump(net, output_dir)

    setLogLevel('error') # avoid unnecessary prints
    CLI(net)
    setLogLevel('info')

    if args.trace:
        stop_tcpdump(net)

    net.stop()

