#!/bin/bash
# ============================================================================
# pcap_filter_test.sh - in-depth self-test for xdpfrer's pcap filter mode.
#
# Exercises the replication-ingress pcap filter path with hand-crafted frames
# injected via AF_PACKET (test/inject_frame.py). Only whether the filter MATCHES
# is checked - not delivery or replies. Verification is by exact counter deltas
# (Received / Unmatched) and, for per-filter attribution, by the per-flow
# seqgen sequence number reported by `xdppref-ctl list`.
#
# Topology (own isolated netns "xdpfrer-pcaptest"):
#
#     inject_frame.py --> inj0 <=veth=> mon0  [xdpfrer -m prf, filter-only]
#                                          `--> egr0 (throwaway egress)
#
# Frames injected on inj0 arrive on mon0's RX and hit the replicate XDP filter.
#
# Requires root and locally built src/xdpfrer + src/xdppref-ctl.
#
# Usage:
#   sudo ./test/pcap_filter_test.sh
# (also invoked as the "pcap" suite from selftest.sh)
# ============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/src"
XDPFRER="$SRC_DIR/xdpfrer"
XDPCTL="$SRC_DIR/xdppref-ctl"
INJECT="$SCRIPT_DIR/inject_frame.py"

NS="xdpfrer-pcaptest"
LOGDIR="/tmp/xdpfrer-pcaptest.$$"
HOLDER_PIDFILE="$LOGDIR/holder.pid"
HOLDER_PID=""
# Full packet capture of everything injected on inj0, for offline inspection
# (e.g. Wireshark). Fixed path so it is easy to find after a run.
INJ_PCAP="/tmp/xdpfrer-pcaptest-inj0.pcap"
TCPDUMP_PID=""
N=5                                  # frames injected per case

# stdbuf: force line-buffering so xdpfrer's counters reach the log while running.
if command -v stdbuf >/dev/null 2>&1; then
    STDBUF=(stdbuf -oL -eL)
else
    STDBUF=()
fi

# --- colors (shared style with selftest.sh) ---------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

# --- counters ---------------------------------------------------------------
# When sourced by selftest.sh these may already exist; only initialise if unset.
: "${PASS_COUNT:=0}"
: "${FAIL_COUNT:=0}"
: "${WARN_COUNT:=0}"
if ! declare -p FAILED_TESTS >/dev/null 2>&1; then
    declare -a FAILED_TESTS=()
fi

PCAP_LOG=""          # the running xdpfrer instance log
PCAP_PID=""          # its pid

pass()  { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT+1)); FAILED_TESTS+=("[pcap] $1"); }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN_COUNT=$((WARN_COUNT+1)); }
info()  { echo -e "  ${BLUE}[..]${NC}   $1"; }
subcase() { echo -e "${BOLD}-- $1${NC}"; }

dump_log() {
    [ -f "$1" ] || return 0
    echo -e "    ${YELLOW}--- tail of $(basename "$1") ---${NC}"
    tail -n 8 "$1" | sed 's/^/    | /'
    echo -e "    ${YELLOW}-------------------------------${NC}"
}

# nse <cmd...> : run a command inside the test netns AND the mount namespace of
# the bpffs holder, so /sys/fs/bpf is visible (xdpfrer pins its maps there).
# Falls back to plain netns exec until the holder is up (link setup only).
nse() {
    if [ -n "$HOLDER_PID" ] && [ -e "/proc/$HOLDER_PID/ns/mnt" ]; then
        nsenter --net="/var/run/netns/$NS" --mount="/proc/$HOLDER_PID/ns/mnt" -- "$@"
    else
        ip netns exec "$NS" "$@"
    fi
}

# ============================================================================
# Counter / seqgen readers
# ============================================================================

# counter_val <label> : last cumulative value of Received/Unmatched (0 if none).
counter_val() {
    local v
    v=$(grep -oE "$1: [0-9]+" "$PCAP_LOG" 2>/dev/null | tail -1 | grep -oE '[0-9]+$')
    echo "${v:-0}"
}

# seq_val <match_id_hex> : current seqgen sequence for a flow match_id (0 if none).
# Parses lines like:  "    key=0xffff00000, seq=5 resets=0 encap"
seq_val() {
    local mid="$1" line
    line=$(nse "$XDPCTL" list 2>/dev/null | grep -E "key=$mid," | tail -1)
    if [ -z "$line" ]; then echo 0; return; fi
    echo "$line" | grep -oE 'seq=[0-9]+' | grep -oE '[0-9]+$'
}

settle() { sleep 2; }

# ============================================================================
# Assertions
# ============================================================================

# inject <case> [count] : send frames on inj0.
inject() {
    local case="$1" count="${2:-$N}"
    nse python3 "$INJECT" inj0 "$case" "$count"
}

# assert_match <case> <desc> : inject N frames of <case>, expect exactly N more
# Received and 0 more Unmatched.
assert_match() {
    local case="$1" desc="$2"
    local br bu
    br=$(counter_val Received); bu=$(counter_val Unmatched)
    inject "$case" "$N" || { fail "$desc (inject failed)"; return; }
    settle
    local ar au dr du
    ar=$(counter_val Received); au=$(counter_val Unmatched)
    dr=$((ar-br)); du=$((au-bu))
    if [ "$dr" -eq "$N" ] && [ "$du" -eq 0 ]; then
        pass "$desc (Received +$dr, Unmatched +$du)"
    else
        fail "$desc (expected Received +$N/Unmatched +0, got Received +$dr/Unmatched +$du)"
        dump_log "$PCAP_LOG"
    fi
}

# assert_nomatch <case> <desc> : inject N frames, expect exactly N more Unmatched
# and 0 more Received.
assert_nomatch() {
    local case="$1" desc="$2"
    local br bu
    br=$(counter_val Received); bu=$(counter_val Unmatched)
    inject "$case" "$N" || { fail "$desc (inject failed)"; return; }
    settle
    local ar au dr du
    ar=$(counter_val Received); au=$(counter_val Unmatched)
    dr=$((ar-br)); du=$((au-bu))
    if [ "$du" -eq "$N" ] && [ "$dr" -eq 0 ]; then
        pass "$desc (Unmatched +$du, Received +$dr)"
    else
        fail "$desc (expected Unmatched +$N/Received +0, got Unmatched +$du/Received +$dr)"
        dump_log "$PCAP_LOG"
    fi
}

# add_filter <expr> <egress-locator> <desc> : install a filter-only prf flow.
# (runtime add/del are done via radd/rdel below, scoped to $IF.)

# filter_count : number of installed slots shown in pcap_filter_map.
filter_count() {
    nse "$XDPCTL" list 2>/dev/null | grep -cE '^\s*slot=[0-9]+'
}

# ============================================================================
# Environment lifecycle
# ============================================================================
preclean() {
    if [ -n "$TCPDUMP_PID" ]; then kill "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null; TCPDUMP_PID=""; fi
    if [ -n "$PCAP_PID" ]; then kill "$PCAP_PID" 2>/dev/null; wait "$PCAP_PID" 2>/dev/null; PCAP_PID=""; fi
    if [ -n "$HOLDER_PID" ]; then kill "$HOLDER_PID" 2>/dev/null; HOLDER_PID=""; fi
    # kill any stray processes in this netns, then delete it
    ip netns pids "$NS" 2>/dev/null | while read -r p; do kill "$p" 2>/dev/null; done
    ip netns del "$NS" 2>/dev/null
}

teardown() {
    if [ -n "$TCPDUMP_PID" ]; then kill "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null; TCPDUMP_PID=""; fi
    if [ -n "$PCAP_PID" ]; then kill "$PCAP_PID" 2>/dev/null; wait "$PCAP_PID" 2>/dev/null; PCAP_PID=""; fi
    ip netns pids "$NS" 2>/dev/null | while read -r p; do kill "$p" 2>/dev/null; done
    if [ -n "$HOLDER_PID" ]; then kill "$HOLDER_PID" 2>/dev/null; HOLDER_PID=""; fi
    ip netns del "$NS" 2>/dev/null
    [ -f "$INJ_PCAP" ] && echo -e "  ${BLUE}[..]${NC}   inj0 capture saved: $INJ_PCAP"
}

# The interface xdpfrer attaches to is mon0 (the monitored ingress); xdppref-ctl
# takes the ifname as-is in the filter ingress spec.
setup() {
    preclean
    mkdir -p "$LOGDIR"
    ip netns add "$NS" || return 1

    # Persistent mount-ns holder inside the netns that mounts bpffs, mirroring
    # the env files. nse() enters both this mount ns and the netns so xdpfrer
    # can pin its maps under /sys/fs/bpf.
    rm -f "$HOLDER_PIDFILE"
    ip netns exec "$NS" unshare --mount --propagation private bash -c "
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null
        echo \$\$ > $HOLDER_PIDFILE
        exec sleep infinity
    " &
    disown

    local waited=0
    while [ ! -s "$HOLDER_PIDFILE" ]; do
        sleep 0.1; waited=$((waited+1))
        if [ "$waited" -ge 50 ]; then
            fail "pcap: bpffs mount-ns holder did not start"
            return 1
        fi
    done
    HOLDER_PID="$(cat "$HOLDER_PIDFILE")"

    # Silence the kernel's own IPv6 traffic (router solicitations, MLD reports,
    # link-local DAD). Those are IPv6 frames that would hit replicate, miss the
    # filter, and inflate Unmatched during the settle window, breaking the exact
    # counter deltas. XDP sees injected frames regardless (hook is below the
    # stack), so disabling IPv6 autoconf only removes noise. Set defaults before
    # creating the veths so they inherit it.
    nse sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
    nse sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null

    nse ip link set dev lo up

    # ingress veth pair: inj0 (injection) <-> mon0 (monitored, XDP attached)
    nse ip link add inj0 type veth peer name mon0 || return 1
    # throwaway egress veth pair (egr0 is a valid egress target for xdpfrer)
    nse ip link add egr0 type veth peer name egr0p || return 1

    nse ip link set inj0 up
    nse ip link set mon0 up
    nse ip link set egr0 up
    nse ip link set egr0p up
    # egress veth needs a MAC that set_dst_mac expects; not required for match,
    # but keep the link usable.
    nse ip link set egr0 address 02:00:00:00:00:00 2>/dev/null

    # Capture everything injected on inj0 to a pcap for offline inspection.
    # Use net-ns-only exec (NOT nse): tcpdump only needs to see inj0, and the
    # bpffs holder's private mount namespace would otherwise hide the output
    # file from the host. -U = unbuffered writes so frames are not lost on kill.
    if command -v tcpdump >/dev/null 2>&1; then
        rm -f "$INJ_PCAP"
        ip netns exec "$NS" tcpdump -i inj0 -w "$INJ_PCAP" -U >/dev/null 2>&1 &
        TCPDUMP_PID=$!
        sleep 0.5   # let tcpdump open the capture socket before injection
        if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
            warn "tcpdump failed to start - no inj0 capture"
            TCPDUMP_PID=""
        else
            info "capturing inj0 traffic to $INJ_PCAP"
        fi
    else
        warn "tcpdump not found - skipping inj0 pcap capture"
    fi

    return 0
}

# start the filter-only replicator on mon0 with an initial filter so the maps
# and XDP program are attached. Uses a locator that is never matched by the
# attribution cases.
start_replicator() {
    PCAP_LOG="$LOGDIR/pcap.mon0.log"
    : > "$PCAP_LOG"
    nse "${STDBUF[@]}" "$XDPFRER" -m prf \
        -i 'mon0:filter:ip6 and src host 5f00:0:0:1::111' \
        -e egr0:5f00:0:0:8:f:1011:: >"$PCAP_LOG" 2>&1 &
    PCAP_PID=$!

    local waited=0
    while ! grep -qE "Config replication|Installed pcap filter" "$PCAP_LOG" 2>/dev/null; do
        sleep 0.5; waited=$((waited+1))
        if [ "$waited" -ge 20 ]; then return 1; fi
    done
    # give the XDP attach a moment to settle
    sleep 1
    return 0
}

# ============================================================================
# Test groups
# ============================================================================

# xppref-ctl ingress ifname for filters added at runtime on mon0.
IF=mon0

# runtime add/del helpers scoped to mon0
radd() { # <expr> <egress-locator> <desc>
    if nse "$XDPCTL" add -m prf -i "$IF:filter:$1" -e "egr0:$2" >/dev/null 2>&1; then
        pass "$3"; return 0
    else
        fail "$3 (add failed)"; return 1
    fi
}
rdel() { nse "$XDPCTL" del -m prf -i "$IF:filter:$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------
# Group 1: match matrix
# ------------------------------------------------------------------
group_match_matrix() {
    echo -e "${BOLD}== Group 1: match matrix ==${NC}"

    # The replicator was started with 'ip6 and src host ::111' already installed
    # (slot 0). Use it for the src-host case, then swap filters for the rest.

    subcase "1.1 ip6 and src host A"
    assert_match   "src_a" "1.1 src host A matches"
    assert_nomatch "src_b" "1.1 src host B does not match"
    rdel 'ip6 and src host 5f00:0:0:1::111'

    subcase "1.2 ip6 and dst host D"
    radd 'ip6 and dst host 5f00:0:0:89::9' '5f00:0:0:8:f:1011::' "1.2 install dst-host filter"
    assert_match   "dst_match" "1.2 dst host D matches"
    assert_nomatch "dst_other" "1.2 other dst does not match"
    rdel 'ip6 and dst host 5f00:0:0:89::9'

    subcase "1.3 ip6 (any IPv6)"
    radd 'ip6' '5f00:0:0:8:f:1011::' "1.3 install ip6 filter"
    assert_match "ip6_any" "1.3 arbitrary IPv6 matches"
    rdel 'ip6'

    subcase "1.4 tcp port 80"
    radd 'ip6 and tcp port 80' '5f00:0:0:8:f:1011::' "1.4 install tcp-port filter"
    assert_match   "tcp80" "1.4 tcp port 80 matches"
    assert_nomatch "tcp81" "1.4 tcp port 81 does not match"
    rdel 'ip6 and tcp port 80'

    subcase "1.5 udp port 53"
    radd 'ip6 and udp port 53' '5f00:0:0:8:f:1011::' "1.5 install udp-port filter"
    assert_match   "udp53" "1.5 udp port 53 matches"
    assert_nomatch "udp54" "1.5 udp port 54 does not match"
    rdel 'ip6 and udp port 53'

    subcase "1.6 icmp6"
    radd 'icmp6' '5f00:0:0:8:f:1011::' "1.6 install icmp6 filter"
    assert_match   "icmp6" "1.6 icmp6 matches"
    assert_nomatch "tcp80" "1.6 tcp does not match icmp6 filter"
    rdel 'icmp6'

    subcase "1.7 src A and tcp port 80"
    radd 'ip6 and src host 5f00:0:0:1::111 and tcp port 80' '5f00:0:0:8:f:1011::' "1.7 install combined filter"
    assert_match   "a_tcp80" "1.7 src A + tcp 80 matches"
    assert_nomatch "a_tcp81" "1.7 src A + tcp 81 does not match"
    assert_nomatch "b_tcp80" "1.7 src B + tcp 80 does not match"
    rdel 'ip6 and src host 5f00:0:0:1::111 and tcp port 80'

    subcase "1.8 src A or src B"
    radd 'ip6 and (src host 5f00:0:0:1::111 or src host 5f00:0:0:1::222)' '5f00:0:0:8:f:1011::' "1.8 install or filter"
    assert_match   "src_a" "1.8 src A matches (or)"
    assert_match   "src_b" "1.8 src B matches (or)"
    assert_nomatch "src_c" "1.8 src C does not match (or)"
    rdel 'ip6 and (src host 5f00:0:0:1::111 or src host 5f00:0:0:1::222)'

    subcase "1.9 not src A"
    radd 'ip6 and not src host 5f00:0:0:1::111' '5f00:0:0:8:f:1011::' "1.9 install not filter"
    assert_match   "src_b" "1.9 src B matches (not A)"
    assert_nomatch "src_a" "1.9 src A does not match (not A)"
    rdel 'ip6 and not src host 5f00:0:0:1::111'

    subcase "1.10 ip6[6] = 58 (next-header == ICMPv6, raw offset)"
    radd 'ip6[6] = 58' '5f00:0:0:8:f:1011::' "1.10 install byte-offset filter"
    assert_match   "nh_icmp6" "1.10 next-header 58 matches"
    assert_nomatch "nh_tcp"   "1.10 next-header 6 does not match"
    rdel 'ip6[6] = 58'

    subcase "1.11 length (greater 100)"
    radd 'greater 100' '5f00:0:0:8:f:1011::' "1.11 install length filter"
    assert_match   "large" "1.11 large frame matches (>100)"
    assert_nomatch "small" "1.11 small frame does not match (>100)"
    rdel 'greater 100'

    subcase "1.12 boundary: field beyond 64-byte snapshot"
    # A filter that inspects a byte well past the snapshot (ip6[80]) must never
    # match, even though the injected 'oversize' frame carries a marker there.
    radd 'ip6[80] = 0xde' '5f00:0:0:8:f:1011::' "1.12 install past-snapshot filter"
    assert_nomatch "oversize" "1.12 byte past 64B snapshot does not match (documents limit)"
    rdel 'ip6[80] = 0xde'
}

# ------------------------------------------------------------------
# Group 2: install-layer error paths
# ------------------------------------------------------------------
group_install_layer() {
    echo -e "${BOLD}== Group 2: install layer ==${NC}"

    subcase "2.1 IPv4 filter installs but is inert"
    if radd 'ip and src host 10.0.0.1' '5f00:0:0:8:f:1011::' "2.1 IPv4 filter installs"; then
        assert_nomatch "ipv4" "2.1 IPv4 frame not matched (dropped before filter)"
        rdel 'ip and src host 10.0.0.1'
    fi

    subcase "2.2 invalid expression rejected"
    local before after
    before=$(filter_count)
    if nse "$XDPCTL" add -m prf -i "$IF:filter:this is not valid pcap" -e "egr0:5f00:0:0:8:f:1011::" >/dev/null 2>&1; then
        fail "2.2 invalid expression was accepted"
        rdel 'this is not valid pcap'
    else
        after=$(filter_count)
        if [ "$after" -eq "$before" ]; then
            pass "2.2 invalid expression rejected, no slot consumed"
        else
            fail "2.2 invalid expression rejected but slot count changed ($before -> $after)"
        fi
    fi

    subcase "2.3 over-long filter (>64 instructions) rejected"
    # A long chain of OR'd host matches compiles to many instructions; enough
    # terms exceed MAX_CBPF_INSNS (64).
    local expr="ip6"
    local i
    for i in $(seq 1 40); do
        expr="$expr and not src host 5f00:0:0:1::$i"
    done
    before=$(filter_count)
    if nse "$XDPCTL" add -m prf -i "$IF:filter:$expr" -e "egr0:5f00:0:0:8:f:1011::" >/dev/null 2>&1; then
        fail "2.3 over-long filter was accepted"
        rdel "$expr"
    else
        after=$(filter_count)
        if [ "$after" -eq "$before" ]; then
            pass "2.3 over-long filter rejected, no slot consumed"
        else
            fail "2.3 over-long filter rejected but slot count changed ($before -> $after)"
        fi
    fi
}

# ------------------------------------------------------------------
# Group 3: multi-filter / slot mechanics + per-filter attribution
# ------------------------------------------------------------------
group_multi_filter() {
    echo -e "${BOLD}== Group 3: multi-filter & attribution ==${NC}"

    subcase "3.1 fill all 8 slots"
    local i ok=1
    for i in $(seq 1 8); do
        if ! nse "$XDPCTL" add -m prf -i "$IF:filter:ip6 and src host 5f00:0:0:2::$i" \
                -e "egr0:5f00:0:0:8:f:1011::" >/dev/null 2>&1; then
            ok=0; break
        fi
    done
    local cnt; cnt=$(filter_count)
    if [ "$ok" -eq 1 ] && [ "$cnt" -eq 8 ]; then
        pass "3.1 all 8 slots filled (pcap_filter_map shows $cnt)"
    else
        fail "3.1 could not fill 8 slots (installed=$cnt)"
    fi

    subcase "3.2 9th filter rejected (no free slots)"
    if nse "$XDPCTL" add -m prf -i "$IF:filter:ip6 and src host 5f00:0:0:2::99" \
            -e "egr0:5f00:0:0:8:f:1011::" >/dev/null 2>&1; then
        fail "3.2 9th filter was accepted"
    else
        cnt=$(filter_count)
        [ "$cnt" -eq 8 ] && pass "3.2 9th rejected, still 8 slots" \
                          || fail "3.2 9th rejected but slot count=$cnt"
    fi

    subcase "3.3 delete one, add another (slot reuse)"
    rdel 'ip6 and src host 5f00:0:0:2::1'
    cnt=$(filter_count)
    [ "$cnt" -eq 7 ] && pass "3.3 slot freed (now $cnt)" || fail "3.3 expected 7 slots, got $cnt"
    if nse "$XDPCTL" add -m prf -i "$IF:filter:ip6 and src host 5f00:0:0:2::200" \
            -e "egr0:5f00:0:0:8:f:1011::" >/dev/null 2>&1; then
        cnt=$(filter_count)
        [ "$cnt" -eq 8 ] && pass "3.3 freed slot reused (back to $cnt)" \
                         || fail "3.3 re-add slot count=$cnt"
    else
        fail "3.3 re-add into freed slot failed"
    fi

    # Clear all slots before the attribution test for a clean slate.
    for i in $(seq 2 8); do rdel "ip6 and src host 5f00:0:0:2::$i"; done
    rdel 'ip6 and src host 5f00:0:0:2::200'

    subcase "3.4 per-filter attribution via seqgen"
    # Install filter A (src A) and filter B (src B) as the first two flows so
    # they land in slots 0 and 1 -> match_ids 0xffff00000 and 0xffff00001.
    radd 'ip6 and src host 5f00:0:0:1::111' '5f00:0:0:8:f:1011::' "3.4 install filter A (slot 0)"
    radd 'ip6 and src host 5f00:0:0:1::222' '5f00:0:0:8:f:2012::' "3.4 install filter B (slot 1)"

    local mA=0xffff00000 mB=0xffff00001
    local a0 b0 a1 b1

    # Inject frames matching A only.
    a0=$(seq_val "$mA"); b0=$(seq_val "$mB")
    inject "src_a" "$N"; settle
    a1=$(seq_val "$mA"); b1=$(seq_val "$mB")
    if [ "$((a1-a0))" -eq "$N" ] && [ "$((b1-b0))" -eq 0 ]; then
        pass "3.4 frames from A advanced only filter A's seq (A +$((a1-a0)), B +$((b1-b0)))"
    else
        fail "3.4 A-attribution wrong (A +$((a1-a0)), B +$((b1-b0)); expected A +$N, B +0)"
    fi

    # Inject frames matching B only.
    a0=$(seq_val "$mA"); b0=$(seq_val "$mB")
    inject "src_b" "$N"; settle
    a1=$(seq_val "$mA"); b1=$(seq_val "$mB")
    if [ "$((b1-b0))" -eq "$N" ] && [ "$((a1-a0))" -eq 0 ]; then
        pass "3.4 frames from B advanced only filter B's seq (A +$((a1-a0)), B +$((b1-b0)))"
    else
        fail "3.4 B-attribution wrong (A +$((a1-a0)), B +$((b1-b0)); expected B +$N, A +0)"
    fi

    # Inject frames matching neither -> both seqs unchanged, Unmatched grows.
    a0=$(seq_val "$mA"); b0=$(seq_val "$mB")
    assert_nomatch "src_c" "3.4 frames from C match no filter"
    a1=$(seq_val "$mA"); b1=$(seq_val "$mB")
    if [ "$((a1-a0))" -eq 0 ] && [ "$((b1-b0))" -eq 0 ]; then
        pass "3.4 non-matching frames advanced neither seq"
    else
        fail "3.4 non-matching frames changed a seq (A +$((a1-a0)), B +$((b1-b0)))"
    fi

    rdel 'ip6 and src host 5f00:0:0:1::111'
    rdel 'ip6 and src host 5f00:0:0:1::222'
}

# ============================================================================
# Entry point
# ============================================================================

# run_pcap_suite: the body, callable both standalone and from selftest.sh.
run_pcap_suite() {
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD} pcap filter in-depth tests${NC}"
    echo -e "${BOLD}============================================================${NC}"

    if ! setup; then
        fail "pcap: failed to set up test namespace"
        teardown
        return
    fi
    if ! start_replicator; then
        fail "pcap: replicator failed to become ready"
        dump_log "$PCAP_LOG"
        teardown
        return
    fi
    pass "replicator ready on mon0 (filter-only)"

    group_match_matrix
    group_install_layer
    group_multi_filter

    teardown
}

# Standalone invocation (not sourced): do root/binary checks, run, summarise.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error:${NC} must run as root (sudo $0)"
        exit 2
    fi
    for b in "$XDPFRER" "$XDPCTL"; do
        if [ ! -x "$b" ]; then
            echo -e "${RED}Error:${NC} $b not found or not executable"
            echo "Build first:  make -C \"$SRC_DIR\""
            exit 2
        fi
    done
    if [ ! -f "$INJECT" ]; then
        echo -e "${RED}Error:${NC} $INJECT not found"
        exit 2
    fi

    trap 'teardown' EXIT INT TERM

    run_pcap_suite

    echo ""
    echo -e "  ${GREEN}PASS: $PASS_COUNT${NC}   ${RED}FAIL: $FAIL_COUNT${NC}   ${YELLOW}WARN: $WARN_COUNT${NC}"
    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo -e "  ${RED}Failed:${NC}"
        for t in "${FAILED_TESTS[@]}"; do echo "    - $t"; done
        exit 1
    fi
    rm -rf "$LOGDIR"
    exit 0
fi
