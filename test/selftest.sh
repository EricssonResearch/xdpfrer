#!/bin/bash
# ============================================================================
# xdpfrer automated self-test
#
# Runs the FRER (L2) and PREF (L3/SRv6) scenarios documented in the README to
# completion, without any user interaction. Each of the four virtual test
# environments is set up, exercised, and torn down in turn.
#
# Verification is counter-based (README "verify the output" step): a replicator
# must report Received > 0 and an eliminator must report Dropped > 0 for the
# redundancy pipeline to be considered working. Threshold/delta assertions are
# used (not exact counts) to stay robust against ping timing.
#
# Requirements:
#   - must be run as root
#   - locally built binaries src/xdpfrer and src/xdppref-ctl (run `make` in src/)
#
# Usage:
#   sudo ./test/selftest.sh                # run all environments
#   sudo ./test/selftest.sh srv6           # run a subset
#   sudo ./test/selftest.sh frer srv6_multi_prf
#
# Environment names: frer srv6 srv6_multi_prf srv6_multi_pef
# (frer_physical is intentionally excluded: it needs real NICs.)
# ============================================================================

# NOTE: we deliberately do NOT use `set -e`/`set -u`. This script sources the
# interactive env files (via the XDPFRER_AUTOMATED guard), whose setup routines
# run many `ip`/`sysctl`/`ethtool` commands that may return non-zero benignly.
# Errors are handled explicitly instead.
set -o pipefail

# The env files use aliases (nsx/tx/lx, n1..n9) inside their configure_netenv
# functions. Bash only expands aliases in scripts when this is enabled, and it
# must be set before the env files are sourced/parsed.
shopt -s expand_aliases

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/src"
XDPFRER="$SRC_DIR/xdpfrer"
XDPCTL="$SRC_DIR/xdppref-ctl"

# xdpfrer's stdout is fully-buffered when redirected to a file, so its readiness
# line and counters would not appear in the logs until it exits. Force
# line-buffering via stdbuf (propagates through ip netns exec / nsenter via
# LD_PRELOAD). Empty if stdbuf is unavailable.
if command -v stdbuf >/dev/null 2>&1; then
    STDBUF=(stdbuf -oL -eL)
else
    STDBUF=()
fi

LOGDIR="/tmp/xdpfrer-selftest.$$"

# --- colors -----------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

# --- counters ---------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
declare -a FAILED_TESTS=()

# Per-environment result tracking (name -> "pass/fail/warn")
declare -a ENV_SUMMARY=()

# PIDs of background xdpfrer instances for the currently active environment.
declare -a PIDS=()
# Log files for the active environment (for readiness polling / debugging).
declare -a LOGS=()

# Name of the currently active environment (for cleanup on trap).
CURRENT_ENV=""

# ============================================================================
# Logging helpers
# ============================================================================
pass()  { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail()  {
    echo -e "  ${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAILED_TESTS+=("[$CURRENT_ENV] $1")
}
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN_COUNT=$((WARN_COUNT+1)); }
info()  { echo -e "  ${BLUE}[..]${NC}   $1"; }
subcase() { echo -e "${BOLD}-- $1${NC}"; }
envhdr() {
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD} Environment: $1${NC}"
    echo -e "${BOLD}============================================================${NC}"
}

# Print the tail of a log to aid diagnosing a failure.
dump_log() {
    local log="$1"
    if [ -f "$log" ]; then
        echo -e "    ${YELLOW}--- tail of $(basename "$log") ---${NC}"
        tail -n 8 "$log" | sed 's/^/    | /'
        echo -e "    ${YELLOW}-------------------------------${NC}"
    fi
}

# ============================================================================
# Process lifecycle
# ============================================================================

# Set by start_instance to the log path of the instance just launched.
LAST_LOG=""

# start_instance <logname> <cmd...>
# Launches an xdpfrer instance in the background, redirecting output to a log,
# and records its PID/log. Sets LAST_LOG to the log path.
#
# NOTE: must NOT be called via $(...) — that would run it in a subshell, losing
# the PID/LOG tracking and orphaning the background process. Call it directly
# and read LAST_LOG afterwards.
start_instance() {
    local logname="$1"; shift
    local log="$LOGDIR/${CURRENT_ENV}.${logname}.log"
    : > "$log"
    "$@" >"$log" 2>&1 &
    PIDS+=("$!")
    LOGS+=("$log")
    LAST_LOG="$log"
}

# wait_ready <log> <pattern> [timeout_sec]
# Polls a log until <pattern> appears (instance finished map setup) or timeout.
# Also fails early if the underlying process is no longer running.
wait_ready() {
    local log="$1" pattern="$2" timeout="${3:-10}"
    local waited=0 max=$((timeout*2))
    while true; do
        if grep -qE "$pattern" "$log" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        waited=$((waited+1))
        if [ "$waited" -ge "$max" ]; then
            return 1
        fi
    done
}

# stop_instances: kill all tracked background instances of the active env.
stop_instances() {
    local pid
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null
    done
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null
    done
    PIDS=()
    LOGS=()
}

# ============================================================================
# Assertion helpers
# ============================================================================

# counter_val <log> <label>  ->  last cumulative value for that label (0 if none)
# Handles both "Received: N" and "..., Dropped: N, ..." formats.
counter_val() {
    local v
    v=$(grep -oE "$2: [0-9]+" "$1" 2>/dev/null | tail -1 | grep -oE '[0-9]+$')
    echo "${v:-0}"
}

# Let the ~1s counter print-loop emit a fresh line after an action.
settle() { sleep 2; }

# assert_counter_grew <log> <label> <baseline> <desc>
assert_counter_grew() {
    local log="$1" label="$2" base="$3" desc="$4"
    local after
    after=$(counter_val "$log" "$label")
    if [ "$after" -gt "$base" ]; then
        pass "$desc ($label: $base -> $after)"
    else
        fail "$desc ($label did not grow: $base -> $after)"
        dump_log "$log"
    fi
}

# run_ping_ok <desc> <cmd...>   -> asserts ping reports 0% packet loss
run_ping_ok() {
    local desc="$1"; shift
    local out
    out=$("$@" 2>&1)
    if echo "$out" | grep -q "0% packet loss"; then
        pass "$desc (ping ok)"
        return 0
    else
        fail "$desc (ping failed / packet loss)"
        echo "$out" | tail -n 3 | sed 's/^/    | /'
        return 1
    fi
}

# run_cmd_ok <desc> <cmd...>    -> asserts command exits 0
run_cmd_ok() {
    local desc="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        pass "$desc"
        return 0
    else
        fail "$desc (exit $?)"
        echo "$out" | tail -n 3 | sed 's/^/    | /'
        return 1
    fi
}

# ============================================================================
# Environment pre-clean (idempotent) + teardown
# ============================================================================

# preclean_ns <semafile> <nsdir> <ns...>
# Force-removes leftovers from a previously aborted run of an environment.
preclean_ns() {
    local semafile="$1" nsdir="$2"; shift 2
    local ns
    for ns in "$@"; do
        if [ -n "$nsdir" ] && [ -s "$nsdir/$ns" ]; then
            kill "$(cat "$nsdir/$ns")" 2>/dev/null
        fi
        ip netns del "$ns" 2>/dev/null
    done
    [ -n "$nsdir" ] && rm -rf "$nsdir" 2>/dev/null
    rm -f "$semafile" 2>/dev/null
}

# Teardown the active environment: stop instances, then call the env's cleanup().
teardown_env() {
    stop_instances
    if declare -F cleanup >/dev/null 2>&1; then
        cleanup >/dev/null 2>&1
    fi
}

# Global trap: ensure no orphaned processes/namespaces on any exit.
on_exit() {
    local rc=$?
    if [ -n "$CURRENT_ENV" ]; then
        teardown_env
    fi
    exit $rc
}
trap on_exit EXIT INT TERM

# ============================================================================
# Environment 1: frer.env  (Layer 2 FRER, talker/listener)
# ============================================================================
test_frer() {
    CURRENT_ENV="frer"
    envhdr "frer (Layer 2 FRER)"

    preclean_ns "/tmp/xdpfrer.envs" "" talker listener frerenv

    info "Setting up environment (source frer.env)"
    XDPFRER_AUTOMATED=1 . "$SCRIPT_DIR/frer.env" > "$LOGDIR/${CURRENT_ENV}.setup.log" 2>&1

    # nsx = frerenv (the switch), tx = talker, lx = listener
    local repl_fwd elim_fwd repl_rev elim_rev
    start_instance "repl_fwd" ip netns exec frerenv "${STDBUF[@]}" "$XDPFRER" -m repl -i aeth0:10 -e enp3s0:55 -e enp6s0:56; repl_fwd="$LAST_LOG"
    start_instance "elim_fwd" ip netns exec frerenv "${STDBUF[@]}" "$XDPFRER" -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20; elim_fwd="$LAST_LOG"
    start_instance "repl_rev" ip netns exec frerenv "${STDBUF[@]}" "$XDPFRER" -m repl -i beth0:20 -e enp4s0:66 -e enp7s0:67; repl_rev="$LAST_LOG"
    start_instance "elim_rev" ip netns exec frerenv "${STDBUF[@]}" "$XDPFRER" -m elim -i enp3s0:66 -i enp6s0:67 -e aeth0:10; elim_rev="$LAST_LOG"

    if ! wait_ready "$repl_fwd" "Config replication" 10 \
       || ! wait_ready "$elim_fwd" "Config recovery" 10 \
       || ! wait_ready "$repl_rev" "Config replication" 10 \
       || ! wait_ready "$elim_rev" "Config recovery" 10; then
        fail "frer: one or more xdpfrer instances failed to become ready"
        dump_log "$LOGDIR/${CURRENT_ENV}.setup.log"
        dump_log "$repl_fwd"; dump_log "$elim_fwd"
        teardown_env; CURRENT_ENV=""
        return
    fi
    pass "all four xdpfrer instances ready"

    # --- sub-case 1: bidirectional repl + elim ------------------------------
    subcase "frer/1: bidirectional replication + elimination"
    local b_rf b_ef b_rr b_er
    b_rf=$(counter_val "$repl_fwd" Received)
    b_ef=$(counter_val "$elim_fwd" Dropped)
    b_rr=$(counter_val "$repl_rev" Received)
    b_er=$(counter_val "$elim_rev" Dropped)

    run_ping_ok "frer/1 connectivity" ip netns exec talker ping 10.0.0.2 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$repl_fwd" Received "$b_rf" "frer/1 forward replicator received"
    assert_counter_grew "$elim_fwd" Dropped  "$b_ef" "frer/1 forward eliminator dropped duplicates"
    assert_counter_grew "$repl_rev" Received "$b_rr" "frer/1 reverse replicator received"
    assert_counter_grew "$elim_rev" Dropped  "$b_er" "frer/1 reverse eliminator dropped duplicates"

    # --- sub-case 2 (warn-only): unmatched VLAN is dropped ------------------
    subcase "frer/2: unmatched VLAN dropped (negative, warn-only)"
    ip netns exec talker ip link add link teth0 name teth0.99 type vlan id 99 2>/dev/null
    ip netns exec talker ip addr add 10.0.0.9/24 dev teth0.99 2>/dev/null
    ip netns exec talker ip link set teth0.99 up 2>/dev/null
    ip netns exec talker ip nei add 10.0.0.2 dev teth0.99 lladdr 00:00:00:02:02:02 2>/dev/null
    if ip netns exec talker ping 10.0.0.2 -I teth0.99 -c 2 -W 1 -w 4 -q 2>&1 | grep -q "0% packet loss"; then
        warn "frer/2 packet on unmatched VLAN 99 was unexpectedly delivered"
    else
        pass "frer/2 unmatched VLAN 99 dropped as expected"
    fi
    ip netns exec talker ip link del teth0.99 2>/dev/null

    teardown_env
    CURRENT_ENV=""
}

# ============================================================================
# Environment 2: srv6.env  (Layer 3 PREF, basic 2-path + pcap filter feature)
# ============================================================================
test_srv6() {
    CURRENT_ENV="srv6"
    envhdr "srv6 (Layer 3 PREF, basic + pcap filter)"

    preclean_ns "/tmp/xdpfrer-srv6.envs" "/tmp/xdpfrer-srv6-mntns" n1 n2 n3 n4 n5 n6 n7 n8 n9

    info "Setting up environment (source srv6.env)"
    XDPFRER_AUTOMATED=1 . "$SCRIPT_DIR/srv6.env" > "$LOGDIR/${CURRENT_ENV}.setup.log" 2>&1

    local n2log n8log
    start_instance "n2_prf" nsrun n2 "${STDBUF[@]}" "$XDPFRER" -m prf -i eth21:fl:10 \
                -e veth0:5f00:0:0:8:f:1011:: -e veth2:5f00:0:0:8:f:2012::; n2log="$LAST_LOG"
    start_instance "n8_pef" nsrun n8 "${STDBUF[@]}" "$XDPFRER" -m pef \
                -i eth84:rsid:f:10110 -i eth87:rsid:f:20120 -e veth0:::; n8log="$LAST_LOG"

    if ! wait_ready "$n2log" "Config replication" 10 || ! wait_ready "$n8log" "Config recovery" 10; then
        fail "srv6: base instances failed to become ready"
        dump_log "$LOGDIR/${CURRENT_ENV}.setup.log"
        dump_log "$n2log"; dump_log "$n8log"
        teardown_env; CURRENT_ENV=""
        return
    fi
    pass "n2 (prf) and n8 (pef) ready"

    local b_rx b_drop b_unm

    # --- sub-case 1: flow label 10 match ------------------------------------
    subcase "srv6/1: flow-label match (fl:10)"
    b_rx=$(counter_val "$n2log" Received)
    b_drop=$(counter_val "$n8log" Dropped)
    run_ping_ok "srv6/1 ping -F 10" nsrun n1 ping 5f00:0:0:89::9 -F 10 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Received "$b_rx"  "srv6/1 n2 replicated fl:10 traffic"
    assert_counter_grew "$n8log" Dropped  "$b_drop" "srv6/1 n8 eliminated duplicates"

    # --- sub-case 2: normal forwarding (negative) ---------------------------
    subcase "srv6/2: normal forwarding (no flow label)"
    b_unm=$(counter_val "$n2log" Unmatched)
    run_ping_ok "srv6/2 ping (no -F) still reaches n9" nsrun n1 ping 5f00:0:0:89::9 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Unmatched "$b_unm" "srv6/2 n2 saw unmatched (normal-forwarded) traffic"

    # --- sub-case 3: runtime add fl:20 --------------------------------------
    subcase "srv6/3: runtime add flow (fl:20) via xdppref-ctl"
    run_cmd_ok "srv6/3 add prf fl:20 on n2" nsrun n2 "$XDPCTL" add -m prf -i eth21:fl:20 \
        -e veth0:5f00:0:0:8:f:1021:: -e veth2:5f00:0:0:8:f:2022::
    run_cmd_ok "srv6/3 add pef for fl:20 on n8" nsrun n8 "$XDPCTL" add -m pef \
        -i eth84:rsid:f:10210 -i eth87:rsid:f:20220 -e veth0:::
    b_rx=$(counter_val "$n2log" Received)
    b_drop=$(counter_val "$n8log" Dropped)
    run_ping_ok "srv6/3 ping -F 20" nsrun n1 ping 5f00:0:0:89::9 -F 20 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Received "$b_rx"  "srv6/3 n2 replicated fl:20 traffic"
    assert_counter_grew "$n8log" Dropped  "$b_drop" "srv6/3 n8 eliminated fl:20 duplicates"

    # --- sub-case 4: runtime del fl:20 --------------------------------------
    subcase "srv6/4: runtime delete flow (fl:20)"
    run_cmd_ok "srv6/4 del prf fl:20 on n2" nsrun n2 "$XDPCTL" del -m prf -i eth21:fl:20
    run_cmd_ok "srv6/4 del pef fl:20 on n8" nsrun n8 "$XDPCTL" del -m pef \
        -i eth84:rsid:f:10210 -i eth87:rsid:f:20220
    # Ping with a never-configured label (99); fl:20 is gone so this must be
    # normal-forwarded. A fresh label avoids the IPv6 flow-label manager EPERM
    # that occurs when re-creating a recently-used label (e.g. 20).
    b_unm=$(counter_val "$n2log" Unmatched)
    run_ping_ok "srv6/4 ping unconfigured -F 99 normal-forwarded" nsrun n1 ping 5f00:0:0:89::9 -F 99 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Unmatched "$b_unm" "srv6/4 removed flow reverted to normal forwarding"

    # --- sub-case 5: pcap filter add ----------------------------------------
    subcase "srv6/5: pcap filter add (source-IP match)"
    run_cmd_ok "srv6/5 add prf filter on n2" nsrun n2 "$XDPCTL" add -m prf \
        -i 'eth21:filter:ip6 and src host 5f00:0:0:1::111' \
        -e veth0:5f00:0:0:8:f:1031:: -e veth2:5f00:0:0:8:f:2032::
    run_cmd_ok "srv6/5 add pef for filter flow on n8" nsrun n8 "$XDPCTL" add -m pef \
        -i eth84:rsid:f:10310 -i eth87:rsid:f:20320 -e veth0:::

    # --- sub-case 6: filter visible in list ---------------------------------
    subcase "srv6/6: filter shown in xdppref-ctl list"
    if nsrun n2 "$XDPCTL" list 2>&1 | grep -q "pcap_filter_map"; then
        pass "srv6/6 pcap_filter_map present in list"
    else
        fail "srv6/6 pcap_filter_map not found in list"
    fi

    # --- sub-case 7: filter match (plain ping from ::111) -------------------
    subcase "srv6/7: pcap filter match (no flow label)"
    b_rx=$(counter_val "$n2log" Received)
    b_drop=$(counter_val "$n8log" Dropped)
    run_ping_ok "srv6/7 ping from ::111 (no -F)" nsrun n1 ping 5f00:0:0:89::9 -I 5f00:0:0:1::111 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Received "$b_rx"  "srv6/7 n2 replicated filter-matched traffic"
    assert_counter_grew "$n8log" Dropped  "$b_drop" "srv6/7 n8 eliminated filter-matched duplicates"

    # --- sub-case 8: flow-label matching coexists with an installed filter --
    # (fl matching takes precedence over the filter; both yield repl+elim, so we
    # verify fl matching still works while the filter is installed. A distinct
    # label 40 is used to avoid re-creating an already-used flow label.)
    subcase "srv6/8: flow-label match coexists with filter (fl:40)"
    run_cmd_ok "srv6/8 add prf fl:40 on n2" nsrun n2 "$XDPCTL" add -m prf -i eth21:fl:40 \
        -e veth0:5f00:0:0:8:f:1041:: -e veth2:5f00:0:0:8:f:2042::
    run_cmd_ok "srv6/8 add pef fl:40 on n8" nsrun n8 "$XDPCTL" add -m pef \
        -i eth84:rsid:f:10410 -i eth87:rsid:f:20420 -e veth0:::
    b_rx=$(counter_val "$n2log" Received)
    b_drop=$(counter_val "$n8log" Dropped)
    run_ping_ok "srv6/8 ping -F 40 from ::111" nsrun n1 ping 5f00:0:0:89::9 -F 40 -I 5f00:0:0:1::111 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Received "$b_rx"  "srv6/8 fl:40 replicated with filter installed"
    assert_counter_grew "$n8log" Dropped  "$b_drop" "srv6/8 fl:40 eliminated with filter installed"
    run_cmd_ok "srv6/8 del prf fl:40 on n2" nsrun n2 "$XDPCTL" del -m prf -i eth21:fl:40
    run_cmd_ok "srv6/8 del pef fl:40 on n8" nsrun n8 "$XDPCTL" del -m pef \
        -i eth84:rsid:f:10410 -i eth87:rsid:f:20420

    # --- sub-case 9: pcap filter del ----------------------------------------
    subcase "srv6/9: pcap filter delete"
    run_cmd_ok "srv6/9 del prf filter on n2" nsrun n2 "$XDPCTL" del -m prf \
        -i 'eth21:filter:ip6 and src host 5f00:0:0:1::111'
    run_cmd_ok "srv6/9 del pef filter flow on n8" nsrun n8 "$XDPCTL" del -m pef \
        -i eth84:rsid:f:10310 -i eth87:rsid:f:20320
    b_unm=$(counter_val "$n2log" Unmatched)
    run_ping_ok "srv6/9 ping from ::111 now normal-forwarded" nsrun n1 ping 5f00:0:0:89::9 -I 5f00:0:0:1::111 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Unmatched "$b_unm" "srv6/9 filter flow reverted to normal forwarding"

    teardown_env
    CURRENT_ENV=""
}

# ============================================================================
# Environment 3: srv6_multi_prf.env  (nested replication, 3 copies)
# ============================================================================
test_srv6_multi_prf() {
    CURRENT_ENV="srv6_multi_prf"
    envhdr "srv6_multi_prf (Layer 3 PREF, nested replication)"

    preclean_ns "/tmp/xdpfrer-srv6_multi_prf.envs" "/tmp/xdpfrer-srv6_multi_prf-mntns" \
        n1 n2 n3 n4 n5 n6 n7 n8 n9

    info "Setting up environment (source srv6_multi_prf.env)"
    XDPFRER_AUTOMATED=1 . "$SCRIPT_DIR/srv6_multi_prf.env" > "$LOGDIR/${CURRENT_ENV}.setup.log" 2>&1

    local n2log n4log n8log
    start_instance "n2_prf" nsrun n2 "${STDBUF[@]}" "$XDPFRER" -m prf -i eth21:fl:10 \
                -e veth0:5f00:0:0:4:f:1011:: -e veth2:5f00:0:0:8:f:2012::; n2log="$LAST_LOG"
    start_instance "n4_prf" nsrun n4 "${STDBUF[@]}" "$XDPFRER" -m prf -i eth43:rsid:f:10110 \
                -e veth0:5f00:0:0:8:f:3013:: -e veth2:5f00:0:0:8:f:4014:: -n; n4log="$LAST_LOG"
    start_instance "n8_pef" nsrun n8 "${STDBUF[@]}" "$XDPFRER" -m pef \
                -i eth85:rsid:f:30130 -i eth86:rsid:f:40140 -i eth87:rsid:f:20120 -e veth0:::; n8log="$LAST_LOG"

    if ! wait_ready "$n2log" "Config replication" 10 \
       || ! wait_ready "$n4log" "Config replication" 10 \
       || ! wait_ready "$n8log" "Config recovery" 10; then
        fail "srv6_multi_prf: base instances failed to become ready"
        dump_log "$LOGDIR/${CURRENT_ENV}.setup.log"
        dump_log "$n2log"; dump_log "$n4log"; dump_log "$n8log"
        teardown_env; CURRENT_ENV=""
        return
    fi
    pass "n2/n4 (prf) and n8 (pef) ready"

    local b_n2 b_n4 b_drop b_unm

    # --- sub-case 1: fl:10 -> 3 copies, n8 eliminates -----------------------
    subcase "srv6_multi_prf/1: nested replication (fl:10, 3 copies)"
    b_n2=$(counter_val "$n2log" Received)
    b_n4=$(counter_val "$n4log" Received)
    b_drop=$(counter_val "$n8log" Dropped)
    run_ping_ok "srv6_multi_prf/1 ping -F 10" nsrun n1 ping 5f00:0:0:89::9 -F 10 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Received "$b_n2"  "srv6_multi_prf/1 n2 replicated"
    assert_counter_grew "$n4log" Received "$b_n4"  "srv6_multi_prf/1 n4 intermediate replicated"
    assert_counter_grew "$n8log" Dropped  "$b_drop" "srv6_multi_prf/1 n8 eliminated duplicate copies"

    # --- sub-case 2: normal forwarding (negative) ---------------------------
    subcase "srv6_multi_prf/2: normal forwarding (no flow label)"
    b_unm=$(counter_val "$n2log" Unmatched)
    run_ping_ok "srv6_multi_prf/2 ping (no -F) reaches n9" nsrun n1 ping 5f00:0:0:89::9 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Unmatched "$b_unm" "srv6_multi_prf/2 n2 saw unmatched traffic"

    # --- sub-case 3: runtime add fl:20 chain --------------------------------
    subcase "srv6_multi_prf/3: runtime add flow (fl:20)"
    run_cmd_ok "srv6_multi_prf/3 add prf fl:20 on n2" nsrun n2 "$XDPCTL" add -m prf \
        -i eth21:fl:20 -e veth0:5f00:0:0:4:f:1021::
    run_cmd_ok "srv6_multi_prf/3 add prf on n4" nsrun n4 "$XDPCTL" add -m prf \
        -i eth43:rsid:f:10210 -e veth0:5f00:0:0:8:f:3023:: -e veth2:5f00:0:0:8:f:4024:: -n
    run_cmd_ok "srv6_multi_prf/3 add pef on n8" nsrun n8 "$XDPCTL" add -m pef \
        -i eth85:rsid:f:30230 -i eth86:rsid:f:40240 -e veth0:::
    b_drop=$(counter_val "$n8log" Dropped)
    run_ping_ok "srv6_multi_prf/3 ping -F 20" nsrun n1 ping 5f00:0:0:89::9 -F 20 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n8log" Dropped "$b_drop" "srv6_multi_prf/3 n8 eliminated fl:20 duplicates"

    teardown_env
    CURRENT_ENV=""
}

# ============================================================================
# Environment 4: srv6_multi_pef.env  (multi-path elimination, 7 nodes)
# ============================================================================
test_srv6_multi_pef() {
    CURRENT_ENV="srv6_multi_pef"
    envhdr "srv6_multi_pef (Layer 3 PREF, multi-path elimination)"

    preclean_ns "/tmp/xdpfrer-srv6_multi_pef.envs" "/tmp/xdpfrer-srv6_multi_pef-mntns" \
        n1 n2 n3 n4 n5 n6 n7

    info "Setting up environment (source srv6_multi_pef.env)"
    XDPFRER_AUTOMATED=1 . "$SCRIPT_DIR/srv6_multi_pef.env" > "$LOGDIR/${CURRENT_ENV}.setup.log" 2>&1

    local n2log n5log n6log
    start_instance "n2_prf" nsrun n2 "${STDBUF[@]}" "$XDPFRER" -m prf -i eth21:fl:10 \
                -e veth0:5f00:0:0:5:f:1011:: -e veth2:5f00:0:0:5:f:2012:: -e veth4:5f00:0:0:6:f:3013::; n2log="$LAST_LOG"
    start_instance "n5_pef" nsrun n5 "${STDBUF[@]}" "$XDPFRER" -m pef \
                -i eth53:rsid:f:10110 -i eth54:rsid:f:20120 -e veth0:5f00:0:0:6:f:1014:: -n; n5log="$LAST_LOG"
    start_instance "n6_pef" nsrun n6 "${STDBUF[@]}" "$XDPFRER" -m pef \
                -i eth65:rsid:f:10140 -i eth62:rsid:f:30130 -e veth0:::; n6log="$LAST_LOG"

    if ! wait_ready "$n2log" "Config replication" 10 \
       || ! wait_ready "$n5log" "Config recovery" 10 \
       || ! wait_ready "$n6log" "Config recovery" 10; then
        fail "srv6_multi_pef: base instances failed to become ready"
        dump_log "$LOGDIR/${CURRENT_ENV}.setup.log"
        dump_log "$n2log"; dump_log "$n5log"; dump_log "$n6log"
        teardown_env; CURRENT_ENV=""
        return
    fi
    pass "n2 (prf), n5 + n6 (pef) ready"

    local b_n2 b_n5 b_n6 b_unm b_n6unm

    # --- sub-case 1: fl:10 -> 3 paths, n5 + n6 eliminate --------------------
    subcase "srv6_multi_pef/1: multi-path elimination (fl:10)"
    b_n2=$(counter_val "$n2log" Received)
    b_n5=$(counter_val "$n5log" Dropped)
    b_n6=$(counter_val "$n6log" Dropped)
    run_ping_ok "srv6_multi_pef/1 ping -F 10" nsrun n1 ping 5f00:0:0:67::7 -F 10 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Received "$b_n2" "srv6_multi_pef/1 n2 replicated to 3 paths"
    assert_counter_grew "$n5log" Dropped  "$b_n5" "srv6_multi_pef/1 n5 intermediate elimination"
    assert_counter_grew "$n6log" Dropped  "$b_n6" "srv6_multi_pef/1 n6 final elimination"

    # --- sub-case 2: normal forwarding (negative) ---------------------------
    subcase "srv6_multi_pef/2: normal forwarding (no flow label)"
    b_unm=$(counter_val "$n2log" Unmatched)
    run_ping_ok "srv6_multi_pef/2 ping (no -F) reaches n7" nsrun n1 ping 5f00:0:0:67::7 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n2log" Unmatched "$b_unm" "srv6_multi_pef/2 n2 saw unmatched traffic"

    # --- sub-case 3: runtime add fl:20 (paths 1+2, eliminated fully at n5) ---
    subcase "srv6_multi_pef/3: runtime add flow (fl:20)"
    run_cmd_ok "srv6_multi_pef/3 add prf fl:20 on n2" nsrun n2 "$XDPCTL" add -m prf \
        -i eth21:fl:20 -e veth0:5f00:0:0:5:f:1021:: -e veth2:5f00:0:0:5:f:2022::
    run_cmd_ok "srv6_multi_pef/3 add pef fl:20 on n5" nsrun n5 "$XDPCTL" add -m pef \
        -i eth53:rsid:f:10210 -i eth54:rsid:f:20220 -e veth0:::
    b_n5=$(counter_val "$n5log" Dropped)
    b_n6unm=$(counter_val "$n6log" Unmatched)
    run_ping_ok "srv6_multi_pef/3 ping -F 20" nsrun n1 ping 5f00:0:0:67::7 -F 20 -c 5 -W 1 -w 8 -q
    settle
    assert_counter_grew "$n5log" Dropped   "$b_n5"    "srv6_multi_pef/3 n5 eliminated fl:20 duplicates"
    assert_counter_grew "$n6log" Unmatched "$b_n6unm" "srv6_multi_pef/3 n6 saw fl:20 as unmatched (consumed at n5)"

    teardown_env
    CURRENT_ENV=""
}

# ============================================================================
# Main
# ============================================================================

# Run the standalone pcap-filter suite as a child process and fold its PASS/FAIL/
# WARN tallies into the aggregate counters. Kept as a subprocess to avoid
# function/variable collisions (it defines its own counter_val/LOGDIR/etc).
run_pcap_subprocess() {
    CURRENT_ENV="pcap"
    local out rc
    out=$("$SCRIPT_DIR/pcap_filter_test.sh"); rc=$?
    echo "$out"
    # Fold child tallies into ours from its summary line "PASS: N   FAIL: M   WARN: K".
    local line p f w
    line=$(echo "$out" | grep -oE 'PASS: [0-9]+ +FAIL: [0-9]+ +WARN: [0-9]+' | tail -1)
    if [ -n "$line" ]; then
        p=$(echo "$line" | grep -oE 'PASS: [0-9]+' | grep -oE '[0-9]+')
        f=$(echo "$line" | grep -oE 'FAIL: [0-9]+' | grep -oE '[0-9]+')
        w=$(echo "$line" | grep -oE 'WARN: [0-9]+' | grep -oE '[0-9]+')
        PASS_COUNT=$((PASS_COUNT + p))
        WARN_COUNT=$((WARN_COUNT + w))
        if [ "$f" -gt 0 ]; then
            FAIL_COUNT=$((FAIL_COUNT + f))
            FAILED_TESTS+=("[pcap] $f assertion(s) failed — see pcap output above")
        fi
    elif [ "$rc" -ne 0 ]; then
        fail "pcap suite exited non-zero ($rc) with no summary"
    fi
    CURRENT_ENV=""
}

usage() {
    cat <<EOF
Usage: sudo $0 [ENV ...]

Environments: frer srv6 srv6_multi_prf srv6_multi_pef pcap
With no arguments, all suites are run sequentially.
EOF
}

main() {
    # Handle -h/--help
    case "${1:-}" in
        -h|--help) usage; exit 0 ;;
    esac

    # Must be root
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error:${NC} this self-test must be run as root (sudo $0)"
        exit 2
    fi

    # Local binaries must exist
    local missing=0
    if [ ! -x "$XDPFRER" ]; then
        echo -e "${RED}Error:${NC} $XDPFRER not found or not executable"
        missing=1
    fi
    if [ ! -x "$XDPCTL" ]; then
        echo -e "${RED}Error:${NC} $XDPCTL not found or not executable"
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        echo "Build them first:  make -C \"$SRC_DIR\""
        exit 2
    fi

    # Select environments
    local -a envs
    if [ "$#" -eq 0 ]; then
        envs=(frer srv6 srv6_multi_prf srv6_multi_pef pcap)
    else
        envs=("$@")
    fi

    mkdir -p "$LOGDIR"
    echo -e "${BOLD}xdpfrer self-test${NC}"
    echo "  binaries : $XDPFRER"
    echo "             $XDPCTL"
    echo "  logs     : $LOGDIR"
    echo "  running  : ${envs[*]}"

    local e fails_before
    for e in "${envs[@]}"; do
        fails_before=$FAIL_COUNT
        case "$e" in
            frer)            test_frer ;;
            srv6)            test_srv6 ;;
            srv6_multi_prf)  test_srv6_multi_prf ;;
            srv6_multi_pef)  test_srv6_multi_pef ;;
            pcap)            run_pcap_subprocess ;;
            *)
                echo -e "${RED}Unknown environment: $e${NC}"
                usage
                exit 2
                ;;
        esac
        if [ "$FAIL_COUNT" -gt "$fails_before" ]; then
            ENV_SUMMARY+=("$e: FAIL")
        else
            ENV_SUMMARY+=("$e: ok")
        fi
    done

    # Summary
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD} Summary${NC}"
    echo -e "${BOLD}============================================================${NC}"
    local line
    for line in "${ENV_SUMMARY[@]}"; do
        if echo "$line" | grep -q "FAIL"; then
            echo -e "  ${RED}$line${NC}"
        else
            echo -e "  ${GREEN}$line${NC}"
        fi
    done
    echo "  ------------------------------------------------------------"
    echo -e "  ${GREEN}PASS: $PASS_COUNT${NC}   ${RED}FAIL: $FAIL_COUNT${NC}   ${YELLOW}WARN: $WARN_COUNT${NC}"

    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo ""
        echo -e "  ${RED}Failed assertions:${NC}"
        for line in "${FAILED_TESTS[@]}"; do
            echo "    - $line"
        done
        echo ""
        echo "  Logs preserved in: $LOGDIR"
        exit 1
    fi

    # Success: clean up logs
    rm -rf "$LOGDIR"
    echo ""
    echo -e "  ${GREEN}All environments passed.${NC}"
    exit 0
}

main "$@"
