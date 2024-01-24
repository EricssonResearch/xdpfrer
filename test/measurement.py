#!/usr/bin/python3

from subprocess import Popen, run, run, PIPE, DEVNULL
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import concurrent.futures
import platform
import shlex
import time
import glob
import sys
import os

OUT_NONE = 1
OUT_PIPE = 2
OUT_STDOUT = 3

PY_VER_MAJOR = platform.sys.version_info.major
PY_VER_MINOR = platform.sys.version_info.minor

#platform.sys.version_info.major
def exec_bg(cmd, out=OUT_NONE):
    """
    Execute the @cmd in the background, with optional
    stdout/stderr output saved to stdouts map
    Nonblockig, @cmd running in the bacground

    @out tells what would we like to do the output. Valid values:
    'OUT_NONE' - no output at all (devnull)
    'OUT_STDOUT' - output straight into the stdout
    'OUT_PIPE' - output saved into pipe, use Popen.communicate() on return value

    @return Popen object with the running command
    """
    cmdout = -1
    if out == OUT_NONE:
        cmdout = DEVNULL
    elif out == OUT_STDOUT:
        cmdout = None
    elif out == OUT_PIPE:
        cmdout = PIPE
    else:
        print("exec_bg: invalid output specified.")
        print("Use: none, pipe or stdout")
    kwargs = {
        "stdout" : cmdout,
        "stderr" : cmdout,
        "text" : True
    }
    if PY_VER_MAJOR >= 3 and PY_VER_MINOR >= 10:
        kwargs["pipesize"] = 10000000
    p = Popen(shlex.split(cmd), **kwargs)
    return p

def exec_fg(cmd, silent=True, timeout=None):
    """
    Execute the @cmd in foreground, with optional
    stdout/stderr output saved to stdouts map
    Blocking until the command returns
    @return CompletedProcess object of the finished command
    """
    os.environ['LC_ALL']='C'
    kwargs = {
        "text" : True,
        "capture_output" : silent,
        "timeout" : timeout
    }
    if PY_VER_MAJOR >= 3 and PY_VER_MINOR >= 10:
        kwargs["pipesize"] = 10000000
    r = run(shlex.split(cmd), **kwargs)
    return r

######################################################################


R2EXE = "/usr/local/bin/r2dtwo"
XDPEXE = "/usr/local/bin/xdpfrer"
INTERFACESWITCHER = "/usr/local/bin/interface_switcher"

NSX= "ip netns exec frerenv"
TX = "ip netns exec talker"
LX = "ip netns exec listener"

cpu = {
    "ping": 6,
    "r2br0": 7,
    "r2br1": 8,
    "iperf_server": 9,
    "iperf_client": 10,
    "napi1": 11,
    "napi2": 12,
    "napi3": 13,
    "napi4": 14,
    "interrupt_min": 15,
    "interrupt_max": 23,
}
IFNAMES = ["enp3s0", "enp4s0", "enp6s0", "enp7s0"]
SPEED = 100
THREADED = True

PKTS_ADAPT = 10000
PKTS_1MS = 10000
ERROR_TEST_TIME = 15
XDP_ERROR_TEST = True

def run_tests():
    exec_fg("killall -SIGTERM r2dtwo")
    exec_fg("killall tcpdump")
    exec_fg("killall -SIGTERM xdpfrer")

    stress = [
			# ("stress", f"taskset -c {cpu['r2br0']}-{cpu['r2br1']} chrt -r 1 hackbench -T -l 10000000 -s 1000 -g 1 -f 10"),
			("stress", f"stress-ng --taskset {cpu['r2br0']} --fault 5", f"stress-ng --taskset {cpu['r2br1']} --fault 5"),
            # ("brutal", f"taskset -c {cpu['ping']} hackbench -T -l 10000000 -s 10000 -g 5 -f 5"),
            ( "idle", "echo", "echo" ),
    ]

    exe = [
        # ("r2", f"{NSX} taskset -c {cpu['r2br0']} {R2EXE} r2br0.ini",
        #         f"{NSX} taskset -c {cpu['r2br1']} {R2EXE} r2br1.ini"),
        # ("r2_rt", f"{NSX} taskset -c {cpu['r2br0']} chrt -r 99 {R2EXE} r2br0.ini",
        #         f"{NSX} taskset -c {cpu['r2br1']} chrt -r 99 {R2EXE} r2br1.ini"),
        ("xdp", f"{NSX} {XDPEXE}")
    ]

    ping = [
        ("adaptive_unpin", f"{TX} ping 10.0.0.2 -A -s 1000 -I teth0.10 -c {PKTS_ADAPT} -q"),
        ("adaptive_rt", f"{TX} chrt 99 ping 10.0.0.2 -A -s 1000 -I teth0.10 -c {PKTS_ADAPT} -q"),
        ("adaptive_pin", f"{TX} taskset -c {cpu['ping']} chrt 99 ping 10.0.0.2 -A -s 1000 -I teth0.10 -c {PKTS_ADAPT} -q"),
        ("1ms_unpin", f"{TX} ping 10.0.0.2 -i 0.001 -s 1000 -I teth0.10 -c {PKTS_1MS} -q"),
        ("1ms_rt", f"{TX} chrt 99 ping 10.0.0.2 -i 0.001 -s 1000 -I teth0.10 -c {PKTS_1MS} -q"),
        ("1ms_pin", f"{TX} taskset -c {cpu['ping']} chrt 99 ping 10.0.0.2 -i 0.001 -s 1000 -I teth0.10 -c {PKTS_1MS} -q"),
        ("1ms_iperf_pin", f"{TX} taskset -c {cpu['ping']} chrt 99 ping 10.0.0.2 -i 0.001 -s 1000 -I teth0.10 -c {PKTS_1MS} -q"),
    ]

    for s in stress:
        for e in exe:
            for p in ping:
                pexe1 = None
                piperf_server = None
                piperf_client = None
                test = f"{s[0]}_{e[0]}_{p[0]}"
                pcap = test + ".pcap"

                if "r2" in e[0] and "iperf" in p[0]:
                    continue
                print('\n\n-------------------------')
                print("Test case: ", test)
                print("-------------------------")

                ptcpdump = exec_bg(f"{TX} tcpdump -ni teth0.10 icmp -w {pcap} -s 100 -B 10000")
                pstress1 = exec_bg(s[1])
                pstress2 = exec_bg(s[2])
                pexe = exec_bg(e[1])
                if "r2" in e[0]:
                    pexe1 = exec_bg(e[2])

                print("EXECUTE: ", p[1])
                time.sleep(4)
                if "iperf" in p[0]:
                    piperf_server = exec_bg(f"{LX} taskset -c {cpu['iperf_server']} iperf -s -u -e", out=OUT_STDOUT)
                    piperf_client = exec_bg(f"{TX} taskset -c {cpu['iperf_client']} iperf -c 10.0.0.2 -u -i1 -l 10000 -b100M -P10 -t30")
                exec_fg(p[1], silent=False)
                time.sleep(1)

                pstress1.kill()
                pstress2.kill()
                ptcpdump.terminate()
                pexe.terminate()
                if pexe1:
                    pexe1.terminate()
                if "iperf" in p[0]:
                    piperf_server.terminate()
                    piperf_client.terminate()
                time.sleep(1)

def run_error_tests():
    exec_fg("killall tcpdump")
    exec_fg("killall -SIGTERM xdpfrer")

    ping = f"{TX} chrt 99 ping 10.0.0.2 -i 0.01 -s 1000 -I teth0.10"
    xdpfrer = f"{NSX} {XDPEXE}"
    ifshutdown_xdp = [(f"{IFNAMES[0]}", f"{NSX} {INTERFACESWITCHER} $(pgrep xdpfrer) {IFNAMES[0]}"),
        (f"{IFNAMES[0]}", f"{NSX} {INTERFACESWITCHER} $(pgrep xdpfrer) {IFNAMES[0]}"),
        (f"all_route", f"{NSX} {INTERFACESWITCHER} $(pgrep xdpfrer) {IFNAMES[0]}; {NSX} {INTERFACESWITCHER} $(pgrep xdpfrer) {IFNAMES[2]}"),
        (f"all_route", f"{NSX} {INTERFACESWITCHER} $(pgrep xdpfrer) {IFNAMES[2]};"),
        (f"all_route", f"{NSX} {INTERFACESWITCHER} $(pgrep xdpfrer) {IFNAMES[0]};")]

    ifshutdown_r2 = [(f"{IFNAMES[0]}", f"ip link set dev {IFNAMES[0]} down"),
        (f"{IFNAMES[0]}", f"ip link set dev {IFNAMES[0]} up"),
        (f"all_route", f"ip link set dev {IFNAMES[0]} down; ip link set dev {IFNAMES[2]} down"),
        (f"all_route", f"ip link set dev {IFNAMES[2]} up;"),
        (f"all_route", f"ip link set dev {IFNAMES[0]} up")]

    # Change speed on one route.
    if XDP_ERROR_TEST:
        print("Initialize XDPFRER...")
        pexe = exec_bg(xdpfrer)
        print(f"Change speed of {IFNAMES[2]} and {IFNAMES[3]} to {SPEED}Mb/s...")
        exec_fg(f"ethtool -s {IFNAMES[2]} autoneg on speed {SPEED} duplex full", silent=False)
        exec_fg(f"ethtool -s {IFNAMES[3]} autoneg on speed {SPEED} duplex full", silent=False)
    else:
        print("Initialize R2DTWO...")
        print(f"Create delay on {IFNAMES[2]} and {IFNAMES[3]}...")
        r2exe1 = exec_bg(f"{R2EXE} r2br0.ini")
        r2exe2 = exec_bg(f"{R2EXE} r2br1.ini")
        exec_fg(f"tc qdisc add dev {IFNAMES[2]} root netem delay 5ms", silent=False)
        exec_fg(f"tc qdisc add dev {IFNAMES[3]} root netem delay 5ms", silent=False)

    time.sleep(5)

    # First test.
    test = f"error_{'xdp' if XDP_ERROR_TEST else 'r2'}_{ifshutdown_xdp[0][0]}"
    pcap = test + ".pcap"
    print('\n\n-------------------------')
    print("Test case: ", test)
    print("-------------------------")
    ptcpdump = exec_bg(f"{TX} tcpdump -ni teth0.10 icmp -w {pcap} -s 100 -B 10000")
    time.sleep(3) # wait for the reset of the history window which is 2 seconds
    pping = exec_bg(ping, out=OUT_STDOUT)
    time.sleep(ERROR_TEST_TIME / 3.0)
    os.system(ifshutdown_xdp[0][1]) if XDP_ERROR_TEST else os.system(ifshutdown_r2[0][1])
    time.sleep(ERROR_TEST_TIME / 3.0)
    os.system(ifshutdown_xdp[1][1]) if XDP_ERROR_TEST else os.system(ifshutdown_r2[1][1])
    time.sleep(ERROR_TEST_TIME / 3.0)
    ptcpdump.terminate()
    pping.send_signal(2)
    time.sleep(1)

    # Second Test.
    test = f"error_{'xdp' if XDP_ERROR_TEST else 'r2'}_{ifshutdown_xdp[2][0]}"
    pcap = test + ".pcap"
    print('\n\n-------------------------')
    print("Test case: ", test)
    print("-------------------------")
    ptcpdump = exec_bg(f"{TX} tcpdump -ni teth0.10 icmp -w {pcap} -s 100 -B 10000")
    time.sleep(3) # wait for the reset of the history window which is 2 seconds
    pping = exec_bg(ping, out=OUT_STDOUT)
    time.sleep(ERROR_TEST_TIME / 4.0)
    os.system(ifshutdown_xdp[2][1]) if XDP_ERROR_TEST else os.system(ifshutdown_r2[2][1])
    time.sleep(ERROR_TEST_TIME / 4.0)
    os.system(ifshutdown_xdp[3][1]) if XDP_ERROR_TEST else os.system(ifshutdown_r2[3][1])
    time.sleep(ERROR_TEST_TIME / 4.0)
    os.system(ifshutdown_xdp[4][1]) if XDP_ERROR_TEST else os.system(ifshutdown_r2[4][1])
    time.sleep(ERROR_TEST_TIME / 4.0)
    ptcpdump.terminate()
    pping.send_signal(2)
    time.sleep(1)

    # Reset speed on all routes.
    if XDP_ERROR_TEST:
        pexe.terminate()
        exec_fg(f"ethtool -s {IFNAMES[2]} autoneg on speed 2500 duplex full", silent=False)
        exec_fg(f"ethtool -s {IFNAMES[3]} autoneg on speed 2500 duplex full", silent=False)
    else:
        r2exe1.terminate()
        r2exe2.terminate()
        exec_fg(f"tc qdisc del dev {IFNAMES[2]} root netem delay 5ms", silent=False)
        exec_fg(f"tc qdisc del dev {IFNAMES[3]} root netem delay 5ms", silent=False)

def test_data_worker(fn):
    print(fn)
    os.system(f"echo {fn.rstrip('.pcap')} > {fn}.txt")
    rtts_from_pcap_cmd = f'tshark -r {fn} -Y "icmp.type==0" -l -O icmp -T fields -e icmp.resptime | sort -n -r >> {fn}.txt'
    os.system(rtts_from_pcap_cmd) # we already have a pipe in cmd unfortinately...
    os.sync()

def error_test_data_worker(fn):
    print(fn)
    os.system(f"echo {fn.rstrip('.pcap')} > {fn}.txt")
    rtts_from_pcap_cmd = f'tshark -r {fn} -Y "icmp.type==0" -l -O icmp -T fields -e icmp.seq -e icmp.resptime -e icmp.data_time -e icmp.data_time_relative >> {fn}.txt'
    os.system(rtts_from_pcap_cmd)
    os.sync()

def get_data():
    fns = glob.glob("*.pcap")
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(fns))
    os.system("clear")
    for fn in fns:
        if "error" in fn:
            pool.submit(error_test_data_worker, fn)
        else:
            pool.submit(test_data_worker, fn)
    pool.shutdown(wait=True)
    print("done")

def formatter_min(val, tick):
    # print(f"val: {val}, tick: {tick}")
    if val < 0.19:
        return ""
    return str(f"{val:.1f}")

def formatter_maj(val, tick):
    # print(f"val: {val}, tick: {tick}")
    if val < 0.09:
        return ""
    return str(f"{val:.1f}")

def formatter_min_xdp(val, tick):
    # print(f"val: {val}, tick: {tick}")
    if val < 0.019 or (val > 0.05 and val < 0.15):
        return ""
    return str(f"{val:.2f}")

def formatter_maj_xdp(val, tick):
    # print(f"val: {val}, tick: {tick}")
    if val < 0.009:
        return ""
    return str(f"{val:.2f}")

def gen_plots():
    os.system("clear")
    DPI = 96

    print("Initialize plots...")
    sns.set_theme(style="whitegrid", palette="pastel")
    sns.set_context("notebook")
    df = pd.concat(map(pd.read_csv, glob.glob('*_pin.pcap.txt')), axis=1)
    df.drop(list(range(0, 10)), inplace=True)
    df.sort_index(axis=1, inplace=True, ascending=True)

    print("Start to create boxplot...")
    plt.figure(figsize=(2000/DPI, 800/DPI), dpi=DPI)
    sns.boxplot(data=df, orient="h", fliersize=2)
    plt.subplots_adjust(left=0.2, bottom=0.1)
    plt.rcParams['axes.grid'] = True
    plt.xticks(rotation = 90)
    plt.gcf().gca().xaxis.set_major_formatter(plt.FuncFormatter(lambda x, pos: '{:,.3f}'.format(x) + ' ms'))
    plt.tight_layout()
    plt.savefig("all.pdf", format="pdf")

    print("Start to create r2rt plot...")
    plt.figure(figsize=(1.2*600/DPI, 1.2*400/DPI), dpi=DPI)
    sns.ecdfplot(data=df.filter(axis=1, items=['idle_r2_1ms_pin', 'stress_r2_rt_1ms_pin','stress_r2_1ms_pin']), complementary=True, log_scale=True)
    plt.gcf().gca().xaxis.set_major_formatter(plt.FuncFormatter(formatter_maj))
    plt.gcf().gca().xaxis.set_minor_formatter(plt.FuncFormatter(formatter_min))
    plt.gcf().gca().xaxis.set_tick_params(which='minor', width=1.0, length=5, labelsize=8, labelcolor='0.25')
    ###plt.xticks(rotation = 45, minor=True)
    plt.setp(plt.gcf().gca().xaxis.get_minorticklabels(), rotation=45)
    # plt.gcf().gca().ticklabel_format(useMathText = False)
    plt.gcf().gca().xaxis.grid(True, which='minor')
    plt.legend(labels = ['uFRER (default prio) and extra CPU load', 'uFRER (realtime prio) and extra CPU load', 'uFRER only (no extra load)'])
    plt.xlabel("RTT (millisec)")
    plt.tight_layout()
    plt.savefig("r2rt.pdf", format="pdf")


    print("Start to create idlexdp plots...")
    f, (ax1, ax2) = plt.subplots(2, 1, figsize=(500/DPI, 800/DPI), dpi=DPI, sharex=True)
    ax1.xaxis.grid(True, which='minor')
    ax2.xaxis.grid(True, which='minor')
    ax1.xaxis.set_major_formatter(plt.FuncFormatter(lambda x: str(x)))
    sns.ecdfplot(data=df.filter(axis=1, items=['idle_r2_rt_1ms_pin','idle_xdp_1ms_pin']), complementary=True, ax=ax1, log_scale=True).set_title("No extra CPU load")
    ax1.legend(labels = ['XDP FRER', 'uFRER'])
    plt.xlabel("RTT (millisec)")
    plt.tight_layout()
    sns.ecdfplot(data=df.filter(axis=1, items=['stress_r2_rt_1ms_pin','stress_xdp_1ms_pin']), complementary=True, ax=ax2, log_scale=True).set_title("Loaded CPU (stress-ng)")
    plt.gcf().gca().xaxis.set_major_formatter(plt.FuncFormatter(formatter_maj_xdp))
    plt.gcf().gca().xaxis.set_minor_formatter(plt.FuncFormatter(formatter_min_xdp))
    plt.gcf().gca().xaxis.set_tick_params(which='minor', width=1.0, length=5, labelsize=8, labelcolor='0.25')
    ###plt.xticks(rotation = 45, minor=True)
    plt.setp(plt.gcf().gca().xaxis.get_minorticklabels(), rotation=45)
    ax2.legend(labels = ['XDP FRER', 'uFRER'])
    plt.savefig("idlexdp.pdf", format="pdf")


    print("Start to create loadedxdp plot...")
    plt.figure(figsize=(600/DPI, 400/DPI), dpi=DPI)
    sns.ecdfplot(data=df.filter(axis=1, items=["idle_xdp_1ms_pin", "idle_xdp_1ms_iperf_pin"]), complementary=True, log_scale=True)
    plt.gcf().gca().xaxis.set_major_formatter(plt.FuncFormatter(formatter_maj_xdp))
    plt.gcf().gca().xaxis.set_minor_formatter(plt.FuncFormatter(formatter_min_xdp))
    plt.gcf().gca().xaxis.set_tick_params(which='minor', width=1.0, length=5, labelsize=8, labelcolor='0.25')
    ###plt.xticks(rotation = 45, minor=True)
    plt.setp(plt.gcf().gca().xaxis.get_minorticklabels(), rotation=45)
    plt.gcf().gca().xaxis.grid(True, which='minor')
    plt.legend(labels = ['With UDP background traffic', 'Without background traffic'])
    plt.xlabel("RTT (millisec)")
    plt.tight_layout()
    plt.savefig("loadedxdp.pdf", format="pdf")

    print("Start to create error simulation plots...")
    files = []
    files.append((f"(a) Faster path down", f"error_{'xdp' if XDP_ERROR_TEST else 'r2'}_{IFNAMES[0]}.pcap.txt"))
    files.append((f"(b) Both paths down", f"error_{'xdp' if XDP_ERROR_TEST else 'r2'}_all_route.pcap.txt"))

    fig, axs = plt.subplots(len(files), figsize=(1.5*600/DPI, 1.5*400/DPI), dpi=DPI)
    plt.tight_layout()
    plt.subplots_adjust(hspace=0.1, left=0.13, top=0.95, bottom=0.1)
    plt.rcParams['axes.grid'] = True

    # Try to open the current file. After successful open, read all data from the file.
    # Store data in an array which contains dictionaries. One dictionary stores a single line.
    # If a line plot has break(s), it will be more than one dictionary in the data array.
    for i in range(0, len(files)):
        res_time_data = []
        seq_data = []
        res_time_points = dict()
        seq_points = dict()
        first_relative_seconds = 0
        try:
            with open(files[i][1], "r") as file:
                lines = file.readlines()[1:]
                max_res_time = max([float(item.split('\t')[1]) for item in lines])
                min_res_time = min([float(item.split('\t')[1]) for item in lines])
                max_seq = max([int(item.split('\t')[0]) for item in lines])

                for j in range(0, (len(lines) - 1)):
                    seq = int(lines[j].split('\t')[0])
                    res_time = float(lines[j].split('\t')[1])
                    time = list(filter(('').__ne__, lines[j].split('\t')[2].split(' ')))[3].split(".")[0]
                    hours = int(time.split(":")[0])
                    minutes = int(time.split(":")[1])
                    seconds = int(time.split(":")[2])
                    miliseconds = float(lines[j].split('\t')[3].rstrip('\n'))
                    relative_seconds = hours * 3600 + minutes * 60 + seconds + miliseconds

                    if j == 0:
                        first_relative_seconds = relative_seconds
                    relative_seconds -= first_relative_seconds

                    next_seq = int(lines[j+1].split('\t')[0])
                    if next_seq == (seq + 1):
                        res_time_points[relative_seconds] = res_time
                        seq_points[relative_seconds] = seq / (max_seq / (max_res_time - min_res_time)) + min_res_time
                    else:
                        res_time_data.append(res_time_points)
                        seq_data.append(seq_points)
                        res_time_points = dict()
                        seq_points = dict()
                        while next_seq != (seq + 1):
                            seq += 1
                file.close()

            res_time_data.append(res_time_points)
            seq_data.append(seq_points)
            [sns.lineplot(ax=axs[i], data=d, color="b", linewidth=1, label="RTT") if i == 0 else sns.lineplot(ax=axs[i], data=d, color="b", linewidth=1) for d in res_time_data]
            [sns.lineplot(ax=axs[i], data=d, color="orange", linewidth=1, label="ICMP sequence numbers") if i == 0 else sns.lineplot(ax=axs[i], data=d, color="orange", linewidth=1) for d in seq_data]

            if i == 0:
                axs[i].legend()
            axs[i].set_title(files[i][0])
            if i == 0:
                axs[i].axvline(ERROR_TEST_TIME / 3.0, ls='--', color="red")
                axs[i].axvline(2 * ERROR_TEST_TIME / 3.0, ls='--', color="red")
            else:
                axs[i].axvline(ERROR_TEST_TIME / 4.0, ls='--', color="red")
                axs[i].axvline(2 * ERROR_TEST_TIME / 4.0, ls='--', color="red")
                axs[i].axvline(3 * ERROR_TEST_TIME / 4.0, ls='--', color="red")
            axs[i].yaxis.set_major_formatter(plt.FuncFormatter(lambda y, pos: '{:,.3f}'.format(y) + ' ms'))

            if i == len(files) - 1:
                axs[i].set(xlabel="Time (s)", ylabel="Ping status")
                axs[i].xaxis.set_major_formatter(plt.FuncFormatter(lambda x, pos: '{:,.1f}'.format(x)))
            else:
                axs[i].set(xlabel="", ylabel="Ping status")
                axs[i].xaxis.set_major_formatter(plt.FuncFormatter(lambda x, pos: ''))
        except Exception as e:
            print(e)

    # plt.savefig(f"error_{'xdp' if XDP_ERROR_TEST else 'r2'}_sim.pdf", format="pdf")
    plt.savefig(f"error.pdf", format="pdf")

def pin_napi_threads():
    print("Pin napi threads to CPUs...")
    pids = exec_fg("ps aux")
    for line in str(pids.stdout).splitlines():
        pid = list(filter(('').__ne__, str(line).split(' ')))[1]
        command = str(line).split(' ')[-1]
        if "napi" in command:
            if IFNAMES[0] in command:
                exec_fg(f"taskset -cp {cpu['napi1']} {pid}", silent=False)
            elif IFNAMES[1] in command:
                exec_fg(f"taskset -cp {cpu['napi2']} {pid}", silent=False)
            elif IFNAMES[2] in command:
                exec_fg(f"taskset -cp {cpu['napi3']} {pid}", silent=False)
            elif IFNAMES[3] in command:
                exec_fg(f"taskset -cp {cpu['napi4']} {pid}", silent=False)

def change_interrupts():
    number_of_interrupts = len(os.popen("cat /proc/interrupts | grep enp.s0-").read().splitlines())
    if number_of_interrupts != 0:
        # Set 1 combined interrupt to every interface.
        for ifname in IFNAMES:
            command = f"ethtool -L {ifname} combined 1"
            print("EXECUTE: ", command)
            exec_fg(command, silent=False)

        # Disable irqbalance.
        print("EXECUTE:  systemctl stop irqbalance")
        exec_fg("systemctl stop irqbalance", silent=False)

        # Set RX and TX interrupts to specific CPUs.
        irqs = []
        irq_cpus = [x for x in range(cpu['interrupt_min'], cpu['interrupt_max'] + 1)]
        interrupts = os.popen("cat /proc/interrupts | grep enp.s0-").read()
        for item in str(interrupts).splitlines():
            irqs.append(int(list(filter(('').__ne__, item.split(' ')))[0].rstrip(":")))
        
        for i in range(0, len(irqs)):
            command = f"echo {irq_cpus[i]} > /proc/irq/{irqs[i]}/smp_affinity_list"
            print("EXECUTE: ", command)
            os.system(command)

def main():
    global IFNAMES
    global THREADED
    global XDPEXE
    global cpu

    os.system('clear')
    if len(sys.argv) < 2:
        print("args: data, plot, test [softirq|restricted] or error")
        return

    if "softirq" in sys.argv:
        THREADED = False
    if "restricted" in sys.argv or os.cpu_count() < cpu['interrupt_max']:
        # Running on a laptop or not enough CPU core
        cpu = {
            "ping": 1,
            "r2br0": 2,
            "r2br1": 3,
            "iperf_server": 4,
            "iperf_client": 5,
            "napi1": 6,
            "napi2": 6,
            "napi3": 6,
            "napi4": 6,
            "interrupt_min": 7,
            "interrupt_max": 7,
        }

    if "data" in sys.argv or "plot" in sys.argv:
        THREADED = False

    if THREADED == True:
        for item in IFNAMES:
            exec_fg(f'sh -c "echo 1 > /sys/class/net/{item}/threaded"', silent=False)
        pin_napi_threads()

    change_interrupts()

    try:
        if "test" in sys.argv[1]:
            run_tests()
        elif "error" in sys.argv[1]:
            run_error_tests()
        elif "data" in sys.argv[1]:
            get_data()
        elif "plot" in sys.argv[1]:
            gen_plots()
        else:
            print("args: data, plot, test or error")
    except KeyboardInterrupt:
        print("Interrupted, cleanup...")
        exec_fg("killall r2dtwo")
        exec_fg("killall xdpfrer")
        exec_fg("killall stress-ng")
        exec_fg("killall taskset")
        exec_fg("killall ping")
        exec_fg("killall tcpdump")
        exec_fg("killall -9 iperf")
        exec_fg(f"ethtool -s {IFNAMES[2]} autoneg on speed 2500 duplex full", silent=False)
        exec_fg(f"ethtool -s {IFNAMES[3]} autoneg on speed 2500 duplex full", silent=False)
        if not XDP_ERROR_TEST:
            exec_fg(f"tc qdisc del dev {IFNAMES[2]} root netem delay 5ms", silent=False)
            exec_fg(f"tc qdisc del dev {IFNAMES[3]} root netem delay 5ms", silent=False)

main()
