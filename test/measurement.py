#!/usr/bin/python3

from subprocess import Popen, run, run, PIPE, DEVNULL
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import concurrent.futures
import platform
import numpy as np
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
DPI = 96

def run_tests():
    exec_fg("killall -SIGTERM r2dtwo")
    exec_fg("killall tcpdump")
    exec_fg("killall -SIGTERM xdpfrer")

    stress = [
		("stress", f"stress-ng --taskset {cpu['r2br0']} --fault 5", f"stress-ng --taskset {cpu['r2br1']} --fault 5"),
        ( "idle", "echo", "echo" ),
    ]

    exe = {
        # "r2_rt": [f"{NSX} taskset -c {cpu['r2br0']} chrt -r 99 {R2EXE} r2br0.ini",
        #           f"{NSX} taskset -c {cpu['r2br1']} chrt -r 99 {R2EXE} r2br1.ini"],
        # "r2": [f"{NSX} taskset -c {cpu['r2br0']} {R2EXE} r2br0.ini",
        #        f"{NSX} taskset -c {cpu['r2br1']} {R2EXE} r2br1.ini"],
        "xdp": [f"{NSX} {XDPEXE} -m repl -i aeth0:10 -e enp3s0:55 -e enp6s0:56",
                f"{NSX} {XDPEXE} -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20",
                f"{NSX} {XDPEXE} -m repl -i beth0:20 -e enp4s0:66 -e enp7s0:67",
                f"{NSX} {XDPEXE} -m elim -i enp3s0:66 -i enp6s0:67 -e aeth0:10"]
    }

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
        for ekey, evalue in exe.items():
            for p in ping:
                pexes = []
                piperf_server = None
                piperf_client = None
                test = f"{s[0]}_{ekey}_{p[0]}"
                pcap = test + ".pcap"

                if "r2" in ekey and "iperf" in p[0]:
                    continue
                print('\n\n-------------------------')
                print("Test case: ", test)
                print("-------------------------")

                ptcpdump = exec_bg(f"{TX} tcpdump -ni teth0.10 icmp -w {pcap} -s 100 -B 10000")
                pstress1 = exec_bg(s[1])
                pstress2 = exec_bg(s[2])
                for instance in evalue:
                    pexes.append(exec_bg(instance))

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
                for pexe in pexes:
                    pexe.terminate()
                if "iperf" in p[0]:
                    piperf_server.terminate()
                    piperf_client.terminate()
                time.sleep(1)

def run_error_tests():
    exec_fg("killall tcpdump")
    exec_fg("killall -SIGTERM xdpfrer")

    ping = f"{TX} chrt 99 ping 10.0.0.2 -i 0.01 -s 1000 -I teth0.10"
    xdpfrer = [f"{NSX} {XDPEXE} -m repl -i aeth0:10 -e enp3s0:55 -e enp6s0:56",
               f"{NSX} {XDPEXE} -m elim -i enp4s0:55 -i enp7s0:56 -e beth0:20",
               f"{NSX} {XDPEXE} -m repl -i beth0:20 -e enp4s0:66 -e enp7s0:67",
               f"{NSX} {XDPEXE} -m elim -i enp3s0:66 -i enp6s0:67 -e aeth0:10"]

    ifshutdown = [(f"{IFNAMES[0]}", f"{NSX} ip link set dev {IFNAMES[0]} down"),
        (f"{IFNAMES[0]}", f"{NSX}ip link set dev {IFNAMES[0]} up"),
        (f"all_route", f"{NSX} ip link set dev {IFNAMES[0]} down; {NSX} ip link set dev {IFNAMES[2]} down"),
        (f"all_route", f"{NSX} ip link set dev {IFNAMES[2]} up;"),
        (f"all_route", f"{NSX} ip link set dev {IFNAMES[0]} up")]

    # Change speed on one route.
    if XDP_ERROR_TEST:
        print("Initialize XDPFRER...")
        pexes = []
        for instance in xdpfrer:
            pexes.append(exec_bg(instance))
        print(f"Change speed of {IFNAMES[2]} and {IFNAMES[3]} to {SPEED}Mb/s...")
        exec_fg(f"{NSX} ethtool -s {IFNAMES[2]} autoneg on speed {SPEED} duplex full", silent=False)
        exec_fg(f"{NSX} ethtool -s {IFNAMES[3]} autoneg on speed {SPEED} duplex full", silent=False)
    else:
        print("Initialize R2DTWO...")
        print(f"Create delay on {IFNAMES[2]} and {IFNAMES[3]}...")
        r2exe1 = exec_bg(f"{R2EXE} r2br0.ini")
        r2exe2 = exec_bg(f"{R2EXE} r2br1.ini")
        exec_fg(f"{NSX} tc qdisc add dev {IFNAMES[2]} root netem delay 5ms", silent=False)
        exec_fg(f"{NSX} tc qdisc add dev {IFNAMES[3]} root netem delay 5ms", silent=False)

    time.sleep(5)

    # First test.
    test = f"error_{'xdp' if XDP_ERROR_TEST else 'r2'}_{ifshutdown[0][0]}"
    pcap = test + ".pcap"
    print('\n\n-------------------------')
    print("Test case: ", test)
    print("-------------------------")
    ptcpdump = exec_bg(f"{TX} tcpdump -ni teth0.10 icmp -w {pcap} -s 100 -B 10000")
    time.sleep(3) # wait for the reset of the history window which is 2 seconds
    pping = exec_bg(ping, out=OUT_STDOUT)
    time.sleep(ERROR_TEST_TIME / 3.0)
    os.system(ifshutdown[0][1])
    time.sleep(ERROR_TEST_TIME / 3.0)
    os.system(ifshutdown[1][1])
    time.sleep(ERROR_TEST_TIME / 3.0)
    ptcpdump.terminate()
    pping.send_signal(2)
    time.sleep(1)

    # Second Test.
    test = f"error_{'xdp' if XDP_ERROR_TEST else 'r2'}_{ifshutdown[2][0]}"
    pcap = test + ".pcap"
    print('\n\n-------------------------')
    print("Test case: ", test)
    print("-------------------------")
    ptcpdump = exec_bg(f"{TX} tcpdump -ni teth0.10 icmp -w {pcap} -s 100 -B 10000")
    time.sleep(3) # wait for the reset of the history window which is 2 seconds
    pping = exec_bg(ping, out=OUT_STDOUT)
    time.sleep(ERROR_TEST_TIME / 4.0)
    os.system(ifshutdown[2][1])
    time.sleep(ERROR_TEST_TIME / 4.0)
    os.system(ifshutdown[3][1])
    time.sleep(ERROR_TEST_TIME / 4.0)
    os.system(ifshutdown[4][1])
    time.sleep(ERROR_TEST_TIME / 4.0)
    ptcpdump.terminate()
    pping.send_signal(2)
    time.sleep(1)

    # Reset speed on all routes.
    if XDP_ERROR_TEST:
        for exe in pexes:
            exe.terminate()
        exec_fg(f"{NSX} ethtool -s {IFNAMES[2]} autoneg on speed 2500 duplex full", silent=False)
        exec_fg(f"{NSX} ethtool -s {IFNAMES[3]} autoneg on speed 2500 duplex full", silent=False)
    else:
        r2exe1.terminate()
        r2exe2.terminate()
        exec_fg(f"{NSX} tc qdisc del dev {IFNAMES[2]} root netem delay 5ms", silent=False)
        exec_fg(f"{NSX} tc qdisc del dev {IFNAMES[3]} root netem delay 5ms", silent=False)

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
    sns.set_theme(style="whitegrid", palette="pastel")
    sns.set_context("notebook")
    all_files = glob.glob('*_pin.pcap.txt')
    if all_files == []:
        print("There are no files to generate plots!")
        return
    df = pd.concat(map(pd.read_csv, all_files), axis=1)
    df.drop(list(range(0, 10)), inplace=True)
    df.sort_index(axis=1, inplace=True, ascending=True)

    print("Start to create boxplot... ", end="")
    plt.figure(figsize=(2000/DPI, 800/DPI), dpi=DPI)
    sns.boxplot(data=df, orient="h", fliersize=2)
    plt.subplots_adjust(left=0.2, bottom=0.1)
    plt.rcParams['axes.grid'] = True
    plt.xticks(rotation = 90)
    plt.gcf().gca().xaxis.set_major_formatter(plt.FuncFormatter(lambda x, pos: '{:,.3f}'.format(x) + ' ms'))
    plt.tight_layout()
    plt.savefig("all.pdf", format="pdf")
    print("[✓]")

    print("Start to create r2rt plot... ", end="")
    neccessary_files = ['idle_r2_1ms_pin.pcap.txt', 'stress_r2_rt_1ms_pin.pcap.txt','stress_r2_1ms_pin.pcap.txt']
    if not all([os.path.isfile(file) for file in neccessary_files]):
        print("[x]")
    else:
        plt.figure(figsize=(1.2*600/DPI, 1.2*400/DPI), dpi=DPI)
        sns.ecdfplot(data=df.filter(axis=1, items=[file.rstrip(".pcap.txt") for file in neccessary_files]), complementary=True, log_scale=True)
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
        print("[✓]")


    print("Start to create idlexdp plots... ", end="")
    neccessary_files = ['idle_r2_rt_1ms_pin.pcap.txt','idle_xdp_1ms_pin.pcap.txt', 'stress_r2_rt_1ms_pin.pcap.txt','stress_xdp_1ms_pin.pcap.txt']
    if not all([os.path.isfile(file) for file in neccessary_files]):
        print("[x]")
    else:
        f, (ax1, ax2) = plt.subplots(2, 1, figsize=(500/DPI, 800/DPI), dpi=DPI, sharex=True)
        ax1.xaxis.grid(True, which='minor')
        ax2.xaxis.grid(True, which='minor')
        ax1.xaxis.set_major_formatter(plt.FuncFormatter(lambda x: str(x)))
        sns.ecdfplot(data=df.filter(axis=1, items=[file.rstrip(".pcap.txt") for file in neccessary_files[:2]]), complementary=True, ax=ax1, log_scale=True).set_title("No extra CPU load")
        ax1.legend(labels = ['XDP FRER', 'uFRER'])
        plt.xlabel("RTT (millisec)")
        plt.tight_layout()
        sns.ecdfplot(data=df.filter(axis=1, items=[file.rstrip(".pcap.txt") for file in neccessary_files[2:]]), complementary=True, ax=ax2, log_scale=True).set_title("Loaded CPU (stress-ng)")
        plt.gcf().gca().xaxis.set_major_formatter(plt.FuncFormatter(formatter_maj_xdp))
        plt.gcf().gca().xaxis.set_minor_formatter(plt.FuncFormatter(formatter_min_xdp))
        plt.gcf().gca().xaxis.set_tick_params(which='minor', width=1.0, length=5, labelsize=8, labelcolor='0.25')
        ###plt.xticks(rotation = 45, minor=True)
        plt.setp(plt.gcf().gca().xaxis.get_minorticklabels(), rotation=45)
        ax2.legend(labels = ['XDP FRER', 'uFRER'])
        plt.savefig("idlexdp.pdf", format="pdf")
        print("[✓]")


    print("Start to create loadedxdp plot... ", end="")
    neccessary_files = ["idle_xdp_1ms_pin.pcap.txt", "idle_xdp_1ms_iperf_pin.pcap.txt"]
    if not all([os.path.isfile(file) for file in neccessary_files]):
        print("[x]")
    else:
        plt.figure(figsize=(600/DPI, 400/DPI), dpi=DPI)
        sns.ecdfplot(data=df.filter(axis=1, items=[file.rstrip(".pcap.txt") for file in neccessary_files]), complementary=True, log_scale=True)
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
        print("[✓]")

def gen_error_plots():
    exes = ['xdp', 'r2']
    for e in exes:
        print(f'Start to create error_{e}.pdf... ', end="")
        fig, axs = plt.subplots(2, figsize=(1.5*600/DPI, 1.5*400/DPI), dpi=DPI)
        plt.subplots_adjust(hspace=0.1, left=0.13, top=0.95, bottom=0.1)
        plt.rcParams['axes.grid'] = True
        
        files = [f'error_{e}_{IFNAMES[0]}.pcap.txt', f'error_{e}_all_route.pcap.txt']
        plot_titles = ['(a) Faster path down', '(b) Both paths down']
        for i in range(len(files)):
            try:
                df = pd.read_csv(f'{files[i]}', delimiter='\t', header=0, usecols=[0, 1, 2, 3], names=['Seq', 'Res_time', 'Time', 'Miliseconds'])
            except:
                print("[x]")
                return
            
            if df.size == 0:
                print("[x]")
                return

            df['Hours'] = df['Time'].apply(lambda time : int(time.replace('  ', ' ').split(' ')[3].split(".")[0].split(":")[0]))
            df['Minutes'] = df['Time'].apply(lambda time : int(time.replace('  ', ' ').split(' ')[3].split(".")[0].split(":")[1]))
            df['Seconds'] = df['Time'].apply(lambda time : int(time.replace('  ', ' ').split(' ')[3].split(".")[0].split(":")[2]))
            df['Nanoseconds'] = df['Time'].apply(lambda time : int(time.replace('  ', ' ').split(' ')[3].split(".")[1]))
            df['Relative_seconds'] = df['Hours'] * 3600000000000 + df['Minutes'] * 60000000000 + df['Seconds'] * 1000000000 + df['Nanoseconds']
            df['Relative_seconds'] = df['Relative_seconds'] - df['Relative_seconds'][0]
            df['Relative_seconds'] = df['Relative_seconds'] / 1000000000
            df['Seq_points'] = df['Seq'] / (df['Seq'].max() / (df['Res_time'].max() - df['Res_time'].min())) + df['Res_time'].min()
            
            # Fill missing data with np.nan
            for j in range(df['Seq'].min(), df['Seq'].max() - 1):
                if not (j in df['Seq'].unique()):
                    row = pd.DataFrame({'Seq': j, 'Res_time': float(np.nan), 'Time': np.nan, 'Miliseconds': np.nan, 'Hours': np.nan, 
                                    'Minutes': np.nan, 'Seconds': np.nan, 'Relative_seconds': np.nan, 'Seq_points': np.nan}, index=[0])
                    df = pd.concat([df, row], ignore_index = True)
                    df.reset_index()
            df.sort_values(by=['Seq'], inplace=True)
            
            # Create plots
            sns.lineplot(x=df['Relative_seconds'], y=df['Res_time'], linewidth=1, label="RTT", ax=axs[i], legend=False, hue=df['Res_time'].isna().cumsum(),
                            palette=['b'] * (sum(df['Res_time'].isna()) + 1))
            sns.lineplot(x=df['Relative_seconds'], y=df['Seq_points'], color="orange", linewidth=1, label="ICMP sequence numbers", ax=axs[i], legend=False)

            # Set red lines and labels
            if i == 0:
                axs[i].legend()
            axs[i].set_title(plot_titles[i])
            if i == 0:
                axs[i].axvline(ERROR_TEST_TIME / 3.0, ls='--', color='red')
                axs[i].axvline(2 * ERROR_TEST_TIME / 3.0, ls='--', color='red')
            else:
                axs[i].axvline(ERROR_TEST_TIME / 4.0, ls='--', color='red')
                axs[i].axvline(2 * ERROR_TEST_TIME / 4.0, ls='--', color='red')
                axs[i].axvline(3 * ERROR_TEST_TIME / 4.0, ls='--', color='red')
            axs[i].yaxis.set_major_formatter(plt.FuncFormatter(lambda y, pos: '{:,.3f}'.format(y) + ' ms'))

            if i == len(files) - 1:
                axs[i].set(xlabel='Time (s)', ylabel='Ping status')
                axs[i].xaxis.set_major_formatter(plt.FuncFormatter(lambda x, pos: '{:,.1f}'.format(x)))
            else:
                axs[i].set(xlabel='', ylabel='Ping status')
                axs[i].xaxis.set_major_formatter(plt.FuncFormatter(lambda x, pos: ''))

        plt.tight_layout()
        plt.savefig(f'error_{e}.pdf', format='pdf')
        print("[✓]")

def pin_napi_threads():
    print("Pin napi threads to CPUs...")
    pids = exec_fg("ps aux")
    for line in str(pids.stdout).splitlines():
        pid = list(filter(('').__ne__, str(line).split(' ')))[1]
        command = str(line).split(' ')[-1]
        if "napi" in command:
            if IFNAMES[0] in command:
                exec_fg(f"{NSX} taskset -cp {cpu['napi1']} {pid}", silent=False)
            elif IFNAMES[1] in command:
                exec_fg(f"{NSX} taskset -cp {cpu['napi2']} {pid}", silent=False)
            elif IFNAMES[2] in command:
                exec_fg(f"{NSX} taskset -cp {cpu['napi3']} {pid}", silent=False)
            elif IFNAMES[3] in command:
                exec_fg(f"{NSX} taskset -cp {cpu['napi4']} {pid}", silent=False)

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
            exec_fg(f'{NSX} sh -c "echo 1 > /sys/class/net/{item}/threaded"', silent=False)
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
            gen_error_plots()
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
        exec_fg(f"{NSX} ethtool -s {IFNAMES[2]} autoneg on speed 2500 duplex full", silent=False)
        exec_fg(f"{NSX} ethtool -s {IFNAMES[3]} autoneg on speed 2500 duplex full", silent=False)
        if not XDP_ERROR_TEST:
            exec_fg(f"{NSX} tc qdisc del dev {IFNAMES[2]} root netem delay 5ms", silent=False)
            exec_fg(f"{NSX} tc qdisc del dev {IFNAMES[3]} root netem delay 5ms", silent=False)

main()
