#!/usr/bin/env python3
# tcpquality.py holds the two ends and the analysis of lab/tcpquality.sh. Each subcommand prints
# one line of key=value pairs.
#
#   serve <ip> <port> <bytes> <seed>
#       TCP server. A connection that sends "ping\n" gets "pong\n" and is closed; one that sends
#       "go\n" gets <bytes> of a pseudo-random stream from <seed>, then a FIN, and the server
#       prints the byte count and the stream's SHA-256. One that sends
#       "up <samplefile> <mark-bytes> <markfile>\n" is read until EOF the way fetch reads; the
#       server then writes the samples, prints the byte count and SHA-256 of what it read, sends
#       the same line back and closes.
#   fetch <ip> <port> <samplefile> <mark-bytes> <markfile>
#       sends "go\n", reads until EOF, creates <markfile> once <mark-bytes> have been read, writes
#       "<wall-clock time> <bytes>" for every read to <samplefile> and prints the byte count and
#       SHA-256 of what it read.
#   push <ip> <port> <bytes> <seed> <samplefile> <mark-bytes> <markfile>
#       the upload: sends "up <samplefile> <mark-bytes> <markfile>\n" and <bytes> made of the
#       first 4 MiB + 1 bytes of the stream from <seed> repeated, then a FIN, waits for the
#       server's line and prints the byte count and SHA-256 of what it sent and its own CPU seconds.
#       The samples are the server's reads. The block's odd length divides no power-of-two buffer,
#       so data shifted by a whole lap of a receive buffer still changes the hash.
#   analyze <samplefile> <outage-start> <outage-end>
#       the transfer's duration and mean rate, the rate before the outage and from one second after
#       recovery to the end, the recovery time from the end of the outage to the first byte after
#       it, the stall across the outage, and the longest gap between reads outside the outage.
#       Without reads on both sides of the outage it prints undetermined=1 and no numbers. With "-"
#       for both ends the run had no outage, and it prints the duration, the mean rate and the
#       longest gap between reads.
#   median <resultfile>
#       the median of every numeric key over the result lines in <resultfile>, and how many runs
#       were undetermined.
#   cpuratio <logfile>
#       over the RESULT lines of tcpquality.sh runs with CPU=1 for gvisor and wgstack: per netstack
#       the median, quartiles and range of the agent's CPU seconds per GB, the median throughput
#       and CPU shares, then the ratio of the wgstack and gVisor medians with a bootstrap 95%
#       interval, resampling each netstack's runs on their own 10,000 times. A run whose sender
#       used SENDER_BOUND or more of one CPU measured the sender, and is left out and counted.
#   cpupaired <logfile>
#       over the PLAN line and the PAIRED lines `lab/lab paired` writes: two arms, x and y, ran at
#       the same time in two VMs, a and b, and swapped VMs every round. A pair is the run of x and
#       the run of y with the same round and run number; its ratio is x's agent CPU seconds per GB
#       over y's. Per arm it prints the median, quartiles and range, as cpuratio does, and per
#       round the median ratio. The estimate is the geometric mean of the median ratio of the pairs
#       with x in VM a and the median ratio of those with x in VM b, which cancels a steady
#       difference between the two VMs' CPUs; that difference is printed as vm_a_over_b. The 95%
#       interval resamples the pairs of each side on their own 10,000 times. A pair is left out
#       when a run is missing, failed (pass=0, no CPU time, undetermined), started without the
#       start barrier (sync=timeout) or measured its sender; the counts are printed against the
#       PLAN's rounds times runs. With fewer than half the planned pairs on either side it prints
#       no RATIO line and fails. It also prints the median share of the longer run's window that
#       the two runs overlapped, and warns below OVERLAP_WARN and for runs that started late.
#       MBITRATIO gives the ratio of the arms' rates in the same way, for throughput targets.
#       The sender is sender_cpu_share when present, divided by the number of streams, since
#       iperf3 runs one thread per stream. When the runs carry vm_cpu_s_per_gb, the same analysis
#       follows for the whole VM's CPU per byte, its lines prefixed with VM (VMCPU, VMRATIO and so
#       on), with a warning when an arm keeps more than VM_BUSY_SHARE of the VM's vCPUs (from the
#       PLAN line) busy. The
#       kernel arm (by its name), whose agent process does no work, has no RATIO line but a line
#       saying so, and is compared by VMRATIO only.
#   iperf <jsonfile>
#       reads the output of `iperf3 -J` and prints received=<bytes the receiver read>,
#       sent=<bytes the sender wrote>, the receiver's duration and rate in Mbit/s and the sender's TCP
#       retransmits, or received=0 and the error when iperf3 failed.
#   uecho <ip> <port>
#       UDP echo server: sends every datagram back to where it came from.
#   uping <ip> <port> <seconds> <interval_ms> <prefix>
#       sends a 100-byte UDP datagram every <interval_ms> for <seconds>, each carrying its sequence
#       number and send time, reads the echoes and waits one more second for late ones. It prints
#       <prefix>_sent, <prefix>_lost (no echo), and over the echoed datagrams the round-trip time's
#       median, 99th percentile and maximum in ms and the jitter, the mean absolute difference of
#       the round-trip times of datagrams sent one after the other, in ms. Only the client's clock
#       is read, so the two namespaces' clocks never meet. The default 10 ms is a game's tick.
#   latpaired <logfile>
#       over the PAIRED lines of runs with UDPPING=1: per arm the median over runs of the idle and
#       the under-load round-trip values, the sum of lost datagrams, the median bulk rate and the
#       median and maximum number of the VM's CPUs busy during the transfer (vm_busy), then
#       for the p99 and the jitter, under load and idle, the ratio of x over y with its 95% interval,
#       estimated like cpupaired's RATIO with the same PLAN-based counting: a run whose pinger
#       printed no value counts as failed, and with fewer than half the planned pairs on a side
#       there is no ratio and the result is 1.
#   udpgso <ifname> on|off|show
#       sets or reads the device's tx-udp-segmentation feature through the SIOCETHTOOL ioctl, as
#       `ethtool -K <ifname> tx-udp-segmentation off` would, for lab VMs without ethtool; run it in
#       the device's network namespace. It prints the feature's requested and active state read
#       back from the device, and fails with a message when an ioctl fails or the state read back
#       differs from the one asked for.
import ctypes
import fcntl
import hashlib
import math
import os
import random
import socket
import statistics
import struct
import sys
import time

SENDER_BOUND = 0.7


def serve(ip, port, nbytes, seed):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((ip, int(port)))
    ls.listen(8)
    while True:
        c, _ = ls.accept()
        f = c.makefile("rb")
        line = f.readline()
        if line.startswith(b"up "):
            reply = receive(f.read1, *line.decode().split()[1:])
            print(reply, flush=True)
            c.sendall(reply.encode() + b"\n")
            c.close()
            continue
        if line != b"go\n":
            c.sendall(b"pong\n")
            c.close()
            continue
        rng = random.Random(int(seed))
        h = hashlib.sha256()
        sent = 0
        while sent < int(nbytes):
            chunk = rng.randbytes(min(65536, int(nbytes) - sent))
            c.sendall(chunk)
            h.update(chunk)
            sent += len(chunk)
        c.shutdown(socket.SHUT_WR)
        c.recv(1)
        c.close()
        print("sent=%d sha256=%s" % (sent, h.hexdigest()), flush=True)


def fetch(ip, port, samplefile, markbytes, markfile):
    s = socket.create_connection((ip, int(port)), timeout=60)
    s.sendall(b"go\n")
    line = receive(s.recv, samplefile, markbytes, markfile)
    s.close()
    print(line, flush=True)


def push(ip, port, nbytes, seed, samplefile, markbytes, markfile):
    s = socket.create_connection((ip, int(port)), timeout=60)
    s.sendall(("up %s %s %s\n" % (samplefile, markbytes, markfile)).encode())
    # one block of the stream sent again and again keeps the client's CPU per byte low
    block = memoryview(random.Random(int(seed)).randbytes(min((4 << 20) + 1, int(nbytes))))
    h = hashlib.sha256()
    sent = 0
    while sent < int(nbytes):
        chunk = block[:min(len(block), int(nbytes) - sent)]
        s.sendall(chunk)
        h.update(chunk)
        sent += len(chunk)
    s.shutdown(socket.SHUT_WR)
    s.makefile("rb").readline()
    s.close()
    t = os.times()
    print("sent=%d sha256=%s cpu_s=%.3f" % (sent, h.hexdigest(), t.user + t.system), flush=True)


def receive(read, samplefile, markbytes, markfile):
    # calls read until EOF, writes the samples and returns the line with the byte count and SHA-256
    h = hashlib.sha256()
    got = 0
    marked = False
    samples = []
    while True:
        b = read(262144)
        if not b:
            break
        samples.append((time.time(), len(b)))
        h.update(b)
        got += len(b)
        if not marked and got >= int(markbytes):
            open(markfile, "w").close()
            marked = True
    with open(samplefile, "w") as f:
        for t, n in samples:
            f.write("%.6f %d\n" % (t, n))
    return "received=%d sha256=%s" % (got, h.hexdigest())


def analyze(samplefile, start, end):
    try:
        rows = [tuple(map(float, l.split())) for l in open(samplefile)]
    except FileNotFoundError:
        rows = []
    times = [t for t, _ in rows]
    if start == "-" and end == "-":
        if len(rows) < 2:
            print("undetermined=1 samples=%d" % len(rows))
            return
        d = times[-1] - times[0]
        print("undetermined=0 samples=%d duration_s=%.3f overall_mbit=%.2f max_gap_s=%.3f"
              % (len(rows), d, sum(n for _, n in rows) * 8 / d / 1e6 if d > 0 else float("nan"),
                 max(b - a for a, b in zip(times, times[1:]))))
        return
    start, end = float(start), float(end)
    if not any(t < start for t in times) or not any(t > end for t in times):
        print("undetermined=1 samples=%d" % len(rows))
        return
    t0, t1 = times[0], times[-1]
    mbit = lambda b, d: b * 8 / d / 1e6 if d > 0 else float("nan")
    before = sum(n for t, n in rows if t < start)
    last_before = max(t for t in times if t < start)
    first_after = min(t for t in times if t > end)
    steady_from = first_after + 1.0
    after = sum(n for t, n in rows if t >= steady_from)
    # a gap overlapping [start, end] belongs to the outage and its recovery, not to the transfer
    outside = [b - a for a, b in zip(times, times[1:]) if b <= start or a >= end]
    print("undetermined=0 samples=%d duration_s=%.2f overall_mbit=%.2f before_mbit=%.2f after_mbit=%.2f "
          "recovery_s=%.3f outage_stall_s=%.3f max_gap_outside_s=%.3f"
          % (len(rows), t1 - t0, mbit(sum(n for _, n in rows), t1 - t0), mbit(before, start - t0),
             mbit(after, t1 - steady_from), first_after - end, first_after - last_before, max(outside, default=0.0)))


def median(resultfile):
    runs = [dict(kv.split("=", 1) for kv in l.split() if "=" in kv) for l in open(resultfile) if l.strip()]
    keys = []
    for r in runs:
        keys += [k for k in r if k not in keys]
    done = [r for r in runs if r.get("undetermined") == "0"]
    out = ["runs=%d undetermined=%d" % (len(runs), len(runs) - len(done))]
    for k in keys:
        try:
            vals = [float(r[k]) for r in done if k in r]
        except ValueError:
            continue
        if vals and k not in ("undetermined", "t_start", "t_end", "pass"):
            out.append("%s=%g" % (k, statistics.median(vals)))
    print(" ".join(out))


def cpuratio(logfile):
    runs = {"gvisor": [], "wgstack": []}
    left_out = {"gvisor": 0, "wgstack": 0}
    for l in open(logfile):
        if not l.startswith("RESULT "):
            continue
        r = dict(kv.split("=", 1) for kv in l.split()[1:] if "=" in kv)
        if r.get("mode") not in runs or "agent_cpu_s_per_gb" not in r:
            continue
        sender = float(r.get("client_cpu_share", r.get("lan_cpu_share", "0")))
        if sender >= SENDER_BOUND:
            left_out[r["mode"]] += 1
            continue
        runs[r["mode"]].append((float(r["agent_cpu_s_per_gb"]), float(r["overall_mbit"]),
                                float(r["agent_cpu_share"]), sender))
    for mode, rs in runs.items():
        if len(rs) < 2:
            print("CPU mode=%s runs=%d sender_bound_runs=%d too few runs" % (mode, len(rs), left_out[mode]))
            return 1
        c = [r[0] for r in rs]
        q1, _, q3 = statistics.quantiles(c, n=4, method="inclusive")
        print("CPU mode=%s runs=%d sender_bound_runs=%d cpu_s_per_gb=%.3f q1=%.3f q3=%.3f min=%.3f max=%.3f "
              "mbit=%.1f agent_cpu_share=%.2f sender_cpu_share=%.2f"
              % (mode, len(rs), left_out[mode], statistics.median(c), q1, q3, min(c), max(c),
                 statistics.median(r[1] for r in rs), statistics.median(r[2] for r in rs),
                 statistics.median(r[3] for r in rs)))
    g = [r[0] for r in runs["gvisor"]]
    w = [r[0] for r in runs["wgstack"]]
    rng = random.Random(1)
    boot = sorted(statistics.median(rng.choices(w, k=len(w))) / statistics.median(rng.choices(g, k=len(g)))
                  for _ in range(10000))
    print("RATIO wgstack_over_gvisor=%.3f ci95_low=%.3f ci95_high=%.3f"
          % (statistics.median(w) / statistics.median(g), boot[249], boot[9749]))
    return 0


OVERLAP_WARN = 0.9
# a VM with more busy CPUs than this share of its vCPUs is near saturation: the whole VM's CPU per
# byte then includes waiting and switching that a less loaded VM does not have
VM_BUSY_SHARE = 0.75


def kernel_arm(name):
    # the kernel-mode agent does its WireGuard and TCP work outside its process
    return name.split(":")[-1] == "kernel"


def sender_share(r):
    # with one sending thread per stream, the mean share of a stream's thread
    v = r.get("sender_cpu_share", r.get("client_cpu_share", r.get("lan_cpu_share", "0")))
    return float(v) / int(r.get("streams", "1"))


def iperf(jsonfile):
    import json
    try:
        j = json.load(open(jsonfile))
    except (OSError, ValueError) as e:
        print("received=0 sent=0 error=%s" % str(e).replace(" ", "_"))
        return 0
    end = j.get("end", {})
    rcv, snd = end.get("sum_received", {}), end.get("sum_sent", {})
    if "error" in j or not rcv:
        print("received=0 sent=0 error=%s" % str(j.get("error", "no_result")).replace(" ", "_"))
        return 0
    # fairness between the streams of one run: Jain's index of the bytes each stream's receiver read
    # (1 is equal shares) and the smallest stream over the largest; one stream gives no values
    per = [s.get("receiver", {}).get("bytes", 0) for s in end.get("streams", [])]
    fair = ""
    if len(per) > 1 and sum(per) > 0:
        fair = " stream_jain=%.4f stream_min_over_max=%.3f" % (
            sum(per) ** 2 / (len(per) * sum(b * b for b in per)), min(per) / max(per) if max(per) else 0)
    print("received=%d sent=%d duration_s=%.3f mbit=%.2f retransmits=%s%s"
          % (rcv["bytes"], snd.get("bytes", 0), rcv["seconds"], rcv["bits_per_second"] / 1e6,
             snd.get("retransmits", "-"), fair))
    return 0


def cpupaired(logfile):
    data = load_paired(logfile)
    rc = 0
    for arm in ("x", "y"):
        if kernel_arm(data[1].get(arm, arm)):
            print("RATIO unavailable: arm %s (%s) is the kernel-mode agent, whose work runs outside its process; "
                  "compare the arms by VMRATIO" % (arm, data[1].get(arm, arm)))
            break
    else:
        rc = cpupaired_key(data, "agent_cpu_s_per_gb", vm=False)
    with open(logfile) as f:
        text = f.read()
    plan = data[0]
    split = plan.get("split") == "1"
    if " vm_cpu_s_per_gb=" in text:
        # with --split the VM line is both VMs together, so the busy share is checked against both
        vcpus = int(plan.get("vcpus", "4")) + (int(plan.get("peer_vcpus", "0")) if split else 0)
        rc = cpupaired_key(data, "vm_cpu_s_per_gb", vm=True, vcpus=vcpus) or rc
    if split:
        # the agent VM alone: the agent's process and the kernel work of its NIC, or kernel WireGuard,
        # on the agent's vCPUs only; then the peer VM, and the host's threads of both VMs
        for key, pre, share, vcpus in (
                ("agentvm_cpu_s_per_gb", "AGENTVM", "agentvm_cpu_share", int(plan.get("vcpus", "4"))),
                ("peervm_cpu_s_per_gb", "PEERVM", "peervm_cpu_share", int(plan.get("peer_vcpus", "4"))),
                ("host_qemu_s_per_gb", "HOSTQEMU", "host_qemu_share", None)):
            if " %s=" % key in text:
                rc = cpupaired_key(data, key, vm=vcpus is not None, pre=pre, share_key=share, vcpus=vcpus) or rc
    rc = paired_ratio(data, "overall_mbit", "MBITRATIO", sender_check=True) or rc
    return rc


def load_paired(logfile):
    # the PLAN line and the PAIRED lines of `lab/lab paired`: (plan, arm names, runs by (round, run, arm))
    runs, names, plan = {}, {}, {}
    for l in open(logfile):
        if l.startswith("PLAN "):
            plan = dict(kv.split("=", 1) for kv in l.split()[1:] if "=" in kv)
            continue
        if not l.startswith("PAIRED "):
            continue
        r = dict(kv.split("=", 1) for kv in l.split()[1:] if "=" in kv)
        if r.get("arm") not in ("x", "y") or r.get("vm") not in ("a", "b"):
            continue
        names[r["arm"]] = r.get("name", r["arm"])
        runs[(int(r.get("round", 0)), int(r.get("run", 0)), r["arm"])] = r
    return plan, names, runs


def planned_keys(plan, runs):
    # the (round, run) of every planned pair; a log without the plan has the pairs that appear in it
    if "rounds" in plan and "runs" in plan:
        return [(rnd, run) for rnd in range(1, int(plan["rounds"]) + 1) for run in range(1, int(plan["runs"]) + 1)]
    return sorted({(k[0], k[1]) for k in runs})


def side_of(rnd):
    # x is in VM a in odd rounds and in VM b in even rounds
    return "a" if rnd % 2 == 1 else "b"


def classify_pair(x, y, key, sender_check):
    # why a pair is left out ("failed", "sync_timeout" or "sender_bound"), or None when it is used
    why = None
    for r in (x, y):
        try:
            ok = float(r.get(key, "0")) > 0
        except ValueError:
            ok = False
        if r.get("pass") == "0" or r.get("undetermined") == "1" or not ok:
            why = why or "failed"
        elif r.get("sync") == "timeout":
            why = why or "sync_timeout"
        elif sender_check and sender_share(r) >= SENDER_BOUND:
            why = why or "sender_bound"
    return why


def ratio_ci(pairs):
    # the median ratio of each side, and the sorted geometric means of 10,000 resamplings of the sides
    ma, mb = statistics.median(pairs["a"]), statistics.median(pairs["b"])
    rng = random.Random(1)
    boot = sorted(math.sqrt(statistics.median(rng.choices(pairs["a"], k=len(pairs["a"])))
                            * statistics.median(rng.choices(pairs["b"], k=len(pairs["b"]))))
                  for _ in range(10000))
    return ma, mb, boot


def paired_ratio(data, key, label, sender_check=False):
    # the ratio of x over y of one value per run, paired and estimated like cpupaired's RATIO, with
    # the same PLAN-based counting: a planned pair is left out when a run is missing, failed (pass=0,
    # undetermined, or no positive value for the key) or started without the barrier, and with
    # fewer than half the planned pairs on either side there is no ratio and the result is 1
    plan, names, runs = data
    keys = planned_keys(plan, runs)
    expected = {"a": 0, "b": 0}
    pairs = {"a": [], "b": []}
    counts = {"missing": 0, "failed": 0, "sync_timeout": 0}
    if sender_check:
        counts["sender_bound"] = 0
    for rnd, run in keys:
        side = side_of(rnd)
        expected[side] += 1
        x, y = runs.get((rnd, run, "x")), runs.get((rnd, run, "y"))
        if x is None or y is None:
            counts["missing"] += 1
            continue
        why = classify_pair(x, y, key, sender_check)
        if why:
            counts[why] += 1
            continue
        pairs[side].append(float(x[key]) / float(y[key]))
    left = " ".join("%s=%d" % kv for kv in counts.items())
    for side in ("a", "b"):
        if len(pairs[side]) < 2 or 2 * len(pairs[side]) < expected[side]:
            print("%s key=%s TOO FEW x_in_vm=%s pairs=%d of %d planned; no ratio %s"
                  % (label, key, side, len(pairs[side]), expected[side], left))
            return 1
    ma, mb, boot = ratio_ci(pairs)
    print("%s key=%s x_over_y=%.3f ci95_low=%.3f ci95_high=%.3f pairs=%d planned=%d %s x=%s y=%s"
          % (label, key, math.sqrt(ma * mb), boot[249], boot[9749], len(pairs["a"]) + len(pairs["b"]), len(keys),
             left, names.get("x", "x"), names.get("y", "y")))
    return 0


def cpupaired_key(data, key, vm, pre=None, share_key="vm_cpu_share", vcpus=None):
    # vm: the key is a VM's CPU per byte, so the busy share is checked against the VM's vCPUs.
    # pre, share_key and vcpus name another such value: `lab/lab paired --split` has the agent VM,
    # the peer VM and the host
    plan, names, runs = data
    if pre is None:
        pre = "VM" if vm else ""
    keys = planned_keys(plan, runs)
    expected = {"a": 0, "b": 0}
    pairs = {"a": [], "b": []}
    by_round = {}
    arm_vals = {"x": [], "y": []}
    counts = {"missing": 0, "failed": 0, "sync_timeout": 0, "sender_bound": 0}
    late = 0
    overlaps = []
    for rnd, run in keys:
        side = side_of(rnd)
        expected[side] += 1
        x, y = runs.get((rnd, run, "x")), runs.get((rnd, run, "y"))
        if x is None or y is None:
            counts["missing"] += 1
            continue
        late += sum(r.get("sync") == "late" for r in (x, y))
        why = classify_pair(x, y, key, True)
        if why:
            counts[why] += 1
            continue
        vals = [(float(r[key]), float(r["overall_mbit"]), float(r.get("agent_cpu_share", "nan")), sender_share(r),
                 float(r.get(share_key, "nan"))) for r in (x, y)]
        arm_vals["x"].append(vals[0])
        arm_vals["y"].append(vals[1])
        ratio = vals[0][0] / vals[1][0]
        pairs[side].append(ratio)
        by_round.setdefault(rnd, []).append(ratio)
        if all(k in r for r in (x, y) for k in ("t_start", "t_end")):
            xs, xe, ys, ye = (float(v) for v in (x["t_start"], x["t_end"], y["t_start"], y["t_end"]))
            longer = max(xe - xs, ye - ys)
            if longer > 0:
                overlaps.append(max(0.0, min(xe, ye) - max(xs, ys)) / longer)
    for arm in ("x", "y"):
        rs = arm_vals[arm]
        if len(rs) < 2:
            continue
        c = [r[0] for r in rs]
        q1, _, q3 = statistics.quantiles(c, n=4, method="inclusive")
        print("%sCPU arm=%s name=%s runs=%d cpu_s_per_gb=%.3f q1=%.3f q3=%.3f min=%.3f max=%.3f "
              "mbit=%.1f agent_cpu_share=%.2f sender_cpu_share=%.2f %s=%.2f"
              % (pre, arm, names.get(arm, arm), len(rs), statistics.median(c), q1, q3, min(c), max(c),
                 statistics.median(r[1] for r in rs), statistics.median(r[2] for r in rs),
                 statistics.median(r[3] for r in rs), share_key, statistics.median(r[4] for r in rs)))
    for rnd in sorted(by_round):
        print(pre + "ROUND round=%d x_in_vm=%s pairs=%d ratio_median=%.3f" % (rnd, side_of(rnd), len(by_round[rnd]),
                                                                         statistics.median(by_round[rnd])))
    print(pre + "LEFT_OUT planned=%d used=%d %s" % (len(keys), len(pairs["a"]) + len(pairs["b"]),
                                              " ".join("%s=%d" % kv for kv in counts.items())))
    if late:
        print(pre + "WARN %d runs started after the planned start time (SYNC go with a negative wait); the pairs are kept" % late)
    for side in ("a", "b"):
        planned = sorted({rnd for rnd, _ in keys if side_of(rnd) == side})
        absent = [rnd for rnd in planned if rnd not in by_round]
        if absent and len(absent) < len(planned):
            print(pre + "WARN x_in_vm=%s: no pair is left from round(s) %s, so this side rests on %d agent start(s)"
                  % (side, ",".join(map(str, absent)), len(planned) - len(absent)))
    ok = True
    for side in ("a", "b"):
        if len(pairs[side]) < 2 or 2 * len(pairs[side]) < expected[side]:
            print(pre + "TOO FEW x_in_vm=%s pairs=%d of %d planned; fewer than half remain, so no ratio is given"
                  % (side, len(pairs[side]), expected[side]))
            ok = False
    if not ok:
        return 1
    ma, mb, boot = ratio_ci(pairs)
    for side, m in (("a", ma), ("b", mb)):
        print(pre + "PAIRS x_in_vm=%s pairs=%d ratio_median=%.3f min=%.3f max=%.3f"
              % (side, len(pairs[side]), m, min(pairs[side]), max(pairs[side])))
    overlap = statistics.median(overlaps) if overlaps else None
    print(pre + "RATIO x_over_y=%.3f ci95_low=%.3f ci95_high=%.3f pairs=%d left_out=%d vm_a_over_b=%.3f overlap=%s x=%s y=%s"
          % (math.sqrt(ma * mb), boot[249], boot[9749], len(pairs["a"]) + len(pairs["b"]), sum(counts.values()),
             math.sqrt(ma / mb), "%.2f" % overlap if overlap is not None else "unknown",
             names.get("x", "x"), names.get("y", "y")))
    if vm:
        # the VMs' vCPU count comes from the PLAN line; runs from before it was written there had 4
        if vcpus is None:
            vcpus = int(plan.get("vcpus", "4"))
        limit = VM_BUSY_SHARE * vcpus
        for arm in ("x", "y"):
            busy = [r[4] for r in arm_vals[arm] if r[4] == r[4]]
            if busy and statistics.median(busy) > limit:
                print(pre + "WARN arm %s (%s) keeps %.2f of the VM's %d CPUs busy, above %.2f: that VM is near saturation, "
                      "so its CPU per byte includes contention the other VM may not have and the ratio is not like for like"
                      % (arm, names.get(arm, arm), statistics.median(busy), vcpus, limit))
    # --split runs the arms one after the other, so they never overlap and nothing is to warn about
    if overlap is not None and overlap < OVERLAP_WARN and plan.get("split") != "1":
        print(pre + "WARN overlap %.2f is below %.1f: the faster arm's run ends first and the slower arm finishes without "
              "the other VM's load, so the slower arm's CPU per byte comes out low; with the 3-5%% the VMs add to each "
              "other, the ratio of the faster arm over the slower one may be about %.1f%% too high"
              % (overlap, OVERLAP_WARN, (1 - overlap) * 4))
    return 0


PING_BYTES = 100


def uecho(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, int(port)))
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data, addr)


def uping(ip, port, seconds, interval_ms, prefix):
    import select
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, int(port)))
    s.setblocking(False)
    step = int(float(interval_ms) * 1e6)
    start = time.monotonic_ns()
    stop_send = start + int(float(seconds) * 1e9)
    stop_read = stop_send + 1000000000
    rtt = {}
    seq = 0
    nxt = start
    while True:
        now = time.monotonic_ns()
        if now >= nxt and nxt < stop_send:
            pad = bytes(PING_BYTES - 16)
            try:
                s.send(struct.pack("!QQ", seq, now) + pad)
            except OSError:
                # a send the socket refuses (a full buffer, an ICMP error reported on the
                # connected socket) counts as sent and, without an echo, as lost
                pass
            seq += 1
            nxt += step
            continue
        if now >= stop_read:
            break
        wait = (min(nxt, stop_read) if nxt < stop_send else stop_read) - now
        r, _, _ = select.select([s], [], [], max(wait, 0) / 1e9)
        if not r:
            continue
        while True:
            try:
                b = s.recv(2048)
            except (BlockingIOError, ConnectionRefusedError):
                break
            if len(b) >= 16:
                k, t = struct.unpack_from("!QQ", b)
                rtt.setdefault(k, (time.monotonic_ns() - t) / 1e6)
    got = sorted(rtt.values())
    out = ["%s_sent=%d" % (prefix, seq), "%s_lost=%d" % (prefix, seq - len(rtt))]
    if got:
        rank = lambda q: got[max(0, math.ceil(q * len(got)) - 1)]
        series = [rtt[k] for k in sorted(rtt)]
        jitter = (sum(abs(b - a) for a, b in zip(series, series[1:])) / (len(series) - 1)) if len(series) > 1 else 0.0
        out += ["%s_p50_ms=%.3f" % (prefix, rank(0.5)), "%s_p99_ms=%.3f" % (prefix, rank(0.99)),
                "%s_max_ms=%.3f" % (prefix, got[-1]), "%s_jitter_ms=%.3f" % (prefix, jitter)]
    print(" ".join(out), flush=True)
    return 0


def latpaired(logfile):
    runs = {}
    names = {}
    for l in open(logfile):
        if not l.startswith("PAIRED "):
            continue
        r = dict(kv.split("=", 1) for kv in l.split()[1:] if "=" in kv)
        if r.get("arm") not in ("x", "y") or r.get("pass") == "0" or r.get("sync") == "timeout":
            continue
        names[r["arm"]] = r.get("name", r["arm"])
        runs[(int(r.get("round", 0)), int(r.get("run", 0)), r["arm"])] = r
    keys = ["udp_idle_p50_ms", "udp_idle_p99_ms", "udp_idle_max_ms", "udp_idle_jitter_ms",
            "udp_load_p50_ms", "udp_load_p99_ms", "udp_load_max_ms", "udp_load_jitter_ms"]
    if not any("udp_load_p99_ms" in r for r in runs.values()):
        print("LAT no run has UDP round-trip values; run with UDPPING=1")
        return 1
    for arm in ("x", "y"):
        rs = [r for k, r in runs.items() if k[2] == arm]
        vals = []
        for k in keys:
            v = [float(r[k]) for r in rs if k in r]
            if v:
                vals.append("%s=%.3f" % (k[4:], max(v) if k.endswith("_max_ms") else statistics.median(v)))
        lost = sum(int(r.get(p + "_lost", "0")) for r in rs for p in ("udp_idle", "udp_load"))
        sent = sum(int(r.get(p + "_sent", "0")) for r in rs for p in ("udp_idle", "udp_load"))
        mbit = [float(r["overall_mbit"]) for r in rs if "overall_mbit" in r]
        busy = [float(r["vm_cpu_share"]) for r in rs if "vm_cpu_share" in r]
        print("LAT arm=%s name=%s runs=%d %s lost=%d sent=%d bulk_mbit=%s vm_busy=%s vm_busy_max=%s"
              % (arm, names.get(arm, arm), len(rs), " ".join(vals), lost, sent,
                 "%.1f" % statistics.median(mbit) if mbit else "-",
                 "%.2f" % statistics.median(busy) if busy else "-", "%.2f" % max(busy) if busy else "-"))
    rc = 0
    data = load_paired(logfile)
    for key in ("udp_load_p50_ms", "udp_load_p99_ms", "udp_load_jitter_ms", "udp_idle_p99_ms", "udp_idle_jitter_ms"):
        rc = paired_ratio(data, key, "LATRATIO") or rc
    return rc


# ---- lab/lab paired --split: the agent in a VM of its own ----
# The agent VM holds only the home namespace; the peer VM holds the client, the vps, the router and
# the LAN host. tcpquality.sh runs in the peer VM and reaches the agent VM through agentd.

CLONE_NEWNET = 0x40000000


def read_netns(ns, paths):
    # the contents of /proc/thread-self/net/<path> in the network namespace ns ("" is the caller's),
    # read by this thread alone after setns, so that a threaded agentd is not disturbed
    out = {}
    own = None
    try:
        if ns:
            own = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
            fd = os.open("/run/netns/" + ns, os.O_RDONLY)
            try:
                os.setns(fd, CLONE_NEWNET)
            finally:
                os.close(fd)
        for p in paths:
            try:
                with open("/proc/thread-self/net/" + p) as f:
                    out[p] = f.read()
            except OSError:
                out[p] = ""
    finally:
        if own is not None:
            os.setns(own, CLONE_NEWNET)
            os.close(own)
    return out


SNMP_KEYS = {("TcpExt", "TCPOFOQueue"): "tcp_ofoq", ("TcpExt", "TCPOFODrop"): "tcp_ofodrop",
             ("TcpExt", "TCPRcvQDrop"): "tcp_rcvqdrop", ("TcpExt", "TCPBacklogDrop"): "tcp_backlogdrop",
             ("TcpExt", "PruneCalled"): "tcp_prune", ("TcpExt", "TCPDSACKRecv"): "tcp_dsackrecv",
             ("TcpExt", "TCPSACKReorder"): "tcp_sackreorder", ("TcpExt", "TCPTSReorder"): "tcp_tsreorder",
             ("TcpExt", "TCPLostRetransmit"): "tcp_lostretrans", ("TcpExt", "TCPSpuriousRTOs"): "tcp_spurrto",
             ("TcpExt", "TCPFastRetrans"): "tcp_fastretrans", ("TcpExt", "TCPTimeouts"): "tcp_timeouts",
             ("Tcp", "InSegs"): "tcp_insegs", ("Tcp", "OutSegs"): "tcp_outsegs",
             ("Tcp", "RetransSegs"): "tcp_retrans", ("Udp", "InDatagrams"): "udp_in",
             ("Udp", "OutDatagrams"): "udp_out", ("Udp", "RcvbufErrors"): "udp_rcvbuferr",
             ("Udp", "SndbufErrors"): "udp_sndbuferr"}


def snap_line(prefix, pid="", cg="", *specs):
    # one line of cumulative counters, each key starting with <prefix>_:
    #   busy_us, user_us, sys_us, soft_us, irq_us, steal_us and cpu<N>_us (busy per CPU) from
    #   /proc/stat, busy being user, nice, system, irq and softirq as in tcpquality.sh; ctxt;
    #   with a pid, proc_us (from the cgroup's cpu.stat when cg is given) and proc_vcs and
    #   proc_nvcs, the voluntary and involuntary context switches summed over its threads.
    # specs: if:<ns>:<ifname> adds if_<ns>_<ifname>_{rxp,rxb,txp,txb} from /proc/net/dev and
    # snmp:<ns> adds snmp_<ns>_<counter> from /proc/net/snmp, read in that namespace.
    hz = os.sysconf("SC_CLK_TCK")
    us = lambda ticks: int(ticks) * 1000000 // hz
    kv = [("t", "%.6f" % time.time())]
    with open("/proc/stat") as f:
        for line in f:
            v = line.split()
            if not v:
                continue
            if v[0] == "cpu":
                kv += [("busy_us", us(sum(int(v[i]) for i in (1, 2, 3, 6, 7)))), ("user_us", us(int(v[1]) + int(v[2]))),
                       ("sys_us", us(v[3])), ("irq_us", us(v[6])), ("soft_us", us(v[7])), ("steal_us", us(v[8]))]
            elif v[0].startswith("cpu"):
                kv.append((v[0] + "_us", us(sum(int(v[i]) for i in (1, 2, 3, 6, 7)))))
            elif v[0] == "ctxt":
                kv.append(("ctxt", v[1]))
    # the per-CPU input backlog: packets dropped because netdev_max_backlog was full, and rounds of
    # net_rx_action that ran out of budget or time (hex columns 2 and 3)
    try:
        with open("/proc/net/softnet_stat") as f:
            rows = [l.split() for l in f if l.strip()]
        kv += [("softnet_drop", sum(int(r[1], 16) for r in rows)), ("softnet_squeeze", sum(int(r[2], 16) for r in rows))]
    except (OSError, ValueError, IndexError):
        pass
    if pid:
        if cg:
            with open(cg + "/cpu.stat") as f:
                kv.append(("proc_us", next(l.split()[1] for l in f if l.startswith("usage_usec"))))
        else:
            with open("/proc/%s/stat" % pid) as f:
                st = f.read().rsplit(")", 1)[1].split()
            kv.append(("proc_us", us(int(st[11]) + int(st[12]))))
        vcs = nvcs = 0
        for tid in os.listdir("/proc/%s/task" % pid):
            try:
                with open("/proc/%s/task/%s/status" % (pid, tid)) as f:
                    for l in f:
                        if l.startswith("voluntary_ctxt_switches"):
                            vcs += int(l.split()[1])
                        elif l.startswith("nonvoluntary_ctxt_switches"):
                            nvcs += int(l.split()[1])
            except OSError:
                pass
        kv += [("proc_vcs", vcs), ("proc_nvcs", nvcs)]
    out = ["%s_%s=%s" % (prefix, k, v) for k, v in kv]
    by_ns = {}
    for spec in specs:
        kind, _, rest = spec.partition(":")
        ns = rest.split(":")[0]
        by_ns.setdefault(ns, []).append((kind, rest))
    for ns, items in by_ns.items():
        got = read_netns(ns, ["dev", "snmp", "netstat"])
        # the WireGuard interface of a kernel-mode agent or server, when the namespace has one: its
        # drops show packets lost inside WireGuard's queues, which no other counter here sees
        if any(kind == "if" for kind, _ in items) and any(l.split(":")[0].strip() == "wgft0" for l in got["dev"].splitlines()):
            items = items + [("if", ns + ":wgft0")]
        for kind, rest in items:
            if kind == "if":
                ifname = rest.split(":")[1]
                for l in got["dev"].splitlines():
                    name, _, nums = l.partition(":")
                    if name.strip() == ifname:
                        n = nums.split()
                        out += ["if_%s_%s_%s=%s" % (ns, ifname, k, n[i])
                                for k, i in (("rxb", 0), ("rxp", 1), ("rxerr", 2), ("rxdrop", 3), ("txb", 8), ("txp", 9), ("txerr", 10), ("txdrop", 11))]
            elif kind == "snmp":
                lines = got["snmp"].splitlines() + got["netstat"].splitlines()
                for hdr, val in zip(lines[0::2], lines[1::2]):
                    h, v = hdr.split(), val.split()
                    for name, num in zip(h[1:], v[1:]):
                        k = SNMP_KEYS.get((h[0].rstrip(":"), name))
                        if k:
                            out.append("snmp_%s_%s=%s" % (ns, k, num))
    return " ".join(out)


def snap(prefix, pid="", cg="", *specs):
    print(snap_line(prefix, pid, cg, *specs))
    return 0


def snapdiff(nbytes, window_s, direction, before, after):
    # the run's values from two snap lines (several snap lines joined by spaces): per VM prefix
    # (agentvm, peervm, and vm in a single-VM lab) its CPU per GB, its busy share and the shares of
    # user, system, softirq, irq and steal time, the busiest single CPU and the context switches;
    # for the agent process its CPU per GB, share and context switches; per interface packets per GB
    # and the mean packet size; per namespace TCP segments and UDP datagrams per GB. With both
    # agentvm and peervm, vm_cpu_s_per_gb and vm_cpu_share are the two VMs together. The tunnel
    # (vps pub1) is split into the data direction and the reverse, the ACKs.
    b = dict(kv.split("=", 1) for kv in before.split() if "=" in kv)
    a = dict(kv.split("=", 1) for kv in after.split() if "=" in kv)
    n, t = float(nbytes), float(window_s)
    gb = n / 1e9
    d = lambda k: float(a[k]) - float(b[k]) if k in a and k in b else None
    out = []
    put = lambda k, v, fmt="%.3f": out.append(("%s=" + fmt) % (k, v))
    prefixes = sorted({k.split("_", 1)[0] for k in a if k.endswith("_busy_us")})
    total = 0.0
    for p in prefixes:
        busy = d(p + "_busy_us") / 1e6
        total += busy
        if p != "vm":
            put(p + "_cpu_s_per_gb", busy / gb if gb > 0 else -1)
            put(p + "_cpu_share", busy / t)
        for k in ("user", "sys", "soft", "irq", "steal"):
            put("%s_%s_share" % (p, k), d("%s_%s_us" % (p, k)) / 1e6 / t)
        cpus = [d(k) for k in a if k.startswith(p + "_cpu") and k.endswith("_us") and k[len(p) + 4:-3].isdigit()]
        if cpus:
            put(p + "_maxcpu", max(cpus) / 1e6 / t, "%.2f")
        for k in ("softnet_drop", "softnet_squeeze"):
            if d("%s_%s" % (p, k)):
                put("%s_%s" % (p, k), d("%s_%s" % (p, k)), "%.0f")
        if d(p + "_ctxt") is not None:
            put(p + "_ctxt_per_s", d(p + "_ctxt") / t, "%.0f")
        if d(p + "_proc_us") is not None:
            put(p + "_proc_cs_per_s", (d(p + "_proc_vcs") + d(p + "_proc_nvcs")) / t, "%.0f")
            put(p + "_proc_nvcs_per_s", d(p + "_proc_nvcs") / t, "%.0f")
    if "agentvm" in prefixes and "peervm" in prefixes:
        put("vm_cpu_s_per_gb", total / gb if gb > 0 else -1)
        put("vm_cpu_share", total / t)
    for k in sorted(a):
        if k.startswith("if_") and k.endswith("_rxp"):
            base = k[:-4]
            for dirn in ("rx", "tx"):
                pk, by = d(base + "_%sp" % dirn), d(base + "_%sb" % dirn)
                if pk is None or gb <= 0:
                    continue
                name = base[3:]
                put("%s_%sp_per_gb" % (name, dirn), pk / gb, "%.0f")
                if pk > 0:
                    put("%s_%s_avg_b" % (name, dirn), by / pk, "%.0f")
                for e in ("drop", "err"):
                    if d(base + "_%s%s" % (dirn, e)):
                        put("%s_%s%s" % (name, dirn, e), d(base + "_%s%s" % (dirn, e)), "%.0f")
        elif k.startswith("snmp_") and gb > 0 and d(k) is not None:
            if any(k.endswith(c) for c in ("_insegs", "_outsegs", "_retrans", "_udp_in", "_udp_out")):
                put(k[5:] + "_per_gb", d(k) / gb, "%.0f")
            elif d(k):
                # error and TcpExt counters: the count in the window, only when not zero
                put(k[5:], d(k), "%.0f")
    # the tunnel at the server's end: on a download the agent sends the data and the vps receives it
    rx, tx = d("if_vps_pub1_rxp"), d("if_vps_pub1_txp")
    if rx is not None and gb > 0:
        data, ack = (rx, tx) if direction == "down" else (tx, rx)
        put("tun_data_pkts_per_gb", data / gb, "%.0f")
        put("tun_ack_pkts_per_gb", ack / gb, "%.0f")
    # the TCP receiver's segments after GRO: the client on a download, the LAN host on an upload
    seg = d("snmp_client_tcp_insegs" if direction == "down" else "snmp_lan_tcp_insegs")
    if seg:
        put("recv_seg_avg_b", n / seg, "%.0f")
    print(" ".join(out))
    return 0


def agentd(ip, port, tokenfile):
    # the agent VM's end: one JSON request per connection, {"token", "op": "run", "argv", "env",
    # "timeout"} runs a command and {"op": "snap", "args"} takes a snapshot in this process, with
    # no fork, so that reading the counters costs the agent VM almost nothing. The token, which the
    # host puts into both VMs, keeps other guests on the bridge out.
    import json
    import hmac
    import subprocess
    import threading
    with open(tokenfile) as f:
        token = f.read().strip().encode()

    def one(c):
        with c:
            f = c.makefile("rwb")
            try:
                req = json.loads(f.readline())
            except ValueError:
                return
            if not hmac.compare_digest(str(req.get("token", "")).encode(), token):
                return
            rc, out, err = 0, "", ""
            try:
                if req.get("op") == "snap":
                    out = snap_line(*req["args"]) + "\n"
                else:
                    env = dict(os.environ)
                    env.update(req.get("env", {}))
                    for k in req.get("unset", []):
                        env.pop(k, None)
                    p = subprocess.run(req["argv"], env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                       timeout=req.get("timeout", 120))
                    rc, out, err = p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
            except subprocess.TimeoutExpired:
                rc, err = 124, "agentd: timed out\n"
            except (OSError, KeyError, StopIteration, ValueError) as e:
                rc, err = 1, "agentd: %s\n" % e
            f.write((json.dumps({"rc": rc, "out": out, "err": err}) + "\n").encode())
            f.flush()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ip, int(port)))
    srv.listen(16)
    print("agentd: listening on %s:%s" % (ip, port), flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


def agentx(addr, tokenfile, *args):
    # the peer VM's end: agentx <ip:port> <tokenfile> [--env K=V]... [--unset K]... -- argv...,
    # or agentx <ip:port> <tokenfile> --snap <snap args...>. Prints what the command printed and
    # exits with its status.
    import json
    env, unset, argv, op = {}, [], [], "run"
    i = 0
    while i < len(args):
        if args[i] == "--env":
            k, _, v = args[i + 1].partition("=")
            env[k] = v
            i += 2
        elif args[i] == "--unset":
            unset.append(args[i + 1])
            i += 2
        elif args[i] == "--snap":
            op, argv = "snap", list(args[i + 1:])
            break
        elif args[i] == "--":
            argv = list(args[i + 1:])
            break
        else:
            argv = list(args[i:])
            break
    with open(tokenfile) as f:
        token = f.read().strip()
    host, port = addr.rsplit(":", 1)
    req = {"token": token, "op": op, "env": env, "unset": unset, "timeout": 120}
    req["args" if op == "snap" else "argv"] = argv
    try:
        with socket.create_connection((host, int(port)), timeout=150) as c:
            c.sendall((json.dumps(req) + "\n").encode())
            f = c.makefile("rb")
            resp = json.loads(f.readline() or b"{}")
    except (OSError, ValueError) as e:
        print("agentx: %s: %s" % (addr, e), file=sys.stderr)
        return 1
    if "rc" not in resp:
        print("agentx: %s refused the request; check the token" % addr, file=sys.stderr)
        return 1
    sys.stdout.write(resp["out"])
    sys.stderr.write(resp["err"])
    return resp["rc"]


def pcores():
    # the P-cores of a hybrid Intel host, from the cpu_core PMU; empty elsewhere
    try:
        with open("/sys/devices/cpu_core/cpus") as f:
            spec = f.read().strip()
    except OSError:
        return set()
    out = set()
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        out.update(range(int(lo), int(hi or lo) + 1))
    return out


def hostsample(out, interval, *specs):
    # on the host, every <interval> seconds until killed: the busy time of every host CPU (ticks)
    # and, per VM given as <label>=<qemu pid>, the run time (ns, schedstat) of its vCPU threads,
    # its vhost workers and its other threads, and the vhost run time split by whether the
    # worker sat on a P-core at the sample. Incus pins only the vCPU threads, so the vhost workers
    # and the rest of qemu float over the host; these lines show where their time went.
    pc = pcores()
    last, vhost_p, vhost_e, kind = {}, {}, {}, {}
    step = float(interval)
    with open(out, "a") as f:
        while True:
            t0 = time.time()
            parts = ["t=%.3f" % t0]
            with open("/proc/stat") as st:
                for line in st:
                    v = line.split()
                    if v and v[0].startswith("cpu") and v[0] != "cpu":
                        parts.append("h%s=%d" % (v[0], sum(int(v[i]) for i in (1, 2, 3, 6, 7))))
            for spec in specs:
                if spec.startswith("tap:"):
                    # tap:<label>=<host interface>: the drops of a VM's tap; tx is towards the guest
                    label, dev = spec[4:].split("=")
                    for k in ("tx_dropped", "rx_dropped", "tx_packets"):
                        try:
                            with open("/sys/class/net/%s/statistics/%s" % (dev, k)) as g:
                                parts.append("tap_%s_%s=%s" % (label, k, g.read().strip()))
                        except OSError:
                            pass
                    continue
                label, pid = spec.split("=")
                cat = {"vcpu": 0, "vhost": 0, "other": 0}
                vhost_p.setdefault(label, 0)
                vhost_e.setdefault(label, 0)
                try:
                    tids = os.listdir("/proc/%s/task" % pid)
                except OSError:
                    tids = []
                for tid in tids:
                    try:
                        with open("/proc/%s/task/%s/comm" % (pid, tid)) as g:
                            comm = g.read().strip()
                        with open("/proc/%s/task/%s/schedstat" % (pid, tid)) as g:
                            ns = int(g.read().split()[0])
                        with open("/proc/%s/task/%s/stat" % (pid, tid)) as g:
                            proc = int(g.read().rsplit(")", 1)[1].split()[36])
                    except (OSError, ValueError, IndexError):
                        continue
                    if tid not in kind:
                        # Incus pins each vCPU thread to one CPU and leaves the rest of qemu on every CPU; the
                        # vCPU threads keep qemu's name, so they are told apart by that pinning
                        try:
                            with open("/proc/%s/task/%s/status" % (pid, tid)) as g:
                                allowed = next(l.split()[1] for l in g if l.startswith("Cpus_allowed_list"))
                        except (OSError, StopIteration):
                            allowed = "-"
                        kind[tid] = ("vhost" if comm.startswith("vhost-") else
                                     "vcpu" if comm.startswith("CPU ") or (comm.startswith("qemu") and allowed.isdigit())
                                     else "other")
                    c = kind[tid]
                    cat[c] += ns
                    if c == "vhost":
                        dlt = ns - last.get(tid, ns)
                        last[tid] = ns
                        if proc in pc:
                            vhost_p[label] += dlt
                        else:
                            vhost_e[label] += dlt
                parts += ["%s_%s_ns=%d" % (label, k, v) for k, v in cat.items()]
                parts += ["%s_vhostp_ns=%d" % (label, vhost_p[label]), "%s_vhoste_ns=%d" % (label, vhost_e[label])]
            f.write(" ".join(parts) + "\n")
            f.flush()
            time.sleep(max(0.0, step - (time.time() - t0)))


def hostwin(samples, logfile):
    # adds to every PAIRED line of <logfile> with t_start and t_end (host clock) the host's values
    # over that window, interpolated between the samples of hostsample: host_busy_s (all host CPUs),
    # host_pcore_busy_s, and per VM label host_<label>_{vcpu,vhost,other}_s; host_qemu_s_per_gb and
    # host_qemu_share are all threads of all VMs, the cost of the guests on the host including the
    # threads Incus does not pin; host_vhost_pcore_frac is the share of vhost time on P-cores.
    rows = []
    with open(samples) as f:
        for line in f:
            kv = dict(x.split("=", 1) for x in line.split() if "=" in x)
            if "t" in kv:
                rows.append({k: float(v) for k, v in kv.items()})
    if len(rows) < 2:
        print("hostwin: fewer than two samples in %s" % samples, file=sys.stderr)
        return 1
    hz = os.sysconf("SC_CLK_TCK")
    pc = pcores()

    def at(key, t):
        for i in range(1, len(rows)):
            if rows[i]["t"] >= t:
                r0, r1 = rows[i - 1], rows[i]
                if key not in r0 or key not in r1:
                    return None
                w = (t - r0["t"]) / (r1["t"] - r0["t"]) if r1["t"] > r0["t"] else 1.0
                w = min(max(w, 0.0), 1.0)
                return r0[key] + w * (r1[key] - r0[key])
        return rows[-1].get(key)

    keys = sorted(rows[-1])
    labels = sorted({k.split("_", 1)[0] for k in keys if k.endswith("_vcpu_ns")})
    drops = [k for k in keys if k.startswith("tap_") and k.endswith("_dropped")]
    out = []
    with open(logfile) as f:
        lines = f.read().splitlines()
    for line in lines:
        if not line.startswith("PAIRED ") or " t_start=" not in line or " host_busy_s=" in line:
            out.append(line)
            continue
        r = dict(x.split("=", 1) for x in line.split()[1:] if "=" in x)
        t0, t1 = float(r["t_start"]), float(r["t_end"])
        if t0 < rows[0]["t"] or t1 > rows[-1]["t"]:
            out.append(line)
            continue
        dl = lambda k: (at(k, t1) or 0.0) - (at(k, t0) or 0.0)
        win = t1 - t0
        busy = sum(dl(k) for k in keys if k.startswith("hcpu")) / hz
        pbusy = sum(dl(k) for k in keys if k.startswith("hcpu") and int(k[4:]) in pc) / hz
        add = ["host_busy_s=%.3f" % busy, "host_pcore_busy_s=%.3f" % pbusy, "host_cpu_share=%.3f" % (busy / win)]
        if drops:
            # packets the hosts' taps between the two VMs dropped in the window: the lab, not the agent
            add.append("host_tap_drops=%d" % round(sum(dl(k) for k in drops)))
        qemu = vp = ve = 0.0
        for lb in labels:
            for c in ("vcpu", "vhost", "other"):
                v = dl("%s_%s_ns" % (lb, c)) / 1e9
                qemu += v
                add.append("host_%s_%s_s=%.3f" % (lb, c, v))
            vp += dl(lb + "_vhostp_ns")
            ve += dl(lb + "_vhoste_ns")
        gb = float(r.get("bytes", "0") or 0) / 1e9
        add += ["host_qemu_s=%.3f" % qemu, "host_qemu_share=%.3f" % (qemu / win),
                "host_qemu_s_per_gb=%.3f" % (qemu / gb if gb > 0 else -1),
                "host_vhost_pcore_frac=%s" % ("%.2f" % (vp / (vp + ve)) if vp + ve > 0 else "-")]
        out.append(line + " " + " ".join(add))
    with open(logfile, "w") as f:
        f.write("\n".join(out) + "\n")
    return 0


SIOCETHTOOL = 0x8946
ETHTOOL_GSTRINGS, ETHTOOL_GSSET_INFO, ETHTOOL_GFEATURES, ETHTOOL_SFEATURES = 0x1B, 0x37, 0x3A, 0x3B
ETH_SS_FEATURES, ETH_GSTRING_LEN = 4, 32
UDP_GSO_FEATURE = "tx-udp-segmentation"


def ethtool(sock, ifname, buf):
    # struct ifreq: the name, then ifr_data pointing at the ethtool command, padded to 40 bytes
    ifr = bytearray(struct.pack("16sP", ifname.encode(), ctypes.addressof(buf)).ljust(40, b"\0"))
    fcntl.ioctl(sock.fileno(), SIOCETHTOOL, ifr)


ETHTOOL_GCHANNELS, ETHTOOL_SCHANNELS = 0x3C, 0x3D


def channels(ifname, count=""):
    # reads, or sets to <count>, the device's combined channels (queue pairs) through SIOCETHTOOL, as
    # `ethtool -L <ifname> combined <count>` would; prints the combined count read back
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        buf = ctypes.create_string_buffer(struct.pack("9I", ETHTOOL_GCHANNELS, *([0] * 8)))
        ethtool(s, ifname, buf)
        v = list(struct.unpack("9I", buf.raw[:36]))
        if count:
            v[0], v[8] = ETHTOOL_SCHANNELS, int(count)
            ethtool(s, ifname, ctypes.create_string_buffer(struct.pack("9I", *v)))
            buf = ctypes.create_string_buffer(struct.pack("9I", ETHTOOL_GCHANNELS, *([0] * 8)))
            ethtool(s, ifname, buf)
            v = list(struct.unpack("9I", buf.raw[:36]))
    except OSError as e:
        print("channels: %s: %s" % (ifname, e), file=sys.stderr)
        return 1
    print("combined=%d max_combined=%d" % (v[8], v[4]))
    if count and v[8] != int(count):
        print("channels: %s: combined stays %d" % (ifname, v[8]), file=sys.stderr)
        return 1
    return 0


def udpgso(ifname, op):
    if op not in ("on", "off", "show"):
        print("usage: udpgso <ifname> on|off|show", file=sys.stderr)
        return 2
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = ctypes.create_string_buffer(struct.pack("IIQI", ETHTOOL_GSSET_INFO, 0, 1 << ETH_SS_FEATURES, 0))
        ethtool(s, ifname, info)
        count = struct.unpack_from("I", info, 16)[0]
        names = ctypes.create_string_buffer(struct.pack("III", ETHTOOL_GSTRINGS, ETH_SS_FEATURES, count)
                                            + bytes(count * ETH_GSTRING_LEN))
        ethtool(s, ifname, names)
        raw = names.raw[12:]
        feature_names = [raw[i * ETH_GSTRING_LEN:(i + 1) * ETH_GSTRING_LEN].split(b"\0")[0].decode()
                         for i in range(count)]
        if UDP_GSO_FEATURE not in feature_names:
            print("udpgso: %s: the device has no feature named %s" % (ifname, UDP_GSO_FEATURE), file=sys.stderr)
            return 1
        idx = feature_names.index(UDP_GSO_FEATURE)
        blocks, blk, bit = (count + 31) // 32, idx // 32, 1 << (idx % 32)
        if op != "show":
            body = b"".join(struct.pack("II", bit if b == blk else 0, bit if b == blk and op == "on" else 0)
                            for b in range(blocks))
            ethtool(s, ifname, ctypes.create_string_buffer(struct.pack("II", ETHTOOL_SFEATURES, blocks) + body))
        feats = ctypes.create_string_buffer(struct.pack("II", ETHTOOL_GFEATURES, blocks) + bytes(16 * blocks))
        ethtool(s, ifname, feats)
        _, requested, active, _ = struct.unpack_from("IIII", feats, 8 + 16 * blk)
    except (OSError, UnicodeDecodeError) as e:
        print("udpgso: %s: %s" % (ifname, e), file=sys.stderr)
        return 1
    state = lambda m: "on" if m & bit else "off"
    print("feature=%s requested=%s active=%s" % (UDP_GSO_FEATURE, state(requested), state(active)))
    # the set command reports a change it could not make only in its return flags, so the state is
    # read back and compared instead
    if op != "show" and (state(requested) != op or state(active) != op):
        print("udpgso: %s: %s stays %s" % (ifname, UDP_GSO_FEATURE, state(active)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    sys.exit({"serve": serve, "fetch": fetch, "push": push, "analyze": analyze, "median": median,
              "cpuratio": cpuratio, "cpupaired": cpupaired, "udpgso": udpgso, "iperf": iperf,
              "uecho": uecho, "uping": uping, "latpaired": latpaired, "snap": snap, "snapdiff": snapdiff,
              "agentd": agentd, "agentx": agentx, "channels": channels, "hostsample": hostsample, "hostwin": hostwin}[cmd](*args))
