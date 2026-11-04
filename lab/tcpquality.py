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
                ("host_qemu_s_per_gb", "HOSTQEMU", "host_qemu_share", None),
                ("host_agent_s_per_gb", "HOSTAGENT", "host_qemu_share", None),
                ("host_peer_s_per_gb", "HOSTPEER", "host_qemu_share", None)):
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


def in_netns(ns, fn):
    # fn() run by this thread alone in the network namespace ns ("" is the caller's), as read_netns
    own = None
    try:
        if ns:
            own = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
            fd = os.open("/run/netns/" + ns, os.O_RDONLY)
            try:
                os.setns(fd, CLONE_NEWNET)
            finally:
                os.close(fd)
        return fn()
    finally:
        if own is not None:
            os.setns(own, CLONE_NEWNET)
            os.close(own)


# the rows of /proc/interrupts that are not numbered: timer, rescheduling and function call IPIs, TLB
# shootdowns, IRQ work, and the posted-interrupt vectors
NAMED_IRQS = ("LOC", "RES", "CAL", "TLB", "IWI", "PIN", "NPI", "PIW", "NMI")


def parse_interrupts(text):
    # /proc/interrupts summed over CPUs: the named rows, and per virtio device its input, output and
    # config vectors (virtio<N>-input.<q> adds to virtio<N>_input)
    out = {}
    lines = text.splitlines()
    if not lines:
        return out
    ncpu = len(lines[0].split())
    for l in lines[1:]:
        v = l.split()
        if not v:
            continue
        label = v[0].rstrip(":")
        nums = []
        for x in v[1:1 + ncpu]:
            if not x.isdigit():
                break
            nums.append(int(x))
        if label in NAMED_IRQS:
            out["irq_" + label] = out.get("irq_" + label, 0) + sum(nums)
        elif label.isdigit() and v[-1].startswith("virtio"):
            dev, _, kind = v[-1].partition("-")
            kind = kind.split(".")[0] or "other"
            k = "irq_%s_%s" % (dev, kind)
            out[k] = out.get(k, 0) + sum(nums)
    return out


def parse_softirqs(text):
    # /proc/softirqs summed over CPUs, as sirq_<name>
    out = {}
    for l in text.splitlines()[1:]:
        v = l.split()
        if v and v[0].endswith(":"):
            out["sirq_" + v[0][:-1]] = sum(int(x) for x in v[1:] if x.isdigit())
    return out


def cpuidle_counters(base="/sys/devices/system/cpu"):
    # per idle state of the guest's cpuidle driver, summed over CPUs: how often the CPUs entered it
    # and for how long (us); nothing when the guest has no cpuidle driver
    out = {}
    try:
        cpus = [d for d in os.listdir(base) if d.startswith("cpu") and d[3:].isdigit()]
    except OSError:
        return out
    for c in cpus:
        d = os.path.join(base, c, "cpuidle")
        try:
            states = [s for s in os.listdir(d) if s.startswith("state")]
        except OSError:
            continue
        for st in states:
            try:
                with open(os.path.join(d, st, "name")) as f:
                    name = f.read().strip().replace("-", "_").replace(" ", "_")
                with open(os.path.join(d, st, "usage")) as f:
                    usage = int(f.read())
                with open(os.path.join(d, st, "time")) as f:
                    us = int(f.read())
            except (OSError, ValueError):
                continue
            out["idle_%s_usage" % name] = out.get("idle_%s_usage" % name, 0) + usage
            out["idle_%s_us" % name] = out.get("idle_%s_us" % name, 0) + us
    return out


def guest_counters():
    # the counters snap_line adds in every VM: interrupts, softirqs and idle states
    kv = []
    for path, parse in (("/proc/interrupts", parse_interrupts), ("/proc/softirqs", parse_softirqs)):
        try:
            with open(path) as f:
                kv += sorted(parse(f.read()).items())
        except (OSError, ValueError):
            pass
    kv += sorted(cpuidle_counters().items())
    return kv


# Placement in the agent VM of `lab/lab paired --split`: which vCPUs took the data NIC's interrupts
# and on which vCPU the agent's data-plane thread ran. With one NIC queue a single vCPU takes every
# interrupt of the NIC and runs its receive softirq; whether the agent's one data-plane thread shares
# that vCPU changes how much work each wake-up finds, and so the throughput and the CPU per byte.

ETHTOOL_GDRVINFO = 0x03
NIC_DEVICES = {}


def nic_device(ns, ifname):
    # the virtio device behind <ifname> in the namespace ns, such as virtio12: the PCI address that
    # `ethtool -i` reports (bus_info of struct ethtool_drvinfo, at byte 100), and the virtio<N> entry
    # under that PCI device in sysfs, which is the same in every namespace; "" when there is none
    if (ns, ifname) in NIC_DEVICES:
        return NIC_DEVICES[(ns, ifname)]

    def bus():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buf = ctypes.create_string_buffer(struct.pack("I", ETHTOOL_GDRVINFO) + bytes(192))
            ethtool(s, ifname, buf)
        finally:
            s.close()
        return buf.raw[100:132].split(b"\0")[0].decode(errors="replace")
    dev = ""
    try:
        entries = os.listdir("/sys/bus/pci/devices/%s" % in_netns(ns, bus))
        dev = next((e for e in sorted(entries) if e.startswith("virtio") and e[6:].isdigit()), "")
    except OSError:
        pass
    NIC_DEVICES[(ns, ifname)] = dev
    return dev


def parse_irq_cpus(text, dev):
    # /proc/interrupts: the counts per CPU of every vector of the virtio device dev (virtio12-input.0,
    # virtio12-output.0, virtio12-config), summed over the vectors, and the IRQ numbers of the
    # vectors, the input ones first
    lines = text.splitlines()
    if not lines or not dev:
        return [], []
    ncpu = len(lines[0].split())
    per, irqs = [0] * ncpu, []
    for l in lines[1:]:
        v = l.split()
        if not v or not v[0].rstrip(":").isdigit() or not v[-1].startswith(dev + "-"):
            continue
        for i, x in enumerate(v[1:1 + ncpu]):
            if not x.isdigit():
                break
            per[i] += int(x)
        irqs.append((0 if "-input" in v[-1] else 1, int(v[0].rstrip(":"))))
    return per, [n for _, n in sorted(irqs)]


def irq_affinity(irqs, cpus="", base="/proc/irq"):
    # sets the affinity of every IRQ in irqs to the CPU list cpus when given, and returns the effective
    # affinity of each, joined by "+" (the input vector first)
    eff = []
    for n in irqs:
        if cpus:
            with open("%s/%d/smp_affinity_list" % (base, n), "w") as f:
                f.write(cpus)
        try:
            with open("%s/%d/effective_affinity_list" % (base, n)) as f:
                eff.append(f.read().strip())
        except OSError:
            with open("%s/%d/smp_affinity_list" % (base, n)) as f:
                eff.append(f.read().strip())
    return "+".join(eff) or "-"


def nicirq_counters(ns, ifname):
    # snap_line's nicirq:<ns>:<ifname>: nicirq_cpu<N>, the interrupts of the NIC's device taken by
    # CPU N so far, and nicirq_eff, the vectors' effective affinity now
    dev = nic_device(ns, ifname)
    try:
        with open("/proc/interrupts") as f:
            per, irqs = parse_irq_cpus(f.read(), dev)
        eff = irq_affinity(irqs) if irqs else "-"
    except OSError:
        return []
    return [("nicirq_cpu%d" % i, c) for i, c in enumerate(per)] + [("nicirq_eff", eff)]


def parse_thread_sched(text):
    # se.nr_migrations of /proc/<pid>/task/<tid>/sched (kernels with the scheduler debug file), or None
    for l in text.splitlines():
        k, _, v = l.partition(":")
        if k.strip() == "se.nr_migrations":
            try:
                return int(v.split()[0])
            except (ValueError, IndexError):
                return None
    return None


def find_thread(pid, comm, proc="/proc"):
    # the first thread of pid named comm, or None
    try:
        tids = sorted(os.listdir("%s/%s/task" % (proc, pid)), key=int)
    except (OSError, ValueError):
        return None
    for tid in tids:
        try:
            with open("%s/%s/task/%s/comm" % (proc, pid, tid)) as f:
                if f.read().strip() == comm:
                    return tid
        except OSError:
            pass
    return None


def thread_state(pid, tid, proc="/proc"):
    # (state, processor) of a thread from its stat (fields 3 and 39), or None when it has gone
    try:
        with open("%s/%s/task/%s/stat" % (proc, pid, tid)) as f:
            st = f.read().rsplit(")", 1)[1].split()
        return st[0], int(st[36])
    except (OSError, ValueError, IndexError):
        return None


class ThreadSampler:
    # samples every interval seconds on which CPU one thread of a process is: samples, running (state
    # R: on a CPU or waiting for one) and per CPU the samples there, all cumulative from the first
    # snapshot, so that snapdiff takes the window's part. It lives in agentd, which outlives the
    # snapshots; the thread stops when the process has gone
    def __init__(self, pid, comm, ncpu, interval=0.05, proc="/proc"):
        self.pid, self.comm, self.proc, self.interval = str(pid), comm, proc, interval
        self.samples = self.running = 0
        self.oncpu = [0] * ncpu
        self.tid = None
        self.alive = True

    def sample(self):
        if self.tid is None:
            self.tid = find_thread(self.pid, self.comm, self.proc)
            if self.tid is None:
                self.alive = os.path.exists("%s/%s" % (self.proc, self.pid))
                return
        s = thread_state(self.pid, self.tid, self.proc)
        if s is None:
            self.tid = None
            self.alive = os.path.exists("%s/%s" % (self.proc, self.pid))
            return
        state, cpu = s
        self.samples += 1
        self.running += state == "R"
        if 0 <= cpu < len(self.oncpu):
            self.oncpu[cpu] += 1

    def start(self):
        import threading

        def loop():
            while self.alive:
                self.sample()
                time.sleep(self.interval)
        threading.Thread(target=loop, daemon=True).start()
        return self

    def counters(self, label):
        # the cumulative counts, and from the thread's own files the scheduler's run and wait time
        # (schedstat, ns), its migrations and the CPU it is on now; nothing before the thread is found
        tid = self.tid or find_thread(self.pid, self.comm, self.proc)
        if tid is None:
            return []
        p = "thr_%s_" % label
        kv = [(p + "samples", self.samples), (p + "running", self.running)]
        kv += [(p + "oncpu%d" % i, c) for i, c in enumerate(self.oncpu)]
        base = "%s/%s/task/%s/" % (self.proc, self.pid, tid)
        try:
            with open(base + "schedstat") as f:
                ss = f.read().split()
            kv += [(p + "run_us", int(ss[0]) // 1000), (p + "wait_us", int(ss[1]) // 1000)]
        except (OSError, ValueError, IndexError):
            pass
        try:
            with open(base + "sched") as f:
                mig = parse_thread_sched(f.read())
            if mig is not None:
                kv.append((p + "mig", mig))
        except OSError:
            pass
        s = thread_state(self.pid, tid, self.proc)
        if s is not None:
            kv.append((p + "now", s[1]))
        return kv


THREAD_SAMPLERS = {}


def thread_counters_of(pid, label, comm):
    # snap_line's thread:<label>:<comm>: the sampler of that thread of pid, started on the first call
    key = (str(pid), comm)
    s = THREAD_SAMPLERS.get(key)
    if s is None or not s.alive:
        for k in [k for k, v in THREAD_SAMPLERS.items() if not v.alive]:
            del THREAD_SAMPLERS[k]
        s = THREAD_SAMPLERS[key] = ThreadSampler(pid, comm, os.cpu_count() or 1).start()
    return s.counters(label)


ETH_SS_STATS, ETHTOOL_GSTATS = 1, 0x1D
# the device statistics snap keeps: packets, drops and the notifications (virtio-net's kicks)
ETHSTAT_WORDS = ("kick", "packets", "drop", "notif")


def ethstats_raw(ifname):
    # `ethtool -S <ifname>` through SIOCETHTOOL, which needs no rights: {name: value}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = ctypes.create_string_buffer(struct.pack("IIQI", ETHTOOL_GSSET_INFO, 0, 1 << ETH_SS_STATS, 0))
        ethtool(s, ifname, info)
        count = struct.unpack_from("I", info, 16)[0]
        names = ctypes.create_string_buffer(struct.pack("III", ETHTOOL_GSTRINGS, ETH_SS_STATS, count)
                                            + bytes(count * ETH_GSTRING_LEN))
        ethtool(s, ifname, names)
        stats = ctypes.create_string_buffer(struct.pack("II", ETHTOOL_GSTATS, count) + bytes(8 * count))
        ethtool(s, ifname, stats)
    finally:
        s.close()
    raw = names.raw[12:]
    keys = [raw[i * ETH_GSTRING_LEN:(i + 1) * ETH_GSTRING_LEN].split(b"\0")[0].decode(errors="replace")
            for i in range(count)]
    vals = struct.unpack_from("%dQ" % count, stats.raw, 8)
    return dict(zip(keys, vals))


def ethstats_keep(stats):
    return {k.replace("-", "_"): v for k, v in stats.items() if any(w in k for w in ETHSTAT_WORDS)}


def read_ethstats(ns, ifname):
    try:
        return ethstats_keep(in_netns(ns, lambda: ethstats_raw(ifname)))
    except OSError:
        return {}


MSR_KVM_POLL_CONTROL = 0x4B564D05
KVM_CPUID_FEATURES, KVM_FEATURE_POLL_CONTROL = 0x40000001, 12


def pollctl(op, base="/dev/cpu"):
    # in a KVM guest, as root: show, or turn on or off, the host's halt polling for every vCPU of
    # this VM through MSR_KVM_POLL_CONTROL (bit 0 set: the host may poll; the guest's haltpoll
    # cpuidle driver clears it). It changes nothing on the host and ends with the VM. Needs the msr
    # module (modprobe msr) and a CPU model with kvm-poll-control
    if op not in ("on", "off", "show"):
        print("usage: pollctl on|off|show", file=sys.stderr)
        return 2
    try:
        cpus = sorted(int(d) for d in os.listdir(base) if d.isdigit())
    except OSError as e:
        print("pollctl: %s: %s; load the msr module" % (base, e), file=sys.stderr)
        return 1
    if not cpus:
        print("pollctl: no CPU under %s" % base, file=sys.stderr)
        return 1
    try:
        fd = os.open("%s/%d/cpuid" % (base, cpus[0]), os.O_RDONLY)
        try:
            eax = struct.unpack("4I", os.pread(fd, 16, KVM_CPUID_FEATURES))[0]
        finally:
            os.close(fd)
        if not eax >> KVM_FEATURE_POLL_CONTROL & 1:
            print("pollctl: the VM has no kvm-poll-control feature", file=sys.stderr)
            return 1
    except OSError:
        # no cpuid device: the MSR access below tells instead
        pass
    vals = []
    for c in cpus:
        path = "%s/%d/msr" % (base, c)
        try:
            fd = os.open(path, os.O_RDWR if op != "show" else os.O_RDONLY)
            try:
                if op != "show":
                    os.pwrite(fd, struct.pack("<Q", 1 if op == "on" else 0), MSR_KVM_POLL_CONTROL)
                vals.append(struct.unpack("<Q", os.pread(fd, 8, MSR_KVM_POLL_CONTROL))[0] & 1)
            finally:
                os.close(fd)
        except OSError as e:
            print("pollctl: cpu %d: %s" % (c, e), file=sys.stderr)
            return 1
    state = "on" if all(vals) else "off" if not any(vals) else "mixed"
    print("host_halt_poll=%s cpus=%d" % (state, len(cpus)))
    if op != "show" and state != op:
        print("pollctl: the host's halt polling stays %s" % state, file=sys.stderr)
        return 1
    return 0


def guestinfo(*nics):
    # the guest facts that decide how its idle time and its NICs cost the host, printed once per VM
    # at setup: the cpuidle driver and governor, the haltpoll parameters, the clock source, the
    # kernel command line, and per <ifname> the virtio device behind it, its queues and features.
    # sysfs shows the interfaces of the namespace that mounted it, so run it under `ip netns exec`
    def cat(path):
        try:
            with open(path) as f:
                return f.read().strip().replace(" ", ",") or "-"
        except OSError:
            return "-"
    out = ["cpuidle_driver=" + cat("/sys/devices/system/cpu/cpuidle/current_driver"),
           "cpuidle_governor=" + cat("/sys/devices/system/cpu/cpuidle/current_governor_ro"),
           "guest_halt_poll_ns=" + cat("/sys/module/haltpoll/parameters/guest_halt_poll_ns"),
           "cpuidle_haltpoll_force=" + cat("/sys/module/cpuidle_haltpoll/parameters/force"),
           "clocksource=" + cat("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
           "cmdline=" + cat("/proc/cmdline")]
    print(" ".join(out))
    for ifname in nics:
        link = "/sys/class/net/%s/device" % ifname
        dev = os.path.realpath(link) if os.path.exists(link) else "-"
        try:
            q = len([x for x in os.listdir("/sys/class/net/%s/queues" % ifname) if x.startswith("tx-")])
        except OSError as e:
            print("nic=%s error=%s" % (ifname, str(e).replace(" ", "_")))
            continue
        print("nic=%s device=%s tx_queues=%d features=%s" % (ifname, os.path.basename(dev), q, cat(dev + "/features")))
    return 0


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
    #   busy_us, user_us, sys_us, soft_us, irq_us, steal_us, cpu<N>_us (busy per CPU) and
    #   cpu<N>_soft_us (softirq per CPU) from
    #   /proc/stat, busy being user, nice, system, irq and softirq as in tcpquality.sh; ctxt;
    #   with a pid, proc_us (from the cgroup's cpu.stat when cg is given) and proc_vcs and
    #   proc_nvcs, the voluntary and involuntary context switches summed over its threads.
    # specs: if:<ns>:<ifname> adds if_<ns>_<ifname>_{rxp,rxb,txp,txb} from /proc/net/dev and
    # snmp:<ns> adds snmp_<ns>_<counter> from /proc/net/snmp, read in that namespace;
    # nicirq:<ns>:<ifname> adds nicirq_cpu<N> and nicirq_eff (nicirq_counters) and, with a pid,
    # thread:<label>:<comm> adds thr_<label>_* (ThreadSampler, which keeps sampling between calls in
    # a long-lived process such as agentd).
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
                kv.append((v[0] + "_soft_us", us(v[7])))
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
    kv += guest_counters()
    # nicirq:<ns>:<ifname> and thread:<label>:<comm> (with a pid): the placement counters above
    for spec in specs:
        kind, _, rest = spec.partition(":")
        if kind == "nicirq":
            kv += nicirq_counters(*rest.split(":", 1))
        elif kind == "thread" and pid:
            kv += thread_counters_of(pid, *rest.split(":", 1))
    out = ["%s_%s=%s" % (prefix, k, v) for k, v in kv]
    by_ns = {}
    for spec in specs:
        kind, _, rest = spec.partition(":")
        if kind in ("nicirq", "thread"):
            continue
        ns = rest.split(":")[0]
        by_ns.setdefault(ns, []).append((kind, rest))
    for ns, items in by_ns.items():
        got = read_netns(ns, ["dev", "snmp", "netstat"])
        # the WireGuard interface of a kernel-mode agent or server, when the namespace has one: its
        # drops show packets lost inside WireGuard's queues, which no other counter here sees
        if any(kind == "if" for kind, _ in items) and any(l.split(":")[0].strip() == "wgft0" for l in got["dev"].splitlines()):
            items = items + [("if", ns + ":wgft0")]
        for kind, rest in items:
            if kind == "eth":
                ifname = rest.split(":")[1]
                out += ["eth_%s_%s_%s=%d" % (ns, ifname, k, v) for k, v in sorted(read_ethstats(ns, ifname).items())]
            elif kind == "if":
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


def placement_parts(p, d, a, t):
    # snapdiff's placement values of the VM prefix p (d: the window's increase of a key, a: the
    # after snapshot, t: the window in seconds). For the agent and the peer VM, the busy share of each vCPU
    # (<p>_cpu<N>_busy, 1.0 is the whole vCPU) and its softirq part (<p>_cpu<N>_soft); when the snapshots have them, the data NIC's
    # interrupts per vCPU as fractions (<p>_nicirq_cpu<N>_frac), the vCPU that took most
    # (<p>_nicirq_top_cpu) and the vectors' effective affinity (<p>_nicirq_eff); and per sampled
    # thread label L the fraction of samples on each vCPU (<p>_thr_L_cpu<N>_frac), the share of
    # samples in state R, its migrations, its wait for a CPU as a share of the window, and
    # <p>_thr_L_on_nicirq_frac, the chance that the thread was on the vCPU taking the NIC's
    # interrupts (the sum over vCPUs of the two fractions' products)
    out = []
    put = lambda k, v, fmt="%.3f": out.append(("%s=" + fmt) % (k, v))
    pre = p + "_"

    def per_cpu(head, tail):
        # {N: increase} of the keys <p>_<head><N><tail>
        got = {}
        for k in a:
            if k.startswith(pre + head) and k.endswith(tail):
                n = k[len(pre + head):len(k) - len(tail)]
                if n.isdigit() and d(k) is not None:
                    got[int(n)] = d(k)
        return got
    if p in ("agentvm", "peervm"):
        for n, v in sorted(per_cpu("cpu", "_us").items()):
            put("%s_cpu%d_busy" % (p, n), v / 1e6 / t, "%.2f")
        for n, v in sorted(per_cpu("cpu", "_soft_us").items()):
            put("%s_cpu%d_soft" % (p, n), v / 1e6 / t, "%.2f")
    nic = per_cpu("nicirq_cpu", "")
    nic_frac = {}
    if nic and sum(nic.values()) > 0:
        tot = sum(nic.values())
        nic_frac = {n: v / tot for n, v in nic.items()}
        for n, f in sorted(nic_frac.items()):
            put("%s_nicirq_cpu%d_frac" % (p, n), f, "%.2f")
        put(p + "_nicirq_top_cpu", max(nic, key=lambda n: (nic[n], -n)), "%d")
    if pre + "nicirq_eff" in a:
        out.append("%s_nicirq_eff=%s" % (p, a[pre + "nicirq_eff"]))
    labels = sorted({k[len(pre + "thr_"):-len("_samples")] for k in a
                     if k.startswith(pre + "thr_") and k.endswith("_samples")})
    for lb in labels:
        q = "%sthr_%s_" % (pre, lb)
        n = d(q + "samples")
        if not n:
            continue
        on = per_cpu("thr_%s_oncpu" % lb, "")
        for c, v in sorted(on.items()):
            put("%s_thr_%s_cpu%d_frac" % (p, lb, c), v / n, "%.2f")
        if d(q + "running") is not None:
            put("%s_thr_%s_running_frac" % (p, lb), d(q + "running") / n, "%.2f")
        if d(q + "mig") is not None:
            put("%s_thr_%s_mig" % (p, lb), d(q + "mig"), "%.0f")
        if d(q + "wait_us") is not None:
            put("%s_thr_%s_wait_share" % (p, lb), d(q + "wait_us") / 1e6 / t)
        if nic_frac:
            put("%s_thr_%s_on_nicirq_frac" % (p, lb), sum(v / n * nic_frac.get(c, 0) for c, v in on.items()), "%.2f")
    return out


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
        # interrupts and softirqs per second (the virtio vectors also per GB), and the idle states:
        # entries per second and the share of the window spent in each, summed over the VM's CPUs
        for k in sorted(a_ for a_ in a if a_.startswith(p + "_irq_") or a_.startswith(p + "_sirq_")):
            v = d(k)
            if v is None or not v:
                continue
            put(k + "_per_s", v / t, "%.0f")
            if "_virtio" in k and gb > 0:
                put(k + "_per_gb", v / gb, "%.0f")
        for k in sorted(a_ for a_ in a if a_.startswith(p + "_idle_") and a_.endswith("_usage")):
            st = k[len(p) + 6:-6]
            if d(k) is not None:
                put("%s_idle_%s_per_s" % (p, st), d(k) / t, "%.0f")
            if d("%s_idle_%s_us" % (p, st)) is not None:
                put("%s_idle_%s_share" % (p, st), d("%s_idle_%s_us" % (p, st)) / 1e6 / t)
        out.extend(placement_parts(p, d, a, t))
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
    # device statistics (ethtool -S): per GB, and the notifications also per second
    for k in sorted(a):
        if k.startswith("eth_") and d(k) and gb > 0:
            put(k[4:] + "_per_gb", d(k) / gb, "%.0f")
            if "kick" in k or "notif" in k:
                put(k[4:] + "_per_s", d(k) / t, "%.0f")
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


# the per-thread counters hostsample adds up: run and wait from schedstat (ns), utime, stime and
# guest_time from stat (clock ticks), the voluntary and involuntary context switches from status
THREAD_KEYS = ("run", "wait", "utime", "stime", "guest", "vcs", "nvcs")


def thread_counters(pid, tid):
    # one thread's cumulative counters, or None when it has gone; also its comm, the CPU it last ran
    # on and its allowed CPUs
    base = "/proc/%s/task/%s/" % (pid, tid)
    try:
        with open(base + "comm") as g:
            comm = g.read().strip()
        with open(base + "schedstat") as g:
            ss = g.read().split()
        with open(base + "stat") as g:
            st = g.read().rsplit(")", 1)[1].split()
        vcs = nvcs = 0
        allowed = "-"
        with open(base + "status") as g:
            for l in g:
                if l.startswith("voluntary_ctxt_switches"):
                    vcs = int(l.split()[1])
                elif l.startswith("nonvoluntary_ctxt_switches"):
                    nvcs = int(l.split()[1])
                elif l.startswith("Cpus_allowed_list"):
                    allowed = l.split()[1]
        # stat after the comm: utime is field 14, stime 15, processor 39 and guest_time 43
        vals = {"run": int(ss[0]), "wait": int(ss[1]), "utime": int(st[11]), "stime": int(st[12]),
                "guest": int(st[40]), "vcs": vcs, "nvcs": nvcs}
        return comm, int(st[36]), allowed, vals
    except (OSError, ValueError, IndexError):
        return None


def thread_kind(comm, allowed):
    # Incus pins each vCPU thread to one CPU and leaves the rest of qemu on every CPU; the vCPU
    # threads keep qemu's name, so they are told apart by that pinning. vhost_task workers are named
    # vhost-<qemu pid> and live in qemu's thread group
    if comm.startswith("vhost-"):
        return "vhost"
    if comm.startswith("CPU ") or (comm.startswith("qemu") and allowed.isdigit()):
        return "vcpu"
    return "other"


class HostSampler:
    # the state of hostsample between samples. Every class (vcpu, vhost, other) of every VM is the sum
    # of the increases of its threads since the previous sample, so a thread that exits takes only
    # its last interval with it instead of its whole history
    def __init__(self, pcores=None):
        self.pc = pcores if pcores is not None else set()
        self.last, self.kind, self.cpus = {}, {}, {}
        self.tot, self.vhost_p, self.vhost_e = {}, {}, {}

    def vm(self, label, pid, threads, busy=None, irq=None):
        # threads: {tid: (comm, processor, allowed, counters)}; busy and irq: per host CPU from
        # proc_stat_cpus. Returns the key=value parts of the VM
        tot = self.tot.setdefault(label, {(c, k): 0 for c in ("vcpu", "vhost", "other") for k in THREAD_KEYS})
        self.vhost_p.setdefault(label, 0)
        self.vhost_e.setdefault(label, 0)
        cpus = self.cpus.setdefault(label, set())
        for tid, (comm, proc, allowed, vals) in threads.items():
            key = (label, tid)
            if key not in self.kind:
                self.kind[key] = thread_kind(comm, allowed)
                if self.kind[key] == "vcpu" and allowed.isdigit():
                    cpus.add(int(allowed))
            c = self.kind[key]
            prev = self.last.get(key)
            # a thread first seen in the first sample starts the totals with its history; one born
            # later counts all of it, which it ran since the previous sample
            for k in THREAD_KEYS:
                inc = vals[k] - (prev[k] if prev else 0)
                if inc > 0:
                    tot[(c, k)] += inc
            if c == "vhost" and prev is not None:
                dlt = max(0, vals["run"] - prev["run"])
                if proc in self.pc:
                    self.vhost_p[label] += dlt
                else:
                    self.vhost_e[label] += dlt
            self.last[key] = vals
        parts = ["%s_pid=%s" % (label, pid)]
        parts += ["%s_%s_ns=%d" % (label, c, tot[(c, "run")]) for c in ("vcpu", "vhost", "other")]
        parts += ["%s_vhostp_ns=%d" % (label, self.vhost_p[label]), "%s_vhoste_ns=%d" % (label, self.vhost_e[label])]
        for c in ("vcpu", "vhost", "other"):
            parts += ["%s_%s_%s=%d" % (label, c, k, tot[(c, k)]) for k in THREAD_KEYS if k != "run"]
        if busy is not None and irq is not None:
            # the host CPUs the vCPU threads are pinned to: all their busy time and their irq and
            # softirq time, which the vCPU threads' run time leaves out
            parts += ["%s_vcpucpu_busy=%d" % (label, sum(busy.get(n, 0) for n in cpus)),
                      "%s_vcpucpu_irq=%d" % (label, sum(irq.get(n, 0) for n in cpus)),
                      "%s_vcpucpu_n=%d" % (label, len(cpus))]
        return parts


def proc_stat_cpus(text):
    # per host CPU from /proc/stat: busy (user, nice, system, irq, softirq) and irq+softirq, in ticks
    busy, irq = {}, {}
    for line in text.splitlines():
        v = line.split()
        if v and v[0].startswith("cpu") and v[0] != "cpu":
            n = int(v[0][3:])
            busy[n] = sum(int(v[i]) for i in (1, 2, 3, 6, 7))
            irq[n] = int(v[6]) + int(v[7])
    return busy, irq


def hostsample(out, interval, *specs):
    # on the host, every <interval> seconds until killed: the busy time of every host CPU (ticks)
    # and its irq and softirq time, and per VM given as <label>=<qemu pid> the counters of its vCPU
    # threads, its vhost workers and its other threads: run and runqueue wait (ns, schedstat), user,
    # system and guest time (ticks), and the voluntary and involuntary context switches; the vhost
    # run time split by whether the worker sat on a P-core at the sample. Incus pins only the vCPU
    # threads, so the vhost workers and the rest of qemu float over the host; these lines show where
    # their time went. In a vCPU thread, guest time is the time in the guest, system time is KVM in
    # the host kernel (exits, interrupt injection and halt polling) and user time beyond guest time
    # is qemu's own device code. Reading /proc of qemu, which runs as another user, needs no rights.
    sampler = HostSampler(pcores())
    step = float(interval)
    with open(out, "a") as f:
        while True:
            t0 = time.time()
            parts = ["t=%.3f" % t0]
            with open("/proc/stat") as st:
                busy, irq = proc_stat_cpus(st.read())
            parts += ["hcpu%d=%d" % kv for kv in sorted(busy.items())]
            parts += ["hirq%d=%d" % kv for kv in sorted(irq.items())]
            for spec in specs:
                if spec.startswith("tap:"):
                    # tap:<label>=<host interface>: the drops of a VM's tap; tx is towards the guest
                    label, dev = spec[4:].split("=")
                    for k in ("tx_dropped", "rx_dropped", "tx_packets", "rx_packets"):
                        try:
                            with open("/sys/class/net/%s/statistics/%s" % (dev, k)) as g:
                                parts.append("tap_%s_%s=%s" % (label, k, g.read().strip()))
                        except OSError:
                            pass
                    continue
                label, pid = spec.split("=")
                try:
                    tids = os.listdir("/proc/%s/task" % pid)
                except OSError:
                    tids = []
                threads = {}
                for tid in tids:
                    got = thread_counters(pid, tid)
                    if got is not None:
                        threads[tid] = got
                parts += sampler.vm(label, pid, threads, busy, irq)
            f.write(" ".join(parts) + "\n")
            f.flush()
            time.sleep(max(0.0, step - (time.time() - t0)))


def kvmsample(out, interval, root="/sys/kernel/debug/kvm"):
    # needs root, so the owner starts it next to a measurement: every <interval> seconds until
    # killed, the per-VM statistics KVM keeps in debugfs (<pid>-<fd>/<stat>, each the sum over the
    # VM's vCPUs), as kvm_<pid>_<stat>=<value>. hostwin merges them by the qemu pid that hostsample
    # writes, so the two files need no other link
    step = float(interval)
    with open(out, "a") as f:
        while True:
            t0 = time.time()
            parts = ["t=%.3f" % t0]
            try:
                vms = sorted(os.listdir(root))
            except OSError as e:
                print("kvmsample: %s: %s" % (root, e), file=sys.stderr)
                return 1
            for vmdir in vms:
                pid = vmdir.split("-", 1)[0]
                if not pid.isdigit():
                    continue
                for name in sorted(os.listdir(os.path.join(root, vmdir))):
                    if name not in KVM_STATS:
                        continue
                    try:
                        with open(os.path.join(root, vmdir, name)) as g:
                            parts.append("kvm_%s_%s=%s" % (pid, name, g.read().strip()))
                    except (OSError, ValueError):
                        pass
            f.write(" ".join(parts) + "\n")
            f.flush()
            if step <= 0:
                return 0
            time.sleep(max(0.0, step - (time.time() - t0)))


# the KVM statistics kvmsample keeps: halt polling, exits and interrupt injection (Linux x86
# names; a name the kernel does not have is skipped)
KVM_STATS = ("exits", "halt_exits", "halt_successful_poll", "halt_attempted_poll", "halt_poll_invalid",
             "halt_wakeup", "halt_poll_success_ns", "halt_poll_fail_ns", "halt_wait_ns",
             "irq_exits", "irq_injections", "nmi_injections", "irq_window_exits",
             "io_exits", "mmio_exits", "signal_exits", "request_irq_exits", "preemption_reported",
             "preemption_other", "notify_window_exits", "req_event", "host_state_reload", "fpu_reload",
             "insn_emulation", "blocking", "directed_yield_attempted", "directed_yield_successful",
             "guest_mode", "l1d_flush")


def read_samples(path):
    rows = []
    with open(path) as f:
        for line in f:
            kv = {}
            for x in line.split():
                k, eq, v = x.partition("=")
                if not eq:
                    continue
                try:
                    kv[k] = float(v)
                except ValueError:
                    pass
            if "t" in kv:
                rows.append(kv)
    return rows


def interp(rows, key, t):
    # the value of key at time t, linear between the samples on either side
    for i in range(1, len(rows)):
        if rows[i]["t"] >= t:
            r0, r1 = rows[i - 1], rows[i]
            if key not in r0 or key not in r1:
                return None
            w = (t - r0["t"]) / (r1["t"] - r0["t"]) if r1["t"] > r0["t"] else 1.0
            w = min(max(w, 0.0), 1.0)
            return r0[key] + w * (r1[key] - r0[key])
    return rows[-1].get(key)


# the guest's busy share of a VM label in a PAIRED line
GUEST_SHARE = {"agent": "agentvm_cpu_share", "peer": "peervm_cpu_share"}


def hostwin_line(r, rows, hz, pc, kvm=None):
    # the host's values over the window of one PAIRED line r (a dict), as key=value strings
    t0, t1 = float(r["t_start"]), float(r["t_end"])
    keys = sorted(rows[-1])
    labels = sorted({k.split("_", 1)[0] for k in keys if k.endswith("_vcpu_ns")})
    drops = [k for k in keys if k.startswith("tap_") and k.endswith("_dropped")]
    dl = lambda k: (interp(rows, k, t1) or 0.0) - (interp(rows, k, t0) or 0.0)
    win = t1 - t0
    gb = float(r.get("bytes", "0") or 0) / 1e9
    per_gb = lambda v: v / gb if gb > 0 else -1
    busy = sum(dl(k) for k in keys if k.startswith("hcpu")) / hz
    pbusy = sum(dl(k) for k in keys if k.startswith("hcpu") and int(k[4:]) in pc) / hz
    add = ["host_busy_s=%.3f" % busy, "host_pcore_busy_s=%.3f" % pbusy, "host_cpu_share=%.3f" % (busy / win)]
    if any(k.startswith("hirq") for k in keys):
        add.append("host_irq_s=%.3f" % (sum(dl(k) for k in keys if k.startswith("hirq")) / hz))
    if drops:
        # packets the hosts' taps between the two VMs dropped in the window: the lab, not the agent
        add.append("host_tap_drops=%d" % round(sum(dl(k) for k in drops)))
    qemu = vp = ve = 0.0
    for lb in labels:
        vm_s = 0.0
        for c in ("vcpu", "vhost", "other"):
            v = dl("%s_%s_ns" % (lb, c)) / 1e9
            qemu += v
            vm_s += v
            add.append("host_%s_%s_s=%.3f" % (lb, c, v))
        vp += dl(lb + "_vhostp_ns")
        ve += dl(lb + "_vhoste_ns")
        add += ["host_%s_s=%.3f" % (lb, vm_s), "host_%s_s_per_gb=%.3f" % (lb, per_gb(vm_s))]
        if lb + "_vcpu_guest" in rows[-1]:
            # the vCPU threads split by where their time went (ticks, so about 1 %% of a window of
            # 10 s): in the guest, in KVM in the host kernel, and in qemu's user space beyond the guest
            guest = dl(lb + "_vcpu_guest") / hz
            ktime = dl(lb + "_vcpu_stime") / hz
            qtime = max(0.0, dl(lb + "_vcpu_utime") / hz - guest)
            add += ["host_%s_vcpu_guest_s=%.3f" % (lb, guest), "host_%s_vcpu_kvm_s=%.3f" % (lb, ktime),
                    "host_%s_vcpu_qemu_s=%.3f" % (lb, qtime),
                    "host_%s_vcpu_wait_s=%.3f" % (lb, dl(lb + "_vcpu_wait") / 1e9),
                    "host_%s_vcpu_blocks_per_s=%.0f" % (lb, dl(lb + "_vcpu_vcs") / win),
                    "host_%s_vcpu_preempt_per_s=%.0f" % (lb, dl(lb + "_vcpu_nvcs") / win),
                    "host_%s_vhost_blocks_per_s=%.0f" % (lb, dl(lb + "_vhost_vcs") / win)]
        if lb + "_vcpucpu_busy" in rows[-1]:
            # on the CPUs the vCPUs are pinned to: irq and softirq time, and busy time that is not the
            # vCPU threads' (other tasks and interrupts); the guest runs on none of it
            other = dl(lb + "_vcpucpu_busy") / hz - dl(lb + "_vcpu_ns") / 1e9
            add += ["host_%s_vcpucpu_irq_s=%.3f" % (lb, dl(lb + "_vcpucpu_irq") / hz),
                    "host_%s_vcpucpu_not_vcpu_s=%.3f" % (lb, other)]
        share = GUEST_SHARE.get(lb)
        if share and share in r and r.get("window_s"):
            # the vCPU threads' run time beyond what the guest counts as busy: halt polling, exits,
            # and the guest's own idle polling if it has any; per GB, the cost the guest cannot see
            beyond = dl(lb + "_vcpu_ns") / 1e9 - float(r[share]) * float(r["window_s"])
            add += ["host_%s_vcpu_beyond_guest_s=%.3f" % (lb, beyond),
                    "host_%s_vcpu_beyond_guest_s_per_gb=%.3f" % (lb, per_gb(beyond))]
        if kvm is not None and lb + "_pid" in rows[-1]:
            pid = "%d" % rows[-1][lb + "_pid"]
            for k in sorted(kvm[-1]):
                pre = "kvm_%s_" % pid
                if k.startswith(pre):
                    v = (interp(kvm, k, t1) or 0.0) - (interp(kvm, k, t0) or 0.0)
                    name = k[len(pre):]
                    if name.endswith("_ns"):
                        add.append("host_%s_kvm_%s_s=%.3f" % (lb, name[:-3], v / 1e9))
                    else:
                        add.append("host_%s_kvm_%s_per_s=%.0f" % (lb, name, v / win))
    add += ["host_qemu_s=%.3f" % qemu, "host_qemu_share=%.3f" % (qemu / win),
            "host_qemu_s_per_gb=%.3f" % per_gb(qemu),
            "host_vhost_pcore_frac=%s" % ("%.2f" % (vp / (vp + ve)) if vp + ve > 0 else "-")]
    return add


def hostwin(samples, logfile, kvmfile=""):
    # adds to every PAIRED line of <logfile> with t_start and t_end (host clock) the host's values
    # over that window, interpolated between the samples of hostsample: host_busy_s (all host CPUs),
    # host_pcore_busy_s, host_irq_s, and per VM label host_<label>_{vcpu,vhost,other}_s and their sum
    # host_<label>_s (and per GB); when the samples have them, the vCPU threads' guest, KVM and qemu
    # time, runqueue wait, blocking sleeps and preemptions, and their run time beyond the guest's
    # busy time; with <kvmfile> from kvmsample, the KVM statistics of each VM. host_qemu_s_per_gb and
    # host_qemu_share are all threads of all VMs, the cost of the guests on the host including the
    # threads Incus does not pin; host_vhost_pcore_frac is the share of vhost time on P-cores.
    rows = read_samples(samples)
    if len(rows) < 2:
        print("hostwin: fewer than two samples in %s" % samples, file=sys.stderr)
        return 1
    kvm = None
    if kvmfile:
        kvm = read_samples(kvmfile)
        if len(kvm) < 2:
            print("hostwin: fewer than two samples in %s; leaving the KVM statistics out" % kvmfile, file=sys.stderr)
            kvm = None
    hz = os.sysconf("SC_CLK_TCK")
    pc = pcores()
    out = []
    with open(logfile) as f:
        lines = f.read().splitlines()
    for line in lines:
        if not line.startswith("PAIRED ") or " t_start=" not in line or " host_busy_s=" in line:
            out.append(line)
            continue
        r = dict(x.split("=", 1) for x in line.split()[1:] if "=" in x)
        if float(r["t_start"]) < rows[0]["t"] or float(r["t_end"]) > rows[-1]["t"]:
            out.append(line)
            continue
        out.append(line + " " + " ".join(hostwin_line(r, rows, hz, pc, kvm)))
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
              "agentd": agentd, "agentx": agentx, "channels": channels, "hostsample": hostsample, "hostwin": hostwin,
              "kvmsample": kvmsample, "pollctl": pollctl, "guestinfo": guestinfo}[cmd](*args))
