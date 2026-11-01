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
    print("received=%d sent=%d duration_s=%.3f mbit=%.2f retransmits=%s"
          % (rcv["bytes"], snd.get("bytes", 0), rcv["seconds"], rcv["bits_per_second"] / 1e6,
             snd.get("retransmits", "-")))
    return 0


def cpupaired(logfile):
    rc = cpupaired_key(logfile, "agent_cpu_s_per_gb", "")
    with open(logfile) as f:
        if any(l.startswith("PAIRED ") and " vm_cpu_s_per_gb=" in l for l in f):
            rc = cpupaired_key(logfile, "vm_cpu_s_per_gb", "VM") or rc
    rc = paired_ratio(logfile, "overall_mbit", "MBITRATIO", sender_check=True) or rc
    return rc


def paired_ratio(logfile, key, label, sender_check=False):
    # the ratio of x over y of one value per run, paired and estimated like cpupaired's RATIO, with
    # the same PLAN-based counting: a planned pair is left out when a run is missing, failed (pass=0,
    # undetermined, or no positive value for the key) or started without the barrier, and with
    # fewer than half the planned pairs on either side there is no ratio and the result is 1
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
    if "rounds" in plan and "runs" in plan:
        keys = [(rnd, run) for rnd in range(1, int(plan["rounds"]) + 1) for run in range(1, int(plan["runs"]) + 1)]
    else:
        keys = sorted({(k[0], k[1]) for k in runs})
    side_of = lambda rnd: "a" if rnd % 2 == 1 else "b"
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
    ma, mb = statistics.median(pairs["a"]), statistics.median(pairs["b"])
    rng = random.Random(1)
    boot = sorted(math.sqrt(statistics.median(rng.choices(pairs["a"], k=len(pairs["a"])))
                            * statistics.median(rng.choices(pairs["b"], k=len(pairs["b"]))))
                  for _ in range(10000))
    print("%s key=%s x_over_y=%.3f ci95_low=%.3f ci95_high=%.3f pairs=%d planned=%d %s x=%s y=%s"
          % (label, key, math.sqrt(ma * mb), boot[249], boot[9749], len(pairs["a"]) + len(pairs["b"]), len(keys),
             left, names.get("x", "x"), names.get("y", "y")))
    return 0


def cpupaired_key(logfile, key, pre):
    runs = {}
    names = {}
    plan = {}
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
    if "rounds" in plan and "runs" in plan:
        keys = [(rnd, run) for rnd in range(1, int(plan["rounds"]) + 1) for run in range(1, int(plan["runs"]) + 1)]
    else:
        keys = sorted({(k[0], k[1]) for k in runs})
    # x is in VM a in odd rounds and in VM b in even rounds
    side_of = lambda rnd: "a" if rnd % 2 == 1 else "b"
    expected = {"a": 0, "b": 0}
    pairs = {"a": [], "b": []}
    by_round = {}
    arm_vals = {"x": [], "y": []}
    counts = {"missing": 0, "failed": 0, "sync_timeout": 0, "sender_bound": 0}
    late = 0
    overlaps = []
    if not pre:
        for arm in ("x", "y"):
            if kernel_arm(names.get(arm, arm)):
                print("RATIO unavailable: arm %s (%s) is the kernel-mode agent, whose work runs outside its process; "
                      "compare the arms by VMRATIO" % (arm, names.get(arm, arm)))
                return 0
    for rnd, run in keys:
        side = side_of(rnd)
        expected[side] += 1
        x, y = runs.get((rnd, run, "x")), runs.get((rnd, run, "y"))
        if x is None or y is None:
            counts["missing"] += 1
            continue
        late += sum(r.get("sync") == "late" for r in (x, y))
        why = None
        vals = []
        for r in (x, y):
            if (r.get("pass") == "0" or r.get("undetermined") == "1" or key not in r
                    or float(r[key]) <= 0):
                why = why or "failed"
            elif r.get("sync") == "timeout":
                why = why or "sync_timeout"
            else:
                sender = sender_share(r)
                if sender >= SENDER_BOUND:
                    why = why or "sender_bound"
                vals.append((float(r[key]), float(r["overall_mbit"]),
                             float(r["agent_cpu_share"]), sender, float(r.get("vm_cpu_share", "nan"))))
        if why:
            counts[why] += 1
            continue
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
              "mbit=%.1f agent_cpu_share=%.2f sender_cpu_share=%.2f vm_cpu_share=%.2f"
              % (pre, arm, names.get(arm, arm), len(rs), statistics.median(c), q1, q3, min(c), max(c),
                 statistics.median(r[1] for r in rs), statistics.median(r[2] for r in rs),
                 statistics.median(r[3] for r in rs), statistics.median(r[4] for r in rs)))
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
    ma, mb = statistics.median(pairs["a"]), statistics.median(pairs["b"])
    for side, m in (("a", ma), ("b", mb)):
        print(pre + "PAIRS x_in_vm=%s pairs=%d ratio_median=%.3f min=%.3f max=%.3f"
              % (side, len(pairs[side]), m, min(pairs[side]), max(pairs[side])))
    rng = random.Random(1)
    boot = sorted(math.sqrt(statistics.median(rng.choices(pairs["a"], k=len(pairs["a"])))
                            * statistics.median(rng.choices(pairs["b"], k=len(pairs["b"]))))
                  for _ in range(10000))
    overlap = statistics.median(overlaps) if overlaps else None
    print(pre + "RATIO x_over_y=%.3f ci95_low=%.3f ci95_high=%.3f pairs=%d left_out=%d vm_a_over_b=%.3f overlap=%s x=%s y=%s"
          % (math.sqrt(ma * mb), boot[249], boot[9749], len(pairs["a"]) + len(pairs["b"]), sum(counts.values()),
             math.sqrt(ma / mb), "%.2f" % overlap if overlap is not None else "unknown",
             names.get("x", "x"), names.get("y", "y")))
    if pre:
        # the VMs' vCPU count comes from the PLAN line; runs from before it was written there had 4
        vcpus = int(plan.get("vcpus", "4"))
        limit = VM_BUSY_SHARE * vcpus
        for arm in ("x", "y"):
            busy = [r[4] for r in arm_vals[arm] if r[4] == r[4]]
            if busy and statistics.median(busy) > limit:
                print(pre + "WARN arm %s (%s) keeps %.2f of the VM's %d CPUs busy, above %.2f: that VM is near saturation, "
                      "so its CPU per byte includes contention the other VM may not have and the ratio is not like for like"
                      % (arm, names.get(arm, arm), statistics.median(busy), vcpus, limit))
    if overlap is not None and overlap < OVERLAP_WARN:
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
    for key in ("udp_load_p99_ms", "udp_load_jitter_ms", "udp_idle_p99_ms", "udp_idle_jitter_ms"):
        rc = paired_ratio(logfile, key, "LATRATIO") or rc
    return rc


SIOCETHTOOL = 0x8946
ETHTOOL_GSTRINGS, ETHTOOL_GSSET_INFO, ETHTOOL_GFEATURES, ETHTOOL_SFEATURES = 0x1B, 0x37, 0x3A, 0x3B
ETH_SS_FEATURES, ETH_GSTRING_LEN = 4, 32
UDP_GSO_FEATURE = "tx-udp-segmentation"


def ethtool(sock, ifname, buf):
    # struct ifreq: the name, then ifr_data pointing at the ethtool command, padded to 40 bytes
    ifr = bytearray(struct.pack("16sP", ifname.encode(), ctypes.addressof(buf)).ljust(40, b"\0"))
    fcntl.ioctl(sock.fileno(), SIOCETHTOOL, ifr)


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
              "uecho": uecho, "uping": uping, "latpaired": latpaired}[cmd](*args))
