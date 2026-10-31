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
import hashlib
import os
import random
import socket
import statistics
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
        if vals and k not in ("undetermined",):
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


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    sys.exit({"serve": serve, "fetch": fetch, "push": push, "analyze": analyze, "median": median,
              "cpuratio": cpuratio}[cmd](*args))
