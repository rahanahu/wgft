#!/usr/bin/env python3
# tcpquality.py holds the two ends and the analysis of lab/tcpquality.sh. Each subcommand prints
# one line of key=value pairs.
#
#   serve <ip> <port> <bytes> <seed>
#       TCP server. A connection that sends "ping\n" gets "pong\n" and is closed; one that sends
#       "go\n" gets <bytes> of a pseudo-random stream from <seed>, then a FIN, and the server
#       prints the byte count and the stream's SHA-256.
#   fetch <ip> <port> <samplefile>
#       sends "go\n", reads until EOF, writes "<wall-clock time> <bytes>" for every read to
#       <samplefile> and prints the byte count and SHA-256 of what it read.
#   analyze <samplefile> <outage-start> <outage-end>
#       the transfer's duration and mean rate, the rate before the outage and from one second after
#       recovery to the end, the longest gap between reads, and the recovery time: from the end
#       of the outage to the first byte after it.
import hashlib
import random
import socket
import sys
import time


def serve(ip, port, nbytes, seed):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((ip, int(port)))
    ls.listen(8)
    while True:
        c, _ = ls.accept()
        line = c.makefile("rb").readline()
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


def fetch(ip, port, samplefile):
    s = socket.create_connection((ip, int(port)), timeout=60)
    s.sendall(b"go\n")
    h = hashlib.sha256()
    got = 0
    samples = []
    while True:
        b = s.recv(262144)
        if not b:
            break
        samples.append((time.time(), len(b)))
        h.update(b)
        got += len(b)
    s.close()
    with open(samplefile, "w") as f:
        for t, n in samples:
            f.write("%.6f %d\n" % (t, n))
    print("received=%d sha256=%s" % (got, h.hexdigest()), flush=True)


def analyze(samplefile, start, end):
    start, end = float(start), float(end)
    rows = [tuple(map(float, l.split())) for l in open(samplefile)]
    if not rows:
        print("samples=0")
        return
    t0, t1 = rows[0][0], rows[-1][0]
    before = sum(n for t, n in rows if t < start)
    after_first = next((t for t, n in rows if t > end), None)
    recovery = (after_first - end) if after_first is not None else float("nan")
    # throughput after recovery: from one second after the first byte past the outage to the end
    steady_from = (after_first or end) + 1.0
    after = sum(n for t, n in rows if t >= steady_from)
    gap = max((rows[i][0] - rows[i - 1][0] for i in range(1, len(rows))), default=0.0)
    mbit = lambda b, d: b * 8 / d / 1e6 if d > 0 else float("nan")
    print("samples=%d duration_s=%.2f before_mbit=%.2f after_mbit=%.2f overall_mbit=%.2f recovery_s=%.3f max_gap_s=%.3f"
          % (len(rows), t1 - t0, mbit(before, start - t0), mbit(after, t1 - steady_from),
             mbit(sum(n for _, n in rows), t1 - t0), recovery, gap))


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"serve": serve, "fetch": fetch, "analyze": analyze}[cmd](*args)
