#!/usr/bin/env python3
# memload.py is the hostile-load generator of lab/agentmem.sh. Each subcommand prints its result as
# one line of key=value pairs, the way lab/traffic.py does. The raw senders need root, and the client
# network namespace must drop its own outgoing RSTs (agentmem.sh adds that nft rule), because the
# kernel there knows none of the connections these tools open or half-open.
#
#   serve-noread <ip> <port> <rcvbuf>   accept connections and never read them; <rcvbuf> bytes is
#                                       the receive buffer set on the listener (inherited), so the
#                                       agent's own netstack is what has to hold the data
#   synflood <ip> <port> <srcs-csv> <ports-per-src> <seconds> <pps>
#                                       raw SYNs from every (source address, source port) in turn,
#                                       never completing the handshake
#   ooo <ip> <port> <srcs-csv> <conns> <segs> <seconds>
#                                       <conns> connections opened with a raw handshake, then
#                                       <segs> one-byte segments on every second byte past a hole
#                                       at the first byte, in rounds, for <seconds>; after that the
#                                       holes are filled, in reverse order, and the connections reset
#   udpmany <ip> <port> <srcs-csv> <ports-per-src> <seconds> <pps>
#                                       raw UDP datagrams from every (source address, source port)
#                                       in turn
import asyncio
import os
import random
import socket
import struct
import sys
import time


def out(**kv):
    print(' '.join('%s=%s' % (k, v) for k, v in kv.items()), flush=True)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip_header(src, dst, proto, payload_len, ident=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + payload_len, ident & 0xffff, 0x4000, 64, proto, 0, src, dst)
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]


def tcp_segment(src, dst, sport, dport, seq, ack, flags, payload=b'', opts=b'', win=65535):
    off = (20 + len(opts)) // 4
    t = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, off << 4, flags, win, 0, 0) + opts
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(t) + len(payload))
    c = csum(pseudo + t + payload)
    t = t[:16] + struct.pack('!H', c) + t[18:]
    return ip_header(src, dst, 6, len(t) + len(payload)) + t + payload


# MSS 1300 (below the tunnel's), SACK permitted, window scale 7: the scale makes the peer advertise a
# window beyond 64 KiB, so segments far past the hole are still inside it
SYN_OPTS = struct.pack('!BBH', 2, 4, 1300) + b'\x04\x02' + b'\x01' + struct.pack('!BBB', 3, 3, 7)

SYN, ACK, RST, PSH, FIN = 0x02, 0x10, 0x04, 0x08, 0x01


def raw_sender():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    return s


def paced(sock, dst, seconds, pps, make):
    # make(i) returns the i-th packet; the loop sends pps a second for <seconds>
    t0 = time.monotonic()
    end = t0 + seconds
    sent = busy = i = 0
    while True:
        now = time.monotonic()
        if now >= end:
            break
        due = int((now - t0) * pps) - i
        if due <= 0:
            time.sleep(0.001)
            continue
        for _ in range(min(due, 512)):
            try:
                sock.sendto(make(i), (dst, 0))
                sent += 1
            except OSError:
                busy += 1
            i += 1
    return sent, busy, time.monotonic() - t0


# ---- servers ---------------------------------------------------------------------------------

def serve_noread(ip, port, rcvbuf):
    async def main():
        keep = []

        async def handler(r, w):
            keep.append((r, w))  # never read, never closed
            await asyncio.sleep(3600)

        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        ls.bind((ip, port))
        ls.listen(4096)
        srv = await asyncio.start_server(handler, sock=ls, limit=1)
        out(listening='%s:%d' % (ip, port))
        async with srv:
            await srv.serve_forever()
    asyncio.run(main())


# ---- raw clients -----------------------------------------------------------------------------

def tuples(srcs, ports_per_src, first_port=1024):
    n = 0
    while True:
        p = first_port + (n // len(srcs)) % ports_per_src
        yield srcs[n % len(srcs)], p
        n += 1


def synflood(ip, port, srcs, ports_per_src, seconds, pps):
    dst = socket.inet_aton(ip)
    packed = [socket.inet_aton(s) for s in srcs]
    gen = tuples(packed, ports_per_src)
    sock = raw_sender()

    def make(i):
        src, sport = next(gen)
        return tcp_segment(src, dst, sport, port, random.getrandbits(32), 0, SYN, opts=SYN_OPTS)
    sent, busy, el = paced(sock, ip, seconds, pps, make)
    out(sent=sent, busy=busy, seconds='%.1f' % el, pps=int(sent / el), tuples=len(srcs) * ports_per_src)


def udpmany(ip, port, srcs, ports_per_src, seconds, pps):
    dst = socket.inet_aton(ip)
    packed = [socket.inet_aton(s) for s in srcs]
    gen = tuples(packed, ports_per_src)
    sock = raw_sender()
    payload = b'u' * 64

    def make(i):
        src, sport = next(gen)
        u = struct.pack('!HHHH', sport, port, 8 + len(payload), 0)
        return ip_header(src, dst, 17, len(u) + len(payload)) + u + payload
    sent, busy, el = paced(sock, ip, seconds, pps, make)
    out(sent=sent, busy=busy, seconds='%.1f' % el, pps=int(sent / el), tuples=len(srcs) * ports_per_src)


def ooo(ip, port, srcs, conns, segs, seconds):
    dst = socket.inet_aton(ip)
    packed = [socket.inet_aton(s) for s in srcs]
    sock = raw_sender()
    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    rx.settimeout(0.2)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    cs = {}  # (src, sport) -> [our next seq, peer's next seq]
    for n in range(conns):
        src, sport = packed[n % len(packed)], 20000 + n
        isn = random.getrandbits(32)
        cs[(src, sport)] = [isn + 1, None]
        sock.sendto(tcp_segment(src, dst, sport, port, isn, 0, SYN, opts=SYN_OPTS), (ip, 0))
    deadline = time.monotonic() + 10
    pending = len(cs)
    while pending and time.monotonic() < deadline:
        try:
            p = rx.recv(65535)
        except socket.timeout:
            continue
        ihl = (p[0] & 0x0f) * 4
        if p[12:16] != dst:
            continue
        sport_, dport_, seq, ack, offs, flags = struct.unpack('!HHIIBB', p[ihl:ihl + 14])
        if sport_ != port or flags & 0x12 != 0x12:
            continue
        key = (p[16:20], dport_)
        st = cs.get(key)
        if st is None or st[1] is not None:
            continue
        st[1] = (seq + 1) & 0xffffffff
        sock.sendto(tcp_segment(key[0], dst, dport_, port, st[0], st[1], ACK), (ip, 0))
        pending -= 1
    est = [(k, v) for k, v in cs.items() if v[1] is not None]
    out(progress='established', attempted=conns, established=len(est))
    # One-byte segments on every second byte, from byte 1 on: the first byte is the hole, so nothing
    # is ever in order, and every segment is its own interval. Several rounds repeat the same offsets,
    # then move on to new ones, until the time is out.
    t0 = time.monotonic()
    sent = 0
    rnd = 0
    while time.monotonic() - t0 < seconds and est:
        base = rnd * 2 * segs
        for (src, sport), (snd, rcv) in est:
            for j in range(segs):
                off = 1 + base + 2 * j
                try:
                    sock.sendto(tcp_segment(src, dst, sport, port, snd + off, rcv, ACK, payload=b'o'), (ip, 0))
                    sent += 1
                except OSError:
                    pass
            if time.monotonic() - t0 >= seconds:
                break
        rnd += 1
        if rnd * 2 * segs > 60000:  # stay inside the peer's window
            rnd = 0
    out(progress='flooded', sent=sent, seconds='%.1f' % (time.monotonic() - t0))
    # fill the holes, in reverse order, so that the tables drain and the data is delivered
    filled = 0
    hi = min((rnd + 1) * 2 * segs, 60000)
    for (src, sport), (snd, rcv) in est:
        for off in range(hi, -1, -1):
            if off % 2 == 0:
                try:
                    sock.sendto(tcp_segment(src, dst, sport, port, snd + off, rcv, ACK, payload=b'f'), (ip, 0))
                    filled += 1
                except OSError:
                    pass
    out(progress='filled', filled=filled)
    time.sleep(3)
    for (src, sport), (snd, rcv) in est:
        try:
            # the client's own nft rule drops outgoing RSTs, this one included (EPERM); the
            # connections then end with the agent and server processes
            sock.sendto(tcp_segment(src, dst, sport, port, snd, rcv, RST | ACK), (ip, 0))
        except OSError:
            break
    out(sent=sent, filled=filled, established=len(est))


def main():
    a = sys.argv[1:]
    cmd = a[0] if a else ''
    if cmd == 'serve-noread':
        serve_noread(a[1], int(a[2]), int(a[3]))
    elif cmd == 'synflood':
        synflood(a[1], int(a[2]), a[3].split(','), int(a[4]), float(a[5]), float(a[6]))
    elif cmd == 'udpmany':
        udpmany(a[1], int(a[2]), a[3].split(','), int(a[4]), float(a[5]), float(a[6]))
    elif cmd == 'ooo':
        ooo(a[1], int(a[2]), a[3].split(','), int(a[4]), int(a[5]), float(a[6]))
    else:
        print('usage: memload.py <subcommand> ...; see the header of this file', file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
