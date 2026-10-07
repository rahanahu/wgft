#!/usr/bin/env python3
# traffic.py is the traffic generator and the small servers lab/exhaustion.sh and lab/usage.sh
# run inside the sandbox's network namespaces. Each subcommand prints its result as one line of
# key=value pairs, so the shell side reads a number with its field helper:
#
#   serve-close-first <ip> <port>     accept, write one line and close first; reads nothing
#   serve-lines <ip> <port>           TCP line echo, one reply per line, keeps the connection open
#   serve-source <ip> <port> <bytes>  write <bytes> bytes and close
#   serve-udp-echo <ip> <port>        UDP echo of each datagram
#   serve-http <ip> <port> <dir>      HTTP/1.1 file server for <dir>
#   serve-udp-blast <ip> <port> <size> <seconds>
#                                     on each datagram, send <size>-byte datagrams back to its
#                                     sender as fast as possible for <seconds>
#   churn <ip> <port> <rate> <seconds> client-first|server-first [stopfile|-] [first-port]
#                                     open and close short connections at <rate> a second, until
#                                     <seconds> pass or <stopfile> appears, from source ports taken
#                                     in turn from <first-port> when given
#   tcp-rtt <ip> <port> <interval> <seconds> [stopfile]
#                                     one connection, one line per <interval>, round-trip times,
#                                     until <seconds> pass or <stopfile> appears
#   udp-rtt <ip> <port> <interval> <seconds>
#                                     one datagram per <interval>, round-trip times and losses
#   hold <ip> <port> <srcs-csv> <per-src> <bytes> <hold-seconds>
#                                     open connections from several source addresses at once,
#                                     each writing <bytes>, and hold them open
#   ackflood <ip> <port> <seconds>    open one connection to a line echo, learn its sequence
#                                     numbers, then send it duplicate pure ACKs through a raw
#                                     socket, and check the connection still echoes afterwards
#   bulk-up <ip> <port> <bytes>       send <bytes> to tools/echo, read its byte count
#   bulk-down <ip> <port>             read from serve-source until EOF
#   keys <ip> <port> <count> <think>  an interactive session: one byte, wait for its echo
#
# Long-running subcommands also print "progress ..." lines with flush, so the shell side can poll
# a log file for a stage having been reached instead of sleeping.
import asyncio
import errno
import os
import socket
import struct
import sys
import time


def out(**kv):
    print(' '.join('%s=%s' % (k, v) for k, v in kv.items()), flush=True)


def pct(xs, p):
    if not xs:
        return -1
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def ms(x):
    return '%.1f' % (x * 1000) if x >= 0 else '-1'


# ---- servers ---------------------------------------------------------------------------------

def serve(ip, port, handler):
    async def main():
        srv = await asyncio.start_server(handler, ip, port, backlog=4096, reuse_address=True)
        out(listening='%s:%d' % (ip, port))
        async with srv:
            await srv.serve_forever()
    asyncio.run(main())


async def close_first(r, w):
    try:
        w.write(b'bye\n')
        await w.drain()
    except OSError:
        pass
    w.close()


async def lines(r, w):
    try:
        while True:
            line = await r.readline()
            if not line:
                break
            w.write(line)
            await w.drain()
    except OSError:
        pass
    w.close()


def source_handler(total):
    chunk = b's' * 65536

    async def h(r, w):
        left = total
        try:
            while left > 0:
                n = min(left, len(chunk))
                w.write(chunk[:n])
                await w.drain()
                left -= n
        except OSError:
            pass
        w.close()
    return h


def serve_http(ip, port, directory):
    import functools
    import http.server

    class Handler(http.server.SimpleHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer((ip, port), functools.partial(Handler, directory=directory))
    out(listening='%s:%d' % (ip, port))
    srv.serve_forever()


def udp_echo(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    out(listening='%s:%d' % (ip, port))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)


def udp_blast(ip, port, size, seconds):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    out(listening='%s:%d' % (ip, port))
    payload = b'b' * size
    while True:
        _, a = s.recvfrom(65535)
        sent = 0
        end = time.monotonic() + seconds
        s.setblocking(False)
        while time.monotonic() < end:
            for _ in range(64):
                try:
                    s.sendto(payload, a)
                    sent += 1
                except BlockingIOError:
                    time.sleep(0.0005)
                    break
                except OSError:
                    break
        s.setblocking(True)
        out(blast_to=a[0], sent=sent, seconds=seconds)


# ---- clients ---------------------------------------------------------------------------------

def churn(ip, port, rate, seconds, order, stopfile=None, first_port=0):
    # A short connection each 1/rate seconds, at most `limit` at once, for <seconds> or until
    # <stopfile> exists, whichever comes first. A progress line each second carries the wall clock,
    # so the shell side can tell how many connections had closed by the time of a log line. With
    # <first_port>, the client binds its source ports in turn from there up to 64999 and wraps, so
    # that no 4-tuple comes back within a TIME_WAIT period at the rates used here; the kernel's
    # own choice can reuse one sooner. The range overlaps the namespace's ephemeral range
    # (32768-60999 by default) on purpose, to have 55,000 ports; a port that another socket of the
    # namespace holds at that moment, one the kernel handed out or one in TIME_WAIT from an
    # earlier run, is skipped. client-first writes one
    # line, half-closes and reads to EOF, so the client sends the first FIN; server-first reads the
    # server's line and EOF before it closes, so the server sends the first FIN.
    limit = 256
    stats = {'ok': 0, 'fail': 0, 'started': 0}
    lat = []

    nextport = [first_port]

    async def connect():
        if not first_port:
            return await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
        # a port still held by another socket of the namespace (one the kernel handed out, or one
        # of an earlier run in TIME_WAIT) is skipped, not counted as a failed connection
        for _ in range(65000 - first_port):
            local = ('0.0.0.0', nextport[0])
            nextport[0] = nextport[0] + 1 if nextport[0] < 64999 else first_port
            try:
                return await asyncio.wait_for(asyncio.open_connection(ip, port, local_addr=local), 10)
            except OSError as e:
                if e.errno != errno.EADDRINUSE:
                    raise
        raise OSError(errno.EADDRINUSE, 'no free source port')

    async def one():
        t0 = time.monotonic()
        try:
            r, w = await connect()
            if order == 'client-first':
                w.write(b'hi\n')
                await w.drain()
                w.write_eof()
            data = await asyncio.wait_for(r.read(), 10)
            w.close()
            if not data:
                raise OSError('empty reply')
            stats['ok'] += 1
            lat.append(time.monotonic() - t0)
        except (OSError, asyncio.TimeoutError):
            stats['fail'] += 1

    async def main():
        sem = asyncio.Semaphore(limit)
        tasks = set()
        start = time.monotonic()
        next_report = start + 1
        i = 0
        while True:
            now = time.monotonic()
            if now - start >= seconds or (stopfile and os.path.exists(stopfile)):
                break
            due = int((now - start) * rate)
            while i < due:
                await sem.acquire()
                t = asyncio.ensure_future(one())
                t.add_done_callback(lambda _t: sem.release())
                tasks.add(t)
                t.add_done_callback(tasks.discard)
                i += 1
            if now >= next_report:
                out(progress=int(now - start), epoch='%.2f' % time.time(), started=i, ok=stats['ok'],
                    fail=stats['fail'])
                next_report += 1
            await asyncio.sleep(0.002)
        load_end = time.monotonic()
        # a last progress line at the moment the load stops, so a log line from its final second
        # still has a count next to it
        out(progress=int(load_end - start), epoch='%.2f' % time.time(), started=i, ok=stats['ok'],
            fail=stats['fail'])
        if tasks:
            await asyncio.wait(tasks)
        elapsed = load_end - start
        out(started=i, ok=stats['ok'], fail=stats['fail'], seconds='%.1f' % elapsed,
            rate='%d' % (stats['ok'] / elapsed), p50_ms=ms(pct(lat, 0.5)), p99_ms=ms(pct(lat, 0.99)))
    asyncio.run(main())


def tcp_rtt(ip, port, interval, seconds, stopfile=None):
    rtts, fails, reconnects = [], 0, 0
    s = None
    end = time.monotonic() + seconds
    i = 0
    while time.monotonic() < end and not (stopfile and os.path.exists(stopfile)):
        t0 = time.monotonic()
        try:
            if s is None:
                s = socket.create_connection((ip, port), timeout=5)
                s.settimeout(5)
            msg = b'k%d\n' % i
            s.sendall(msg)
            got = b''
            while not got.endswith(b'\n'):
                d = s.recv(4096)
                if not d:
                    raise OSError('closed')
                got += d
            rtts.append(time.monotonic() - t0)
        except OSError:
            fails += 1
            if s is not None:
                s.close()
                reconnects += 1
            s = None
        i += 1
        time.sleep(max(0, interval - (time.monotonic() - t0)))
    if s is not None:
        s.close()
    out(sent=i, ok=len(rtts), fail=fails, reconnects=reconnects, p50_ms=ms(pct(rtts, 0.5)),
        p99_ms=ms(pct(rtts, 0.99)), max_ms=ms(max(rtts) if rtts else -1))


def udp_rtt(ip, port, interval, seconds):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, port))
    s.settimeout(1.0)
    rtts, lost = [], 0
    end = time.monotonic() + seconds
    i = 0
    while time.monotonic() < end:
        t0 = time.monotonic()
        tag = b'g%08d' % i + b'.' * 92
        try:
            s.send(tag)
            while True:
                d = s.recv(2048)
                if d[:9] == tag[:9]:
                    break
            rtts.append(time.monotonic() - t0)
        except OSError:
            lost += 1
        i += 1
        time.sleep(max(0, interval - (time.monotonic() - t0)))
    out(sent=i, ok=len(rtts), lost=lost, p50_ms=ms(pct(rtts, 0.5)), p99_ms=ms(pct(rtts, 0.99)),
        max_ms=ms(max(rtts) if rtts else -1))


def hold(ip, port, srcs, per, nbytes, hold_s):
    payload = b'h' * nbytes

    async def one(src):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, local_addr=(src, 0)), 10)
        except (OSError, asyncio.TimeoutError):
            return None
        try:
            w.write(payload)
            await asyncio.wait_for(w.drain(), 10)
        except (OSError, asyncio.TimeoutError):
            pass
        return w

    async def main():
        t0 = time.monotonic()
        ws = await asyncio.gather(*[one(s) for s in srcs for _ in range(per)])
        held = [w for w in ws if w is not None]
        out(attempted=len(srcs) * per, established=len(held), open_seconds='%.2f' % (time.monotonic() - t0))
        await asyncio.sleep(hold_s)
        for w in held:
            w.close()
    asyncio.run(main())


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ackflood(ip, port, seconds):
    # Learn the connection's sequence numbers from the last segment the peer sent us: its sequence
    # number plus its length is our rcv_nxt, and its acknowledgment number is our snd_nxt once our
    # line has been echoed. The client network namespace is expected to run without TCP
    # timestamps, so a bare 20-byte TCP header is a segment the peer accepts.
    sniff = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    sniff.bind(('eth0', 0))
    sniff.setblocking(False)
    c = socket.create_connection((ip, port), timeout=5)
    c.settimeout(5)
    src_ip, src_port = c.getsockname()
    c.sendall(b'before\n')
    got = b''
    while not got.endswith(b'\n'):
        got += c.recv(4096)
    time.sleep(0.5)
    dst = socket.inet_aton(ip)
    last = None
    while True:
        try:
            p = sniff.recv(65535)
        except BlockingIOError:
            break
        ihl = (p[0] & 0x0f) * 4
        if p[9] != 6 or p[12:16] != dst:
            continue
        sport, dport, seq, ack = struct.unpack('!HHII', p[ihl:ihl + 12])
        if sport != port or dport != src_port:
            continue
        doff = (p[ihl + 12] >> 4) * 4
        plen = struct.unpack('!H', p[2:4])[0] - ihl - doff
        last = (seq, ack, plen)
    sniff.close()
    if last is None:
        out(error='no-segment-seen')
        return
    snd_nxt, rcv_nxt = last[1], (last[0] + last[2]) & 0xffffffff
    src = socket.inet_aton(src_ip)
    tcp = struct.pack('!HHIIBBHHH', src_port, port, snd_nxt, rcv_nxt, 5 << 4, 0x10, 502, 0, 0)
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, src, dst)
    iph = iph[:10] + struct.pack('!H', csum(iph)) + iph[12:]
    pkt = iph + tcp
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw.setblocking(False)
    out(progress='flooding', sport=src_port)
    sent, busy = 0, 0
    t0 = time.monotonic()
    end = t0 + seconds
    while time.monotonic() < end:
        for _ in range(256):
            try:
                raw.sendto(pkt, (ip, 0))
                sent += 1
            except BlockingIOError:
                busy += 1
                break
            except OSError:
                busy += 1
                break
    el = time.monotonic() - t0
    raw.close()
    alive = 0
    try:
        c.sendall(b'after\n')
        got = b''
        while not got.endswith(b'\n'):
            d = c.recv(4096)
            if not d:
                break
            got += d
        alive = 1 if got == b'after\n' else 0
    except OSError:
        pass
    c.close()
    out(sent=sent, seconds='%.1f' % el, pps=int(sent / el), alive_after=alive)


def bulk_up(ip, port, nbytes):
    s = socket.create_connection((ip, port), timeout=10)
    s.settimeout(30)
    chunk = b'u' * 65536
    t0 = time.monotonic()
    left = nbytes
    while left > 0:
        n = min(left, len(chunk))
        s.sendall(chunk[:n])
        left -= n
    s.shutdown(socket.SHUT_WR)
    reply = b''
    while True:
        d = s.recv(4096)
        if not d:
            break
        reply += d
    el = time.monotonic() - t0
    s.close()
    got = reply.split(b'got=')[-1].split(b';')[0].split()[0].decode() if b'got=' in reply else '-1'
    out(sent=nbytes, echoed=got, mbit='%.0f' % (nbytes * 8 / el / 1e6))


def bulk_down(ip, port):
    s = socket.create_connection((ip, port), timeout=10)
    s.settimeout(30)
    t0 = time.monotonic()
    n = 0
    while True:
        d = s.recv(262144)
        if not d:
            break
        n += len(d)
    el = time.monotonic() - t0
    s.close()
    out(received=n, mbit='%.0f' % (n * 8 / el / 1e6))


def keys(ip, port, count, think):
    s = socket.create_connection((ip, port), timeout=10)
    s.settimeout(5)
    rtts, bad = [], 0
    for i in range(count):
        t0 = time.monotonic()
        k = bytes([97 + i % 26]) + b'\n'
        try:
            s.sendall(k)
            got = b''
            while not got.endswith(b'\n'):
                d = s.recv(64)
                if not d:
                    raise OSError('closed')
                got += d
            if got != k:
                bad += 1
            rtts.append(time.monotonic() - t0)
        except OSError:
            bad += 1
            break
        time.sleep(think)
    s.close()
    out(keys=count, echoed=len(rtts) - bad, p50_ms=ms(pct(rtts, 0.5)), p99_ms=ms(pct(rtts, 0.99)))


def main():
    a = sys.argv[1:]
    cmd = a[0] if a else ''
    if cmd == 'serve-close-first':
        serve(a[1], int(a[2]), close_first)
    elif cmd == 'serve-lines':
        serve(a[1], int(a[2]), lines)
    elif cmd == 'serve-source':
        serve(a[1], int(a[2]), source_handler(int(a[3])))
    elif cmd == 'serve-http':
        serve_http(a[1], int(a[2]), a[3])
    elif cmd == 'serve-udp-echo':
        udp_echo(a[1], int(a[2]))
    elif cmd == 'serve-udp-blast':
        udp_blast(a[1], int(a[2]), int(a[3]), float(a[4]))
    elif cmd == 'churn':
        churn(a[1], int(a[2]), float(a[3]), float(a[4]), a[5], a[6] if len(a) > 6 and a[6] != '-' else None,
              int(a[7]) if len(a) > 7 else 0)
    elif cmd == 'tcp-rtt':
        tcp_rtt(a[1], int(a[2]), float(a[3]), float(a[4]), a[5] if len(a) > 5 else None)
    elif cmd == 'udp-rtt':
        udp_rtt(a[1], int(a[2]), float(a[3]), float(a[4]))
    elif cmd == 'hold':
        hold(a[1], int(a[2]), a[3].split(','), int(a[4]), int(a[5]), float(a[6]))
    elif cmd == 'ackflood':
        ackflood(a[1], int(a[2]), float(a[3]))
    elif cmd == 'bulk-up':
        bulk_up(a[1], int(a[2]), int(a[3]))
    elif cmd == 'bulk-down':
        bulk_down(a[1], int(a[2]))
    elif cmd == 'keys':
        keys(a[1], int(a[2]), int(a[3]), float(a[4]))
    else:
        print('usage: traffic.py <subcommand> ...; see the header of this file', file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
