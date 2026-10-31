#!/usr/bin/env python3
# agentmem.py computes the design's process bound of the userspace agent for given settings, and
# summarizes one run's probe file against it. lab/agentmem.sh calls it.
#
#   agentmem.py bound <gvisor|wgstack> <K> <U> <L-tcp> <L-udp> [wg-total-mib wg-transient-mib wg-mfix-mib]
#   agentmem.py summarize <gvisor|wgstack> <K> <U> <L-tcp> <L-udp> <probe.jsonl> <rss-peak-mib> <gctrace-peak-mib>
#
# The terms are those of docs/design/userspace/memory-agent-host.md and memory-server.md, for an
# agent behind a kernel-mode vpsd: a live heap that is a sum of terms, the process bound being twice
# that sum (GOGC 100) plus the goroutine stacks plus the runtime's 10 MiB and 5 % of the live heap.
# With gVisor the accept queue is 1790 MiB for each TCP listener (an untrusted public side); with
# wgstack the netstack terms come from Device.Bound, which the probe file records.
#
# The wireguard-go queues depend on the CPU count C = CPUs + 6 of the agent host: the send side holds
# N_tx = 1153 + C buffers of 64 KiB, the receive side 1027, and with wgstack the send batching budget
# adds W_tx: P_max more buffers, plus the k_tx = 32 buffers the TUN reader keeps
# (docs/design/userspace/wgstack-batching.md). CPUs is this host's count unless AGENTMEM_CPUS sets
# it; P_max is the agent's default for K and U unless WGFT_AGENT_BATCH_MIB sets it in MiB.
import json
import os
import sys

MIB = 1.0
BUF = 64 / 1024  # MiB of one wireguard-go buffer on Linux
K_TX = 32


def cpus():
    return int(os.environ.get('AGENTMEM_CPUS') or os.cpu_count() or 1)


def n_tx():
    return 1153 + cpus() + 6


def p_max(K, U):
    upper = n_tx() * K_TX
    mib = os.environ.get('WGFT_AGENT_BATCH_MIB', '')
    if mib != '':
        return min(int(int(mib) / BUF), upper)
    soft = 32 + U * 12 / 1024 + K * 44 / 1024
    return min(int(soft / 4 / BUF), upper)


def common(K, U, Ltcp, Lcud):
    return {
        'fixed (runtime, tunnel)': 20,
        'responses and UDP listener reads': 7 + 0.46 * Lcud,
        'UDP sessions': 1.2 * U / 1024,
    }


def gvisor_terms(K, U, Ltcp, Lcud):
    t = common(K, U, Ltcp, Lcud)
    t.update({
        'wireguard-go queues ((N_tx + 1027) x 64 KiB + 65 MiB)': (n_tx() + 1027) * BUF + 65,
        'reassembly and peer': 4 + 0.15,
        'UDP receive accounting': 10.4,
        'netstack output queue': 64,
        'TCP flows (1,598 KiB x K)': 1598 * K / 1024,
        'TCP boost': 357,
        'empty-ACK queue (514 KiB x K + 108 MiB)': 514 * K / 1024 + 108,
        'closed-connection table': 128,
        'accept queue (1,790 MiB x listeners)': 1790 * Ltcp,
        'trial dials, old generations': 4.4,
    })
    return t


def wgstack_terms(K, U, Ltcp, Lcud, total, transient, mfix):
    t = common(K, U, Ltcp, Lcud)
    t.update({
        'wireguard-go queues ((N_tx + k_tx + P_max + 1027) x 64 KiB + 65 MiB)':
            (n_tx() + K_TX + p_max(K, U) + 1027) * BUF + 65,
        'peer wait': 0.15,
        'TCP relay share (74 KiB x K)': 74 * K / 1024,
        'trial dials, one old generation (4.4 MiB + M_fix)': 4.4 + mfix,
        'wgstack Bound.Total': total,
        'wgstack Bound.Transient': transient,
    })
    return t


def process_bound(live, K, U):
    stacks = (2.2 * U + 24 * K) / 1024 + 2
    return 2 * live + stacks + 10 + 0.05 * live


def bound(ns, K, U, Ltcp, Lcud, wg=None):
    if ns == 'gvisor':
        terms = gvisor_terms(K, U, Ltcp, Lcud)
    else:
        terms = wgstack_terms(K, U, Ltcp, Lcud, *wg)
    live = sum(terms.values())
    return live, process_bound(live, K, U), terms


def read_probe(path):
    rows = []
    for line in open(path):
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def main():
    a = sys.argv[1:]
    cmd, ns = a[0], a[1]
    K, U, Lt, Lu = int(a[2]), int(a[3]), int(a[4]), int(a[5])
    if cmd == 'bound':
        wg = tuple(float(x) for x in a[6:9]) if ns == 'wgstack' else None
        live, proc, terms = bound(ns, K, U, Lt, Lu, wg)
        for k, v in terms.items():
            print('%-52s %10.1f MiB' % (k, v))
        print('%-52s %10.1f MiB' % ('live heap bound', live))
        print('%-52s %10.1f MiB' % ('process bound', proc))
        return
    rows = read_probe(a[6])
    rss_peak, gc_peak = float(a[7]), float(a[8])
    wg = None
    st_max = {}
    if rows:
        b = next((r['bound'] for r in rows if 'bound' in r), None)
        if ns == 'wgstack' and b:
            wg = (b['Total'] / 2**20, b['Transient'] / 2**20, b['Fix'] / 2**20)
        for r in rows:
            for k, v in (r.get('stats') or {}).items():
                if isinstance(v, (int, float)) and v > st_max.get(k, 0):
                    st_max[k] = v
    if ns == 'wgstack' and wg is None:
        print('RESULT error=no-bound-in-probe')
        sys.exit(1)
    live_b, proc_b, _ = bound(ns, K, U, Lt, Lu, wg)
    live_peak = max((r['live'] for r in rows), default=0) / 2**20
    heap_peak = max((r['heap'] for r in rows), default=0) / 2**20
    total_peak = max((r['total'] for r in rows), default=0) / 2**20
    probe_rss = max((r['rss'] for r in rows), default=0) / 2**20
    probe_hwm = max((r['hwm'] for r in rows), default=0) / 2**20
    idle_rss = rows[2]['rss'] / 2**20 if len(rows) > 2 else 0
    idle_live = rows[2]['live'] / 2**20 if len(rows) > 2 else 0
    peak_rss = max(rss_peak, probe_rss, probe_hwm)
    peak_live = max(live_peak, gc_peak)
    print('RESULT netstack=%s K=%d U=%d tcp_listeners=%d samples=%d idle_rss_mib=%.0f idle_live_mib=%.0f '
          'peak_rss_mib=%.0f peak_live_mib=%.0f peak_heap_mib=%.0f peak_runtime_total_mib=%.0f '
          'live_bound_mib=%.0f process_bound_mib=%.0f rss_over_bound=%.3f live_over_bound=%.3f' % (
              ns, K, U, Lt, len(rows), idle_rss, idle_live, peak_rss, peak_live, heap_peak, total_peak,
              live_b, proc_b, peak_rss / proc_b, peak_live / live_b))
    if ns == 'wgstack' and st_max:
        keys = ['Conns', 'SynRows', 'TWRows', 'AcceptQueued', 'CtlQueued', 'ChunkBytes', 'RecordBytes',
                'IntervalBytes', 'Boosted', 'Reserved', 'UDPRxBytes', 'UDPRxDatagrams', 'FragBytes',
                'MSSFloorDrops', 'SynTableFull', 'AcceptOverflow', 'TWEvicted', 'CtlDropped', 'OOODropped',
                'RecvTrimmed', 'UDPDropped', 'BoostGranted', 'AccountingFaults']
        print('STATS max ' + ' '.join('%s=%d' % (k, st_max.get(k, 0)) for k in keys))
        held = st_max.get('ChunkBytes', 0) + st_max.get('RecordBytes', 0) + st_max.get('IntervalBytes', 0)
        print('STATS held_mib(chunks+records+intervals)=%.1f bound_total_mib=%.1f' % (held / 2**20, wg[0]))


if __name__ == '__main__':
    main()
