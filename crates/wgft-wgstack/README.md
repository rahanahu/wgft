<!-- docs-pair: README.ja.md -->
# wgstack

A user-space IPv4 TCP/IP stack for embedding in Rust applications, with an explicit, accounted memory bound.

wgstack is sans-IO: it owns no threads, sockets, timers or randomness.
The application gives it received IPv4 packets, the current time and a random seed, and takes from it the packets to send, the next time to wake it, and events.
It suits applications that cannot or do not want to use the operating system's TCP/IP stack, such as VPNs, tunnels, proxies and network simulators.

The crate depends only on the standard library and forbids `unsafe` code.
It was written for [wgft](https://github.com/rahanahu/wgft), which remains its main user, but does not depend on wgft.

## Status: Experimental

- The API may change in any release.
- Distribution is through Git only; the crate is not on crates.io.
  The package name `wgft-wgstack` is provisional and will change before a crates.io release.
- wgft's userspace mode uses it; it is tested against Linux TCP through wgft's integration lab, by unit and white-box tests, and by fuzzing.

```toml
[dependencies]
wgft-wgstack = { git = "https://github.com/rahanahu/wgft" }
```

Pin a revision with `rev = "..."`; there are no tags for this crate yet.

## Scope and known limits

The stack handles IPv4, TCP, UDP and the ICMPv4 it needs (echo, errors, path MTU discovery), with IPv4 reassembly.
TCP includes SACK, D-SACK, timestamps, window scaling, RACK-TLP, spurious-retransmission undo, CUBIC and NewReno, and SYN cookies.

What it does not do yet:

- **No active open.** The stack accepts connections (`listen_tcp`, `accept`) but cannot connect to a peer.
- **One local address.** A stack has a single IPv4 address (`Config::addr`) and drops packets to any other destination.
  It cannot accept connections to arbitrary destinations, as a transparent proxy or the client side of a VPN would need.
- IPv4 only; no IPv6.
- No ECN negotiation, no TCP keepalive, no urgent data, no per-connection retransmission timeout setting.
- ICMP errors are not delivered to the application.
- Packets go out with TOS 0, TTL 64 and no IP options; received IP options are skipped.
- TIME_WAIT lasts 60 seconds.
- A stack is driven by one owner through `&mut` and does no internal parallelism.

Deviations from the RFCs are recorded, with reasons, in wgft's design document `docs/design/v2/wgstack-rs.md` (in Japanese).

## Using the sans-IO API

A `Stack` is created from a `Config`, a `Budget` (the boost slots, see below), a 64-byte random seed and a `Hook` (`NoHook` when the application needs no boost callbacks).
The application then repeats one turn:

1. pass each received IPv4 packet to `handle_packet`;
2. when the time from `poll_timeout` has come, call `handle_timeout`;
3. take each `Event` from `poll_event` and act on it;
4. send each packet that `poll_transmit` writes into its buffer, including what step 3 queued.

`poll_transmit` needs a buffer of at least the MTU and panics on a shorter one.

Operations never block.
An operation that cannot proceed now returns `Error::WouldBlock` and changes nothing; an event says when it may succeed.
Events are hints, not state: on an event, try the operation, and wait for the next event on `WouldBlock`.

```rust
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use wgft_wgstack::{Budget, Config, Event, NoHook, Stack, Time};

/// One turn of the loop: feed packets in, run timers, handle events, send packets out.
fn turn(stack: &mut Stack, now: Time, received: &[Vec<u8>], send: &mut impl FnMut(&[u8])) {
    for pkt in received {
        stack.handle_packet(now, pkt);
    }
    if stack.poll_timeout().is_some_and(|t| t <= now) {
        stack.handle_timeout(now);
    }
    while let Some(event) = stack.poll_event() {
        match event {
            Event::Acceptable(listener) => {
                while let Ok((conn, _peer)) = stack.accept(now, listener) {
                    // A new connection has room for these 6 bytes; `examples/echo.rs` handles
                    // partial writes and `WouldBlock`.
                    let _ = stack.write(now, conn, b"hello\n");
                    stack.close_conn(now, conn);
                }
            }
            // Readable, Writable, Closed, UdpReadable, UdpWritable, PingReply, ...
            _ => {}
        }
    }
    let mut buf = vec![0u8; stack.config().mtu];
    while let Some(n) = stack.poll_transmit(now, &mut buf) {
        send(&buf[..n]);
    }
}

let addr = Ipv4Addr::new(10, 0, 0, 1);
let config = Config::new(addr, 1500);
let budget = Budget::new(config.limits.boost_slots)?;
let seed = [7u8; 64]; // take 64 bytes from the OS random number generator in real code
let mut stack = Stack::new(config, budget, &seed, NoHook)?;
let mut now = Time::from_nanos(0); // any monotonic clock, from any origin
stack.listen_tcp(now, SocketAddrV4::new(addr, 7))?;
for _ in 0..3 {
    turn(&mut stack, now, &[], &mut |_pkt| {});
    now = now + Duration::from_millis(10);
}
let closed = stack.close(now);
assert!(closed.held.is_zero());
# Ok::<(), Box<dyn std::error::Error>>(())
```

`examples/echo.rs` runs a complete exchange with a hand-written peer: `cargo run --example echo`.

Time is a `Time` in nanoseconds from an origin the application chooses; it must not go backwards.
The seed keys the initial sequence numbers, timestamps and table hashes, so it must be secret and random.

## Memory: limits, accounting and the bound

Every table the stack uses is sized at creation from `Limits` and never grows.
Buffers are fixed-size 16 KiB chunks that a connection takes as data arrives, inside a reservation that the limits fix.
`Bound::for_limits(&limits, mtu)` computes, before anything is allocated, the most heap memory the stack will request; `Stack::held` reports what it holds now, and `Stack::stats` counts every packet dropped and why.

The bound has these terms:

| term | what it covers |
| --- | --- |
| `fix` | tables allocated at creation: connection slots, indexes, half-open and TIME_WAIT rows, the per-port listener and UDP endpoint tables, timers, output lists and the control ring, events, kept pool chunks |
| `floor_conn` | the 256 KiB send and 256 KiB receive floors of every connection slot, and their record and interval arrays |
| `boost` | the boost slots: larger buffers (up to 4 MiB each way) that a busy connection may borrow |
| `frag` | the reassembly byte limit |
| `udp_rx`, `udp_tx` | the UDP receive and send byte budgets and their datagram tables |
| `ping` | ping endpoints and reply buffers |

What happens at each limit:

| limit | when reached |
| --- | --- |
| connection slots (`max_flows` + `accept_queue`) | the final ACK of a new handshake is dropped (`accept_overflow`); the peer may retry |
| accept queue (`accept_queue`, half per listener) | the final ACK is dropped and the half-open row kept until there is room |
| half-open rows (`syn_rows`, half per listener) | SYNs are answered with SYN cookies; dropped if the accept queue is also full |
| TIME_WAIT rows (`tw_rows`) | the oldest row is evicted (`tw_evicted`), which weakens that 4-tuple's protection against old duplicates |
| a connection's send buffer | `write` returns `WouldBlock`; `Event::Writable` follows when acknowledged data frees room |
| a connection's receive buffer | the advertised window closes; out-of-order data beyond the interval table is dropped (`ooo_dropped`) |
| boost slots (`boost_slots`) | the connection stays at its floors; an idle holder may be moved back to its floors |
| control ring (`ctl_slots`) | new control packets (RSTs, handshake replies, ICMP) are dropped (`ctl_dropped`); `send_ping` returns `NoBufferSpace` |
| reassembly (`frag_entries`, `frag_pieces`, `frag_bytes`) | the oldest incomplete datagram is evicted, else the fragment dropped |
| UDP receive budget | new datagrams are dropped (`udp_dropped`) |
| UDP send budget | `send_to` returns `WouldBlock` and `Event::UdpWritable` follows; `send_to_latest` drops the oldest queued datagram instead |
| ping endpoints (16) | `open_ping` returns `TableFull` |

The stack never discards data it has acknowledged in order on its own initiative.
Such data is discarded only in these cases:

- the application ends the connection with `abort`, with `close_conn` while unread data remains (a reset, as Linux does), with `close_listener` while the connection is still in the accept queue, or with `Stack::close`;
- the stack closes the connection after an internal accounting error (`Error::Accounting`).

When a boost slot is taken back, out-of-order data that the stack announced with SACK may be discarded (RFC 2018 reneging), and the peer retransmits it.
Allocation failure is not an abort: tables and buffers are allocated fallibly, `write` returns `Error::NoMemory` without changing state, and a received segment whose buffer cannot be allocated is dropped (`recv_no_memory`).

### What the bound does not include

The bound is the sum of the sizes the stack requests from the allocator.
The process RSS is a different number:

- the allocator adds rounding and its own bookkeeping, and may keep freed memory in the process;
- memory that was allocated but never touched may not be resident at all, so RSS can be below the bound's used part;
- the caller's packet buffers, the `Hook`'s own state, the call stack, and anything the application keeps per connection are outside the stack.

The bound is an upper limit on what the stack holds, not a promise that every allocation within it succeeds.

There is no stack-wide dynamic memory budget yet.
Each table and buffer has its own fixed limit, and the bound is their sum; the stack does not yet move memory between connections, UDP and reassembly according to use.
This is planned, and the current structure (exact accounting of every reservation) is meant to support it.

### The default limits

`Limits::default()` (and `Config::new`) is small and conservative: 16 + 16 connection slots, 64 half-open rows, 1024 TIME_WAIT rows, 32 control slots, reassembly of 8 datagrams in 64 fragments and 256 KiB, UDP budgets of 256 KiB and 128 datagrams each way, no boost slots and 8 kept pool chunks.

Measured on x86_64 Linux, release build, MTU 1420:

- bound 21.6 MiB, of which 4.2 MiB fixed and 16.7 MiB connection floors;
- 4.1 MiB allocated at creation (RSS grew by 4.3 MiB), most of it the per-port listener and UDP endpoint tables, which cost the same at any limits;
- one connection moving 4 MiB each way: no retransmissions, peak allocation 4.2 MiB including creation;
- all 32 slots in use with both floors full: 20.8 MiB allocated, inside the bound; the 33rd handshake is dropped as `accept_overflow`.

Without boost slots a connection's window stays at 256 KiB, which allows about 40 Mbit/s over a 50 ms round trip (computed, not measured).
Each boost slot adds about 7.8 MiB to the bound and lets one busy connection grow to 4 MiB buffers; set `boost_slots` and create the `Budget` with the same number.
For many connections, raise `max_flows` and `accept_queue`; each slot adds about 0.53 MiB to the bound.

```rust
use wgft_wgstack::{Bound, Limits};

let limits = Limits { max_flows: 64, accept_queue: 32, boost_slots: 2, ..Limits::default() };
let bound = Bound::for_limits(&limits, 1500);
assert!(bound.total < 128 << 20);
```

## Safety and panics

- No `unsafe` code (`#![forbid(unsafe_code)]`); packet parsing works on slices with bounds checks.
- A panic inside the stack is a bug. After a panic, drop the `Stack`; do not keep using it.
- The crate's tests and fuzzing run with overflow checks on; enable them in your release builds too:

  ```toml
  [profile.release]
  overflow-checks = true
  ```

  Overflow checks are a code-generation setting of the crate that compiles the code, and only the application's workspace sets profiles.
  The generic parts of the stack (the `Stack<H>` methods, `impl<H: Hook> Stack<H>`) and small functions inlined from them are compiled in the crate that names `Stack<...>`, under that crate's profile.
  A per-package override for `wgft-wgstack` alone therefore leaves that code unchecked; if you narrow the setting, override both `wgft-wgstack` and the crate that names `Stack<...>`.
  Without the checks an arithmetic overflow, which would be a bug, wraps instead of panicking.
  Memory safety does not depend on it, but that stack's state and accounting may then be wrong.

## Threads

A `Stack<NoHook>` and a `Budget` are `Send`: a stack can move between threads, but one owner drives it at a time.
To use several cores, run several stacks, each with its own address.

## Provenance

wgstack is a Rust port of the Go TCP/IP stack in wgft, written by the wgft authors.
It contains no code from gVisor, smoltcp or other TCP/IP stacks.

## License

MIT, see `LICENSE`.
