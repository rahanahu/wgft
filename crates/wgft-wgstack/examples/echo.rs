//! A TCP echo server on a sans-IO `Stack`, driven by a hand-written peer.
//!
//! Run it with `cargo run --example echo`. Real code moves the packets through a TUN device, a tunnel or
//! a simulator instead of the `Peer` below; the loop around the stack stays the same:
//!
//! 1. give every received IPv4 packet to [`Stack::handle_packet`];
//! 2. call [`Stack::handle_timeout`] when the time from [`Stack::poll_timeout`] has come;
//! 3. act on every [`Stack::poll_event`]: accept, read, write, close;
//! 4. send every packet from [`Stack::poll_transmit`], including what step 3 queued.

// The crate's clippy.toml keeps growing collections and strings out of the stack; the example is not the
// stack and may use them.
#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the example is an application around the stack"
)]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use wgft_wgstack::{Budget, Config, ConnId, Error, Event, NoHook, Stack, Time};

const STACK_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const MTU: usize = 1500;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new(STACK_ADDR, MTU);
    let budget = Budget::new(config.limits.boost_slots)?;
    // The seed keys the ISN, timestamp and table hashes. Real code takes 64 bytes from the OS RNG.
    let seed = [7u8; 64];
    let mut stack = Stack::new(config, budget, &seed, NoHook)?;
    println!("bound: {} bytes", stack.bound().total);

    // The stack's clock is the caller's: any monotonic time in nanoseconds from any origin.
    let mut now = Time::from_nanos(0);
    let listener = stack.listen_tcp(now, SocketAddrV4::new(STACK_ADDR, 7))?;

    let mut peer = Peer::new(40000);
    let mut to_stack = vec![peer.syn()];
    let mut echoed = Vec::new();
    let mut echo = Echo::default();

    for _ in 0..100 {
        // 1. Packets from the network.
        for pkt in to_stack.drain(..) {
            stack.handle_packet(now, &pkt);
        }
        // 2. Timers.
        if stack.poll_timeout().is_some_and(|t| t <= now) {
            stack.handle_timeout(now);
        }
        // 3. Events: the stack says what may have become possible; the caller tries it and, on
        // `WouldBlock`, waits for the next event.
        while let Some(event) = stack.poll_event() {
            match event {
                Event::Acceptable(l) => {
                    while let Ok((conn, from)) = stack.accept(now, l) {
                        println!("accepted {conn:?} from {from}");
                    }
                }
                Event::Readable(conn) => {
                    echo.read(&mut stack, now, conn)?;
                    echo.flush(&mut stack, now, conn)?;
                }
                Event::Writable(conn) => echo.flush(&mut stack, now, conn)?,
                Event::Closed(conn) => println!("closed {conn:?}"),
                _ => {}
            }
        }
        // 4. Packets to the network; here the peer answers them.
        let mut out = vec![0u8; MTU];
        while let Some(n) = stack.poll_transmit(now, &mut out) {
            to_stack.extend(peer.receive(&out[..n], &mut echoed));
        }
        if peer.done && to_stack.is_empty() {
            break;
        }
        now = now + Duration::from_millis(1);
    }
    println!("echoed: {:?}", String::from_utf8_lossy(&echoed));
    assert_eq!(echoed, b"hello, stack");
    stack.close_listener(now, listener);
    let closed = stack.close(now);
    assert!(closed.held.is_zero());
    Ok(())
}

/// The echo server's state for its connection: bytes read but not yet taken by `write`, and whether the
/// peer has closed its side.
#[derive(Default)]
struct Echo {
    pending: Vec<u8>,
    peer_closed: bool,
    closed: bool,
}

impl Echo {
    /// Reads everything readable now. `Ok(0)` is the peer's FIN.
    fn read(&mut self, stack: &mut Stack, now: Time, conn: ConnId) -> Result<(), Error> {
        if self.closed {
            // After `close_conn` the handle is closed; later events for it need no action.
            return Ok(());
        }
        let mut buf = [0u8; 1024];
        loop {
            match stack.read(now, conn, &mut buf) {
                Ok(0) => {
                    self.peer_closed = true;
                    return Ok(());
                }
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
                Err(Error::WouldBlock) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Writes as much of the pending bytes as the send buffer takes. `write` may take only part of them, and
    /// returns `WouldBlock` when the buffer is full; `Event::Writable` then says when to try again. Once
    /// everything is written after the peer's FIN, closes the connection.
    fn flush(&mut self, stack: &mut Stack, now: Time, conn: ConnId) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        while !self.pending.is_empty() {
            match stack.write(now, conn, &self.pending) {
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(Error::WouldBlock) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        if self.peer_closed && !self.closed {
            stack.close_conn(now, conn);
            self.closed = true;
        }
        Ok(())
    }
}

/// A minimal TCP client: it connects, sends one message with FIN, and acknowledges what it receives.
struct Peer {
    port: u16,
    snd_nxt: u32,
    rcv_nxt: u32,
    sent: bool,
    done: bool,
}

impl Peer {
    fn new(port: u16) -> Self {
        Self {
            port,
            snd_nxt: 1000,
            rcv_nxt: 0,
            sent: false,
            done: false,
        }
    }

    fn syn(&mut self) -> Vec<u8> {
        // MSS option 1460.
        let p = tcp(self.port, self.snd_nxt, 0, SYN, &[2, 4, 0x05, 0xb4], &[]);
        self.snd_nxt += 1;
        p
    }

    /// Handles one packet from the stack and returns the peer's answers.
    fn receive(&mut self, pkt: &[u8], echoed: &mut Vec<u8>) -> Vec<Vec<u8>> {
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if pkt[9] != 6 {
            return Vec::new();
        }
        let t = &pkt[ihl..];
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let flags = t[13];
        let data = &t[usize::from(t[12] >> 4) * 4..];
        let mut answers = Vec::new();
        if flags & SYN != 0 {
            self.rcv_nxt = seq.wrapping_add(1);
        } else if seq == self.rcv_nxt {
            echoed.extend_from_slice(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(len32(data.len()));
            if flags & FIN != 0 {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.done = true;
            }
        }
        answers.push(tcp(self.port, self.snd_nxt, self.rcv_nxt, ACK, &[], &[]));
        if !self.sent {
            self.sent = true;
            let msg = b"hello, stack";
            answers.push(tcp(
                self.port,
                self.snd_nxt,
                self.rcv_nxt,
                ACK | PSH | FIN,
                &[],
                msg,
            ));
            self.snd_nxt = self.snd_nxt.wrapping_add(len32(msg.len()) + 1);
        }
        answers
    }
}

/// Builds an IPv4 TCP packet from the peer to the stack's port 7.
fn tcp(sport: u16, seq: u32, ack: u32, flags: u8, opts: &[u8], data: &[u8]) -> Vec<u8> {
    let thl = 20 + opts.len();
    let total = 20 + thl + data.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&len16(total).to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&PEER_ADDR.octets());
    p[16..20].copy_from_slice(&STACK_ADDR.octets());
    let ip_sum = checksum(0, &p[..20]);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let t = &mut p[20..];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&7u16.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = u8::try_from(thl / 4).expect("a TCP header length") << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    t[20..thl].copy_from_slice(opts);
    t[thl..].copy_from_slice(data);
    // The TCP checksum covers a pseudo-header of the addresses, the protocol and the TCP length.
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&PEER_ADDR.octets());
    pseudo[4..8].copy_from_slice(&STACK_ADDR.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&len16(thl + data.len()).to_be_bytes());
    let sum = checksum(sum16(0, &pseudo), &p[20..]);
    p[36..38].copy_from_slice(&sum.to_be_bytes());
    p
}

fn sum16(mut acc: u32, b: &[u8]) -> u32 {
    for c in b.chunks(2) {
        acc += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    acc
}

fn checksum(acc: u32, b: &[u8]) -> u16 {
    let mut s = sum16(acc, b);
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !u16::try_from(s).expect("folded to 16 bits")
}

fn len16(n: usize) -> u16 {
    u16::try_from(n).expect("a packet length")
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).expect("a segment length")
}
