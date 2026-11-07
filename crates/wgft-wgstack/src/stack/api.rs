//! アプリケーションの操作 (wgstack-rs.md の「アプリケーションの操作」、Go の `conn.go` と `listener.go`)。
//!
//! 操作はどれも待たずに戻ります。「今はできない」は [`Error::WouldBlock`] で返し、できるようになったら
//! [`Event`] を出します。`WouldBlock` を返す操作は核の状態を変えません。
//!
//! 古い handle (枠が TIME_WAIT の表の行に移った後か、別の接続に使われた後の [`ConnId`]) は Go の古い接続の値と
//! 同じく振る舞います。`delivered` は真を返し、`close_conn` は何もせず、`read` と `write` は [`Error::Closed`] を返し、
//! `abort` は元の接続の行が表に残っていれば行を外して RST を送ります。

use super::shared::EV_ACCEPT;
use super::{Hook, Stack};
use crate::config::BoostPolicy;
use crate::icmp::PingId;
use crate::tcp::boost::Dir;
use crate::tcp::conn::{ConnError, ConnId, State};
use crate::tcp::listen;
use crate::time::Time;
use crate::udp::UdpId;
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};

/// A handle to a listener. It pairs a port with a 32-bit generation, so a handle used after the listener is closed is
/// an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerId {
    pub(crate) port: u16,
    pub(crate) generation: u32,
}

impl ListenerId {
    /// The listener's port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A notification that a connection or listener may have become ready. An event is a trigger, not the source of truth
/// about state: when the caller receives one it tries the operation, and on `WouldBlock` waits for the next event. More
/// kinds may be added, so the caller ignores kinds it does not know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// There may be data to read, an EOF or an error.
    Readable(ConnId),
    /// Space may have opened in the send buffer, or the connection may have become unwritable.
    Writable(ConnId),
    /// The protocol has finished. An event delivered after the slot has been released carries the handle of the
    /// connection that last used the slot.
    Closed(ConnId),
    /// There is a connection in the accept queue.
    Acceptable(ListenerId),
    /// The UDP socket may have a datagram to read.
    UdpReadable(UdpId),
    /// The UDP send budget may have room again. Emitted only for an endpoint whose
    /// [`Stack::send_to`](crate::Stack::send_to) returned [`Error::WouldBlock`].
    UdpWritable(UdpId),
    /// A reply has arrived at the ping endpoint.
    PingReply(PingId),
}

/// The error of an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Not possible now. An event is delivered when it becomes possible.
    WouldBlock,
    /// The handle is closed or stale.
    Closed,
    /// The connection ended because of the peer's RST.
    Reset,
    /// A write was made after the send direction was closed, or to a connection that cannot send.
    BrokenPipe,
    /// The retransmission or window probe attempts are used up.
    TimedOut,
    /// The connection was closed because of an accounting inconsistency.
    Accounting,
    /// A buffer chunk could not be allocated. The state is unchanged.
    NoMemory,
    /// The address is not the stack's address ([`Config::addr`](crate::Config::addr)).
    AddrNotLocal,
    /// Port 0 cannot be listened on.
    PortZero,
    /// The port is already in use.
    AddrInUse,
    /// The destination address or port cannot be used.
    InvalidAddress,
    /// The datagram is too large.
    MessageTooLong,
    /// UDP in this stack is stopped because of a UDP accounting inconsistency.
    UdpStopped,
    /// The table is full.
    TableFull,
    /// The message is not an ICMP echo request, or does not fit in the MTU.
    InvalidMessage,
    /// The control output ring is full.
    NoBufferSpace,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WouldBlock => "operation would block",
            Self::Closed => "use of closed network connection",
            Self::Reset => "connection reset by peer",
            Self::BrokenPipe => "broken pipe",
            Self::TimedOut => "connection timed out",
            Self::Accounting => "closed the connection after an internal accounting error",
            Self::NoMemory => "cannot allocate a buffer chunk",
            Self::AddrNotLocal => "address is not the stack's address",
            Self::PortZero => "port 0 is not supported",
            Self::AddrInUse => "address already in use",
            Self::InvalidAddress => "invalid UDP address",
            Self::MessageTooLong => "message too long",
            Self::UdpStopped => {
                "UDP in this stack stopped after an internal accounting error; recreate the stack to recover"
            }
            Self::TableFull => "all ping endpoints are in use",
            Self::InvalidMessage => "not an ICMP echo request that fits the MTU",
            Self::NoBufferSpace => "the control output ring is full",
        })
    }
}

impl core::error::Error for Error {}

impl From<ConnError> for Error {
    fn from(e: ConnError) -> Self {
        match e {
            ConnError::Reset => Self::Reset,
            ConnError::TimedOut => Self::TimedOut,
            ConnError::Accounting => Self::Accounting,
        }
    }
}

impl<H: Hook> Stack<H> {
    /// Listens for TCP on `addr`, whose address must be the stack's address.
    pub fn listen_tcp(&mut self, now: Time, addr: SocketAddrV4) -> Result<ListenerId, Error> {
        self.clock(now);
        if addr.ip().to_bits() != self.s.addr {
            return Err(Error::AddrNotLocal);
        }
        let port = addr.port();
        if port == 0 {
            return Err(Error::PortZero);
        }
        let generation = self
            .s
            .listeners
            .open(port)
            .map_err(|listen::OpenError::InUse| Error::AddrInUse)?;
        let target = self.s.listener_target(port);
        self.s.events.clear_bits(target, EV_ACCEPT);
        Ok(ListenerId { port, generation })
    }

    /// Returns the connection at the head of the listener's accept queue and the peer's address.
    pub fn accept(&mut self, now: Time, l: ListenerId) -> Result<(ConnId, SocketAddrV4), Error> {
        self.clock(now);
        let s = &mut self.s;
        let Some(row) = s.listeners.get(l.port, l.generation) else {
            return Err(Error::Closed);
        };
        let head = row.qhead;
        if head == crate::output::NIL {
            return Err(Error::WouldBlock);
        }
        listen::dequeue(row, &mut s.qlinks, head);
        let more = row.qhead != crate::output::NIL;
        s.queued -= 1;
        if more {
            self.s.signal_listener(l.port);
        }
        let t = self.conns.tcb_mut(head);
        debug_assert!(t.state != State::Free, "a queued slot is in use");
        t.accepted = true;
        let peer = SocketAddrV4::new(Ipv4Addr::from_bits(t.tup.raddr), t.tup.rport);
        let id = self.conns.id(head);
        if self.s.config.boost == BoostPolicy::AtAccept {
            let now = self.s.now;
            self.conn(head).k.last_demand = now;
            self.try_boost(id, Dir::Recv, now);
        }
        Ok((id, peer))
    }

    /// Closes the listener. Connections in the accept queue and half-open rows are reset with RST and released, and the
    /// port is freed immediately. Does nothing for a stale handle.
    pub fn close_listener(&mut self, now: Time, l: ListenerId) {
        self.clock(now);
        if self.s.listeners.get(l.port, l.generation).is_none() {
            return;
        }
        for id in 0..u32::try_from(self.s.syn.capacity()).unwrap_or(0) {
            let r = *self.s.syn.row(id);
            if r.used && r.listener == l.port {
                self.s.send_ctl(crate::wire::TcpHeader {
                    tup: r.tup,
                    seq: r.iss.wrapping_add(1),
                    ack: r.irs.wrapping_add(1),
                    flags: crate::wire::FLAG_RST | crate::wire::FLAG_ACK,
                    wnd: 0,
                });
                self.s.remove_syn_row(id);
            }
        }
        while let Some(row) = self.s.listeners.get(l.port, l.generation)
            && row.qhead != crate::output::NIL
        {
            let head = row.qhead;
            listen::dequeue(row, &mut self.s.qlinks, head);
            self.s.queued -= 1;
            let mut c = self.conn(head);
            if c.t.state != State::Closed {
                c.send_rst();
            }
            c.release();
        }
        self.s.listeners.close(l.port, l.generation);
        let target = self.s.listener_target(l.port);
        self.s.events.clear_bits(target, EV_ACCEPT);
    }

    /// Copies unread data of connection `id` into `dst` and returns the number of bytes copied. Returns 0 (EOF) once
    /// everything has been read after the peer's FIN, and an error after an RST or an accounting inconsistency. Returns
    /// 0 if `dst` is empty.
    pub fn read(&mut self, now: Time, id: ConnId, dst: &mut [u8]) -> Result<usize, Error> {
        let now = self.clock(now);
        let Some(i) = self.conns.resolve(id) else {
            return Err(Error::Closed);
        };
        let mut c = self.conn(i);
        if c.t.app_closed {
            return Err(Error::Closed);
        }
        if dst.is_empty() {
            return Ok(0);
        }
        if c.b.rcv.unread() > 0 {
            let n = c.b.rcv.read(dst, &mut c.s.chunks);
            c.rcv_space_adjust(now);
            c.ack_on_drain();
            c.window_update();
            let boost = c.k.rdem.add(now, n) && c.note_demand(Dir::Recv, now);
            c.after_input(now);
            if boost {
                self.try_boost(id, Dir::Recv, now);
            }
            return Ok(n);
        }
        if c.b.rcv.read_off > c.b.rcv.nxt_off {
            // 読み取りの位置が受信の位置を超えています (会計の不整合)。EOF や WouldBlock にせず接続を閉じます。
            // 位置を揃えてから閉じるので、以後の read は誤りを重ねて数えません。
            c.b.rcv.read_off = c.b.rcv.nxt_off;
            c.accounting_fault(now);
            return Err(Error::Accounting);
        }
        if c.t.fin_rcvd || (c.t.state == State::Closed && c.t.err.is_none()) {
            return Ok(0);
        }
        if let Some(e) = c.t.err {
            return Err(e.into());
        }
        Err(Error::WouldBlock)
    }

    /// Writes `data` to the send buffer of connection `id` and returns the number of bytes accepted. Returns
    /// `WouldBlock` if there is no space.
    pub fn write(&mut self, now: Time, id: ConnId, data: &[u8]) -> Result<usize, Error> {
        let now = self.clock(now);
        let Some(i) = self.conns.resolve(id) else {
            return Err(Error::Closed);
        };
        let mut c = self.conn(i);
        if c.t.app_closed {
            return Err(Error::Closed);
        }
        if let Some(e) = c.t.err {
            return Err(e.into());
        }
        if c.t.snd_shut || !matches!(c.t.state, State::Established | State::CloseWait) {
            return Err(Error::BrokenPipe);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let space = c.t.snd_cap - (c.t.tail_off - c.t.una_off);
        if space == 0 {
            return Err(Error::WouldBlock);
        }
        let n = usize::try_from(space).map_or(data.len(), |s| s.min(data.len()));
        let off = c.t.tail_off;
        if c.b.snd.write(off, &data[..n], &mut c.s.chunks).is_err() {
            return Err(Error::NoMemory);
        }
        c.t.tail_off += n as u64;
        let boost = c.k.wdem.add(now, n) && c.note_demand(Dir::Send, now);
        c.after_input(now);
        if boost {
            self.try_boost(id, Dir::Send, now);
        }
        Ok(n)
    }

    /// Closes the send direction and queues a FIN after the send buffer. Reading can continue.
    pub fn close_write(&mut self, now: Time, id: ConnId) -> Result<(), Error> {
        let now = self.clock(now);
        let Some(i) = self.conns.resolve(id) else {
            return Err(Error::Closed);
        };
        let mut c = self.conn(i);
        if c.t.app_closed {
            return Err(Error::Closed);
        }
        c.shutdown_write();
        c.after_input(now);
        Ok(())
    }

    /// Closes the connection. If it holds unread in-order data it ends with an RST and releases its slot; otherwise it
    /// queues a FIN after the send buffer. A connection with data left to send stays in its slot until the data is
    /// delivered or the retransmission attempts are used up, and moves to the TIME_WAIT table after the condition for
    /// becoming a row is met. Does nothing for a stale handle.
    pub fn close_conn(&mut self, now: Time, id: ConnId) {
        let now = self.clock(now);
        let Some(i) = self.conns.resolve(id) else {
            return;
        };
        let mut c = self.conn(i);
        if c.t.app_closed {
            return;
        }
        c.t.app_closed = true;
        // Go の Close と同じく、読み取りと書き込みを待つ呼び手を起こします。
        c.signal_read();
        c.signal_write();
        if c.t.state == State::Closed {
            c.release();
        } else if c.b.rcv.unread() > 0 {
            c.send_rst();
            c.release();
        } else {
            c.shutdown_write();
            c.after_input(now);
        }
    }

    /// Sends an RST and releases the connection slot immediately. For a stale handle, if the original connection's row
    /// is still in the TIME_WAIT table, the row is removed and an RST is sent.
    pub fn abort(&mut self, now: Time, id: ConnId) {
        self.clock(now);
        let Some(i) = self.conns.resolve(id) else {
            if (id.slot as usize) < self.conns.len() {
                self.s.abort_tw_row(id.slot, id.generation);
            }
            return;
        };
        let mut c = self.conn(i);
        c.t.app_closed = true;
        if c.t.state != State::Closed {
            c.send_rst();
        }
        c.release();
    }

    /// Returns whether, after the last `close_conn` or `abort`, the connection has finished delivering the data and FIN
    /// it sent. CLOSED, TIME_WAIT and FIN_WAIT_2 with an empty receive buffer count as delivered. Returns true for a
    /// stale handle.
    pub fn delivered(&self, id: ConnId) -> bool {
        let Some(i) = self.conns.resolve(id) else {
            return true;
        };
        let t = self.conns.tcb(i);
        if !t.app_closed {
            return false;
        }
        match t.state {
            State::Closed | State::TimeWait => true,
            State::FinWait2 => self.conns.bufs(i).rcv.empty(),
            _ => false,
        }
    }

    /// The local address of the connection, or `None` for a stale handle.
    pub fn local_addr(&self, id: ConnId) -> Option<SocketAddrV4> {
        let t = self.conns.tcb(self.conns.resolve(id)?);
        Some(SocketAddrV4::new(
            Ipv4Addr::from_bits(t.tup.laddr),
            t.tup.lport,
        ))
    }

    /// The peer's address of the connection, or `None` for a stale handle.
    pub fn peer_addr(&self, id: ConnId) -> Option<SocketAddrV4> {
        let t = self.conns.tcb(self.conns.resolve(id)?);
        Some(SocketAddrV4::new(
            Ipv4Addr::from_bits(t.tup.raddr),
            t.tup.rport,
        ))
    }
}
