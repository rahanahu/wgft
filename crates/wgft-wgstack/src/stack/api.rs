//! アプリケーションの操作 (wgstack-rs.md の「アプリケーションの操作」、Go の `conn.go` と `listener.go`)。
//!
//! 操作はどれも待たずに戻ります。「今はできない」は [`Error::WouldBlock`] で返し、できるようになったら
//! [`Event`] を出します。`WouldBlock` を返す操作は核の状態を変えません。
//!
//! 古い handle (枠が TIME_WAIT の表の行に移った後か、別の接続に使われた後の [`ConnId`]) は Go の古い接続の値と
//! 同じく振る舞います。`delivered` は真を返し、`close_conn` は何もせず、`read` と `write` は [`Error::Closed`] を返し、
//! `abort` は元の接続の行が表に残っていれば行を外して RST を送ります。

use super::{Hook, Stack};
use crate::config::BoostPolicy;
use crate::tcp::boost::Dir;
use crate::tcp::conn::{ConnError, ConnId, State};
use crate::tcp::listen;
use crate::time::Time;
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};

/// 待ち受けの handle です。ポートと 32 bit の世代の組で、閉じた後の handle は誤りになります。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerId {
    pub(crate) port: u16,
    pub(crate) generation: u32,
}

impl ListenerId {
    /// 待ち受けのポートです。
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// 接続と待ち受けの準備の変化の知らせです。知らせはきっかけで、状態の正本ではありません。呼び手は知らせを受けたら
/// 操作を試し、`WouldBlock` なら次の知らせを待ちます。種類は後の段で足すので、知らない種類は無視します。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// 読めるデータか EOF か誤りがあるかもしれません。
    Readable(ConnId),
    /// 送信のバッファに空きができたか、書けない状態になったかもしれません。
    Writable(ConnId),
    /// プロトコルが終わりました。枠を返した後の知らせは、枠を最後に使った接続の handle で出します。
    Closed(ConnId),
    /// accept の待ち行列に接続があります。
    Acceptable(ListenerId),
}

/// 操作の誤りです。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// 今はできません。できるようになったら知らせます。
    WouldBlock,
    /// handle が閉じているか、古い handle です。
    Closed,
    /// 相手の RST で接続が終わりました。
    Reset,
    /// 送信の向きを閉じた後か、送れない状態の接続に書きました。
    BrokenPipe,
    /// 再送か窓の probe の回数を使い切りました。
    TimedOut,
    /// 会計の不整合で接続を閉じました。
    Accounting,
    /// バッファの chunk を確保できませんでした。状態は変えていません。
    NoMemory,
    /// アドレスがこのトンネルのアドレスではありません。
    AddrNotLocal,
    /// ポート 0 で待ち受けることはできません。
    PortZero,
    /// ポートは既に使われています。
    AddrInUse,
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
            Self::AddrNotLocal => "address is not a local address of this tunnel",
            Self::PortZero => "port 0 is not supported",
            Self::AddrInUse => "address already in use",
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
    /// `addr` で TCP を待ち受けます。アドレスはトンネルのアドレスです。
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
        self.s.events.reset(target);
        Ok(ListenerId { port, generation })
    }

    /// 待ち受けの accept の待ち行列の先頭の接続と相手のアドレスを返します。
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

    /// 待ち受けを閉じます。accept の待ち行列の接続と握手の途中の行に RST を送って返し、ポートをその場で空けます。
    /// 古い handle では何もしません。
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
        self.s.events.reset(target);
    }

    /// 接続 `id` の未読のデータを `dst` に写し、写した byte 数を返します。相手の FIN の後に読み終えたら 0 を返し
    /// (EOF)、RST と会計の不整合の後は誤りを返します。`dst` が空なら 0 を返します。
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
        if c.t.fin_rcvd || (c.t.state == State::Closed && c.t.err.is_none()) {
            return Ok(0);
        }
        if let Some(e) = c.t.err {
            return Err(e.into());
        }
        Err(Error::WouldBlock)
    }

    /// 接続 `id` の送信のバッファに `data` を書き、受け取った byte 数を返します。空きが無ければ `WouldBlock` です。
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

    /// 送信の向きを閉じ、送信のバッファの後ろに FIN を置きます。読み取りは続けられます。
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

    /// 接続を閉じます。未読の順序どおりのデータを持てば RST で終えて枠を返し (Linux と同じ)、持たなければ送信の
    /// バッファの後ろに FIN を置きます。送り残しを持つ接続は、届け終えるか再送の回数を使い切るまで枠に残り、行に
    /// 移る条件を満たした後に TIME_WAIT の表に移ります。古い handle では何もしません。
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

    /// Go と同じく [`Stack::close_conn`] と同じ動作です。送り残しを持つ接続は接続の枠に残るので、TIME_WAIT の表の
    /// 追い出しで末尾を失いません。
    pub fn close_for_delivery(&mut self, now: Time, id: ConnId) {
        self.close_conn(now, id);
    }

    /// RST を送り、接続の枠をその場で返します。古い handle では、元の接続の行が TIME_WAIT の表に残っていれば行を
    /// 外して RST を送ります。
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

    /// 最後の `close_conn` か `abort` の後、この接続が送ったデータと FIN を届け終えたかを返します。CLOSED、TIME_WAIT、
    /// 受信のバッファが空の FIN_WAIT_2 を届け終えたとします。古い handle では真を返します。
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

    /// 接続の自分の側のアドレスです。古い handle では `None` です。
    pub fn local_addr(&self, id: ConnId) -> Option<SocketAddrV4> {
        let t = self.conns.tcb(self.conns.resolve(id)?);
        Some(SocketAddrV4::new(
            Ipv4Addr::from_bits(t.tup.laddr),
            t.tup.lport,
        ))
    }

    /// 接続の相手のアドレスです。古い handle では `None` です。
    pub fn peer_addr(&self, id: ConnId) -> Option<SocketAddrV4> {
        let t = self.conns.tcb(self.conns.resolve(id)?);
        Some(SocketAddrV4::new(
            Ipv4Addr::from_bits(t.tup.raddr),
            t.tup.rport,
        ))
    }
}
