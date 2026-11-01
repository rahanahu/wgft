//! Rust の wgstack を [`ClockedDut`] に合わせる adapter です (`docs/design/v2/test-tooling.md` の 2 節と 3 節)。
//!
//! 核の公開の API だけを使います。`inject` は同じ時刻の `handle_packet` の列に、`advance` は新しい時刻での
//! 1 回の `handle_timeout` に、`poll` は `poll_transmit` に写します。`poll_event` の知らせは読み捨て、操作の
//! 結果だけを返します。
//!
//! 応答は凍結した Go の wgstack の `dutserve` と同じ bytes になるように作ります。engine の誤りの文は Go の
//! `net.OpError` の文 (`read tcp 10.200.0.2:80->10.200.0.1:40001: connection reset by peer` の形) で、誤りの
//! 種類は `dutserve` の `errResp` の分け方です。

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::time::Duration;

use wgft_tcpharness::dut::{Accepted, ClockedDut, Datagram, DutError, Op};
use wgft_tcpharness::frame::{self, BoostEvent, Clock, ErrKind, Handle, Hello, MAX_FRAME, VERSION};
use wgft_wgstack::{
    BoostPolicy, Budget, Closed, Config, Congestion, ConnId, Error, Held, Hook, Limits, ListenerId,
    PingId, Stack, Time, UdpId,
};

/// `HELLO_OK` が返す engine の名前です。
pub const ENGINE: &str = "wgstack-rs";

/// `READ` の最大の byte 数の上限です。応答が 1 つの frame に収まる値で、`dutserve` の `maxRead` と同じです。
const MAX_READ: usize = MAX_FRAME - 64;

/// `HELLO` の上限の組の名前です。Go の `limitNames` と同じ順で、初めの 5 つは必ず要ります。
const LIMIT_NAMES: [&str; 9] = [
    "maxFlows",
    "acceptQ",
    "synRows",
    "twRows",
    "ctlSlots",
    "udpRxDgrams",
    "udpTxDgrams",
    "fragEntries",
    "fragPieces",
];

/// handle が指す物です。
#[derive(Clone, Copy, Debug)]
enum Obj {
    Listener(ListenerId),
    Conn {
        id: ConnId,
        local: SocketAddrV4,
        remote: SocketAddrV4,
    },
    Udp(UdpId, SocketAddrV4),
    Ping(PingId, Ipv4Addr),
}

/// boost の hook が見た変化と、`BOOST_POLICY` で渡された答えです。
#[derive(Debug, Default)]
struct HookState {
    /// 接続ごとの handle と floor に戻る時の答え
    policies: HashMap<ConnId, (Handle, bool)>,
    /// 今 boost を持つ接続
    boosted: HashSet<ConnId>,
    /// `EVENTS` がまだ返していない変化
    events: Vec<BoostEvent>,
}

/// 核に渡す hook です。`dutserve` の `OnBoost` の関数と同じく、登録した接続の boost の取得と floor に戻る
/// 問い合わせを変化として残し、問い合わせには `BOOST_POLICY` の答えを返します。
#[derive(Debug, Clone, Default)]
struct DutHook(Rc<RefCell<HookState>>);

impl Hook for DutHook {
    fn boost_granted(&mut self, conn: ConnId) {
        let mut s = self.0.borrow_mut();
        s.boosted.insert(conn);
        if let Some(&(h, _)) = s.policies.get(&conn) {
            s.events.push(BoostEvent { h, boosted: true });
        }
    }

    fn may_return(&mut self, conn: ConnId) -> bool {
        let mut s = self.0.borrow_mut();
        // Go の関数は f(false) の呼び出しごとに変化を残し、floor の答えを返す
        let Some(&(h, floor)) = s.policies.get(&conn) else {
            return true;
        };
        s.events.push(BoostEvent { h, boosted: false });
        floor
    }

    fn boost_returned(&mut self, conn: ConnId) {
        self.0.borrow_mut().boosted.remove(&conn);
    }
}

/// `HELLO` から核を作れなかった理由です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloError(pub String);

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HelloError {}

/// `HELLO` の上限の組を核の表の大きさにします。空なら既定です。名前の無い欄と 0 の欄は本番の値で、表の大きさの
/// 初めの 5 つは必ず要ります (4 節)。
///
/// UDP の datagram の数 (`udpRxDgrams`、`udpTxDgrams`) は、核が UDP を持つ段 (PR 6) までは受け取って使いません。
pub fn limits_from_hello(ls: &[frame::Limit]) -> Result<Limits, HelloError> {
    let def = Limits::default();
    if ls.is_empty() {
        return Ok(def);
    }
    let mut vals = [0usize; LIMIT_NAMES.len()];
    let mut seen = [false; LIMIT_NAMES.len()];
    for l in ls {
        let Some(i) = LIMIT_NAMES.iter().position(|n| *n == l.name) else {
            return Err(HelloError(format!("unknown limit {:?}", l.name)));
        };
        if l.value > 1 << 30 {
            return Err(HelloError(format!(
                "limit {}={} is out of range",
                l.name, l.value
            )));
        }
        vals[i] = usize::try_from(l.value).unwrap_or(usize::MAX);
        seen[i] = true;
    }
    if let Some(i) = seen[..5].iter().position(|s| !s) {
        return Err(HelloError(format!("limit {} is missing", LIMIT_NAMES[i])));
    }
    let or_default = |v: usize, d: usize| if v == 0 { d } else { v };
    Ok(Limits {
        max_flows: vals[0],
        accept_queue: vals[1],
        syn_rows: vals[2],
        tw_rows: vals[3],
        ctl_slots: vals[4],
        frag_entries: or_default(vals[7], def.frag_entries),
        frag_pieces: or_default(vals[8], def.frag_pieces),
        udp_rx_datagrams: or_default(vals[5], def.udp_rx_datagrams),
        udp_tx_datagrams: or_default(vals[6], def.udp_tx_datagrams),
    })
}

/// 手で進める時計の Rust の wgstack です。1 つの `HELLO` から作ります。
pub struct WgstackDut {
    stack: Stack<DutHook>,
    hook: DutHook,
    /// DUT を作ってからの時間 (ns)。Go の `ManualClock` と同じ値です
    now: u64,
    addr: Ipv4Addr,
    objs: Vec<Obj>,
    buf: Vec<u8>,
}

impl fmt::Debug for WgstackDut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgstackDut")
            .field("now", &self.now)
            .field("addr", &self.addr)
            .field("handles", &self.objs.len())
            .finish_non_exhaustive()
    }
}

impl WgstackDut {
    /// `HELLO` から核を作ります。`dutserve` と同じく、`--clock fake` の形と既定の上限だけを受け付けます。
    pub fn new(h: &Hello) -> Result<Self, HelloError> {
        Self::build(h, false)
    }

    /// 記録の照合のために `HELLO` から核を作ります。[`WgstackDut::new`] と違い、上限の組も受け付けます。
    /// Go の `TestRecordingsReplay` が `newDUTServerWith` で上限の組を受け付けるのと同じです。
    pub fn for_replay(h: &Hello) -> Result<Self, HelloError> {
        Self::build(h, true)
    }

    /// fuzz の `replay` の target のために、`HELLO` の上限の組の代わりに表の大きさ `limits` で、渡した `budget`
    /// を持つ核を作ります。作れなければ誤りと `budget` を返します。`HELLO` の版と時計は確かめません。
    pub fn for_fuzz(
        h: &Hello,
        limits: Limits,
        budget: Budget,
    ) -> Result<Self, (HelloError, Budget)> {
        let config = Self::config(h, limits);
        let hook = DutHook::default();
        let stack = Stack::new(config, budget, &h.seed, hook.clone())
            .map_err(|e| (HelloError(format!("wgstack: {e}")), e.into_budget()))?;
        Ok(Self::with_stack(stack, hook, h.addr))
    }

    /// 核を閉じ、`Budget` と最後の会計を返します。
    pub fn close_stack(self) -> Closed {
        let now = self.time();
        self.stack.close(now)
    }

    /// 核の今の保持です。
    pub fn held(&self) -> Held {
        self.stack.held()
    }

    fn config(h: &Hello, limits: Limits) -> Config {
        Config {
            addr: h.addr,
            mtu: usize::try_from(h.mtu).unwrap_or(usize::MAX),
            limits,
            congestion: match h.congestion {
                frame::Congestion::Cubic => Congestion::Cubic,
                frame::Congestion::NewReno => Congestion::NewReno,
            },
            boost: match h.boost {
                frame::Boost::OnDemand => BoostPolicy::OnDemand,
                frame::Boost::AtAccept => BoostPolicy::AtAccept,
                frame::Boost::Never => BoostPolicy::Never,
            },
        }
    }

    fn with_stack(stack: Stack<DutHook>, hook: DutHook, addr: Ipv4Addr) -> Self {
        Self {
            stack,
            hook,
            now: 0,
            addr,
            objs: Vec::new(),
            buf: vec![0; 65536],
        }
    }

    fn build(h: &Hello, replay: bool) -> Result<Self, HelloError> {
        if h.version != VERSION {
            return Err(HelloError(format!(
                "protocol version {} is not {VERSION}",
                h.version
            )));
        }
        if h.clock != Clock::Fake {
            return Err(HelloError(
                "wgstack-dut runs only the fake clock".to_owned(),
            ));
        }
        if !h.limits.is_empty() && !replay {
            return Err(HelloError(format!(
                "HELLO asks for {} non-default limits; wgstack-dut takes only the default limits",
                h.limits.len()
            )));
        }
        let config = Self::config(h, limits_from_hello(&h.limits)?);
        let budget = Budget::new().map_err(|e| HelloError(format!("wgstack: {e}")))?;
        let hook = DutHook::default();
        let stack = Stack::new(config, budget, &h.seed, hook.clone())
            .map_err(|e| HelloError(format!("wgstack: {e}")))?;
        Ok(Self::with_stack(stack, hook, h.addr))
    }

    /// 核の不変条件を確かめます。
    pub fn check_invariants(&self) -> Result<(), String> {
        self.stack.check_invariants().map_err(|e| e.to_string())
    }

    fn time(&self) -> Time {
        Time::from_nanos(self.now)
    }

    fn add(&mut self, o: Obj) -> Handle {
        self.objs.push(o);
        Handle(u32::try_from(self.objs.len()).unwrap_or(u32::MAX))
    }

    fn obj(&self, h: Handle) -> Result<Obj, DutError> {
        let i = usize::try_from(h.0).unwrap_or(usize::MAX);
        if i == 0 || i > self.objs.len() {
            return Err(DutError::Broken(format!("unknown handle {h}")));
        }
        Ok(self.objs[i - 1])
    }

    fn listener(&self, h: Handle) -> Result<ListenerId, DutError> {
        match self.obj(h)? {
            Obj::Listener(l) => Ok(l),
            _ => Err(DutError::Broken(format!("handle {h} is not a listener"))),
        }
    }

    fn conn(&self, h: Handle) -> Result<(ConnId, SocketAddrV4, SocketAddrV4), DutError> {
        match self.obj(h)? {
            Obj::Conn { id, local, remote } => Ok((id, local, remote)),
            _ => Err(DutError::Broken(format!("handle {h} is not a connection"))),
        }
    }
}

/// 核の誤りを Go の `net.OpError` と同じ文の engine の誤りにします。種類は `dutserve` の `errResp` の分け方です。
fn conn_err(op: &str, e: Error, local: SocketAddrV4, remote: SocketAddrV4) -> DutError {
    let (kind, text) = match e {
        Error::Closed => (ErrKind::Closed, "use of closed network connection"),
        Error::Reset => (ErrKind::Reset, "connection reset by peer"),
        Error::BrokenPipe => (ErrKind::BrokenPipe, "broken pipe"),
        // syscall.ETIMEDOUT の Timeout() は真
        Error::TimedOut => (ErrKind::Timeout, "connection timed out"),
        Error::Accounting => (
            ErrKind::Other,
            "wgstack: closed the connection after an internal accounting error",
        ),
        other => {
            return DutError::engine(
                ErrKind::Other,
                format!("{op} tcp {local}->{remote}: {other}"),
            );
        }
    };
    DutError::engine(kind, format!("{op} tcp {local}->{remote}: {text}"))
}

fn listen_err(addr: SocketAddrV4, e: Error) -> DutError {
    let kind = if e == Error::Closed {
        ErrKind::Closed
    } else {
        ErrKind::Other
    };
    DutError::engine(kind, format!("listen tcp {addr}: {e}"))
}

/// UDP の誤りの理由を Go の wgstack の文にします。会計の不整合は最初の違反の文です。
fn udp_reason(stack: &Stack<DutHook>, e: Error) -> String {
    match e {
        Error::AddrNotLocal | Error::PortZero => {
            "address is not a local address and port of this tunnel".to_owned()
        }
        Error::UdpStopped => stack
            .udp_receive_fault()
            .map_or_else(|| e.to_string(), |f| f.to_string()),
        other => other.to_string(),
    }
}

/// `Debug` の形の平らな構造体 (`Name { a: 1, b: [0, 0] }`) を `a=1 b=[0,0]` にします。`STATS`、`BOUND`、`HELD`
/// の応答の文字列です。照合は応答の種類だけを比べるので、欄の名前は Rust の名前のままです。
fn key_values(debug: &str) -> String {
    let inner = debug
        .split_once('{')
        .and_then(|(_, r)| r.rsplit_once('}'))
        .map_or("", |(i, _)| i.trim());
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i32, 0);
    let bytes = inner.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' | b'(' | b'{' => depth += 1,
            b']' | b')' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < inner.len() {
        parts.push(&inner[start..]);
    }
    parts
        .iter()
        .filter_map(|p| p.split_once(':'))
        .map(|(k, v)| format!("{}={}", k.trim(), v.replace(' ', "")))
        .collect::<Vec<_>>()
        .join(" ")
}

impl ClockedDut for WgstackDut {
    fn now(&mut self) -> Result<Duration, DutError> {
        Ok(Duration::from_nanos(self.now))
    }

    fn advance(&mut self, d: Duration) -> Result<Duration, DutError> {
        // Go の ManualClock.Advance の後の 1 回の Tick と同じく、時間 0 でもタイマーを動かす
        self.now = self
            .now
            .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        self.stack.handle_timeout(self.time());
        Ok(Duration::from_nanos(self.now))
    }

    fn inject(&mut self, batch: &[&[u8]]) -> Result<(), DutError> {
        let t = self.time();
        for p in batch {
            self.stack.handle_packet(t, p);
        }
        Ok(())
    }

    fn poll(&mut self, max: usize) -> Result<Vec<Vec<u8>>, DutError> {
        let t = self.time();
        let mut out = Vec::new();
        while out.len() < max {
            let Some(n) = self.stack.poll_transmit(t, &mut self.buf) else {
                break;
            };
            out.push(self.buf[..n].to_vec());
        }
        Ok(out)
    }

    fn tcp_listen(&mut self, port: u16) -> Result<Handle, DutError> {
        let addr = SocketAddrV4::new(self.addr, port);
        let l = self
            .stack
            .listen_tcp(self.time(), addr)
            .map_err(|e| listen_err(addr, e))?;
        Ok(self.add(Obj::Listener(l)))
    }

    fn udp_listen(&mut self, port: u16) -> Result<Handle, DutError> {
        let addr = SocketAddrV4::new(self.addr, port);
        let id = self.stack.bind_udp(self.time(), addr).map_err(|e| {
            let why = udp_reason(&self.stack, e);
            DutError::engine(ErrKind::Other, format!("listen udp {addr}: {why}"))
        })?;
        Ok(self.add(Obj::Udp(id, addr)))
    }

    fn accept(&mut self, listener: Handle) -> Op<Accepted> {
        let l = match self.listener(listener) {
            Ok(l) => l,
            Err(e) => return Op::Failed(e),
        };
        match self.stack.accept(self.time(), l) {
            Ok((id, remote)) => {
                let local = self
                    .stack
                    .local_addr(id)
                    .unwrap_or_else(|| SocketAddrV4::new(self.addr, l.port()));
                let conn = self.add(Obj::Conn { id, local, remote });
                Op::Ready(Accepted { conn, remote })
            }
            Err(Error::WouldBlock) => Op::WouldBlock,
            Err(e) => {
                let kind = if e == Error::Closed {
                    ErrKind::Closed
                } else {
                    ErrKind::Other
                };
                let addr = SocketAddrV4::new(self.addr, l.port());
                let text = if e == Error::Closed {
                    "use of closed network connection".to_owned()
                } else {
                    e.to_string()
                };
                Op::Failed(DutError::engine(kind, format!("accept tcp {addr}: {text}")))
            }
        }
    }

    fn read(&mut self, conn: Handle, max: usize) -> Op<Vec<u8>> {
        let (id, local, remote) = match self.conn(conn) {
            Ok(c) => c,
            Err(e) => return Op::Failed(e),
        };
        if max > MAX_READ {
            return Op::Failed(DutError::Broken(format!(
                "READ asks for {max} bytes; at most {MAX_READ} fit in a frame"
            )));
        }
        let mut b = vec![0; max];
        match self.stack.read(self.time(), id, &mut b) {
            // 最大 0 の READ は空の DATA か誤りで、WOULD_BLOCK を返さない (2 節)
            Ok(_) | Err(Error::WouldBlock) if max == 0 => Op::Ready(Vec::new()),
            Ok(0) => Op::Failed(DutError::engine(ErrKind::Eof, "EOF")),
            Ok(n) => {
                b.truncate(n);
                Op::Ready(b)
            }
            Err(Error::WouldBlock) => Op::WouldBlock,
            Err(e) => Op::Failed(conn_err("read", e, local, remote)),
        }
    }

    fn write(&mut self, conn: Handle, data: &[u8]) -> Op<usize> {
        let (id, local, remote) = match self.conn(conn) {
            Ok(c) => c,
            Err(e) => return Op::Failed(e),
        };
        // dutserve は書ける量で bytes を切ってから Go の Write を呼び、testNet の記録も書ける量までしか渡さないので、
        // Go の繰り返しは 1 回で書き終える。核の write も 1 回で書ける量をすべて受け取るはずで、受け取らなければ
        // 照合が食い違いとして捉える
        let total = match self.stack.write(self.time(), id, data) {
            Ok(n) => n,
            Err(Error::WouldBlock) => return Op::Ready(0),
            Err(e) => return Op::Failed(conn_err("write", e, local, remote)),
        };
        // Go の Write は書いた後にもう 1 回まわり、書けない状態 (相手の RST の後など) を確かめてから戻る。
        // 空の write は同じ確かめだけをして状態を変えない
        match self.stack.write(self.time(), id, &[]) {
            Ok(_) | Err(Error::WouldBlock) => Op::Ready(total),
            Err(e) => Op::Failed(conn_err("write", e, local, remote)),
        }
    }

    fn close(&mut self, h: Handle) -> Result<(), DutError> {
        let t = self.time();
        match self.obj(h)? {
            Obj::Listener(l) => self.stack.close_listener(t, l),
            Obj::Conn { id, .. } => self.stack.close_conn(t, id),
            Obj::Udp(id, _) => self.stack.close_udp(t, id),
            Obj::Ping(..) => {
                return Err(DutError::Broken(
                    "an echo endpoint closes with PING_CLOSE".into(),
                ));
            }
        }
        Ok(())
    }

    fn close_write(&mut self, conn: Handle) -> Result<(), DutError> {
        let (id, local, remote) = self.conn(conn)?;
        self.stack
            .close_write(self.time(), id)
            .map_err(|e| conn_err("close", e, local, remote))
    }

    fn abort(&mut self, conn: Handle) -> Result<(), DutError> {
        let (id, ..) = self.conn(conn)?;
        self.stack.abort(self.time(), id);
        Ok(())
    }

    fn close_for_delivery(&mut self, conn: Handle) -> Result<(), DutError> {
        let (id, ..) = self.conn(conn)?;
        self.stack.close_for_delivery(self.time(), id);
        Ok(())
    }

    fn delivered(&mut self, conn: Handle) -> Result<bool, DutError> {
        let (id, ..) = self.conn(conn)?;
        Ok(self.stack.delivered(id))
    }

    fn boost_policy(&mut self, conn: Handle, floor: bool) -> Result<bool, DutError> {
        let (id, ..) = self.conn(conn)?;
        // 古い handle では Go の OnBoost は関数を登録せず、f(false) を 1 回呼ぶだけ
        if self.stack.peer_addr(id).is_none() {
            return Ok(false);
        }
        let mut s = self.hook.0.borrow_mut();
        s.policies.insert(id, (conn, floor));
        Ok(s.boosted.contains(&id))
    }

    fn events(&mut self) -> Result<Vec<BoostEvent>, DutError> {
        Ok(std::mem::take(&mut self.hook.0.borrow_mut().events))
    }

    fn udp_recv(&mut self, sock: Handle, max: usize) -> Op<Datagram> {
        let (id, _local) = match self.obj(sock) {
            Ok(Obj::Udp(id, l)) => (id, l),
            Ok(_) => {
                return Op::Failed(DutError::Broken(format!(
                    "handle {sock} is not a UDP socket"
                )));
            }
            Err(e) => return Op::Failed(e),
        };
        if max > MAX_READ {
            return Op::Failed(DutError::Broken(format!("UDP_RECV asks for {max} bytes")));
        }
        let mut b = vec![0; max];
        match self.stack.recv_from(self.time(), id, &mut b) {
            Ok((n, from)) => {
                b.truncate(n);
                Op::Ready(Datagram { from, data: b })
            }
            Err(Error::WouldBlock) => Op::WouldBlock,
            Err(Error::Closed) => Op::Failed(DutError::engine(
                ErrKind::Closed,
                "use of closed network connection",
            )),
            Err(e) => Op::Failed(DutError::engine(ErrKind::Other, format!("{e}"))),
        }
    }

    fn udp_send(&mut self, sock: Handle, to: SocketAddrV4, data: &[u8]) -> Op<()> {
        let (id, local) = match self.obj(sock) {
            Ok(Obj::Udp(id, l)) => (id, l),
            Ok(_) => {
                return Op::Failed(DutError::Broken(format!(
                    "handle {sock} is not a UDP socket"
                )));
            }
            Err(e) => return Op::Failed(e),
        };
        match self.stack.send_to(self.time(), id, data, to) {
            Ok(_) => Op::Ready(()),
            Err(Error::WouldBlock) => Op::WouldBlock,
            // Go の `WriteTo` は閉じた socket に net.ErrClosed をそのまま返します。
            Err(Error::Closed) => Op::Failed(DutError::engine(
                ErrKind::Closed,
                "use of closed network connection",
            )),
            Err(e) => {
                let why = udp_reason(&self.stack, e);
                Op::Failed(DutError::engine(
                    ErrKind::Other,
                    format!("write udp {local}->{to}: {why}"),
                ))
            }
        }
    }

    fn ping_open(&mut self, to: Ipv4Addr) -> Result<Handle, DutError> {
        let id = self
            .stack
            .open_ping(self.time(), to)
            .map_err(|e| DutError::engine(ErrKind::Other, format!("dial ping4: {e}")))?;
        Ok(self.add(Obj::Ping(id, to)))
    }

    fn ping_send(&mut self, ep: Handle, data: &[u8]) -> Result<(), DutError> {
        let Obj::Ping(id, r) = self.obj(ep)? else {
            return Err(DutError::Broken(format!(
                "handle {ep} is not an echo endpoint"
            )));
        };
        let l = self.addr;
        match self.stack.send_ping(self.time(), id, data) {
            Ok(_) => Ok(()),
            Err(Error::Closed) => Err(DutError::engine(
                ErrKind::Closed,
                format!("write ping4 {l}->{r}: use of closed network connection"),
            )),
            Err(e) => Err(DutError::engine(
                ErrKind::Other,
                format!("write ping4 {l}->{r}: {e}"),
            )),
        }
    }

    fn ping_recv(&mut self, ep: Handle, max: usize) -> Op<Vec<u8>> {
        let (id, r) = match self.obj(ep) {
            Ok(Obj::Ping(id, r)) => (id, r),
            Ok(_) => {
                return Op::Failed(DutError::Broken(format!(
                    "handle {ep} is not an echo endpoint"
                )));
            }
            Err(e) => return Op::Failed(e),
        };
        let l = self.addr;
        let mut b = vec![0; max];
        match self.stack.recv_ping(self.time(), id, &mut b) {
            Ok(n) => {
                b.truncate(n);
                Op::Ready(b)
            }
            Err(Error::WouldBlock) => Op::WouldBlock,
            Err(Error::Closed) => Op::Failed(DutError::engine(
                ErrKind::Closed,
                format!("read ping4 {l}->{r}: use of closed network connection"),
            )),
            Err(e) => Op::Failed(DutError::engine(
                ErrKind::Other,
                format!("read ping4 {l}->{r}: {e}"),
            )),
        }
    }

    fn ping_close(&mut self, ep: Handle) -> Result<(), DutError> {
        let Obj::Ping(id, _) = self.obj(ep)? else {
            return Err(DutError::Broken(format!(
                "handle {ep} is not an echo endpoint"
            )));
        };
        self.stack.close_ping(self.time(), id);
        Ok(())
    }

    fn stats(&mut self) -> Result<String, DutError> {
        Ok(key_values(&format!("{:?}", self.stack.stats())))
    }

    fn bound(&mut self) -> Result<String, DutError> {
        Ok(key_values(&format!("{:?}", self.stack.bound())))
    }

    fn held(&mut self) -> Result<String, DutError> {
        Ok(key_values(&format!("{:?}", self.stack.held())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_values_flattens_debug() {
        assert_eq!(
            key_values("Stats { a: 1, b: [0, 2], c: 3 }"),
            "a=1 b=[0,2] c=3"
        );
        assert_eq!(key_values("Held { }"), "");
    }

    #[test]
    fn limits_follow_go() {
        assert_eq!(limits_from_hello(&[]), Ok(Limits::default()));
        let l = |name: &str, value| frame::Limit {
            name: name.to_owned(),
            value,
        };
        let five = [
            l("maxFlows", 8),
            l("acceptQ", 4),
            l("synRows", 4),
            l("twRows", 8),
            l("ctlSlots", 8),
        ];
        let got = limits_from_hello(&five).expect("limits");
        assert_eq!(
            (
                got.max_flows,
                got.accept_queue,
                got.syn_rows,
                got.tw_rows,
                got.ctl_slots
            ),
            (8, 4, 4, 8, 8)
        );
        assert_eq!(got.frag_entries, Limits::default().frag_entries);
        assert!(
            limits_from_hello(&five[..4]).is_err(),
            "ctlSlots is required"
        );
        assert!(limits_from_hello(&[l("nope", 1)]).is_err());
        assert!(limits_from_hello(&[l("maxFlows", (1 << 30) + 1)]).is_err());
    }
}
