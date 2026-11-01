//! 手で進める時計の DUT の口です (`docs/design/v2/test-tooling.md` の 2 節と 3 節)。
//!
//! - [`ClockedDut`]:runner が DUT を叩く trait。操作はすべて待たずに戻ります
//! - [`answer`]:3 節の要求を [`ClockedDut`] の呼び出しに写し、応答を作ります。frame の server と
//!   [`Recorded`] が使います
//! - [`Recorded`]:[`ClockedDut`] の呼び出しを 3 節の frame の要求と応答として書き出す包み (transcript) で、
//!   2 節の送り直さない規則を持ちます
//! - [`ProcessDut`]:3 節の口で別のプロセスの DUT を叩く [`ClockedDut`]

use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;
use std::{fmt, thread};

use crate::frame::{self, BoostEvent, ErrKind, Handle, Hello, Kind, Msg};

/// engine が返した誤りです。種類と engine の英語の文を持ちます。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    pub kind: ErrKind,
    pub msg: String,
}

/// DUT の操作の誤りです。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DutError {
    /// engine が返した誤り (3 節の `ERROR`)
    Engine(EngineError),
    /// DUT そのものが壊れた (プロセスが終わった、口の誤り、表に無い応答)。台本はここで失敗します
    Broken(String),
}

impl DutError {
    /// engine の誤りを作ります。
    pub fn engine(kind: ErrKind, msg: impl Into<String>) -> Self {
        Self::Engine(EngineError {
            kind,
            msg: msg.into(),
        })
    }
}

impl fmt::Display for DutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => f.write_str(&e.msg),
            Self::Broken(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for DutError {}

/// 待たずに戻る操作の結果です。結果、待つ必要がある (would block)、誤りを区別し、誤りは種類 (EOF、reset、
/// closed、timeout、その他) を持ちます。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op<T> {
    /// 結果
    Ready(T),
    /// 待つ必要がある。engine は何も変えていません
    WouldBlock,
    /// 誤り
    Failed(DutError),
}

/// 受け入れた接続と相手の addrport です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    pub conn: Handle,
    pub remote: SocketAddrV4,
}

/// 受け取った UDP の datagram と送り手です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub from: SocketAddrV4,
    pub data: Vec<u8>,
}

/// 手で進める時計の DUT です。runner はこの trait だけで DUT を叩きます。
///
/// 操作はすべて待たずに戻ります。待つ必要のある操作は [`Op::WouldBlock`] を返し、engine の状態を
/// 変えません。`write` は待つ必要がある時に `Ready(0)` を返します (3 節の `WROTE 0`)。各操作は 3 節の要求
/// 1 つに当たり、[`answer`] がその対応を持ちます。
pub trait ClockedDut {
    /// DUT を作ってからの時間です。
    fn now(&mut self) -> Result<Duration, DutError>;
    /// 時計を `d` 進め、期限の来たタイマーを動かして、新しい時刻を返します。
    fn advance(&mut self, d: Duration) -> Result<Duration, DutError>;
    /// IPv4 の packet の列を 1 回の書き込みのバッチとして渡します。
    fn inject(&mut self, batch: &[&[u8]]) -> Result<(), DutError>;
    /// engine が今送る packet を `max` まで取ります。
    fn poll(&mut self, max: usize) -> Result<Vec<Vec<u8>>, DutError>;
    /// TCP の待ち受けを開きます。
    fn tcp_listen(&mut self, port: u16) -> Result<Handle, DutError>;
    /// 接続していない UDP の socket を開きます。
    fn udp_listen(&mut self, port: u16) -> Result<Handle, DutError>;
    /// 待ち受けの次の接続を取ります。
    fn accept(&mut self, listener: Handle) -> Op<Accepted>;
    /// 接続から `max` byte まで読みます。`max` が 0 なら空の結果か誤りです。
    fn read(&mut self, conn: Handle, max: usize) -> Op<Vec<u8>>;
    /// 接続が今受け取る分を書きます。待つ必要がある時と空の `data` は `Ready(0)` です。
    fn write(&mut self, conn: Handle, data: &[u8]) -> Op<usize>;
    /// 待ち受け、接続、UDP の socket を閉じます。
    fn close(&mut self, h: Handle) -> Result<(), DutError>;
    /// 接続の送信の向きを閉じます。
    fn close_write(&mut self, conn: Handle) -> Result<(), DutError>;
    /// 接続を RST で閉じます。
    fn abort(&mut self, conn: Handle) -> Result<(), DutError>;
    /// データを届けるまで枠を持つ形で接続を閉じます。
    fn close_for_delivery(&mut self, conn: Handle) -> Result<(), DutError>;
    /// 閉じた接続が送るべきものをすべて届けたかどうかです。
    fn delivered(&mut self, conn: Handle) -> Result<bool, DutError>;
    /// 接続の boost の hook を置き、今 boost を持つかを返します。hook は floor に戻る時に `floor` を答えます。
    fn boost_policy(&mut self, conn: Handle, floor: bool) -> Result<bool, DutError>;
    /// 前の `events` の後に hook が見た boost の変化です。
    fn events(&mut self) -> Result<Vec<BoostEvent>, DutError>;
    /// socket の次の datagram を `max` byte で切って取ります。
    fn udp_recv(&mut self, sock: Handle, max: usize) -> Op<Datagram>;
    /// datagram を送ります。送信の予算が尽きていれば待つ必要があります。
    fn udp_send(&mut self, sock: Handle, to: SocketAddrV4, data: &[u8]) -> Op<()>;
    /// `to` への ICMP の echo の endpoint を開きます。
    fn ping_open(&mut self, to: Ipv4Addr) -> Result<Handle, DutError>;
    /// echo request の message を送ります。
    fn ping_send(&mut self, ep: Handle, data: &[u8]) -> Result<(), DutError>;
    /// 返事の message を `max` byte で切って取ります。
    fn ping_recv(&mut self, ep: Handle, max: usize) -> Op<Vec<u8>>;
    /// echo の endpoint を閉じます。
    fn ping_close(&mut self, ep: Handle) -> Result<(), DutError>;
    /// engine の数の `key=value` の文字列です。
    fn stats(&mut self) -> Result<String, DutError>;
    /// 上界の式の値の `key=value` の文字列です。
    fn bound(&mut self) -> Result<String, DutError>;
    /// 今の保持の量の `key=value` の文字列です。
    fn held(&mut self) -> Result<String, DutError>;

    /// 3 節の要求 `req` を 1 つ DUT に渡し、応答とその frame の bytes を返します。[`Recorded`] が transcript を
    /// 書くのに使います。
    ///
    /// 既定は [`answer_frame`] で、[`answer`] が作った応答を符号化します。別のプロセスを叩く DUT
    /// ([`ProcessDut`]) は、pipe から読んだ応答の bytes をそのまま返します。
    fn exchange_frame(&mut self, req: &Msg) -> Result<Answered, DutError> {
        answer_frame(self, req)
    }
}

/// 要求 1 つの応答の frame です ([`ClockedDut::exchange_frame`])。
#[derive(Debug)]
pub struct Answered {
    /// 応答の frame の bytes (長さ、種類、本体)。transcript にはこれを書きます
    pub frame: Vec<u8>,
    /// 応答を読んだもの。応答の種類の frame でも本体が読めなければ誤り (`DutError::Broken`) です
    pub msg: Result<Msg, DutError>,
}

/// [`answer`] で応答を作り、その frame の bytes と組にします。[`ClockedDut::exchange_frame`] の既定です。
pub fn answer_frame<D: ClockedDut + ?Sized>(d: &mut D, req: &Msg) -> Result<Answered, DutError> {
    let resp = answer(d, req)?;
    let frame = resp.frame().map_err(|e| DutError::Broken(e.to_string()))?;
    Ok(Answered {
        frame,
        msg: Ok(resp),
    })
}

fn u32_of(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn usize_of(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn err_msg(e: DutError) -> Result<Msg, DutError> {
    match e {
        DutError::Engine(e) => Ok(Msg::Error {
            err: e.kind,
            msg: e.msg,
        }),
        DutError::Broken(m) => Err(DutError::Broken(m)),
    }
}

fn ok_or(r: Result<Msg, DutError>) -> Result<Msg, DutError> {
    r.or_else(err_msg)
}

fn op_msg<T>(op: Op<T>, f: impl FnOnce(T) -> Msg) -> Result<Msg, DutError> {
    match op {
        Op::Ready(v) => Ok(f(v)),
        Op::WouldBlock => Ok(Msg::WouldBlock),
        Op::Failed(e) => err_msg(e),
    }
}

/// 3 節の要求 `req` を `d` の呼び出しに写し、応答を返します。DUT が壊れた時だけ誤りを返します。
/// `HELLO` と `--clock real` だけの要求 (`RTO_AT`、`CONN_SOCKET`) と応答の種類は、engine の誤りの応答に
/// します。frame の server (T3c の `wgstack-dut`) と [`Recorded`] が使います。
pub fn answer<D: ClockedDut + ?Sized>(d: &mut D, req: &Msg) -> Result<Msg, DutError> {
    let unsupported = |k: Kind| {
        Ok(Msg::Error {
            err: ErrKind::Other,
            msg: format!("{k} is not a request this DUT answers"),
        })
    };
    match req {
        Msg::Inject(ps) => {
            let batch: Vec<&[u8]> = ps.iter().map(Vec::as_slice).collect();
            ok_or(d.inject(&batch).map(|()| Msg::Ok))
        }
        Msg::Poll { max } => ok_or(d.poll(usize_of(*max)).map(Msg::Packets)),
        Msg::Advance(dt) => ok_or(d.advance(*dt).map(Msg::Time)),
        Msg::Now => ok_or(d.now().map(Msg::Time)),
        Msg::TcpListen { port } => ok_or(d.tcp_listen(*port).map(Msg::Handle)),
        Msg::UdpListen { port } => ok_or(d.udp_listen(*port).map(Msg::Handle)),
        Msg::Accept(l) => op_msg(d.accept(*l), |a| Msg::Accepted {
            h: a.conn,
            remote: a.remote,
        }),
        Msg::Read { h, max } => op_msg(d.read(*h, usize_of(*max)), Msg::Data),
        Msg::Write { h, data } => match d.write(*h, data) {
            Op::WouldBlock => Ok(Msg::Wrote(0)),
            op => op_msg(op, |n| Msg::Wrote(u32_of(n))),
        },
        Msg::Close(h) => ok_or(d.close(*h).map(|()| Msg::Ok)),
        Msg::CloseWrite(h) => ok_or(d.close_write(*h).map(|()| Msg::Ok)),
        Msg::Abort(h) => ok_or(d.abort(*h).map(|()| Msg::Ok)),
        Msg::CloseForDelivery(h) => ok_or(d.close_for_delivery(*h).map(|()| Msg::Ok)),
        Msg::Delivered(h) => ok_or(d.delivered(*h).map(Msg::Bool)),
        Msg::BoostPolicy { h, floor } => ok_or(d.boost_policy(*h, *floor).map(Msg::Bool)),
        Msg::Events => ok_or(d.events().map(Msg::EventList)),
        Msg::UdpRecv { h, max } => op_msg(d.udp_recv(*h, usize_of(*max)), |g| Msg::Datagram {
            from: g.from,
            data: g.data,
        }),
        Msg::UdpSend { h, to, data } => op_msg(d.udp_send(*h, *to, data), |()| Msg::Ok),
        Msg::PingOpen { to } => ok_or(d.ping_open(*to).map(Msg::Handle)),
        Msg::PingSend { h, data } => ok_or(d.ping_send(*h, data).map(|()| Msg::Ok)),
        Msg::PingRecv { h, max } => op_msg(d.ping_recv(*h, usize_of(*max)), Msg::Data),
        Msg::PingClose(h) => ok_or(d.ping_close(*h).map(|()| Msg::Ok)),
        Msg::Stats => ok_or(d.stats().map(Msg::Text)),
        Msg::Bound => ok_or(d.bound().map(Msg::Text)),
        Msg::Held => ok_or(d.held().map(Msg::Text)),
        other => unsupported(other.kind()),
    }
}

/// 応答を操作の結果に戻します。[`ProcessDut`] と [`Recorded`] が使います。
mod back {
    use super::{Accepted, Datagram, DutError, EngineError, Handle, Msg, Op};
    use std::time::Duration;

    fn unexpected(op: &str, resp: &Msg) -> DutError {
        DutError::Broken(format!("{op} answered {resp}"))
    }

    fn engine(resp: Msg) -> Result<DutError, Msg> {
        match resp {
            Msg::Error { err, msg } => Ok(DutError::Engine(EngineError { kind: err, msg })),
            other => Err(other),
        }
    }

    pub(super) fn unit(op: &str, resp: Msg) -> Result<(), DutError> {
        match resp {
            Msg::Ok => Ok(()),
            r => Err(engine(r).unwrap_or_else(|r| unexpected(op, &r))),
        }
    }

    pub(super) fn time(op: &str, resp: Msg) -> Result<Duration, DutError> {
        match resp {
            Msg::Time(t) => Ok(t),
            r => Err(engine(r).unwrap_or_else(|r| unexpected(op, &r))),
        }
    }

    pub(super) fn handle(op: &str, resp: Msg) -> Result<Handle, DutError> {
        match resp {
            Msg::Handle(h) => Ok(h),
            r => Err(engine(r).unwrap_or_else(|r| unexpected(op, &r))),
        }
    }

    pub(super) fn boolean(op: &str, resp: Msg) -> Result<bool, DutError> {
        match resp {
            Msg::Bool(v) => Ok(v),
            r => Err(engine(r).unwrap_or_else(|r| unexpected(op, &r))),
        }
    }

    pub(super) fn text(op: &str, resp: Msg) -> Result<String, DutError> {
        match resp {
            Msg::Text(s) => Ok(s),
            r => Err(engine(r).unwrap_or_else(|r| unexpected(op, &r))),
        }
    }

    pub(super) fn packets(op: &str, resp: Msg) -> Result<Vec<Vec<u8>>, DutError> {
        match resp {
            Msg::Packets(p) => Ok(p),
            r => Err(engine(r).unwrap_or_else(|r| unexpected(op, &r))),
        }
    }

    pub(super) fn events(op: &str, resp: Msg) -> Result<Vec<super::BoostEvent>, DutError> {
        match resp {
            Msg::EventList(v) => Ok(v),
            r => Err(engine(r).unwrap_or_else(|r| unexpected(op, &r))),
        }
    }

    fn op<T>(name: &str, resp: Msg, f: impl FnOnce(Msg) -> Result<T, Msg>) -> Op<T> {
        match resp {
            Msg::WouldBlock => Op::WouldBlock,
            Msg::Error { err, msg } => Op::Failed(DutError::Engine(EngineError { kind: err, msg })),
            r => match f(r) {
                Ok(v) => Op::Ready(v),
                Err(r) => Op::Failed(unexpected(name, &r)),
            },
        }
    }

    pub(super) fn accepted(resp: Msg) -> Op<Accepted> {
        op("ACCEPT", resp, |r| match r {
            Msg::Accepted { h, remote } => Ok(Accepted { conn: h, remote }),
            r => Err(r),
        })
    }

    pub(super) fn data(name: &str, resp: Msg) -> Op<Vec<u8>> {
        op(name, resp, |r| match r {
            Msg::Data(d) => Ok(d),
            r => Err(r),
        })
    }

    pub(super) fn wrote(resp: Msg) -> Op<usize> {
        op("WRITE", resp, |r| match r {
            Msg::Wrote(n) => Ok(usize::try_from(n).unwrap_or(usize::MAX)),
            r => Err(r),
        })
    }

    pub(super) fn datagram(resp: Msg) -> Op<Datagram> {
        op("UDP_RECV", resp, |r| match r {
            Msg::Datagram { from, data } => Ok(Datagram { from, data }),
            r => Err(r),
        })
    }

    pub(super) fn sent(resp: Msg) -> Op<()> {
        op("UDP_SEND", resp, |r| match r {
            Msg::Ok => Ok(()),
            r => Err(r),
        })
    }
}

/// 要求と応答を 1 つずつ交わすものです。[`ProcessDut`] と [`Recorded`] が [`ClockedDut`] をこの上に作ります。
trait Exchange {
    fn exchange(&mut self, req: Msg) -> Result<Msg, DutError>;
}

macro_rules! clocked_via_exchange {
    (impl[$($gen:tt)*] $t:ty) => {
        clocked_via_exchange!(impl[$($gen)*] $t {});
    };
    (impl[$($gen:tt)*] $t:ty { $($extra:item)* }) => {
        impl<$($gen)*> ClockedDut for $t {
            $($extra)*
            fn now(&mut self) -> Result<Duration, DutError> {
                back::time("NOW", self.exchange(Msg::Now)?)
            }
            fn advance(&mut self, d: Duration) -> Result<Duration, DutError> {
                back::time("ADVANCE", self.exchange(Msg::Advance(d))?)
            }
            fn inject(&mut self, batch: &[&[u8]]) -> Result<(), DutError> {
                back::unit("INJECT", self.exchange(Msg::Inject(batch.iter().map(|p| p.to_vec()).collect()))?)
            }
            fn poll(&mut self, max: usize) -> Result<Vec<Vec<u8>>, DutError> {
                back::packets("POLL", self.exchange(Msg::Poll { max: u32_of(max) })?)
            }
            fn tcp_listen(&mut self, port: u16) -> Result<Handle, DutError> {
                back::handle("TCP_LISTEN", self.exchange(Msg::TcpListen { port })?)
            }
            fn udp_listen(&mut self, port: u16) -> Result<Handle, DutError> {
                back::handle("UDP_LISTEN", self.exchange(Msg::UdpListen { port })?)
            }
            fn accept(&mut self, l: Handle) -> Op<Accepted> {
                match self.exchange(Msg::Accept(l)) {
                    Ok(r) => back::accepted(r),
                    Err(e) => Op::Failed(e),
                }
            }
            fn read(&mut self, c: Handle, max: usize) -> Op<Vec<u8>> {
                match self.exchange(Msg::Read { h: c, max: u32_of(max) }) {
                    Ok(r) => back::data("READ", r),
                    Err(e) => Op::Failed(e),
                }
            }
            fn write(&mut self, c: Handle, data: &[u8]) -> Op<usize> {
                match self.exchange(Msg::Write { h: c, data: data.to_vec() }) {
                    Ok(r) => back::wrote(r),
                    Err(e) => Op::Failed(e),
                }
            }
            fn close(&mut self, h: Handle) -> Result<(), DutError> {
                back::unit("CLOSE", self.exchange(Msg::Close(h))?)
            }
            fn close_write(&mut self, c: Handle) -> Result<(), DutError> {
                back::unit("CLOSE_WRITE", self.exchange(Msg::CloseWrite(c))?)
            }
            fn abort(&mut self, c: Handle) -> Result<(), DutError> {
                back::unit("ABORT", self.exchange(Msg::Abort(c))?)
            }
            fn close_for_delivery(&mut self, c: Handle) -> Result<(), DutError> {
                back::unit("CLOSE_FOR_DELIVERY", self.exchange(Msg::CloseForDelivery(c))?)
            }
            fn delivered(&mut self, c: Handle) -> Result<bool, DutError> {
                back::boolean("DELIVERED", self.exchange(Msg::Delivered(c))?)
            }
            fn boost_policy(&mut self, c: Handle, floor: bool) -> Result<bool, DutError> {
                back::boolean("BOOST_POLICY", self.exchange(Msg::BoostPolicy { h: c, floor })?)
            }
            fn events(&mut self) -> Result<Vec<BoostEvent>, DutError> {
                back::events("EVENTS", self.exchange(Msg::Events)?)
            }
            fn udp_recv(&mut self, s: Handle, max: usize) -> Op<Datagram> {
                match self.exchange(Msg::UdpRecv { h: s, max: u32_of(max) }) {
                    Ok(r) => back::datagram(r),
                    Err(e) => Op::Failed(e),
                }
            }
            fn udp_send(&mut self, s: Handle, to: SocketAddrV4, data: &[u8]) -> Op<()> {
                match self.exchange(Msg::UdpSend { h: s, to, data: data.to_vec() }) {
                    Ok(r) => back::sent(r),
                    Err(e) => Op::Failed(e),
                }
            }
            fn ping_open(&mut self, to: Ipv4Addr) -> Result<Handle, DutError> {
                back::handle("PING_OPEN", self.exchange(Msg::PingOpen { to })?)
            }
            fn ping_send(&mut self, ep: Handle, data: &[u8]) -> Result<(), DutError> {
                back::unit("PING_SEND", self.exchange(Msg::PingSend { h: ep, data: data.to_vec() })?)
            }
            fn ping_recv(&mut self, ep: Handle, max: usize) -> Op<Vec<u8>> {
                match self.exchange(Msg::PingRecv { h: ep, max: u32_of(max) }) {
                    Ok(r) => back::data("PING_RECV", r),
                    Err(e) => Op::Failed(e),
                }
            }
            fn ping_close(&mut self, ep: Handle) -> Result<(), DutError> {
                back::unit("PING_CLOSE", self.exchange(Msg::PingClose(ep))?)
            }
            fn stats(&mut self) -> Result<String, DutError> {
                back::text("STATS", self.exchange(Msg::Stats)?)
            }
            fn bound(&mut self) -> Result<String, DutError> {
                back::text("BOUND", self.exchange(Msg::Bound)?)
            }
            fn held(&mut self) -> Result<String, DutError> {
                back::text("HELD", self.exchange(Msg::Held)?)
            }
        }
    };
}

/// 2 節の送り直さない規則の分け方です。状態を変える要求か、答えが変わるまで同じ問い合わせです。
/// 表は設計の 2 節が正本で、Go の `rustdut.classify` と同じです。
pub fn is_query(req: &Msg, resp: &Msg) -> bool {
    match req.kind() {
        Kind::Now | Kind::Delivered | Kind::Stats | Kind::Bound | Kind::Held => true,
        Kind::Accept | Kind::UdpRecv | Kind::UdpSend | Kind::PingRecv => {
            matches!(resp, Msg::WouldBlock)
        }
        Kind::Read => match resp {
            Msg::WouldBlock => true,
            Msg::Data(d) => d.is_empty(),
            _ => false,
        },
        Kind::Write => matches!(resp, Msg::Wrote(0)),
        _ => false,
    }
}

/// [`ClockedDut`] の呼び出しを 3 節の frame の要求と応答として書き出す包みです (2 節の transcript)。
///
/// 2 節の送り直さない規則を持ちます。問い合わせの要求は、前の同じ bytes の問い合わせの後に状態を変える
/// 要求が無ければ中の DUT を呼ばずに前の応答を返し、書き出しません。`NOW` は時刻を一度知った後は送りません。
/// Go の `rustdut` と同じ規則なので、同じ呼び出しの列から同じ bytes の transcript ができます。
///
/// 応答は中の DUT の [`ClockedDut::exchange_frame`] が返した bytes をそのまま書きます。[`ProcessDut`] では
/// pipe から読んだ bytes なので、`WRITE` への `WOULD_BLOCK` や要求に合わない種類の応答も `rustdut` と同じく
/// そのまま残ります。
pub struct Recorded<D, W> {
    inner: D,
    sink: W,
    cache: HashMap<Vec<u8>, Msg>,
    now: Option<Duration>,
    frames: u64,
}

impl<D: fmt::Debug, W> fmt::Debug for Recorded<D, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorded")
            .field("inner", &self.inner)
            .field("now", &self.now)
            .field("frames", &self.frames)
            .finish_non_exhaustive()
    }
}

impl<D: ClockedDut, W: Write> Recorded<D, W> {
    /// `inner` を包みます。`hello` と `hello_ok` は DUT を作った `HELLO` とその応答で、transcript の先頭に
    /// 書きます。
    pub fn new(inner: D, mut sink: W, hello: &Hello, hello_ok: &Msg) -> Result<Self, DutError> {
        let req = Msg::Hello(hello.clone())
            .frame()
            .map_err(|e| DutError::Broken(e.to_string()))?;
        let resp = hello_ok
            .frame()
            .map_err(|e| DutError::Broken(e.to_string()))?;
        sink.write_all(&req)
            .and_then(|()| sink.write_all(&resp))
            .map_err(|e| DutError::Broken(format!("writing the transcript: {e}")))?;
        Ok(Self {
            inner,
            sink,
            cache: HashMap::new(),
            now: None,
            frames: 2,
        })
    }

    /// 最後に知った DUT の時刻です。DUT に問い合わせません。知らなければ 0 です。Go の `CachedNow` です。
    pub fn cached_now(&self) -> Duration {
        self.now.unwrap_or_default()
    }

    /// 書き出した frame の数 (要求と応答の両方) です。
    pub const fn frames(&self) -> u64 {
        self.frames
    }

    /// 中の DUT です。
    pub const fn inner(&self) -> &D {
        &self.inner
    }

    /// 包みを解き、中の DUT と書き出し先を返します。
    pub fn into_parts(self) -> (D, W) {
        (self.inner, self.sink)
    }
}

impl<D: ClockedDut, W: Write> Exchange for Recorded<D, W> {
    fn exchange(&mut self, req: Msg) -> Result<Msg, DutError> {
        if let (Msg::Now, Some(t)) = (&req, self.now) {
            return Ok(Msg::Time(t));
        }
        let frame = req.frame().map_err(|e| DutError::Broken(e.to_string()))?;
        if let Some(r) = self.cache.get(&frame) {
            return Ok(r.clone());
        }
        let Answered { frame: rf, msg } = self.inner.exchange_frame(&req)?;
        self.sink
            .write_all(&frame)
            .and_then(|()| self.sink.write_all(&rf))
            .map_err(|e| DutError::Broken(format!("writing the transcript: {e}")))?;
        self.frames += 2;
        let resp = msg?;
        if let Msg::Time(t) = resp {
            self.now = Some(t);
        }
        if is_query(&req, &resp) {
            self.cache.insert(frame, resp.clone());
        } else {
            self.cache.clear();
        }
        Ok(resp)
    }
}

clocked_via_exchange!(impl[D: ClockedDut, W: Write] Recorded<D, W>);

/// 3 節の口で別のプロセスの DUT を叩く [`ClockedDut`] です。
///
/// プロセスは `<bin> --clock fake` で起こし、環境変数 `WGFT_WGSTACK_DUTSERVE=1` を与えます (Go の
/// `dutserve` はこれで口を出し、Rust の `wgstack-dut` は読み捨てます)。標準エラーは行ごとに `log` に渡します。
pub struct ProcessDut {
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    stdout: BufReader<ChildStdout>,
    stderr: Option<thread::JoinHandle<()>>,
    hello: Hello,
    hello_ok: Msg,
    engine: String,
    broken: Option<String>,
}

impl fmt::Debug for ProcessDut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessDut")
            .field("pid", &self.child.id())
            .field("engine", &self.engine)
            .finish_non_exhaustive()
    }
}

/// Go の `dutserve` に口を出させる環境変数です。
pub const DUTSERVE_ENV: &str = "WGFT_WGSTACK_DUTSERVE";

impl ProcessDut {
    /// `bin` を起こし、`hello` で engine を作ります。
    pub fn spawn(
        bin: &std::path::Path,
        hello: Hello,
        log: impl Fn(&str) + Send + 'static,
    ) -> Result<Self, DutError> {
        let mut child = Command::new(bin)
            .args(["--clock", "fake"])
            .env(DUTSERVE_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| DutError::Broken(format!("starting the DUT {}: {e}", bin.display())))?;
        let stdin = BufWriter::with_capacity(64 << 10, child.stdin.take().expect("piped"));
        let stdout = BufReader::with_capacity(64 << 10, child.stdout.take().expect("piped"));
        let stderr = child.stderr.take().expect("piped");
        let errlog = thread::spawn(move || {
            use std::io::BufRead;
            for line in BufReader::new(stderr).split(b'\n') {
                let Ok(line) = line else { break };
                log(&format!("dut: {}", String::from_utf8_lossy(&line)));
            }
        });
        let mut d = Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr: Some(errlog),
            hello: hello.clone(),
            hello_ok: Msg::Ok,
            engine: String::new(),
            broken: None,
        };
        let resp = d.exchange(Msg::Hello(hello));
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                let _ = d.close();
                return Err(e);
            }
        };
        match &resp {
            Msg::HelloOk { engine, .. } => d.engine.clone_from(engine),
            Msg::Error { msg, .. } => {
                let msg = format!("HELLO refused: {msg}");
                let _ = d.close();
                return Err(DutError::Broken(msg));
            }
            other => {
                let msg = format!("HELLO answered {other}");
                let _ = d.close();
                return Err(DutError::Broken(msg));
            }
        }
        d.hello_ok = resp;
        Ok(d)
    }

    /// engine の名前です (`HELLO_OK`)。
    pub fn engine(&self) -> &str {
        &self.engine
    }

    /// DUT を作った `HELLO` です。
    pub const fn hello(&self) -> &Hello {
        &self.hello
    }

    /// `HELLO` の応答です。
    pub const fn hello_ok(&self) -> &Msg {
        &self.hello_ok
    }

    /// プロセスを終えます。標準入力を閉じ、プロセスと標準エラーの終わりを待ちます。終了コードが 0 でなければ
    /// 誤りです。10 秒で終わらなければ止めます。
    pub fn close(&mut self) -> Result<(), DutError> {
        let Some(mut stdin) = self.stdin.take() else {
            return Ok(());
        };
        let _ = stdin.flush();
        drop(stdin);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                Ok(None) => break None,
                Err(e) => return Err(DutError::Broken(format!("waiting for the DUT: {e}"))),
            }
        };
        let Some(status) = status else {
            let _ = self.child.kill();
            let _ = self.child.wait();
            return Err(DutError::Broken(
                "the DUT process did not end within 10 s of its standard input closing; killed"
                    .to_owned(),
            ));
        };
        if let Some(h) = self.stderr.take() {
            let _ = h.join();
        }
        if status.success() {
            Ok(())
        } else {
            Err(DutError::Broken(format!(
                "the DUT process ended with {status}"
            )))
        }
    }
}

impl ProcessDut {
    /// 要求を 1 つ送り、応答の frame を読みます。Go の `rustdut` の `roundTrip` と同じく、応答の種類の frame
    /// なら本体が読めなくても bytes を返し、読めない時は [`Answered::msg`] を誤りにします。
    fn round_trip(&mut self, req: &Msg) -> Result<Answered, DutError> {
        if let Some(b) = &self.broken {
            return Err(DutError::Broken(b.clone()));
        }
        let Some(stdin) = self.stdin.as_mut() else {
            return Err(DutError::Broken("the DUT process is closed".to_owned()));
        };
        let kind = req.kind();
        let res = (|| {
            frame::write_msg(stdin, req)?;
            stdin.flush().map_err(frame::FrameError::Io)?;
            let (k, body) = frame::read_frame(&mut self.stdout)?;
            if k < 0x80 {
                return Err(frame::FrameError::Proto(frame::ProtoError(format!(
                    "the DUT answered with a request frame 0x{k:02x}"
                ))));
            }
            Ok((k, body))
        })();
        let (k, body) = res.map_err(|e| self.fail(kind, &e))?;
        let len = u32::try_from(1 + body.len()).expect("read_frame bounds the length");
        let mut raw = Vec::with_capacity(5 + body.len());
        raw.extend_from_slice(&len.to_le_bytes());
        raw.push(k);
        raw.extend_from_slice(&body);
        let msg = Msg::decode(k, &body).map_err(|e| self.fail(kind, &e.into()));
        Ok(Answered { frame: raw, msg })
    }

    fn fail(&mut self, kind: Kind, e: &frame::FrameError) -> DutError {
        let msg = format!("rustdut: {kind}: {e}");
        self.broken = Some(msg.clone());
        DutError::Broken(msg)
    }
}

impl Exchange for ProcessDut {
    fn exchange(&mut self, req: Msg) -> Result<Msg, DutError> {
        self.round_trip(&req)?.msg
    }
}

clocked_via_exchange!(impl[] ProcessDut {
    fn exchange_frame(&mut self, req: &Msg) -> Result<Answered, DutError> {
        self.round_trip(req)
    }
});

impl Drop for ProcessDut {
    fn drop(&mut self) {
        if self.stdin.is_some() {
            let _ = self.close();
        }
    }
}

/// 試験の DUT です。runner の試験も使います。
#[cfg(test)]
pub(crate) mod stub {
    use super::{Accepted, BoostEvent, ClockedDut, Datagram, Handle, Op, back, u32_of};
    use super::{Answered, DutError, Exchange, Kind, Msg, answer_frame};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    /// 決めた応答を返す DUT です。受けた要求を数え、`raw` なら応答を [`super::answer`] を通さずにそのまま返します
    /// ([`super::ProcessDut`] と同じ道)。
    pub(crate) struct Stub {
        pub(crate) respond: fn(&Msg) -> Msg,
        pub(crate) raw: bool,
        pub(crate) seen: Vec<Kind>,
    }

    impl Stub {
        pub(crate) fn new(respond: fn(&Msg) -> Msg) -> Self {
            Self {
                respond,
                raw: false,
                seen: Vec::new(),
            }
        }
    }

    impl Exchange for Stub {
        fn exchange(&mut self, req: Msg) -> Result<Msg, DutError> {
            self.seen.push(req.kind());
            Ok((self.respond)(&req))
        }
    }

    clocked_via_exchange!(impl[] Stub {
        fn exchange_frame(&mut self, req: &Msg) -> Result<Answered, DutError> {
            if !self.raw {
                return answer_frame(self, req);
            }
            self.seen.push(req.kind());
            let resp = (self.respond)(req);
            let frame = resp.frame().map_err(|e| DutError::Broken(e.to_string()))?;
            Ok(Answered { frame, msg: Ok(resp) })
        }
    });

    /// 読みは待つ必要を、書き込みは 0 byte を、時計は 5 ms を返す応答です。
    pub(crate) fn idle(req: &Msg) -> Msg {
        match req {
            Msg::Read { .. } | Msg::Accept(_) | Msg::UdpRecv { .. } => Msg::WouldBlock,
            Msg::Write { .. } => Msg::Wrote(0),
            Msg::Now | Msg::Advance(_) => Msg::Time(Duration::from_millis(5)),
            Msg::Stats | Msg::Bound | Msg::Held => Msg::Text("x=1".to_owned()),
            Msg::Delivered(_) => Msg::Bool(false),
            Msg::Poll { .. } => Msg::Packets(Vec::new()),
            _ => Msg::Ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::stub::{Stub, idle};
    use super::*;
    use crate::frame::{Boost, Clock, Congestion, SEED_LEN, VERSION};

    fn hello() -> Hello {
        Hello {
            version: VERSION,
            clock: Clock::Fake,
            addr: Ipv4Addr::new(10, 200, 0, 2),
            mtu: 1420,
            seed: [7; SEED_LEN],
            limits: Vec::new(),
            boost: Boost::OnDemand,
            congestion: Congestion::Cubic,
        }
    }

    fn recorded(stub: Stub) -> Recorded<Stub, Vec<u8>> {
        let ok = Msg::HelloOk {
            engine: "stub".to_owned(),
            version: VERSION,
        };
        Recorded::new(stub, Vec::new(), &hello(), &ok).unwrap()
    }

    /// transcript を frame に分け、種類の列にします。
    fn kinds(t: &[u8]) -> Vec<Kind> {
        let mut r = t;
        let mut out = Vec::new();
        loop {
            match frame::read_frame(&mut r) {
                Ok((k, _)) => out.push(Kind::from_byte(k).unwrap()),
                Err(frame::FrameError::Eof) => return out,
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn query_answers_come_from_the_cache() {
        let c = Handle(3);
        let mut r = recorded(Stub::new(idle));
        for _ in 0..3 {
            assert_eq!(r.read(c, 10), Op::WouldBlock);
            assert_eq!(r.write(c, b"ab"), Op::Ready(0));
            assert_eq!(r.accept(Handle(1)), Op::WouldBlock);
            assert_eq!(r.stats().unwrap(), "x=1");
            assert!(!r.delivered(c).unwrap());
        }
        // 違う bytes の要求は別の問い合わせです。
        assert_eq!(r.read(c, 11), Op::WouldBlock);
        assert_eq!(
            r.inner().seen,
            [
                Kind::Read,
                Kind::Write,
                Kind::Accept,
                Kind::Stats,
                Kind::Delivered,
                Kind::Read
            ]
        );
        assert_eq!(r.frames(), 2 + 2 * 6);
        let (_, t) = r.into_parts();
        let k = kinds(&t);
        assert_eq!(k.len(), 14);
        assert_eq!(
            &k[..4],
            [Kind::Hello, Kind::HelloOk, Kind::Read, Kind::WouldBlock]
        );
    }

    #[test]
    fn a_state_change_clears_the_cache() {
        let c = Handle(3);
        let mut r = recorded(Stub::new(idle));
        assert_eq!(r.read(c, 10), Op::WouldBlock);
        r.inject(&[b"p"]).unwrap();
        assert_eq!(r.read(c, 10), Op::WouldBlock);
        r.poll(1).unwrap();
        assert_eq!(r.read(c, 10), Op::WouldBlock);
        r.close(Handle(9)).unwrap();
        assert_eq!(r.read(c, 10), Op::WouldBlock);
        assert_eq!(
            r.inner().seen,
            [
                Kind::Read,
                Kind::Inject,
                Kind::Read,
                Kind::Poll,
                Kind::Read,
                Kind::Close,
                Kind::Read
            ]
        );
    }

    #[test]
    fn a_result_changes_state() {
        // 結果を返した READ と ACCEPT は状態を変える要求で、問い合わせの答えを使えなくします。
        fn data(req: &Msg) -> Msg {
            match req {
                Msg::Read { .. } => Msg::Data(b"hi".to_vec()),
                Msg::Accept(_) => Msg::Accepted {
                    h: Handle(4),
                    remote: "10.200.0.1:40001".parse().unwrap(),
                },
                other => idle(other),
            }
        }
        let mut r = recorded(Stub::new(data));
        r.stats().unwrap();
        assert_eq!(r.read(Handle(3), 10), Op::Ready(b"hi".to_vec()));
        r.stats().unwrap();
        assert!(matches!(r.accept(Handle(1)), Op::Ready(_)));
        r.stats().unwrap();
        assert_eq!(r.read(Handle(3), 10), Op::Ready(b"hi".to_vec()));
        assert_eq!(
            r.inner().seen,
            [
                Kind::Stats,
                Kind::Read,
                Kind::Stats,
                Kind::Accept,
                Kind::Stats,
                Kind::Read
            ]
        );
    }

    #[test]
    fn now_is_sent_until_the_time_is_known() {
        let mut r = recorded(Stub::new(idle));
        assert_eq!(r.cached_now(), Duration::ZERO);
        assert_eq!(r.now().unwrap(), Duration::from_millis(5));
        assert_eq!(r.now().unwrap(), Duration::from_millis(5));
        // 状態を変える要求の後も、時刻を変えるのは ADVANCE だけなので NOW を送りません。
        r.inject(&[b"p"]).unwrap();
        assert_eq!(r.now().unwrap(), Duration::from_millis(5));
        assert_eq!(r.inner().seen, [Kind::Now, Kind::Inject]);

        // ADVANCE の応答の時刻を覚え、その後の NOW を送りません。
        let mut r = recorded(Stub::new(|req| match req {
            Msg::Advance(d) => Msg::Time(*d),
            other => idle(other),
        }));
        assert_eq!(
            r.advance(Duration::from_millis(1)).unwrap(),
            Duration::from_millis(1)
        );
        assert_eq!(r.now().unwrap(), Duration::from_millis(1));
        assert_eq!(r.cached_now(), Duration::from_millis(1));
        assert_eq!(
            r.advance(Duration::from_millis(2)).unwrap(),
            Duration::from_millis(2)
        );
        assert_eq!(r.now().unwrap(), Duration::from_millis(2));
        assert_eq!(r.inner().seen, [Kind::Advance, Kind::Advance]);
        assert_eq!(r.frames(), 2 + 2 * 2);
    }

    #[test]
    fn empty_data_is_a_query() {
        fn empty(req: &Msg) -> Msg {
            match req {
                Msg::Read { .. } => Msg::Data(Vec::new()),
                other => idle(other),
            }
        }
        let c = Handle(3);
        let mut r = recorded(Stub::new(empty));
        // 最大 0 の READ も、最大が 0 より大きい READ も、空の DATA なら問い合わせです。
        assert_eq!(r.read(c, 0), Op::Ready(Vec::new()));
        assert_eq!(r.read(c, 0), Op::Ready(Vec::new()));
        assert_eq!(r.read(c, 8), Op::Ready(Vec::new()));
        assert_eq!(r.read(c, 8), Op::Ready(Vec::new()));
        r.stats().unwrap();
        assert_eq!(r.inner().seen, [Kind::Read, Kind::Read, Kind::Stats]);
    }

    #[test]
    fn the_answer_frame_is_written_as_given() {
        // 既定の道は answer を通すので、WRITE への待つ必要は WROTE 0 として書きます。
        fn would_block(req: &Msg) -> Msg {
            match req {
                Msg::Write { .. } => Msg::WouldBlock,
                Msg::Stats => Msg::Ok,
                other => idle(other),
            }
        }
        let c = Handle(3);
        let mut r = recorded(Stub::new(would_block));
        assert_eq!(r.write(c, b"ab"), Op::Ready(0));
        assert_eq!(r.write(c, b"ab"), Op::Ready(0));
        let (_, t) = r.into_parts();
        assert_eq!(&kinds(&t)[2..], [Kind::Write, Kind::Wrote]);

        // 応答の bytes を返す DUT では、その bytes を書きます。WRITE への WOULD_BLOCK は rustdut と同じく
        // 状態を変える応答なので送り直し、要求に合わない応答も書いてから壊れたものとして返します。
        let mut stub = Stub::new(would_block);
        stub.raw = true;
        let mut r = recorded(stub);
        assert_eq!(r.write(c, b"ab"), Op::WouldBlock);
        assert_eq!(r.write(c, b"ab"), Op::WouldBlock);
        assert_eq!(
            r.stats(),
            Err(DutError::Broken("STATS answered Ok".to_owned()))
        );
        let (_, t) = r.into_parts();
        assert_eq!(
            &kinds(&t)[2..],
            [
                Kind::Write,
                Kind::WouldBlock,
                Kind::Write,
                Kind::WouldBlock,
                Kind::Stats,
                Kind::Ok
            ]
        );
    }

    #[test]
    fn query_table() {
        let h = Handle(1);
        assert!(is_query(&Msg::Now, &Msg::Time(Duration::ZERO)));
        assert!(is_query(&Msg::Accept(h), &Msg::WouldBlock));
        assert!(!is_query(
            &Msg::Accept(h),
            &Msg::Accepted {
                h,
                remote: "1.2.3.4:5".parse().unwrap()
            }
        ));
        assert!(is_query(&Msg::Read { h, max: 0 }, &Msg::Data(vec![])));
        assert!(!is_query(&Msg::Read { h, max: 1 }, &Msg::Data(vec![1])));
        assert!(!is_query(
            &Msg::Read { h, max: 1 },
            &Msg::Error {
                err: ErrKind::Eof,
                msg: "EOF".into()
            }
        ));
        assert!(is_query(&Msg::Write { h, data: vec![] }, &Msg::Wrote(0)));
        assert!(!is_query(&Msg::Write { h, data: vec![1] }, &Msg::Wrote(1)));
        assert!(is_query(
            &Msg::UdpSend {
                h,
                to: "1.2.3.4:5".parse().unwrap(),
                data: vec![]
            },
            &Msg::WouldBlock
        ));
        assert!(!is_query(&Msg::Inject(vec![]), &Msg::Ok));
        assert!(!is_query(
            &Msg::Advance(Duration::ZERO),
            &Msg::Time(Duration::ZERO)
        ));
    }
}
