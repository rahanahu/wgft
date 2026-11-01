//! DUT の口の frame の符号です (`docs/design/v2/test-tooling.md` の 3 節と付録)。
//!
//! Go の `internal/dutproto` の写しで、同じ値から同じ bytes を作り、同じ bytes を同じ値に読みます。
//! frame は長さ (u32、little endian、種類と本体の byte 数)、種類 (u8)、本体の順に並びます。
//! 本体が運べない値 (65,535 byte を超える文字列、64 byte でない種、表に無い列挙の値、2^63-1 を超える時間) は、
//! 符号化でも復号でも口の誤りです。Go の試験が書き出した例 (`internal/dutproto/testdata/frames/`) と照らします。

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// HELLO が運ぶ口の版です。
pub const VERSION: u16 = 1;

/// frame の長さの欄 (種類と本体) の上限です。これを超える長さは口の誤りです。
pub const MAX_FRAME: usize = 64 << 20;

/// HELLO の種の長さです。
pub const SEED_LEN: usize = 64;

/// 時刻と時間の上限 (2^63-1 nanosecond) です。
const MAX_NANOS: u64 = i64::MAX as u64;

/// 口の誤りです。壊れた frame か本体、本体が運べない値を表します。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoError(pub String);

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dutproto: protocol error: {}", self.0)
    }
}

impl std::error::Error for ProtoError {}

fn proto<T>(msg: impl Into<String>) -> Result<T, ProtoError> {
    Err(ProtoError(msg.into()))
}

/// 要求と応答の種類の番号です。要求は 0x80 より小さく、応答は 0x80 以上です。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    Hello = 0x01,
    Inject = 0x02,
    Poll = 0x03,
    Advance = 0x04,
    Now = 0x05,
    TcpListen = 0x06,
    UdpListen = 0x07,
    Accept = 0x08,
    Read = 0x09,
    Write = 0x0a,
    Close = 0x0b,
    CloseWrite = 0x0c,
    Abort = 0x0d,
    CloseForDelivery = 0x0e,
    Delivered = 0x0f,
    BoostPolicy = 0x10,
    Events = 0x11,
    UdpRecv = 0x12,
    UdpSend = 0x13,
    PingOpen = 0x14,
    PingSend = 0x15,
    PingRecv = 0x16,
    PingClose = 0x17,
    Stats = 0x18,
    Bound = 0x19,
    Held = 0x1a,
    RtoAt = 0x1b,
    ConnSocket = 0x1c,
    HelloOk = 0x80,
    Ok = 0x81,
    Error = 0x82,
    WouldBlock = 0x83,
    Packets = 0x84,
    Time = 0x85,
    Handle = 0x86,
    Accepted = 0x87,
    Data = 0x88,
    Wrote = 0x89,
    Bool = 0x8a,
    EventList = 0x8b,
    Datagram = 0x8c,
    Text = 0x8d,
    Rto = 0x8e,
}

impl Kind {
    const ALL: [Self; 43] = [
        Self::Hello,
        Self::Inject,
        Self::Poll,
        Self::Advance,
        Self::Now,
        Self::TcpListen,
        Self::UdpListen,
        Self::Accept,
        Self::Read,
        Self::Write,
        Self::Close,
        Self::CloseWrite,
        Self::Abort,
        Self::CloseForDelivery,
        Self::Delivered,
        Self::BoostPolicy,
        Self::Events,
        Self::UdpRecv,
        Self::UdpSend,
        Self::PingOpen,
        Self::PingSend,
        Self::PingRecv,
        Self::PingClose,
        Self::Stats,
        Self::Bound,
        Self::Held,
        Self::RtoAt,
        Self::ConnSocket,
        Self::HelloOk,
        Self::Ok,
        Self::Error,
        Self::WouldBlock,
        Self::Packets,
        Self::Time,
        Self::Handle,
        Self::Accepted,
        Self::Data,
        Self::Wrote,
        Self::Bool,
        Self::EventList,
        Self::Datagram,
        Self::Text,
        Self::Rto,
    ];

    /// 番号から種類を引きます。表に無い番号は `None` です。
    pub fn from_byte(b: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| *k as u8 == b)
    }

    /// 要求の種類かどうかです。
    pub const fn is_request(self) -> bool {
        (self as u8) < 0x80
    }

    /// 付録の表の名前です。
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "HELLO",
            Self::Inject => "INJECT",
            Self::Poll => "POLL",
            Self::Advance => "ADVANCE",
            Self::Now => "NOW",
            Self::TcpListen => "TCP_LISTEN",
            Self::UdpListen => "UDP_LISTEN",
            Self::Accept => "ACCEPT",
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Close => "CLOSE",
            Self::CloseWrite => "CLOSE_WRITE",
            Self::Abort => "ABORT",
            Self::CloseForDelivery => "CLOSE_FOR_DELIVERY",
            Self::Delivered => "DELIVERED",
            Self::BoostPolicy => "BOOST_POLICY",
            Self::Events => "EVENTS",
            Self::UdpRecv => "UDP_RECV",
            Self::UdpSend => "UDP_SEND",
            Self::PingOpen => "PING_OPEN",
            Self::PingSend => "PING_SEND",
            Self::PingRecv => "PING_RECV",
            Self::PingClose => "PING_CLOSE",
            Self::Stats => "STATS",
            Self::Bound => "BOUND",
            Self::Held => "HELD",
            Self::RtoAt => "RTO_AT",
            Self::ConnSocket => "CONN_SOCKET",
            Self::HelloOk => "HELLO_OK",
            Self::Ok => "OK",
            Self::Error => "ERROR",
            Self::WouldBlock => "WOULD_BLOCK",
            Self::Packets => "PACKETS",
            Self::Time => "TIME",
            Self::Handle => "HANDLE",
            Self::Accepted => "ACCEPTED",
            Self::Data => "DATA",
            Self::Wrote => "WROTE",
            Self::Bool => "BOOL",
            Self::EventList => "EVENT_LIST",
            Self::Datagram => "DATAGRAM",
            Self::Text => "TEXT",
            Self::Rto => "RTO",
        }
    }

    /// 名前から種類を引きます。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// DUT が作った待ち受け、接続、UDP の socket、ping の endpoint の番号です。DUT が作った順に 1 から付け、
/// 使い直しません。0 は handle ではありません。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(pub u32);

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// HELLO の時計です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clock {
    /// 要求が進める時計
    Fake = 0,
    /// qbench の実時間
    Real = 1,
}

/// HELLO の boost の与え方です。値は Go の wgstack の `BoostPolicy` です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boost {
    OnDemand = 0,
    AtAccept = 1,
    Never = 2,
}

/// HELLO の輻輳の制御の試験の選択です。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    Cubic = 0,
    NewReno = 1,
}

/// ERROR の応答の種類です。client は種類から engine の誤りを作り直します。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrKind {
    Other = 0,
    Timeout = 1,
    Eof = 2,
    Closed = 3,
    Reset = 4,
    BrokenPipe = 5,
}

impl ErrKind {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Timeout,
            2 => Self::Eof,
            3 => Self::Closed,
            4 => Self::Reset,
            5 => Self::BrokenPipe,
            _ => Self::Other,
        }
    }

    /// 表示の名前です。
    pub const fn name(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::Timeout => "timeout",
            Self::Eof => "EOF",
            Self::Closed => "closed",
            Self::Reset => "reset",
            Self::BrokenPipe => "broken-pipe",
        }
    }
}

/// HELLO の上限の組の 1 つです。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limit {
    pub name: String,
    pub value: u64,
}

/// HELLO の本体です。空の `limits` は engine の既定の上限を求めます。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u16,
    pub clock: Clock,
    pub addr: Ipv4Addr,
    pub mtu: u32,
    pub seed: [u8; SEED_LEN],
    pub limits: Vec<Limit>,
    pub boost: Boost,
    pub congestion: Congestion,
}

/// boost の hook の 1 回の呼び出しです。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoostEvent {
    pub h: Handle,
    pub boosted: bool,
}

/// 1 つの要求か応答です。欄の意味は付録の表のとおりです。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Hello(Hello),
    Inject(Vec<Vec<u8>>),
    Poll {
        max: u32,
    },
    Advance(Duration),
    Now,
    TcpListen {
        port: u16,
    },
    UdpListen {
        port: u16,
    },
    Accept(Handle),
    Read {
        h: Handle,
        max: u32,
    },
    Write {
        h: Handle,
        data: Vec<u8>,
    },
    Close(Handle),
    CloseWrite(Handle),
    Abort(Handle),
    CloseForDelivery(Handle),
    Delivered(Handle),
    BoostPolicy {
        h: Handle,
        floor: bool,
    },
    Events,
    UdpRecv {
        h: Handle,
        max: u32,
    },
    UdpSend {
        h: Handle,
        to: SocketAddrV4,
        data: Vec<u8>,
    },
    PingOpen {
        to: Ipv4Addr,
    },
    PingSend {
        h: Handle,
        data: Vec<u8>,
    },
    PingRecv {
        h: Handle,
        max: u32,
    },
    PingClose(Handle),
    Stats,
    Bound,
    Held,
    RtoAt {
        h: Handle,
        at: Duration,
    },
    ConnSocket {
        h: Handle,
        path: String,
    },
    HelloOk {
        engine: String,
        version: u16,
    },
    Ok,
    Error {
        err: ErrKind,
        msg: String,
    },
    WouldBlock,
    Packets(Vec<Vec<u8>>),
    Time(Duration),
    Handle(Handle),
    Accepted {
        h: Handle,
        remote: SocketAddrV4,
    },
    Data(Vec<u8>),
    Wrote(u32),
    Bool(bool),
    EventList(Vec<BoostEvent>),
    Datagram {
        from: SocketAddrV4,
        data: Vec<u8>,
    },
    Text(String),
    Rto {
        known: bool,
        rto: Duration,
    },
}

impl Msg {
    /// 種類です。
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Hello(_) => Kind::Hello,
            Self::Inject(_) => Kind::Inject,
            Self::Poll { .. } => Kind::Poll,
            Self::Advance(_) => Kind::Advance,
            Self::Now => Kind::Now,
            Self::TcpListen { .. } => Kind::TcpListen,
            Self::UdpListen { .. } => Kind::UdpListen,
            Self::Accept(_) => Kind::Accept,
            Self::Read { .. } => Kind::Read,
            Self::Write { .. } => Kind::Write,
            Self::Close(_) => Kind::Close,
            Self::CloseWrite(_) => Kind::CloseWrite,
            Self::Abort(_) => Kind::Abort,
            Self::CloseForDelivery(_) => Kind::CloseForDelivery,
            Self::Delivered(_) => Kind::Delivered,
            Self::BoostPolicy { .. } => Kind::BoostPolicy,
            Self::Events => Kind::Events,
            Self::UdpRecv { .. } => Kind::UdpRecv,
            Self::UdpSend { .. } => Kind::UdpSend,
            Self::PingOpen { .. } => Kind::PingOpen,
            Self::PingSend { .. } => Kind::PingSend,
            Self::PingRecv { .. } => Kind::PingRecv,
            Self::PingClose(_) => Kind::PingClose,
            Self::Stats => Kind::Stats,
            Self::Bound => Kind::Bound,
            Self::Held => Kind::Held,
            Self::RtoAt { .. } => Kind::RtoAt,
            Self::ConnSocket { .. } => Kind::ConnSocket,
            Self::HelloOk { .. } => Kind::HelloOk,
            Self::Ok => Kind::Ok,
            Self::Error { .. } => Kind::Error,
            Self::WouldBlock => Kind::WouldBlock,
            Self::Packets(_) => Kind::Packets,
            Self::Time(_) => Kind::Time,
            Self::Handle(_) => Kind::Handle,
            Self::Accepted { .. } => Kind::Accepted,
            Self::Data(_) => Kind::Data,
            Self::Wrote(_) => Kind::Wrote,
            Self::Bool(_) => Kind::Bool,
            Self::EventList(_) => Kind::EventList,
            Self::Datagram { .. } => Kind::Datagram,
            Self::Text(_) => Kind::Text,
            Self::Rto { .. } => Kind::Rto,
        }
    }

    /// 本体を符号化します。本体が運べない値は口の誤りです。
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut e = Enc::default();
        match self {
            Self::Hello(h) => {
                e.u16(h.version);
                e.u8(h.clock as u8);
                e.addr(h.addr);
                e.u32(h.mtu);
                e.b.extend_from_slice(&h.seed);
                e.len(h.limits.len())?;
                for l in &h.limits {
                    e.str(&l.name)?;
                    e.u64(l.value);
                }
                e.u8(h.boost as u8);
                e.u8(h.congestion as u8);
            }
            Self::Inject(ps) | Self::Packets(ps) => {
                e.len(ps.len())?;
                for p in ps {
                    e.bytes(p)?;
                }
            }
            Self::Poll { max } => e.u32(*max),
            Self::Advance(d) | Self::Time(d) => e.dur(*d)?,
            Self::Now
            | Self::Events
            | Self::Stats
            | Self::Bound
            | Self::Held
            | Self::Ok
            | Self::WouldBlock => {}
            Self::TcpListen { port } | Self::UdpListen { port } => e.u16(*port),
            Self::Accept(h)
            | Self::Close(h)
            | Self::CloseWrite(h)
            | Self::Abort(h)
            | Self::CloseForDelivery(h)
            | Self::Delivered(h)
            | Self::PingClose(h)
            | Self::Handle(h) => e.u32(h.0),
            Self::Read { h, max } | Self::UdpRecv { h, max } | Self::PingRecv { h, max } => {
                e.u32(h.0);
                e.u32(*max);
            }
            Self::Write { h, data } | Self::PingSend { h, data } => {
                e.u32(h.0);
                e.bytes(data)?;
            }
            Self::BoostPolicy { h, floor } => {
                e.u32(h.0);
                e.u8(u8::from(*floor));
            }
            Self::UdpSend { h, to, data } => {
                e.u32(h.0);
                e.addr_port(*to);
                e.bytes(data)?;
            }
            Self::PingOpen { to } => e.addr(*to),
            Self::RtoAt { h, at } => {
                e.u32(h.0);
                e.dur(*at)?;
            }
            Self::ConnSocket { h, path } => {
                e.u32(h.0);
                e.str(path)?;
            }
            Self::HelloOk { engine, version } => {
                e.str(engine)?;
                e.u16(*version);
            }
            Self::Error { err, msg } => {
                e.u8(*err as u8);
                e.str(msg)?;
            }
            Self::Accepted { h, remote } => {
                e.u32(h.0);
                e.addr_port(*remote);
            }
            Self::Data(d) => e.bytes(d)?,
            Self::Wrote(n) => e.u32(*n),
            Self::Bool(v) => e.u8(u8::from(*v)),
            Self::EventList(evs) => {
                e.len(evs.len())?;
                for ev in evs {
                    e.u32(ev.h.0);
                    e.u8(u8::from(ev.boosted));
                }
            }
            Self::Datagram { from, data } => {
                e.addr_port(*from);
                e.bytes(data)?;
            }
            Self::Text(s) => e.str(s)?,
            Self::Rto { known, rto } => {
                e.u8(u8::from(*known));
                e.dur(*rto)?;
            }
        }
        Ok(e.b)
    }

    /// 種類 `kind` の本体を復号します。
    pub fn decode(kind: u8, body: &[u8]) -> Result<Self, ProtoError> {
        let Some(k) = Kind::from_byte(kind) else {
            return proto(format!("unknown frame kind 0x{kind:02x}"));
        };
        let mut d = Dec { b: body };
        let m = match k {
            Kind::Hello => {
                let version = d.u16()?;
                let clock = match d.enum_u8(2, "clock")? {
                    0 => Clock::Fake,
                    _ => Clock::Real,
                };
                let addr = d.addr()?;
                let mtu = d.u32()?;
                let seed: [u8; SEED_LEN] = d.take(SEED_LEN)?.try_into().expect("taken 64 bytes");
                let n = d.list(10)?;
                let mut limits = Vec::with_capacity(n);
                for _ in 0..n {
                    let name = d.str()?;
                    limits.push(Limit {
                        name,
                        value: d.u64()?,
                    });
                }
                let boost = match d.enum_u8(3, "boost policy")? {
                    0 => Boost::OnDemand,
                    1 => Boost::AtAccept,
                    _ => Boost::Never,
                };
                let congestion = match d.enum_u8(2, "congestion control")? {
                    0 => Congestion::Cubic,
                    _ => Congestion::NewReno,
                };
                Self::Hello(Hello {
                    version,
                    clock,
                    addr,
                    mtu,
                    seed,
                    limits,
                    boost,
                    congestion,
                })
            }
            Kind::Inject | Kind::Packets => {
                let n = d.list(4)?;
                let mut ps = Vec::with_capacity(n);
                for _ in 0..n {
                    ps.push(d.bytes()?);
                }
                if k == Kind::Inject {
                    Self::Inject(ps)
                } else {
                    Self::Packets(ps)
                }
            }
            Kind::Poll => Self::Poll { max: d.u32()? },
            Kind::Advance => Self::Advance(d.dur()?),
            Kind::Time => Self::Time(d.dur()?),
            Kind::Now => Self::Now,
            Kind::Events => Self::Events,
            Kind::Stats => Self::Stats,
            Kind::Bound => Self::Bound,
            Kind::Held => Self::Held,
            Kind::Ok => Self::Ok,
            Kind::WouldBlock => Self::WouldBlock,
            Kind::TcpListen => Self::TcpListen { port: d.u16()? },
            Kind::UdpListen => Self::UdpListen { port: d.u16()? },
            Kind::Accept => Self::Accept(d.handle()?),
            Kind::Close => Self::Close(d.handle()?),
            Kind::CloseWrite => Self::CloseWrite(d.handle()?),
            Kind::Abort => Self::Abort(d.handle()?),
            Kind::CloseForDelivery => Self::CloseForDelivery(d.handle()?),
            Kind::Delivered => Self::Delivered(d.handle()?),
            Kind::PingClose => Self::PingClose(d.handle()?),
            Kind::Handle => Self::Handle(d.handle()?),
            Kind::Read => Self::Read {
                h: d.handle()?,
                max: d.u32()?,
            },
            Kind::UdpRecv => Self::UdpRecv {
                h: d.handle()?,
                max: d.u32()?,
            },
            Kind::PingRecv => Self::PingRecv {
                h: d.handle()?,
                max: d.u32()?,
            },
            Kind::Write => Self::Write {
                h: d.handle()?,
                data: d.bytes()?,
            },
            Kind::PingSend => Self::PingSend {
                h: d.handle()?,
                data: d.bytes()?,
            },
            Kind::BoostPolicy => Self::BoostPolicy {
                h: d.handle()?,
                floor: d.bool()?,
            },
            Kind::UdpSend => Self::UdpSend {
                h: d.handle()?,
                to: d.addr_port()?,
                data: d.bytes()?,
            },
            Kind::PingOpen => Self::PingOpen { to: d.addr()? },
            Kind::RtoAt => Self::RtoAt {
                h: d.handle()?,
                at: d.dur()?,
            },
            Kind::ConnSocket => Self::ConnSocket {
                h: d.handle()?,
                path: d.str()?,
            },
            Kind::HelloOk => Self::HelloOk {
                engine: d.str()?,
                version: d.u16()?,
            },
            Kind::Error => Self::Error {
                err: ErrKind::from_u8(d.enum_u8(6, "error kind")?),
                msg: d.str()?,
            },
            Kind::Accepted => Self::Accepted {
                h: d.handle()?,
                remote: d.addr_port()?,
            },
            Kind::Data => Self::Data(d.bytes()?),
            Kind::Wrote => Self::Wrote(d.u32()?),
            Kind::Bool => Self::Bool(d.bool()?),
            Kind::EventList => {
                let n = d.list(5)?;
                let mut evs = Vec::with_capacity(n);
                for _ in 0..n {
                    evs.push(BoostEvent {
                        h: d.handle()?,
                        boosted: d.bool()?,
                    });
                }
                Self::EventList(evs)
            }
            Kind::Datagram => Self::Datagram {
                from: d.addr_port()?,
                data: d.bytes()?,
            },
            Kind::Text => Self::Text(d.str()?),
            Kind::Rto => Self::Rto {
                known: d.bool()?,
                rto: d.dur()?,
            },
        };
        if !d.b.is_empty() {
            return proto(format!("{k}: {} trailing bytes", d.b.len()));
        }
        Ok(m)
    }

    /// 1 つの frame の bytes です。
    pub fn frame(&self) -> Result<Vec<u8>, ProtoError> {
        let body = self.encode()?;
        frame_bytes(self.kind() as u8, &body)
    }
}

fn frame_bytes(kind: u8, body: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let n = 1 + body.len();
    if n > MAX_FRAME {
        return proto(format!("frame of {n} bytes exceeds {MAX_FRAME}"));
    }
    let mut out = Vec::with_capacity(4 + n);
    out.extend_from_slice(&u32::try_from(n).expect("below MAX_FRAME").to_le_bytes());
    out.push(kind);
    out.extend_from_slice(body);
    Ok(out)
}

/// frame の読み書きの誤りです。
#[derive(Debug)]
pub enum FrameError {
    /// 流れが frame の境目で終わった
    Eof,
    /// 読み書きの誤り。frame の途中で終わった流れは `UnexpectedEof` です
    Io(io::Error),
    /// 口の誤り
    Proto(ProtoError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("EOF"),
            Self::Io(e) => e.fmt(f),
            Self::Proto(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<ProtoError> for FrameError {
    fn from(e: ProtoError) -> Self {
        Self::Proto(e)
    }
}

/// 1 つの frame を読み、種類の byte と本体を返します。流れが frame の境目で終わったら [`FrameError::Eof`] です。
pub fn read_frame(r: &mut impl Read) -> Result<(u8, Vec<u8>), FrameError> {
    let mut hdr = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut hdr[got..]) {
            Ok(0) if got == 0 => return Err(FrameError::Eof),
            Ok(0) => return Err(FrameError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(k) => got += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let n = u32::from_le_bytes(hdr) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(ProtoError(format!("frame length {n} out of range 1 to {MAX_FRAME}")).into());
    }
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind).map_err(FrameError::Io)?;
    let mut body = vec![0u8; n - 1];
    r.read_exact(&mut body).map_err(FrameError::Io)?;
    Ok((kind[0], body))
}

/// 1 つの frame を読んで復号します。
pub fn read_msg(r: &mut impl Read) -> Result<Msg, FrameError> {
    let (k, body) = read_frame(r)?;
    Ok(Msg::decode(k, &body)?)
}

/// `m` を 1 つの frame として書きます。
pub fn write_msg(w: &mut impl Write, m: &Msg) -> Result<(), FrameError> {
    let f = m.frame()?;
    w.write_all(&f).map_err(FrameError::Io)
}

#[derive(Default)]
struct Enc {
    b: Vec<u8>,
}

impl Enc {
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn len(&mut self, n: usize) -> Result<(), ProtoError> {
        let Ok(v) = u32::try_from(n) else {
            return proto(format!("length {n} exceeds a u32"));
        };
        self.u32(v);
        Ok(())
    }
    fn dur(&mut self, d: Duration) -> Result<(), ProtoError> {
        let Ok(v) = u64::try_from(d.as_nanos()) else {
            return proto(format!("duration {d:?} overflows"));
        };
        if v > MAX_NANOS {
            return proto(format!("duration {v} ns overflows"));
        }
        self.u64(v);
        Ok(())
    }
    fn bytes(&mut self, b: &[u8]) -> Result<(), ProtoError> {
        self.len(b.len())?;
        self.b.extend_from_slice(b);
        Ok(())
    }
    fn str(&mut self, s: &str) -> Result<(), ProtoError> {
        let Ok(n) = u16::try_from(s.len()) else {
            return proto(format!("string of {} bytes; at most 65535", s.len()));
        };
        self.u16(n);
        self.b.extend_from_slice(s.as_bytes());
        Ok(())
    }
    fn addr(&mut self, a: Ipv4Addr) {
        self.b.extend_from_slice(&a.octets());
    }
    fn addr_port(&mut self, ap: SocketAddrV4) {
        self.addr(*ap.ip());
        self.u16(ap.port());
    }
}

struct Dec<'a> {
    b: &'a [u8],
}

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.b.len() < n {
            return proto(format!("body ends {} bytes short", n - self.b.len()));
        }
        let (v, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(v)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        Ok(self.take(N)?.try_into().expect("taken N bytes"))
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtoError> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32, ProtoError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn bool(&mut self) -> Result<bool, ProtoError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            v => proto(format!("bool byte {v} is neither 0 nor 1")),
        }
    }
    fn handle(&mut self) -> Result<Handle, ProtoError> {
        Ok(Handle(self.u32()?))
    }
    fn dur(&mut self) -> Result<Duration, ProtoError> {
        let v = self.u64()?;
        if v > MAX_NANOS {
            return proto(format!("duration {v} ns overflows"));
        }
        Ok(Duration::from_nanos(v))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, ProtoError> {
        let n = self.u32()? as usize;
        if n > self.b.len() {
            return proto(format!("byte string of {n} bytes in {} left", self.b.len()));
        }
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String, ProtoError> {
        let n = usize::from(self.u16()?);
        let b = self.take(n)?;
        match std::str::from_utf8(b) {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => proto("string is not UTF-8"),
        }
    }
    fn enum_u8(&mut self, n: u8, what: &str) -> Result<u8, ProtoError> {
        let v = self.u8()?;
        if v >= n {
            return proto(format!("{what} {v} is not one of the {n} values"));
        }
        Ok(v)
    }
    fn addr(&mut self) -> Result<Ipv4Addr, ProtoError> {
        Ok(Ipv4Addr::from(self.arr::<4>()?))
    }
    fn addr_port(&mut self) -> Result<SocketAddrV4, ProtoError> {
        let a = self.addr()?;
        Ok(SocketAddrV4::new(a, self.u16()?))
    }
    /// 要素が少なくとも `min` byte を取るとして、壊れた長さで大きな領域を取らないように確かめます。
    fn list(&mut self, min: usize) -> Result<usize, ProtoError> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min) > self.b.len() {
            return proto(format!("list of {n} elements in {} bytes", self.b.len()));
        }
        Ok(n)
    }
}

impl fmt::Display for Msg {
    /// 人が読む形です。Go の `dutproto.Format` と同じ文字列である必要はありません。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = crate::packet::short_hex;
        let k = self.kind();
        match self {
            Self::Inject(ps) | Self::Packets(ps) => {
                let parts: Vec<String> =
                    ps.iter().map(|p| crate::packet::packet_string(p)).collect();
                write!(f, "{k} packets=[{}]", parts.join("; "))
            }
            Self::Write { h, data } | Self::PingSend { h, data } => {
                write!(f, "{k} h={h} data={}", short(data))
            }
            Self::Data(d) => write!(f, "{k} data={}", short(d)),
            Self::Datagram { from, data } => write!(f, "{k} from={from} data={}", short(data)),
            Self::UdpSend { h, to, data } => write!(f, "{k} h={h} to={to} data={}", short(data)),
            Self::Hello(h) => write!(
                f,
                "{k} version={} clock={:?} addr={} mtu={} seed={} limits={:?} boost={:?} congestion={:?}",
                h.version,
                h.clock,
                h.addr,
                h.mtu,
                short(&h.seed),
                h.limits,
                h.boost,
                h.congestion
            ),
            Self::Error { err, msg } => write!(f, "{k} err={} msg={msg:?}", err.name()),
            other => write!(f, "{other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip() {
        for k in Kind::ALL {
            assert_eq!(Kind::from_byte(k as u8), Some(k));
            assert_eq!(Kind::from_name(k.name()), Some(k));
        }
        assert_eq!(Kind::from_byte(0x7f), None);
    }

    #[test]
    fn short_reads_and_eof() {
        let mut empty: &[u8] = &[];
        assert!(matches!(read_frame(&mut empty), Err(FrameError::Eof)));
        let mut cut: &[u8] = &[5, 0, 0, 0, 0x81];
        assert!(matches!(read_frame(&mut cut), Err(FrameError::Io(_))));
    }

    #[test]
    fn refuses_values_the_body_cannot_carry() {
        assert!(Msg::Text("x".repeat(70000)).encode().is_err());
        assert!(
            Msg::Advance(Duration::from_nanos(MAX_NANOS) + Duration::from_nanos(1))
                .encode()
                .is_err()
        );
    }
}
