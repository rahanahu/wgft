//! 台本の値です。Go の runner (`script_run.go`) の値の型を写します。

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;

use crate::dut::EngineError;
use crate::frame::{ErrKind, Handle};
use crate::ip::{Icmp, Ipv4, Quote, Udp};
use crate::packet::{Options, SackBlock, Segment};

use super::harness::Peer;

/// 捕捉した segment と、見えたか、いつ見えたかです。
#[derive(Debug, Clone)]
pub(crate) struct SegV {
    pub(crate) seg: Segment,
    pub(crate) ok: bool,
    /// DUT の時刻 (nanosecond)。Go の zero の time.Time は [`ZERO_TIME`]
    pub(crate) at: i64,
}

/// Go の zero の `time.Time` に当たる時刻です。引き算は飽和します。
pub(crate) const ZERO_TIME: i64 = i64::MIN;

/// 相手と、`connect` と `handshake` が記録した SYN-ACK と接続です。
#[derive(Debug)]
pub(crate) struct PeerV {
    pub(crate) p: RefCell<Peer>,
    pub(crate) synack: Option<Rc<SegV>>,
    pub(crate) conn: Option<Handle>,
}

#[derive(Debug)]
pub(crate) struct ListenerV {
    pub(crate) h: Handle,
    pub(crate) closed: bool,
}

#[derive(Debug)]
pub(crate) struct UdpConnV {
    pub(crate) h: Handle,
    pub(crate) port: u16,
    pub(crate) closed: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct IpV {
    pub(crate) p: Ipv4,
    pub(crate) ok: bool,
    pub(crate) at: i64,
}

/// Go の誤りの値です。`err_string` と `err_kind` が Go と同じ文字列を返すように、Go の誤りの形を持ちます。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GoErr {
    /// engine の誤り (rustdut の `remoteError`)。EOF の種類は [`GoErr::Eof`] にします
    Engine(EngineError),
    /// `io.EOF`
    Eof,
    /// 締め切りの誤り。`Timeout()` が真の誤りで、文は使いません
    Timeout,
    /// `net.ErrClosed`
    Closed,
    /// そのほかの誤りの文
    Other(String),
}

impl GoErr {
    /// engine の誤りの応答から作ります。Go の `respErr` です。
    pub(crate) fn from_engine(e: EngineError) -> Self {
        if e.kind == ErrKind::Eof {
            Self::Eof
        } else {
            Self::Engine(e)
        }
    }

    /// Go の `errString` です。
    pub(crate) fn err_string(&self) -> String {
        match self {
            Self::Engine(e) if e.kind == ErrKind::Timeout => "timeout".to_owned(),
            Self::Engine(e) => e.msg.clone(),
            Self::Eof => "EOF".to_owned(),
            Self::Timeout => "timeout".to_owned(),
            Self::Closed => "use of closed network connection".to_owned(),
            Self::Other(m) => m.clone(),
        }
    }

    /// Go の `errKind` です。
    pub(crate) fn err_kind(&self) -> &'static str {
        if self.err_string() == "timeout" {
            return "timeout";
        }
        match self {
            Self::Eof => "EOF",
            Self::Closed => "closed",
            Self::Engine(e) if e.kind == ErrKind::Closed => "closed",
            _ if self.err_string().contains("connection reset") => "reset",
            _ => "error",
        }
    }
}

/// 名前つきの欄を持つ文の結果です。
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) name: &'static str,
    pub(crate) fields: Vec<(&'static str, V)>,
}

/// 台本の値です。
#[derive(Debug, Clone)]
pub(crate) enum V {
    None,
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    Dur(i64),
    Time(i64),
    Seq(u32),
    Addr(Ipv4Addr),
    AddrPort(SocketAddrV4),
    Seg(Rc<SegV>),
    Opts(Rc<Options>),
    Ts(u32, u32),
    Block(SackBlock),
    List(Rc<Vec<V>>),
    Peer(Rc<PeerV>),
    Listener(Rc<RefCell<ListenerV>>),
    Conn(Handle),
    Err(Rc<GoErr>),
    Record(Rc<Record>),
    Ip(Rc<IpV>),
    Udp(Rc<(Udp, Option<String>)>),
    Icmp(Rc<(Icmp, bool)>),
    Quote(Rc<(Quote, bool)>),
    UdpConn(Rc<RefCell<UdpConnV>>),
}

impl V {
    /// Go の `typeName` です。
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Int(_) => "int",
            Self::Bool(_) => "bool",
            Self::Bytes(_) => "bytes",
            Self::Dur(_) => "duration",
            Self::Time(_) => "time",
            Self::Seq(_) => "seq",
            Self::Addr(_) => "addr",
            Self::AddrPort(_) => "addrport",
            Self::Seg(_) => "segment",
            Self::Opts(_) => "options",
            Self::Ts(..) => "timestamps",
            Self::Block(_) => "block",
            Self::List(_) => "list",
            Self::Peer(_) => "peer",
            Self::Listener(_) => "listener",
            Self::Conn(_) => "connection",
            Self::Err(_) => "error",
            Self::Record(_) => "result",
            Self::Ip(_) => "ipv4",
            Self::Udp(_) => "udp",
            Self::Icmp(_) => "icmp",
            Self::Quote(_) => "quote",
            Self::UdpConn(_) => "udp socket",
        }
    }

    pub(crate) fn list(items: Vec<Self>) -> Self {
        Self::List(Rc::new(items))
    }

    pub(crate) fn seg(seg: Segment, ok: bool, at: i64) -> Self {
        Self::Seg(Rc::new(SegV { seg, ok, at }))
    }

    pub(crate) fn record(name: &'static str, fields: Vec<(&'static str, Self)>) -> Self {
        Self::Record(Rc::new(Record { name, fields }))
    }

    pub(crate) fn err(e: Option<GoErr>) -> Self {
        e.map_or(Self::None, |e| Self::Err(Rc::new(e)))
    }
}
