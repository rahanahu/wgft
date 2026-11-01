//! 口の符号を、Go の試験が書いた frame の例 (`internal/dutproto/testdata/frames/`) と byte の単位で照らします。
//!
//! 例は種類ごとに frame の bytes の `.bin` と、欄の値の `.json` の対です。Rust の符号は `.json` の値から
//! `.bin` と同じ bytes を作り、`.bin` を同じ値に読みます。`bad-` で始まる例は、どの符号も口の誤りとして断る
//! frame です。例は Go の試験 (`go test ./internal/dutproto -update`) が作ります。

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;

use wgft_tcpharness::frame::{
    Boost, BoostEvent, Clock, Congestion, ErrKind, FrameError, Handle, Hello, Kind, Limit, Msg,
    read_frame,
};
use wgft_tcpharness::gojson::{self, Json};

fn frames_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../internal/dutproto/testdata/frames")
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

struct Fields<'a>(&'a Json);

impl Fields<'_> {
    fn get(&self, k: &str) -> &Json {
        self.0.get(k).unwrap_or_else(|| panic!("no field {k}"))
    }
    fn u64(&self, k: &str) -> u64 {
        self.get(k)
            .as_u64()
            .unwrap_or_else(|| panic!("{k} is not an integer"))
    }
    fn u32(&self, k: &str) -> u32 {
        u32::try_from(self.u64(k)).expect("u32")
    }
    fn u16(&self, k: &str) -> u16 {
        u16::try_from(self.u64(k)).expect("u16")
    }
    fn h(&self) -> Handle {
        Handle(self.u32("h"))
    }
    fn bool(&self, k: &str) -> bool {
        self.get(k).as_bool().expect("bool")
    }
    fn str(&self, k: &str) -> String {
        self.get(k).as_str().expect("string").to_owned()
    }
    fn bytes(&self, k: &str) -> Vec<u8> {
        hex(self.get(k).as_str().expect("hex string"))
    }
    fn packets(&self, k: &str) -> Vec<Vec<u8>> {
        self.get(k)
            .as_array()
            .expect("array")
            .iter()
            .map(|p| hex(p.as_str().expect("hex")))
            .collect()
    }
    fn addr(&self, k: &str) -> Ipv4Addr {
        self.str(k).parse().expect("IPv4 address")
    }
    fn addr_port(&self, k: &str) -> SocketAddrV4 {
        self.str(k).parse().expect("IPv4 address and port")
    }
    fn dur(&self, k: &str) -> Duration {
        Duration::from_nanos(self.u64(k))
    }
}

/// `.json` の欄から値を作ります。
fn msg_of(kind: Kind, j: &Json) -> Msg {
    let f = Fields(j);
    match kind {
        Kind::Hello => Msg::Hello(Hello {
            version: f.u16("version"),
            clock: [Clock::Fake, Clock::Real][usize::from(f.u16("clock"))],
            addr: f.addr("addr"),
            mtu: f.u32("mtu"),
            seed: f.bytes("seed").try_into().expect("64 bytes"),
            limits: f
                .get("limits")
                .as_array()
                .expect("array")
                .iter()
                .map(|l| {
                    let l = Fields(l);
                    Limit {
                        name: l.str("name"),
                        value: l.u64("value"),
                    }
                })
                .collect(),
            boost: [Boost::OnDemand, Boost::AtAccept, Boost::Never][usize::from(f.u16("boost"))],
            congestion: [Congestion::Cubic, Congestion::NewReno][usize::from(f.u16("congestion"))],
        }),
        Kind::Inject => Msg::Inject(f.packets("packets")),
        Kind::Packets => Msg::Packets(f.packets("packets")),
        Kind::Poll => Msg::Poll { max: f.u32("max") },
        Kind::Advance => Msg::Advance(f.dur("d")),
        Kind::Now => Msg::Now,
        Kind::TcpListen => Msg::TcpListen {
            port: f.u16("port"),
        },
        Kind::UdpListen => Msg::UdpListen {
            port: f.u16("port"),
        },
        Kind::Accept => Msg::Accept(f.h()),
        Kind::Read => Msg::Read {
            h: f.h(),
            max: f.u32("max"),
        },
        Kind::Write => Msg::Write {
            h: f.h(),
            data: f.bytes("data"),
        },
        Kind::Close => Msg::Close(f.h()),
        Kind::CloseWrite => Msg::CloseWrite(f.h()),
        Kind::Abort => Msg::Abort(f.h()),
        Kind::CloseForDelivery => Msg::CloseForDelivery(f.h()),
        Kind::Delivered => Msg::Delivered(f.h()),
        Kind::BoostPolicy => Msg::BoostPolicy {
            h: f.h(),
            floor: f.bool("floor"),
        },
        Kind::Events => Msg::Events,
        Kind::UdpRecv => Msg::UdpRecv {
            h: f.h(),
            max: f.u32("max"),
        },
        Kind::UdpSend => Msg::UdpSend {
            h: f.h(),
            to: f.addr_port("to"),
            data: f.bytes("data"),
        },
        Kind::PingOpen => Msg::PingOpen { to: f.addr("to") },
        Kind::PingSend => Msg::PingSend {
            h: f.h(),
            data: f.bytes("data"),
        },
        Kind::PingRecv => Msg::PingRecv {
            h: f.h(),
            max: f.u32("max"),
        },
        Kind::PingClose => Msg::PingClose(f.h()),
        Kind::Stats => Msg::Stats,
        Kind::Bound => Msg::Bound,
        Kind::Held => Msg::Held,
        Kind::RtoAt => Msg::RtoAt {
            h: f.h(),
            at: f.dur("at"),
        },
        Kind::ConnSocket => Msg::ConnSocket {
            h: f.h(),
            path: f.str("path"),
        },
        Kind::HelloOk => Msg::HelloOk {
            engine: f.str("engine"),
            version: f.u16("version"),
        },
        Kind::Ok => Msg::Ok,
        Kind::Error => Msg::Error {
            err: [
                ErrKind::Other,
                ErrKind::Timeout,
                ErrKind::Eof,
                ErrKind::Closed,
                ErrKind::Reset,
                ErrKind::BrokenPipe,
            ][usize::from(f.u16("err"))],
            msg: f.str("msg"),
        },
        Kind::WouldBlock => Msg::WouldBlock,
        Kind::Time => Msg::Time(f.dur("now")),
        Kind::Handle => Msg::Handle(f.h()),
        Kind::Accepted => Msg::Accepted {
            h: f.h(),
            remote: f.addr_port("remote"),
        },
        Kind::Data => Msg::Data(f.bytes("data")),
        Kind::Wrote => Msg::Wrote(f.u32("n")),
        Kind::Bool => Msg::Bool(f.bool("v")),
        Kind::EventList => Msg::EventList(
            f.get("events")
                .as_array()
                .expect("array")
                .iter()
                .map(|e| {
                    let e = Fields(e);
                    BoostEvent {
                        h: e.h(),
                        boosted: e.bool("boosted"),
                    }
                })
                .collect(),
        ),
        Kind::Datagram => Msg::Datagram {
            from: f.addr_port("from"),
            data: f.bytes("data"),
        },
        Kind::Text => Msg::Text(f.str("s")),
        Kind::Rto => Msg::Rto {
            known: f.bool("known"),
            rto: f.dur("rto"),
        },
    }
}

#[test]
fn frames_match_go() {
    let dir = frames_dir();
    let mut names: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    names.sort();
    assert!(names.len() > 40, "too few examples under {}", dir.display());
    let mut kinds = std::collections::BTreeSet::new();
    let mut failures = Vec::new();
    for json in names {
        let name = json
            .file_stem()
            .expect("stem")
            .to_string_lossy()
            .into_owned();
        let bin = fs::read(json.with_extension("bin")).expect(".bin beside the .json");
        let j = gojson::parse(&fs::read(&json).expect("read"))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        if j.get("expect").and_then(Json::as_str) == Some("reject") {
            let mut r = bin.as_slice();
            match read_frame(&mut r).and_then(|(k, body)| Ok(Msg::decode(k, &body)?)) {
                Err(FrameError::Proto(_)) => {}
                other => failures.push(format!("{name}: want a protocol error, got {other:?}")),
            }
            continue;
        }
        let kind_name = j.get("kind").and_then(Json::as_str).expect("kind");
        let kind = Kind::from_name(kind_name)
            .unwrap_or_else(|| panic!("{name}: unknown kind {kind_name}"));
        assert_eq!(
            j.get("kind_byte").and_then(Json::as_u64),
            Some(u64::from(kind as u8)),
            "{name}: kind byte"
        );
        kinds.insert(kind_name.to_owned());
        let want = msg_of(kind, j.get("msg").expect("msg"));
        match want.frame() {
            Ok(b) if b == bin => {}
            Ok(b) => failures.push(format!("{name}: encodes to {b:02x?}, Go wrote {bin:02x?}")),
            Err(e) => failures.push(format!("{name}: {e}")),
        }
        let mut r = bin.as_slice();
        match read_frame(&mut r).and_then(|(k, body)| Ok(Msg::decode(k, &body)?)) {
            Ok(m) if m == want => {}
            other => failures.push(format!("{name}: decodes to {other:?}, want {want:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // Go の例は種類のすべてを持つ
    assert_eq!(kinds.len(), 43, "kinds covered: {kinds:?}");
}
