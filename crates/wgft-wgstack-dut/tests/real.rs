//! `--clock real` の形の試験です (`docs/design/v2/test-tooling.md` の 3 節と 5 節)。
//!
//! 同じプロセスの中で [`serve_real`] を別のスレッドで動かし、packet を datagram の socket の対で、要求と応答を
//! pipe で運びます。qbench の Go の側と同じ順 (`HELLO`、`TCP_LISTEN`、`ACCEPT`、`CONN_SOCKET`、`ABORT`) で、
//! 握手、両方の向きの byte の中継、相手の FIN の伝わり方、RST、口の誤りを確かめます。

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::time::{Duration, Instant};

use wgft_tcpharness::frame::{
    self, Boost, Clock, Congestion, ErrKind, Handle, Hello, Kind, Msg, SEED_LEN, VERSION,
};
use wgft_tcpharness::packet::{self, ACK, FIN, Options, PSH, RST, SYN, Segment};
use wgft_wgstack_dut::real::serve_real;

const DUT: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const PEER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 200, 0, 1), 40001);
const PORT: u16 = 5001;

fn hello(clock: Clock) -> Msg {
    Msg::Hello(Hello {
        version: VERSION,
        clock,
        addr: DUT,
        mtu: 1420,
        seed: [3; SEED_LEN],
        limits: Vec::new(),
        boost: Boost::OnDemand,
        congestion: Congestion::Cubic,
    })
}

/// 別のスレッドの DUT と、その packet と要求の口です。
struct Real {
    net: UnixDatagram,
    req: std::io::PipeWriter,
    resp: std::io::PipeReader,
    done: std::thread::JoinHandle<u8>,
}

impl Real {
    fn start() -> Self {
        let (net, dut) = UnixDatagram::pair().expect("socket pair");
        net.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let (req_r, req) = std::io::pipe().expect("pipe");
        let (resp, resp_w) = std::io::pipe().expect("pipe");
        let done = std::thread::spawn(move || serve_real(dut, req_r, resp_w));
        Self {
            net,
            req,
            resp,
            done,
        }
    }

    fn ask(&mut self, m: &Msg) -> Msg {
        frame::write_msg(&mut self.req, m).expect("write");
        let (k, body) = frame::read_frame(&mut self.resp).expect("read");
        Msg::decode(k, &body).expect("decode")
    }

    fn send(&self, s: &Segment) {
        self.net.send(&s.marshal()).expect("send");
    }

    /// 次の TCP の segment を受けます。
    fn recv(&self) -> Segment {
        let mut b = [0u8; 2048];
        let n = self.net.recv(&mut b).expect("a packet from the DUT");
        packet::parse(&b[..n]).expect("TCP")
    }

    /// 終わります。要求の口を閉じると DUT は 0 で終わります。
    fn finish(self) -> u8 {
        drop(self.req);
        self.done.join().expect("the DUT thread")
    }
}

fn seg(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Segment {
    Segment {
        src: PEER,
        dst: SocketAddrV4::new(DUT, PORT),
        seq,
        ack,
        flags,
        window: 65535,
        opts: Options::none(),
        payload: payload.to_vec(),
        ..Segment::default()
    }
}

#[test]
fn relays_bytes_both_ways_and_aborts() {
    let mut d = Real::start();
    assert!(matches!(d.ask(&hello(Clock::Real)), Msg::HelloOk { .. }));
    let Msg::Handle(l) = d.ask(&Msg::TcpListen { port: PORT }) else {
        panic!("TCP_LISTEN");
    };
    assert_eq!(
        d.ask(&Msg::Accept(l)),
        Msg::WouldBlock,
        "nothing to accept yet"
    );
    d.send(&Segment {
        opts: Options {
            mss: Some(1380),
            ..Options::none()
        },
        ..seg(1000, 0, SYN, &[])
    });
    let sa = d.recv();
    assert!(sa.has(SYN | ACK), "{sa:?}");
    let iss = sa.seq.wrapping_add(1);
    d.send(&seg(1001, iss, ACK, &[]));
    // 最後の ACK は駆動の task が読むので、受け入れられるまで問い直す
    let deadline = Instant::now() + Duration::from_secs(5);
    let c = loop {
        match d.ask(&Msg::Accept(l)) {
            Msg::Accepted { h, remote } => {
                assert_eq!(remote, PEER);
                break h;
            }
            Msg::WouldBlock if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            other => panic!("ACCEPT answered {other:?}"),
        }
    };
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("c");
    let ul = UnixListener::bind(&path).expect("bind");
    assert_eq!(
        d.ask(&Msg::ConnSocket {
            h: c,
            path: path.to_string_lossy().into_owned(),
        }),
        Msg::Ok
    );
    let (mut app, _) = ul.accept().expect("the DUT connects");
    app.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    // 相手からアプリケーションへ
    d.send(&seg(1001, iss, ACK | PSH, b"hello"));
    let mut got = [0u8; 5];
    app.read_exact(&mut got).expect("relayed bytes");
    assert_eq!(&got, b"hello");
    // アプリケーションから相手へ。ACK だけの segment は飛ばす
    app.write_all(b"world").expect("write");
    let data = loop {
        let s = d.recv();
        if !s.payload.is_empty() {
            break s;
        }
    };
    assert_eq!((data.seq, data.payload.as_slice()), (iss, &b"world"[..]));
    // 相手の FIN はアプリケーションの EOF になる
    d.send(&seg(1006, iss.wrapping_add(5), ACK | FIN, &[]));
    let mut rest = Vec::new();
    app.read_to_end(&mut rest).expect("EOF");
    assert_eq!(rest, b"");

    // 実時間で答えられない要求は engine の誤りで、口は続く
    let Msg::Error { err, .. } = d.ask(&Msg::Poll { max: 1 }) else {
        panic!("POLL on the real clock");
    };
    assert_eq!(err, ErrKind::Other);
    assert!(matches!(d.ask(&Msg::Stats), Msg::Text(t) if t.contains("acks_immediate=")));
    assert_eq!(
        d.ask(&Msg::RtoAt {
            h: c,
            at: Duration::ZERO
        }),
        Msg::Rto {
            known: false,
            rto: Duration::ZERO
        }
    );

    assert_eq!(d.ask(&Msg::Abort(c)), Msg::Ok);
    let rst = loop {
        let s = d.recv();
        if s.has(RST) {
            break s;
        }
    };
    assert_eq!(rst.dst.port(), PEER.port());
    assert_eq!(d.ask(&Msg::Close(l)), Msg::Ok);
    assert_eq!(d.finish(), 0);
}

#[test]
fn protocol_errors_end_with_code_2() {
    let mut d = Real::start();
    let Msg::Error { msg, .. } = d.ask(&hello(Clock::Fake)) else {
        panic!("a fake clock HELLO");
    };
    assert!(msg.contains("real clock"), "{msg}");
    assert_eq!(d.finish(), 2);

    let mut d = Real::start();
    assert!(matches!(d.ask(&hello(Clock::Real)), Msg::HelloOk { .. }));
    let resp = d.ask(&Msg::Accept(Handle(9)));
    assert_eq!(resp.kind(), Kind::Error, "an unknown handle: {resp:?}");
    assert_eq!(d.finish(), 2);
}

#[test]
fn an_empty_input_ends_at_once() {
    let d = Real::start();
    assert_eq!(d.finish(), 0);
    let mut r = Real::start();
    r.req.flush().expect("flush");
    assert_eq!(r.finish(), 0);
}
