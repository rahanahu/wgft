//! adapter と `wgstack-dut` のバイナリの試験です (`docs/design/v2/test-tooling.md` の 2 節と 3 節)。
//!
//! - 2 節の runner が頼る DUT の約束:最大 0 の `READ` は `WOULD_BLOCK` を返さず、閉じた待ち受けの `CLOSE` は
//!   `OK` を返します
//! - engine の誤りの文と種類が `dutserve` と同じ形であること
//! - バイナリが同じプロセスの adapter と同じ bytes を返すことと、口の誤りの終了コード

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use wgft_tcpharness::dut::{ClockedDut, DutError, Op, ProcessDut, answer_frame};
use wgft_tcpharness::frame::{
    self, Boost, Clock, Congestion, ErrKind, Handle, Hello, Msg, SEED_LEN, VERSION,
};
use wgft_tcpharness::packet::{self, ACK, FIN, Options, RST, SYN, Segment};
use wgft_wgstack_dut::dut::{ENGINE, WgstackDut};

const DUT: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const PEER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 200, 0, 1), 40001);
const PORT: u16 = 80;

fn hello() -> Hello {
    Hello {
        version: VERSION,
        clock: Clock::Fake,
        addr: DUT,
        mtu: 1420,
        seed: [7; SEED_LEN],
        limits: Vec::new(),
        boost: Boost::Never,
        congestion: Congestion::NewReno,
    }
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wgstack-dut"))
}

/// 相手から見た接続の番号です。
struct Peer {
    snd: u32,
    rcv: u32,
}

impl Peer {
    fn seg(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
        self.seg_at(self.snd, flags, payload)
    }

    fn seg_at(&self, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        Segment {
            src: PEER,
            dst: SocketAddrV4::new(DUT, PORT),
            seq,
            ack: self.rcv,
            flags,
            window: 65535,
            opts: Options::none(),
            payload: payload.to_vec(),
            ..Segment::default()
        }
        .marshal()
    }
}

/// 待ち受けを開き、握手を終えて受け入れた接続を返します。
fn connect(d: &mut WgstackDut) -> (Handle, Handle, Peer) {
    let l = d.tcp_listen(PORT).expect("listen");
    let syn = Segment {
        src: PEER,
        dst: SocketAddrV4::new(DUT, PORT),
        seq: 1000,
        flags: SYN,
        window: 65535,
        opts: Options {
            mss: Some(1380),
            ..Options::none()
        },
        ..Segment::default()
    }
    .marshal();
    d.inject(&[&syn]).expect("inject");
    let out = d.poll(1).expect("poll");
    let sa = packet::parse(&out[0]).expect("SYN-ACK");
    assert!(sa.has(SYN | ACK), "{sa:?}");
    let p = Peer {
        snd: 1001,
        rcv: sa.seq.wrapping_add(1),
    };
    d.inject(&[&p.seg(ACK, &[])]).expect("inject");
    let Op::Ready(a) = d.accept(l) else {
        panic!("no connection to accept");
    };
    assert_eq!(a.remote, PEER);
    (l, a.conn, p)
}

fn engine_err<T: std::fmt::Debug>(op: Op<T>) -> (ErrKind, String) {
    match op {
        Op::Failed(DutError::Engine(e)) => (e.kind, e.msg),
        other => panic!("want an engine error, got {other:?}"),
    }
}

#[test]
fn read_zero_and_listener_close_twice() {
    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    let (l, c, _) = connect(&mut d);
    assert_eq!(
        d.read(c, 0),
        Op::Ready(Vec::new()),
        "READ 0 answers empty DATA"
    );
    assert_eq!(d.read(c, 10), Op::WouldBlock);
    // 受け入れの timeout で閉じた待ち受けを、台本の close と後始末がもう一度閉じる
    assert_eq!(d.close(l), Ok(()));
    assert_eq!(d.close(l), Ok(()));
    let (kind, msg) = engine_err(d.accept(l));
    assert_eq!(kind, ErrKind::Closed);
    assert_eq!(
        msg,
        "accept tcp 10.200.0.2:80: use of closed network connection"
    );
    d.close(c).expect("close");
    let (kind, msg) = engine_err(d.read(c, 0));
    assert_eq!(kind, ErrKind::Closed);
    assert_eq!(
        msg,
        "read tcp 10.200.0.2:80->10.200.0.1:40001: use of closed network connection"
    );
    d.check_invariants().expect("invariants");
}

#[test]
fn errors_name_the_connection_as_go_does() {
    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    let (_, c, p) = connect(&mut d);
    // 相手の FIN の後は EOF
    d.inject(&[&p.seg(FIN | ACK, &[])]).expect("inject");
    assert_eq!(engine_err(d.read(c, 10)), (ErrKind::Eof, "EOF".to_owned()));
    d.close_write(c).expect("close_write");
    let (kind, msg) = engine_err(d.write(c, b"x"));
    assert_eq!(kind, ErrKind::BrokenPipe);
    assert_eq!(
        msg,
        "write tcp 10.200.0.2:80->10.200.0.1:40001: broken pipe"
    );

    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    let (_, c, p) = connect(&mut d);
    d.inject(&[&p.seg(RST | ACK, &[])]).expect("inject");
    let (kind, msg) = engine_err(d.read(c, 10));
    assert_eq!(kind, ErrKind::Reset);
    assert_eq!(
        msg,
        "read tcp 10.200.0.2:80->10.200.0.1:40001: connection reset by peer"
    );
    // 相手の RST の後も、アプリケーションが閉じるまで接続は誤りを返し続ける
    let (kind, msg) = engine_err(d.write(c, b"x"));
    assert_eq!(kind, ErrKind::Reset);
    assert_eq!(
        msg,
        "write tcp 10.200.0.2:80->10.200.0.1:40001: connection reset by peer"
    );
}

#[test]
fn listen_errors() {
    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    d.tcp_listen(PORT).expect("listen");
    match d.tcp_listen(PORT) {
        Err(DutError::Engine(e)) => {
            assert_eq!(e.kind, ErrKind::Other);
            assert_eq!(e.msg, "listen tcp 10.200.0.2:80: address already in use");
        }
        other => panic!("{other:?}"),
    }
    match d.tcp_listen(0) {
        Err(DutError::Engine(e)) => {
            assert_eq!(e.msg, "listen tcp 10.200.0.2:0: port 0 is not supported");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        d.read(Handle(1), 1),
        Op::Failed(DutError::Broken(_))
    ));
    assert!(matches!(
        d.read(Handle(9), 1),
        Op::Failed(DutError::Broken(_))
    ));
}

/// 同じ要求の列を別のプロセスの `wgstack-dut` と同じプロセスの adapter に送り、応答が同じ bytes であることを
/// 確かめます。
#[test]
fn binary_answers_as_the_adapter() {
    let h = hello();
    let mut peer = Peer { snd: 1001, rcv: 0 };
    let syn = Segment {
        src: PEER,
        dst: SocketAddrV4::new(DUT, PORT),
        seq: 1000,
        flags: SYN,
        window: 65535,
        opts: Options {
            mss: Some(1380),
            ..Options::none()
        },
        ..Segment::default()
    }
    .marshal();
    let mut local = WgstackDut::new(&h).expect("HELLO");
    let mut remote = ProcessDut::spawn(&bin(), h, |l| eprintln!("{l}")).expect("spawn");
    assert_eq!(remote.engine(), ENGINE);
    let mut steps = vec![
        Msg::TcpListen { port: PORT },
        Msg::Inject(vec![syn]),
        Msg::Poll { max: 1 },
    ];
    let mut i = 0;
    while i < steps.len() {
        let m = steps[i].clone();
        let want = answer_frame(&mut local, &m).expect("adapter");
        let got = remote.exchange_frame(&m).expect("exchange");
        assert_eq!(got.frame, want.frame, "request {i} {m}");
        if let Ok(Msg::Packets(ps)) = &want.msg
            && let Some(sa) = ps.first().and_then(|p| packet::parse(p).ok())
            && sa.has(SYN | ACK)
        {
            peer.rcv = sa.seq.wrapping_add(1);
            steps.extend([
                Msg::Inject(vec![peer.seg(ACK, &[])]),
                Msg::Accept(Handle(1)),
                Msg::Write {
                    h: Handle(2),
                    data: vec![7; 3000],
                },
                Msg::Poll { max: 1 << 20 },
                Msg::Advance(std::time::Duration::from_millis(250)),
                Msg::Poll { max: 1 << 20 },
                Msg::Inject(vec![peer.seg(FIN | ACK, b"hello")]),
                Msg::Read {
                    h: Handle(2),
                    max: 100,
                },
                Msg::Read {
                    h: Handle(2),
                    max: 100,
                },
                Msg::Stats,
                Msg::Bound,
                Msg::Held,
                Msg::Close(Handle(2)),
                Msg::Close(Handle(1)),
                Msg::Close(Handle(1)),
                Msg::Delivered(Handle(2)),
                Msg::Advance(std::time::Duration::from_secs(5)),
                Msg::Poll { max: 1 << 20 },
                Msg::Now,
            ]);
        }
        i += 1;
    }
    assert!(steps.len() > 3, "no SYN-ACK");
    remote.close().expect("close");
}

/// 要求を書いて標準入力を閉じ、応答と終了コードを返します。
fn raw(reqs: &[Msg]) -> (Vec<Msg>, Option<i32>) {
    let mut child = Command::new(bin())
        .args(["--clock", "fake"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    for m in reqs {
        let _ = frame::write_msg(&mut stdin, m);
    }
    let _ = stdin.flush();
    drop(stdin);
    let out = child.wait_with_output().expect("wait");
    let mut r = out.stdout.as_slice();
    let mut resps = Vec::new();
    while let Ok(m) = frame::read_msg(&mut r) {
        resps.push(m);
    }
    (resps, out.status.code())
}

#[test]
fn protocol_errors_end_with_code_2() {
    let (resps, code) = raw(&[]);
    assert_eq!(
        (resps.len(), code),
        (0, Some(0)),
        "stdin closed before HELLO"
    );

    let (resps, code) = raw(&[Msg::Now]);
    assert!(matches!(resps.as_slice(), [Msg::Error { .. }]), "{resps:?}");
    assert_eq!(code, Some(2), "the first request is not HELLO");

    let (resps, code) = raw(&[Msg::Hello(hello()), Msg::Now, Msg::Hello(hello())]);
    assert!(
        matches!(
            resps.as_slice(),
            [Msg::HelloOk { .. }, Msg::Time(_), Msg::Error { .. }]
        ),
        "{resps:?}"
    );
    assert_eq!(code, Some(2), "a second HELLO");

    let (resps, code) = raw(&[Msg::Hello(hello()), Msg::Accept(Handle(3))]);
    assert!(matches!(resps.last(), Some(Msg::Error { .. })), "{resps:?}");
    assert_eq!(code, Some(2), "an unknown handle");

    let (resps, code) = raw(&[Msg::Hello(hello()), Msg::Ok]);
    assert!(matches!(resps.last(), Some(Msg::Error { .. })), "{resps:?}");
    assert_eq!(code, Some(2), "a response kind as a request");

    let (resps, code) = raw(&[
        Msg::Hello(hello()),
        Msg::RtoAt {
            h: Handle(1),
            at: std::time::Duration::ZERO,
        },
        Msg::Now,
    ]);
    assert!(
        matches!(
            resps.as_slice(),
            [Msg::HelloOk { .. }, Msg::Error { .. }, Msg::Time(_)]
        ),
        "a request of the real clock is an engine error: {resps:?}"
    );
    let Msg::Error { msg, .. } = &resps[1] else {
        unreachable!()
    };
    assert_eq!(
        msg,
        "RTO_AT needs --clock real; wgstack-dut runs only the fake clock"
    );
    assert_eq!(code, Some(0));

    let st = Command::new(bin())
        .args(["--clock", "real"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn");
    assert_eq!(
        st.code(),
        Some(2),
        "the real clock needs the packet socketpair on fd 3"
    );
}

#[test]
fn retransmission_timeout_is_a_timeout() {
    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    let (_, c, _) = connect(&mut d);
    assert_eq!(d.write(c, b"never acknowledged"), Op::Ready(18));
    // 相手は何も確認しない。再送の回数を使い切るまで時計を進める
    for _ in 0..3600 {
        d.advance(std::time::Duration::from_secs(1))
            .expect("advance");
        d.poll(usize::MAX).expect("poll");
        match d.read(c, 10) {
            Op::WouldBlock => {}
            op => {
                let (kind, msg) = engine_err(op);
                // syscall.ETIMEDOUT の Timeout() は真なので、dutserve の errResp は timeout にする
                assert_eq!(kind, ErrKind::Timeout);
                assert_eq!(
                    msg,
                    "read tcp 10.200.0.2:80->10.200.0.1:40001: connection timed out"
                );
                let (kind, _) = engine_err(d.write(c, b"x"));
                assert_eq!(kind, ErrKind::Timeout);
                return;
            }
        }
    }
    panic!("the connection did not time out within an hour");
}

#[test]
fn close_for_delivery_delivers() {
    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    let (_, c, p) = connect(&mut d);
    assert_eq!(d.write(c, b"abc"), Op::Ready(3));
    d.close_for_delivery(c).expect("close_for_delivery");
    assert_eq!(d.delivered(c), Ok(false));
    let out = d.poll(usize::MAX).expect("poll");
    assert!(
        out.iter()
            .filter_map(|q| packet::parse(q).ok())
            .any(|q| q.has(FIN)),
        "a FIN after the data"
    );
    // データの 3 byte と FIN を確認する
    let ack = Peer {
        snd: p.snd,
        rcv: p.rcv.wrapping_add(4),
    };
    d.inject(&[&ack.seg(ACK, &[])]).expect("inject");
    assert_eq!(d.delivered(c), Ok(true));
}

#[test]
fn inject_keeps_the_batch_order() {
    // データの後の FIN:データを読んでから EOF
    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    let (_, c, p) = connect(&mut d);
    let data = p.seg_at(p.snd, ACK, b"abc");
    d.inject(&[&data, &p.seg_at(p.snd + 3, FIN | ACK, &[])])
        .expect("inject");
    assert_eq!(d.read(c, 10), Op::Ready(b"abc".to_vec()));
    assert_eq!(engine_err(d.read(c, 10)).0, ErrKind::Eof);

    // 同じ番号の FIN を先に入れると、後のデータは FIN の後なので読めない
    let mut d = WgstackDut::new(&hello()).expect("HELLO");
    let (_, c, p) = connect(&mut d);
    let data = p.seg_at(p.snd, ACK, b"abc");
    d.inject(&[&p.seg_at(p.snd, FIN | ACK, &[]), &data])
        .expect("inject");
    assert_eq!(engine_err(d.read(c, 10)).0, ErrKind::Eof);
}

#[test]
fn limits_only_for_replay() {
    let mut h = hello();
    h.limits = ["maxFlows", "acceptQ", "synRows", "twRows", "ctlSlots"]
        .iter()
        .map(|n| frame::Limit {
            name: (*n).to_owned(),
            value: 8,
        })
        .collect();
    assert!(
        WgstackDut::new(&h).is_err(),
        "dutserve takes only the default limits"
    );
    WgstackDut::for_replay(&h).expect("replay takes the recorded limits");
    let (resps, code) = raw(&[Msg::Hello(h)]);
    assert!(matches!(resps.as_slice(), [Msg::Error { .. }]), "{resps:?}");
    assert_eq!(code, Some(2));
}
