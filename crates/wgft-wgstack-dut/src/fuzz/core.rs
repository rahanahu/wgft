//! `core` の target:Go の `FuzzCore` の写しです。
//!
//! 入力を op と引数の byte の列として読み、手で進める時計の下で packet、時刻の進み、アプリケーションの操作を
//! 核に与えます。各段の後に不変条件と保持の上界を確かめ、最後に核を閉じて会計が 0 に戻ることを確かめます。
//! byte の読み方は Go と同じなので、Go の corpus はそのまま種になります。
//!
//! Go と違う点:Go は書ける量 (`room`) が 1000 byte を超える時だけ 1000 byte を書き、読める時だけ読みます。
//! 核の公開の API は書ける量と読めるかを返さないので、書き込みと読み取りをそのまま呼び、`WouldBlock` と
//! 一部だけの書き込みを受け入れます。Go の wgstack と出力が同じ間は同じ経路をたどり、違えば別の経路を
//! たどります。どちらでも種としては働きます。

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::time::Duration;

use wgft_tcpharness::packet::{ACK, FIN, Options, RST, SYN, Segment, Timestamps};
use wgft_wgstack::{ConnId, Error, NoHook};

use super::net::{DUT, Net, PEER, fuzz_limits};
use super::peer::PeerConn;

/// 1 つの入力で進める段の上限です。Go と同じです。
const MAX_STEPS: usize = 500;

/// 読み残しの入力です。尽きたら 0 を返します (Go の `next`)。
struct Prog<'a>(&'a [u8]);

impl Prog<'_> {
    fn next(&mut self) -> u8 {
        let Some((&b, rest)) = self.0.split_first() else {
            return 0;
        };
        self.0 = rest;
        b
    }
}

/// `core` の target の 1 回分です。
pub fn core(prog: &[u8]) {
    let mut n = Net::new(Net::<NoHook>::config(fuzz_limits()), NoHook);
    let now = n.now();
    let l = n
        .stack()
        .listen_tcp(now, SocketAddrV4::new(DUT, 80))
        .expect("listen on port 80");
    let mut peers: BTreeMap<u16, PeerConn> = BTreeMap::new();
    let mut conns: Vec<ConnId> = Vec::new();
    let mut prog = Prog(prog);
    let wbuf = [0u8; 1000];
    let mut rbuf = [0u8; 3000];
    let mut steps = 0;
    while !prog.0.is_empty() && steps < MAX_STEPS {
        steps += 1;
        let op = prog.next();
        let arg = prog.next();
        let port = 1000 + u16::from(arg % 8);
        match op % 8 {
            0 => {
                // SYN。Go と同じく、相手は arg の bit で SACK-permitted と timestamp を示す
                let syn = Segment {
                    src: SocketAddrV4::new(PEER, port),
                    dst: SocketAddrV4::new(DUT, 80),
                    seq: u32::from(arg) << 20,
                    flags: SYN,
                    window: 65535,
                    opts: Options {
                        mss: Some(1380),
                        ws: 7,
                        sack_permitted: arg & 1 == 0,
                        ts: (arg & 2 == 0).then_some(Timestamps { val: 1, ecr: 0 }),
                        ..Options::none()
                    },
                    ..Segment::default()
                };
                n.inject(&syn);
                for o in n.drain() {
                    if o.flags == SYN | ACK && o.dst.port() == port {
                        peers.insert(
                            port,
                            PeerConn {
                                sport: port,
                                dport: 80,
                                snd: o.ack,
                                rcv: o.seq.wrapping_add(1),
                                ts: o.opts.ts.is_some(),
                                ts_val: 2,
                                dut_ts: o.opts.ts.map_or(0, |t| t.val),
                                wnd: 65535,
                            },
                        );
                    }
                }
            }
            1 => {
                // 中身つきの ACK、ずらした番号
                if let Some(p) = peers.get_mut(&port) {
                    let mut s = p.seg(ACK, vec![0; usize::from(arg) * 7]);
                    let shift = i32::from(prog.next().cast_signed()) * 100;
                    s.seq = s.seq.wrapping_add_signed(shift);
                    n.inject(&s);
                    if s.seq == p.snd {
                        p.snd = p
                            .snd
                            .wrapping_add(u32::try_from(s.payload.len()).expect("small"));
                    }
                }
            }
            2 => n.advance(Duration::from_millis(u64::from(arg) * 10)),
            3 => {
                // flag を変えた segment
                if let Some(p) = peers.get_mut(&port) {
                    let flags =
                        [ACK | FIN, RST, SYN, ACK, RST | ACK, SYN | ACK][usize::from(arg % 6)];
                    let mut s = p.seg(flags, Vec::new());
                    if arg & 8 != 0 {
                        s.ack = s.ack.wrapping_add(u32::from(arg) * 1000);
                    }
                    n.inject(&s);
                    if flags & FIN != 0 {
                        p.snd = p.snd.wrapping_add(1);
                    }
                }
            }
            4 => {
                // 受け取る
                loop {
                    let now = n.now();
                    match n.stack().accept(now, l) {
                        Ok((c, _)) => conns.push(c),
                        Err(Error::WouldBlock) => break,
                        Err(e) => panic!("accept on an open listener: {e}"),
                    }
                }
            }
            5 => {
                // アプリケーションの操作
                if !conns.is_empty() {
                    let c = conns[usize::from(arg) % conns.len()];
                    let what = prog.next() % 6;
                    let now = n.now();
                    let st = n.stack();
                    match what {
                        0 => st.close_conn(now, c),
                        1 => st.abort(now, c),
                        2 => {
                            let _ = st.close_write(now, c);
                        }
                        3 => {
                            let _ = st.write(now, c, &wbuf);
                        }
                        4 => {
                            let _ = st.read(now, c, &mut rbuf);
                        }
                        _ => {
                            let _ = st.delivered(c);
                        }
                    }
                }
            }
            6 => {
                // 出力を読み、相手が確認する
                for o in n.drain() {
                    if let Some(q) = peers.get_mut(&o.dst.port()) {
                        q.absorb(&o);
                    }
                }
                if arg & 1 == 0
                    && let Some(p) = peers.get_mut(&port)
                {
                    let s = p.ack(Vec::new());
                    n.inject(&s);
                }
            }
            _ => {
                // 古い番号と窓の 0
                if let Some(p) = peers.get_mut(&port) {
                    p.wnd = u16::from(arg) * 64;
                    let s = p.ack(Vec::new());
                    n.inject(&s);
                }
            }
        }
        n.check();
    }
    n.drain();
    n.finish();
}
