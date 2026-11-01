//! 白箱の試験の道具 (Go の `helpers_test.go` の写し)。
//!
//! 手で進める時計の核と、トンネルの側の相手を持ちます。相手は segment を組み立てて核に渡し、核が送った packet を
//! 解いて番号を追います。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "test helpers"
)]

use crate::budget::Budget;
use crate::config::{Config, Limits};
use crate::stack::{Event, Hook, ListenerId, Stack};
use crate::tcp::conn::ConnId;
use crate::time::Time;
use crate::wire::{
    self, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, IP_HEADER_LEN, MAX_OPTION_LEN,
    OptWriter, SackBlock, TCP_HEADER_LEN, TcpHeader, Tuple,
};
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::time::Duration;

pub(crate) const DUT: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
pub(crate) const PEER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
pub(crate) const TEST_MTU: usize = 1420;

/// 試験の表の大きさです。上界の試験は表が満ちるところを見るので小さくします。再組み立ての表と UDP の予算は、
/// Go の試験の `smallLimits` と同じく本番の値です。
pub(crate) fn small_limits() -> Limits {
    Limits {
        max_flows: 16,
        accept_queue: 8,
        syn_rows: 16,
        tw_rows: 32,
        ctl_slots: 16,
        ..Limits::default()
    }
}

/// 試験の hook です。boost の変化を順に記録し、`may_return` には `allow_return` を返します (Go の試験の
/// `OnBoost` に当たります)。
#[derive(Debug)]
pub(crate) struct TestHook {
    pub(crate) allow_return: bool,
    /// `(接続, 得たか)` の列です。`may_return` の問い合わせは `asked` に記録します。
    pub(crate) changes: Vec<(ConnId, bool)>,
    pub(crate) asked: Vec<ConnId>,
}

impl Default for TestHook {
    fn default() -> Self {
        Self {
            allow_return: true,
            changes: Vec::new(),
            asked: Vec::new(),
        }
    }
}

impl Hook for TestHook {
    fn boost_granted(&mut self, conn: ConnId) {
        self.changes.push((conn, true));
    }

    fn may_return(&mut self, conn: ConnId) -> bool {
        self.asked.push(conn);
        self.allow_return
    }

    fn boost_returned(&mut self, conn: ConnId) {
        self.changes.push((conn, false));
    }
}

/// 手で進める時計の核と、トンネルの側の相手です。
pub(crate) struct TestNet {
    pub(crate) s: Stack<TestHook>,
    pub(crate) now: Time,
    buf: Vec<u8>,
}

/// 相手が送る segment です。
#[derive(Clone, Debug, Default)]
pub(crate) struct TSeg {
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    /// `None` なら [`PEER`] です。
    pub(crate) src: Option<Ipv4Addr>,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) wnd: u16,
    pub(crate) mss: u16,
    pub(crate) ws: Option<u8>,
    pub(crate) sack_ok: bool,
    pub(crate) ts: Option<(u32, u32)>,
    pub(crate) sack: Vec<SackBlock>,
    pub(crate) payload: Vec<u8>,
}

/// 相手の packet を組み立てます。
pub(crate) fn build_peer(s: &TSeg) -> Vec<u8> {
    let mut o = OptWriter::default();
    if s.mss != 0 {
        o.mss(s.mss);
    }
    if s.sack_ok {
        o.sack_perm();
    }
    if let Some((v, e)) = s.ts {
        o.ts(v, e);
    }
    if let Some(ws) = s.ws
        && s.flags & FLAG_SYN != 0
    {
        o.wscale(ws);
    }
    if !s.sack.is_empty() {
        o.sack(&s.sack);
    }
    let src = s.src.unwrap_or(PEER);
    let mut b = vec![0u8; IP_HEADER_LEN + TCP_HEADER_LEN + MAX_OPTION_LEN + s.payload.len()];
    let h = TcpHeader {
        tup: Tuple {
            laddr: src.to_bits(),
            raddr: DUT.to_bits(),
            lport: s.sport,
            rport: s.dport,
        },
        seq: s.seq,
        ack: s.ack,
        flags: s.flags,
        wnd: s.wnd,
    };
    let off = wire::write_tcp(&mut b, 1, &h, Some(&mut o), s.payload.len());
    b[off..off + s.payload.len()].copy_from_slice(&s.payload);
    let n = wire::finish_tcp(&mut b);
    b.truncate(n);
    b
}

/// 核が送った segment です。
#[derive(Clone, Debug)]
pub(crate) struct Out {
    pub(crate) lport: u16,
    pub(crate) rport: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) wnd: u16,
    pub(crate) mss: Option<u16>,
    pub(crate) wscale: Option<u8>,
    pub(crate) sack_ok: bool,
    pub(crate) ts: Option<(u32, u32)>,
    pub(crate) sack: Vec<SackBlock>,
    pub(crate) payload: Vec<u8>,
}

impl Out {
    pub(crate) fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

impl fmt::Display for Out {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        for (b, c) in [
            (FLAG_SYN, 'S'),
            (FLAG_FIN, 'F'),
            (FLAG_RST, 'R'),
            (FLAG_PSH, 'P'),
            (FLAG_ACK, '.'),
        ] {
            if self.flags & b != 0 {
                s.push(c);
            }
        }
        write!(
            f,
            "{s} seq={} ack={} len={} wnd={}",
            self.seq,
            self.ack,
            self.payload.len(),
            self.wnd
        )
    }
}

/// segment の列を 1 行ずつの文字列にします。
pub(crate) fn show(outs: &[Out]) -> String {
    let mut s = String::new();
    for o in outs {
        let _ = fmt::Write::write_fmt(&mut s, format_args!("[{o}] "));
    }
    s
}

impl TestNet {
    pub(crate) fn new(limits: Limits) -> Self {
        Self::with_seed(limits, [7; 64])
    }

    pub(crate) fn with_seed(limits: Limits, seed: [u8; 64]) -> Self {
        let config = Config {
            limits,
            ..Config::new(DUT, TEST_MTU)
        };
        Self::with_config(config, seed)
    }

    /// 設定 `config` の核です (Go の試験の `TestCongestion` と `TestBoost` を選ぶ時に使います)。
    pub(crate) fn with_config(config: Config, seed: [u8; 64]) -> Self {
        Self::with_budget(config, seed, Budget::new().unwrap())
    }

    /// 渡した `Budget` を使う核です。
    pub(crate) fn with_budget(config: Config, seed: [u8; 64], budget: Budget) -> Self {
        let s = Stack::new(config, budget, &seed, TestHook::default()).unwrap();
        Self {
            s,
            now: Time::ZERO,
            buf: vec![0; 65536],
        }
    }

    pub(crate) fn inject(&mut self, seg: &TSeg) {
        let pkt = build_peer(seg);
        self.write(&pkt);
    }

    pub(crate) fn write(&mut self, pkt: &[u8]) {
        self.s.handle_packet(self.now, pkt);
        self.s.check_invariants().unwrap();
    }

    /// 核が今送るものをすべて読みます。
    pub(crate) fn drain(&mut self) -> Vec<Out> {
        self.drain_raw().iter().map(|p| parse_out(p)).collect()
    }

    /// 核が今送る packet をそのまま読みます。
    pub(crate) fn drain_raw(&mut self) -> Vec<Vec<u8>> {
        let mut res = Vec::new();
        for _ in 0..100_000 {
            let Some(k) = self.s.poll_transmit(self.now, &mut self.buf) else {
                self.s.check_invariants().unwrap();
                return res;
            };
            assert!(k <= TEST_MTU, "packet of {k} bytes exceeds the MTU");
            wire::parse_ipv4(&self.buf[..k]).expect("the core sent a bad IPv4 packet");
            res.push(self.buf[..k].to_vec());
        }
        panic!("the core kept sending");
    }

    pub(crate) fn advance(&mut self, d: Duration) {
        self.now = self.now + d;
        self.s.handle_timeout(self.now);
        self.s.check_invariants().unwrap();
    }

    pub(crate) fn listen(&mut self, port: u16) -> ListenerId {
        self.s
            .listen_tcp(self.now, SocketAddrV4::new(DUT, port))
            .unwrap()
    }

    pub(crate) fn accept(&mut self, l: ListenerId) -> ConnId {
        self.s.accept(self.now, l).unwrap().0
    }

    /// 80 番で待ち受け、相手の 40000 番から窓の scale を付けて接続を開き、accept で受け取った接続と相手の側の
    /// 接続を返します。握手の出力は読み捨てます。
    pub(crate) fn accepted(&mut self, ts: bool) -> (ConnId, PeerConn) {
        self.accepted_sack(ts, false)
    }

    /// `accepted` と同じで、`sack` が真なら相手が SACK-permitted を示します (Go の `accepted(ts, sack)`)。
    pub(crate) fn accepted_sack(&mut self, ts: bool, sack: bool) -> (ConnId, PeerConn) {
        let l = self.listen(80);
        let p = self.handshake_sack(40000, 80, ts, sack, true);
        let c = self.accept(l);
        self.drain();
        (c, p)
    }

    /// 相手から接続を開き、核の SYN-ACK に最後の ACK を返します。
    pub(crate) fn handshake(&mut self, sport: u16, dport: u16, ts: bool, ws: bool) -> PeerConn {
        self.handshake_sack(sport, dport, ts, false, ws)
    }

    /// `handshake` と同じで、`sack` が真なら相手が SACK-permitted を示します。
    pub(crate) fn handshake_sack(
        &mut self,
        sport: u16,
        dport: u16,
        ts: bool,
        sack: bool,
        ws: bool,
    ) -> PeerConn {
        let mut p = PeerConn {
            sport,
            dport,
            iss: 1000,
            snd: 0,
            rcv: 0,
            dut_iss: 0,
            ts,
            ts_val: 5000,
            dut_ts: 0,
            wnd: 65535,
        };
        self.inject(&TSeg {
            sport,
            dport,
            seq: p.iss,
            flags: FLAG_SYN,
            wnd: 65535,
            mss: 1380,
            ws: ws.then_some(7),
            sack_ok: sack,
            ts: ts.then_some((p.ts_val, 0)),
            ..TSeg::default()
        });
        let outs = self.drain();
        assert!(
            outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
            "expected one SYN-ACK, got {}",
            show(&outs)
        );
        let sa = &outs[0];
        assert_eq!(sa.ack, p.iss + 1);
        p.dut_iss = sa.seq;
        p.snd = p.iss + 1;
        p.rcv = sa.seq.wrapping_add(1);
        p.dut_ts = sa.ts.map_or(0, |(v, _)| v);
        self.peer_ack(&mut p, &[]);
        p
    }

    /// 相手から中身を送ります (空なら中身の無い ACK)。
    pub(crate) fn peer_ack(&mut self, p: &mut PeerConn, payload: &[u8]) {
        let seg = p.seg(FLAG_ACK, payload);
        self.inject(&seg);
        p.snd = p.snd.wrapping_add(payload.len() as u32);
    }

    pub(crate) fn peer_fin(&mut self, p: &mut PeerConn) {
        let seg = p.seg(FLAG_ACK | FLAG_FIN, &[]);
        self.inject(&seg);
        p.snd = p.snd.wrapping_add(1);
    }

    /// 知らせをすべて取り出します。
    pub(crate) fn events(&mut self) -> Vec<Event> {
        let mut v = Vec::new();
        while let Some(e) = self.s.poll_event() {
            v.push(e);
        }
        v
    }

    /// 接続から読めるだけ読みます。
    pub(crate) fn read_all(&mut self, c: ConnId) -> Vec<u8> {
        let mut out = Vec::new();
        let mut b = vec![0u8; 65536];
        while let Ok(n) = self.s.read(self.now, c, &mut b) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&b[..n]);
        }
        self.s.check_invariants().unwrap();
        out
    }
}

/// 核が送った packet を解きます。
pub(crate) fn parse_out(pkt: &[u8]) -> Out {
    let ip = wire::parse_ipv4(pkt).expect("the core sent a bad IPv4 packet");
    assert_eq!(ip.proto, wire::PROTO_TCP, "the core sent another protocol");
    let seg = wire::parse_tcp(&ip).expect("the core sent a bad TCP segment");
    Out {
        lport: seg.tup.rport,
        rport: seg.tup.lport,
        seq: seg.seq,
        ack: seg.ack,
        flags: seg.flags,
        wnd: seg.wnd,
        mss: seg.opt.mss,
        wscale: seg.opt.wscale,
        sack_ok: seg.opt.sack_ok,
        ts: seg.opt.ts,
        sack: seg.opt.sack_blocks().to_vec(),
        payload: seg.payload.to_vec(),
    }
}

/// 相手の側の 1 つの接続の番号を追います。`lport` は核から見た相手のポートではなく、相手の側のポートです。
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerConn {
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    /// 相手の ISN です。
    pub(crate) iss: u32,
    /// 相手の次の番号です。
    pub(crate) snd: u32,
    /// 相手が次に受ける番号 (核の番号) です。
    pub(crate) rcv: u32,
    pub(crate) dut_iss: u32,
    pub(crate) ts: bool,
    pub(crate) ts_val: u32,
    pub(crate) dut_ts: u32,
    pub(crate) wnd: u16,
}

impl PeerConn {
    /// 相手の今の番号の segment です。
    pub(crate) fn seg(&mut self, flags: u8, payload: &[u8]) -> TSeg {
        self.ts_val += 1;
        TSeg {
            sport: self.sport,
            dport: self.dport,
            seq: self.snd,
            ack: self.rcv,
            flags,
            wnd: self.wnd,
            ts: self.ts.then_some((self.ts_val, self.dut_ts)),
            payload: payload.to_vec(),
            ..TSeg::default()
        }
    }

    /// 核の segment を受けて、相手の受ける番号を進めます。順序どおりのものだけを数え、中身を返します。
    pub(crate) fn absorb(&mut self, outs: &[Out]) -> Vec<u8> {
        let mut data = Vec::new();
        for o in outs {
            if o.rport != self.sport || o.lport != self.dport {
                continue;
            }
            if let Some((v, _)) = o.ts {
                self.dut_ts = v;
            }
            if o.seq == self.rcv {
                data.extend_from_slice(&o.payload);
                self.rcv = self.rcv.wrapping_add(o.payload.len() as u32);
                if o.has(FLAG_FIN) {
                    self.rcv = self.rcv.wrapping_add(1);
                }
            }
        }
        data
    }
}

/// 相手 `src` から核の `dport` への UDP の datagram を作ります (Go の `buildUDP`)。
pub(crate) fn build_udp(src: SocketAddrV4, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ulen = wire::UDP_HEADER_LEN + payload.len();
    let mut b = vec![0u8; IP_HEADER_LEN + ulen];
    let total = b.len();
    wire::write_ipv4_header(
        &mut b,
        total,
        7,
        wire::PROTO_UDP,
        src.ip().to_bits(),
        DUT.to_bits(),
    );
    let u = &mut b[IP_HEADER_LEN..];
    u[0..2].copy_from_slice(&src.port().to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&(ulen as u16).to_be_bytes());
    u[8..].copy_from_slice(payload);
    let sum = wire::pseudo_sum(src.ip().to_bits(), DUT.to_bits(), wire::PROTO_UDP, ulen);
    let mut cs = !wire::checksum(sum, u);
    if cs == 0 {
        cs = 0xffff;
    }
    u[6..8].copy_from_slice(&cs.to_be_bytes());
    b
}

/// 相手 `src` から核への ICMP の message `msg` を作ります。checksum を書きます (Go の `buildICMP`)。
pub(crate) fn build_icmp(src: Ipv4Addr, msg: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; IP_HEADER_LEN + msg.len()];
    let total = b.len();
    wire::write_ipv4_header(
        &mut b,
        total,
        9,
        wire::PROTO_ICMP,
        src.to_bits(),
        DUT.to_bits(),
    );
    b[IP_HEADER_LEN..].copy_from_slice(msg);
    wire::finish_icmp(&mut b[IP_HEADER_LEN..]);
    b
}

/// option の無い IPv4 の packet を、中身 `size` byte ごとの断片に分けます (Go の `splitIPv4`)。
pub(crate) fn split_ipv4(pkt: &[u8], size: usize, id: u16) -> Vec<Vec<u8>> {
    let payload = &pkt[IP_HEADER_LEN..];
    let mut out = Vec::new();
    let mut off = 0;
    while off < payload.len() {
        let end = (off + size).min(payload.len());
        let mut f = pkt[..IP_HEADER_LEN].to_vec();
        f.extend_from_slice(&payload[off..end]);
        let len = f.len() as u16;
        f[2..4].copy_from_slice(&len.to_be_bytes());
        f[4..6].copy_from_slice(&id.to_be_bytes());
        let mut fl = (off / 8) as u16;
        if end < payload.len() {
            fl |= 0x2000;
        }
        f[6..8].copy_from_slice(&fl.to_be_bytes());
        wire::set_ipv4_checksum(&mut f[..IP_HEADER_LEN]);
        out.push(f);
        off = end;
    }
    out
}
