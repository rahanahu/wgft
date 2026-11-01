//! トンネルの側の相手の TCP の模型です。Go の試験の `peerConn` と `sackPeer` の写しです。

use std::net::SocketAddrV4;

use wgft_tcpharness::packet::{ACK, FIN, Options, SYN, SackBlock, Segment, Timestamps};
use wgft_wgstack::Hook;

use super::net::{DUT, Net, PEER};

/// sequence の比べです (RFC 1982 の 32 bit の算術)。
pub(crate) const fn seq_gt(a: u32, b: u32) -> bool {
    a.wrapping_sub(b).cast_signed() > 0
}

pub(crate) const fn seq_le(a: u32, b: u32) -> bool {
    !seq_gt(a, b)
}

fn seq_max(a: u32, b: u32) -> u32 {
    if seq_gt(a, b) { a } else { b }
}

/// 相手の側の 1 つの接続の番号を追います。Go の `peerConn` です。
#[derive(Debug, Clone)]
pub struct PeerConn {
    pub sport: u16,
    pub dport: u16,
    /// 相手の次の番号
    pub snd: u32,
    /// 相手が次に受ける番号 (DUT の番号)
    pub rcv: u32,
    pub ts: bool,
    pub ts_val: u32,
    pub dut_ts: u32,
    pub wnd: u16,
}

impl PeerConn {
    /// 相手のポート `sport` から DUT のポート `dport` へ接続を開き、DUT の SYN-ACK に最後の ACK を返します。
    /// Go の `testNet.handshake` と同じく、相手の ISN は 1000、timestamp は 5000 から、MSS は 1380 です。
    /// `ws` は窓の scale (無ければ負)、`sack` と `ts` は相手が SACK と timestamp を求めるかです。握手の出力の
    /// うち、この接続の SYN-ACK でないものは読み捨てます。DUT の SYN-ACK が無ければ panic です。
    pub fn connect<H: Hook>(
        n: &mut Net<H>,
        sport: u16,
        dport: u16,
        ws: i64,
        sack: bool,
        ts: bool,
    ) -> (Self, Segment) {
        Self::try_connect(n, sport, dport, ws, sack, ts)
            .unwrap_or_else(|| panic!("no SYN-ACK for port {sport}"))
    }

    /// [`PeerConn::connect`] で、DUT が SYN-ACK を返さなければ `None` を返します。
    pub fn try_connect<H: Hook>(
        n: &mut Net<H>,
        sport: u16,
        dport: u16,
        ws: i64,
        sack: bool,
        ts: bool,
    ) -> Option<(Self, Segment)> {
        let syn = Segment {
            src: SocketAddrV4::new(PEER, sport),
            dst: SocketAddrV4::new(DUT, dport),
            seq: 1000,
            flags: SYN,
            window: 65535,
            opts: Options {
                mss: Some(1380),
                ws,
                sack_permitted: sack,
                ts: ts.then_some(Timestamps { val: 5000, ecr: 0 }),
                ..Options::none()
            },
            ..Segment::default()
        };
        n.inject(&syn);
        let sa = n
            .drain()
            .into_iter()
            .find(|o| o.flags == SYN | ACK && o.dst.port() == sport && o.ack == 1001)?;
        let mut p = Self {
            sport,
            dport,
            snd: 1001,
            rcv: sa.seq.wrapping_add(1),
            ts: ts && sa.opts.ts.is_some(),
            ts_val: 5000,
            dut_ts: sa.opts.ts.map_or(0, |t| t.val),
            wnd: 65535,
        };
        let s = p.ack(Vec::new());
        n.inject(&s);
        Some((p, sa))
    }

    /// 相手の今の番号の segment です。Go の `peerConn.seg` と同じく timestamp の値を 1 つ進めます。
    pub fn seg(&mut self, flags: u8, payload: Vec<u8>) -> Segment {
        self.ts_val = self.ts_val.wrapping_add(1);
        Segment {
            src: SocketAddrV4::new(PEER, self.sport),
            dst: SocketAddrV4::new(DUT, self.dport),
            seq: self.snd,
            ack: self.rcv,
            flags,
            window: self.wnd,
            opts: Options {
                ts: self.ts.then_some(Timestamps {
                    val: self.ts_val,
                    ecr: self.dut_ts,
                }),
                ..Options::none()
            },
            payload,
            ..Segment::default()
        }
    }

    /// 中身を送る segment を作り、番号を進めます (中身が空なら中身の無い ACK)。Go の `peerConn.ack` です。
    pub fn ack(&mut self, payload: Vec<u8>) -> Segment {
        let n = u32::try_from(payload.len()).expect("payload below 4 GiB");
        let s = self.seg(ACK, payload);
        self.snd = self.snd.wrapping_add(n);
        s
    }

    /// FIN を作り、番号を進めます。Go の `peerConn.fin` です。
    pub fn fin(&mut self) -> Segment {
        let s = self.seg(ACK | FIN, Vec::new());
        self.snd = self.snd.wrapping_add(1);
        s
    }

    /// DUT の segment を受けて、受ける番号を進めます。順序どおりのものだけを数えます。Go の
    /// `peerConn.absorb` の 1 つ分です。
    pub fn absorb(&mut self, o: &Segment) {
        if o.dst.port() != self.sport || o.src.port() != self.dport {
            return;
        }
        if let Some(ts) = o.opts.ts {
            self.dut_ts = ts.val;
        }
        if o.seq == self.rcv {
            let n = u32::try_from(o.payload.len()).expect("payload below 4 GiB");
            self.rcv = self.rcv.wrapping_add(n);
            if o.has(FIN) {
                self.rcv = self.rcv.wrapping_add(1);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PeerIv {
    l: u32,
    r: u32,
    touch: u64,
}

/// DUT のデータを受ける相手の受信の側です。順序外の区間を覚え、累積の確認と、最近に伸びた順の SACK の
/// block を返します。Go の `sackPeer` です。
#[derive(Debug, Clone)]
pub struct SackPeer {
    pub p: PeerConn,
    ivs: Vec<PeerIv>,
    touch: u64,
}

impl SackPeer {
    pub fn new(p: PeerConn) -> Self {
        Self {
            p,
            ivs: Vec::new(),
            touch: 0,
        }
    }

    /// 覚えた順序外の区間を捨てます (SACK の取り消し)。
    pub fn renege(&mut self) {
        self.ivs.clear();
    }

    /// 順序外の区間を持つかです。
    pub fn has_ooo(&self) -> bool {
        !self.ivs.is_empty()
    }

    /// DUT の segment `o` を受けます。
    pub fn recv(&mut self, o: &Segment) {
        if let Some(ts) = o.opts.ts {
            self.p.dut_ts = ts.val;
        }
        let s = o.seq;
        let mut e = s.wrapping_add(u32::try_from(o.payload.len()).expect("payload below 4 GiB"));
        if o.has(FIN) {
            e = e.wrapping_add(1);
        }
        if !seq_gt(e, self.p.rcv) {
            return;
        }
        self.touch += 1;
        if seq_le(s, self.p.rcv) {
            self.p.rcv = e;
        } else {
            self.ivs.push(PeerIv {
                l: s,
                r: e,
                touch: self.touch,
            });
        }
        // 区間を合わせ、累積の確認に届いた区間を取り込む。Go の slices.SortFunc は安定でないが、同じ左端の
        // 区間は次の合わせで 1 つになるので、順の違いは結果に出ない
        self.ivs
            .sort_by_key(|iv| iv.l.wrapping_sub(self.p.rcv).cast_signed());
        let mut m: Vec<PeerIv> = Vec::with_capacity(self.ivs.len());
        for iv in self.ivs.drain(..) {
            if let Some(last) = m.last_mut()
                && seq_le(iv.l, last.r)
            {
                last.r = seq_max(last.r, iv.r);
                last.touch = last.touch.max(iv.touch);
                continue;
            }
            m.push(iv);
        }
        for iv in m {
            if seq_le(iv.l, self.p.rcv) {
                self.p.rcv = seq_max(self.p.rcv, iv.r);
                continue;
            }
            self.ivs.push(iv);
        }
    }

    /// 最近に伸びた順の SACK の block を最大 `max` 個返します。
    pub fn blocks(&self, max: usize) -> Vec<SackBlock> {
        let mut ivs = self.ivs.clone();
        ivs.sort_by_key(|iv| std::cmp::Reverse(iv.touch));
        ivs.iter()
            .take(max)
            .map(|iv| SackBlock {
                left: iv.l,
                right: iv.r,
            })
            .collect()
    }

    /// 今の累積の確認と SACK の block を持つ ACK です。Go の `sackPeer.ack` です。
    pub fn ack(&mut self) -> Segment {
        let mut s = self.p.seg(ACK, Vec::new());
        s.opts.sack = self.blocks(3);
        s
    }
}
