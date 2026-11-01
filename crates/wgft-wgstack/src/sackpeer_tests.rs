//! SACK を返す相手と scoreboard の数え直し (Go の `sackpeer_test.go` の写し)。

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::many_single_char_names,
    reason = "test helpers follow the Go names"
)]

use crate::buf::records::{REC_IN_Q, REC_IN_T};
use crate::seq;
use crate::stack::ns;
use crate::tcp::conn::RecList;
use crate::tcp::ctx::Conn;
use crate::tcp::sack::{DUP_THRESH, idx};
use crate::testnet_tests::{Out, PeerConn, TestNet};
use crate::wire::{FLAG_ACK, FLAG_FIN, SackBlock};

/// DUT のデータを受ける相手の受信の側です。順序外の区間を覚え、累積の確認と、最近に伸びた順の SACK の block を
/// 返します。
#[derive(Clone, Debug)]
pub(crate) struct SackPeer {
    pub(crate) p: PeerConn,
    pub(crate) ivs: Vec<PeerIv>,
    pub(crate) touch: i64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerIv {
    pub(crate) l: u32,
    pub(crate) r: u32,
    pub(crate) touch: i64,
}

impl SackPeer {
    pub(crate) fn new(p: PeerConn) -> Self {
        Self {
            p,
            ivs: Vec::new(),
            touch: 0,
        }
    }

    /// DUT の segment `o` を受けます。
    pub(crate) fn recv(&mut self, o: &Out) {
        if let Some((v, _)) = o.ts {
            self.p.dut_ts = v;
        }
        let s = o.seq;
        let mut e = s.wrapping_add(o.payload.len() as u32);
        if o.has(FLAG_FIN) {
            e = e.wrapping_add(1);
        }
        if !seq::gt(e, self.p.rcv) {
            return;
        }
        self.touch += 1;
        if seq::le(s, self.p.rcv) {
            self.p.rcv = e;
        } else {
            self.ivs.push(PeerIv {
                l: s,
                r: e,
                touch: self.touch,
            });
        }
        // 区間を合わせ、累積の確認に届いた区間を取り込みます。
        self.ivs
            .sort_by_key(|iv| iv.l.wrapping_sub(self.p.rcv) as i32);
        let mut m: Vec<PeerIv> = Vec::new();
        for iv in &self.ivs {
            if let Some(last) = m.last_mut()
                && seq::le(iv.l, last.r)
            {
                last.r = seq::max(last.r, iv.r);
                last.touch = last.touch.max(iv.touch);
                continue;
            }
            m.push(*iv);
        }
        self.ivs.clear();
        for iv in m {
            if seq::le(iv.l, self.p.rcv) {
                self.p.rcv = seq::max(self.p.rcv, iv.r);
                continue;
            }
            self.ivs.push(iv);
        }
    }

    /// 最近に伸びた順の SACK の block を最大 `max` 個返します。
    pub(crate) fn blocks(&self, max: usize) -> Vec<SackBlock> {
        let mut ivs = self.ivs.clone();
        ivs.sort_by_key(|iv| -iv.touch);
        ivs.iter()
            .take(max)
            .map(|iv| SackBlock {
                left: iv.l,
                right: iv.r,
            })
            .collect()
    }

    /// 今の累積の確認と SACK の block を DUT に送ります。
    pub(crate) fn ack(&mut self, n: &mut TestNet) {
        let mut s = self.p.seg(FLAG_ACK, &[]);
        s.sack = self.blocks(3);
        n.inject(&s);
    }

    /// `outs` を順に受け、受けるたびに ACK を返します。`drop` が真の segment は失います。引数は segment の位置と
    /// segment です。
    pub(crate) fn deliver_with(
        &mut self,
        n: &mut TestNet,
        outs: &[Out],
        drop: impl Fn(usize, &Out) -> bool,
    ) {
        for (i, o) in outs.iter().enumerate() {
            if drop(i, o) {
                continue;
            }
            self.recv(o);
            self.ack(n);
        }
    }

    /// `outs` をすべて順に受け、受けるたびに ACK を返します。
    pub(crate) fn deliver(&mut self, n: &mut TestNet, outs: &[Out]) {
        self.deliver_with(n, outs, |_, _| false);
    }
}

/// 接続の scoreboard の欄を記録を順に調べて求め直し、増減で保つ値と比べます (Go の `checkScoreboard`)。
pub(crate) fn check_scoreboard(c: &mut Conn<'_>) {
    let (mut sacked, mut beyond_b, mut rtx) = (0u32, 0u32, 0u32);
    let mut beyond_c = 0i32;
    let mut s = c.t.snd_una;
    let n = c.b.recs.len();
    let loss = idx(c.t.loss_idx);
    for i in 0..n {
        let r = *c.b.recs.at(i);
        assert_eq!(
            r.seq.wrapping_sub(c.t.snd_una),
            s.wrapping_sub(c.t.snd_una),
            "record {i} start"
        );
        s = s.wrapping_add(u32::from(r.length));
        if c.is_sacked(i) {
            sacked += u32::from(r.length);
            if i >= loss {
                beyond_b += u32::from(r.length);
                beyond_c += 1;
            }
            for k in i..(i + idx(r.skip)).min(n) {
                assert!(c.is_sacked(k), "record {i} skips over unSACKed record {k}");
            }
        }
        if c.rtx_live(i) {
            rtx += u32::from(r.length);
        }
    }
    if n > 0 {
        assert_eq!(s, c.t.snd_max, "records end at SND.MAX");
    }
    let t = &*c.t;
    assert_eq!(
        (sacked, beyond_b, beyond_c, rtx),
        (t.sacked, t.beyond_bytes, t.beyond_cnt, t.rtx_bytes),
        "scoreboard: recounted (sacked, beyond bytes, beyond count, rtx) vs kept"
    );
    assert!(
        loss <= n && idx(t.rxt_idx) <= n,
        "loss_idx {} rxt_idx {} beyond {n} records",
        t.loss_idx,
        t.rxt_idx
    );
    check_list(c, "transmit list", c.t.t_list, REC_IN_T, true);
    check_list(c, "lost queue", c.t.lost_q, REC_IN_Q, false);
    let (mut rack_beyond, mut sacked_recs) = (0u32, 0i32);
    for i in 0..n {
        if c.is_sacked(i) {
            sacked_recs += 1;
            continue;
        }
        let l = u32::from(c.b.recs.at(i).length);
        if c.rack_lost(i) && i >= loss {
            rack_beyond += l;
        }
        // SACK 済みでない記録は、送り残しの list か損失の待ち行列にあるか、境目の手前で送り直しを待ちます。
        let (in_t, in_q) = (c.gen_flag(i, REC_IN_T), c.gen_flag(i, REC_IN_Q));
        assert!(!(in_t && in_q), "record {i} is in both lists");
        assert!(
            in_t || in_q || (i < loss && !c.rtx_live(i)),
            "record {i} is in no list"
        );
    }
    assert_eq!(
        (rack_beyond, sacked_recs),
        (c.t.rack_lost_beyond, c.t.sacked_recs),
        "RACK lost beyond and SACKed records"
    );
    // pipe を RFC 6675 の定義どおりに求めます。
    let mut pipe: i64 = 0;
    for i in 0..n {
        if c.is_sacked(i) {
            continue;
        }
        let l = i64::from(c.b.recs.at(i).length);
        if i >= loss && !c.rack_lost(i) {
            pipe += l;
        }
        if c.rtx_live(i) {
            pipe += l;
        }
    }
    if !c.t.sack_ok && !c.t.in_recovery && c.t.dup_acks > 0 {
        pipe -= pipe.min(c.t.dup_acks.min(DUP_THRESH - 1) * i64::from(c.seg_mss()));
    }
    assert_eq!(pipe, i64::from(c.pipe()), "pipe recomputed");
}

/// list を先頭からたどり、節と印と数が合うこと、送った時刻の順の list が時刻の順であることを確かめます。
fn check_list(c: &mut Conn<'_>, name: &str, l: RecList, flag: u8, time_order: bool) {
    let n = c.b.recs.len();
    let mut count = 0;
    let mut last = i64::MIN;
    let mut a = l.head;
    for k in 0..l.n {
        let i = c.rec_idx(a);
        assert!(i < n, "{name} entry {k} at record {i} of {n}");
        assert!(
            c.gen_flag(i, flag) && !c.is_sacked(i),
            "{name} holds record {i} without its flag or SACKed"
        );
        let r = *c.b.recs.at(i);
        if time_order {
            assert!(
                ns(r.sent_at) >= last,
                "{name} out of transmit order at record {i}"
            );
        }
        last = ns(r.sent_at);
        count += 1;
        if k == l.n - 1 {
            assert!(a == l.tail && r.next == 0, "{name} tail mismatch");
            break;
        }
        assert!(r.next != 0, "{name} ends after {} of {}", k + 1, l.n);
        a = a.wrapping_add_signed(r.next);
    }
    let flagged = (0..n).filter(|&i| c.gen_flag(i, flag)).count() as i32;
    assert!(
        flagged == l.n && count == l.n,
        "{name} has {} entries, {flagged} flagged records",
        l.n
    );
}
