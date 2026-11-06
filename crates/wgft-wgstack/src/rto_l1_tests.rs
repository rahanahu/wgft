//! HyStart++ の外の slow start の 1 ACK の増分 (L = 1、RFC 5681 3.1、RFC 3465 2.3) の境界の試験です。
//!
//! 実装の担当とは別の担当が、`docs/design/v2/wgstack-rs.md` の規則から書きました。HyStart++ の外の slow start
//! (`flag` は窓が ssthresh より小さく HyStart++ が動かない間) に入る所と出る所を、本物の ACK と時計の進みで通ります。
//! 増分は、12 segment を 1 つの ACK で確認した時の窓の増分 (1 SMSS なら L = 1、2 SMSS なら L = 2) で見ます。
//! 見る前に ssthresh を大きな値に書き込み、窓が ssthresh に届く経路を、見る ACK の前に起こさないようにします。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]
#![expect(
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    reason = "test data"
)]

use crate::sackpeer_tests::SackPeer;
use crate::testnet_tests::{DUT, Out, TEST_MTU, TestNet, small_limits};
use crate::wire::{FLAG_ACK, SackBlock};
use crate::{Config, Congestion, ConnId};
use core::time::Duration;

const CCS: [Congestion; 2] = [Congestion::NewReno, Congestion::Cubic];
const RTT: Duration = Duration::from_millis(20);

struct Rig {
    n: TestNet,
    c: ConnId,
    q: SackPeer,
    mss: u32,
    /// 最初に送った中身つきの segment です。
    outs: Vec<Out>,
}

fn payload(outs: Vec<Out>) -> Vec<Out> {
    outs.into_iter().filter(|o| !o.payload.is_empty()).collect()
}

fn write_all(n: &mut TestNet, c: ConnId, len: usize) {
    let data = vec![0u8; len];
    let mut off = 0;
    while off < len {
        match n.s.write(n.now, c, &data[off..]) {
            Ok(k) if k > 0 => off += k,
            _ => break,
        }
    }
}

impl Rig {
    /// timestamp を交渉し、`sack` なら SACK も交渉した接続に、RTT の標本を入れて `segs` segment を送らせます。
    fn new(cc: Congestion, sack: bool, segs: usize) -> Self {
        let config = Config {
            limits: small_limits(),
            congestion: cc,
            ..Config::new(DUT, TEST_MTU)
        };
        let mut n = TestNet::with_config(config, [7; 64]);
        let (c, p) = n.accepted_sack(true, sack);
        let mss = {
            let v = n.s.conn(c.slot);
            let mss = v.seg_mss();
            let t = v.t;
            let rtt = RTT.as_nanos() as i64;
            (t.srtt, t.rttvar, t.min_rtt, t.has_rtt, t.has_min_rtt) =
                (rtt, rtt / 2, rtt, true, true);
            t.rto = crate::tcp::RTO_MIN;
            mss
        };
        write_all(&mut n, c, segs * mss as usize);
        let outs = payload(n.drain());
        n.advance(RTT);
        Self {
            n,
            c,
            q: SackPeer::new(p),
            mss,
            outs,
        }
    }

    fn flag(&mut self) -> bool {
        let c = self.n.s.conn(self.c.slot);
        c.t.cwnd < c.t.ssthresh && !c.hystart_on()
    }

    fn cwnd(&mut self) -> u32 {
        self.n.s.conn(self.c.slot).t.cwnd
    }

    fn ssthresh(&mut self) -> u32 {
        self.n.s.conn(self.c.slot).t.ssthresh
    }

    fn set_ssthresh(&mut self, v: u32) {
        self.n.s.conn(self.c.slot).t.ssthresh = v;
    }

    fn rtos(&self) -> u64 {
        self.n.s.stats().rtos
    }

    /// RTO が `total` 回になるまで時計を進めます。
    fn wait_rto(&mut self, total: u64) {
        for _ in 0..4000 {
            if self.rtos() >= total {
                return;
            }
            self.n.advance(Duration::from_millis(5));
        }
        panic!("RTO number {total} never fired");
    }

    fn take(&mut self) -> Vec<Out> {
        payload(self.n.drain())
    }

    /// 核が出したものを相手に届けて確認させることを、静かになるまで繰り返します。
    fn settle(&mut self) {
        for _ in 0..64 {
            let outs = self.take();
            if outs.is_empty() {
                return;
            }
            self.q.deliver(&mut self.n, &outs);
        }
        panic!("the sender never went quiet");
    }

    /// 損失の無い接続の元の segment をすべて届けます。
    fn deliver_originals(&mut self) {
        let outs = self.outs.clone();
        self.q.deliver(&mut self.n, &outs);
    }

    /// 黙った後の窓の戻しを 1 segment で済ませ、ssthresh を大きな値にして窓を 10 SMSS にし、12 segment を 1 つの
    /// ACK で確認した時の窓の増分を返します。ssthresh の書き込みは、印を下ろす経路をこの ACK の前に起こさないためです。
    fn probe(&mut self) -> u32 {
        self.probe_with(true)
    }

    /// `probe` と同じで、`poke` が偽なら ssthresh を書き込まず初期値のままにします (最初の slow start の確認です)。
    fn probe_with(&mut self, poke: bool) -> u32 {
        let mss = self.mss;
        self.settle();
        write_all(&mut self.n, self.c, mss as usize);
        self.settle();
        {
            let t = self.n.s.conn(self.c.slot).t;
            if poke {
                t.ssthresh = 100 * mss;
            }
            t.cwnd = 40 * mss;
        }
        write_all(&mut self.n, self.c, 60 * mss as usize);
        let outs = self.take();
        assert!(outs.len() >= 12, "{} segments in flight", outs.len());
        self.n.s.conn(self.c.slot).t.cwnd = 10 * mss;
        self.n.advance(Duration::from_millis(1));
        for o in &outs[..12] {
            self.q.recv(o);
        }
        let (before, una) = {
            let t = &*self.n.s.conn(self.c.slot).t;
            (t.cwnd, t.snd_una)
        };
        self.q.ack(&mut self.n);
        let t = &*self.n.s.conn(self.c.slot).t;
        assert_eq!(
            t.snd_una.wrapping_sub(una),
            12 * mss,
            "the probe ACK covers 12 segments; recovery {}",
            t.in_recovery
        );
        t.cwnd - before
    }

    /// 元の segment をすべて失う最初の RTO を起こし、印を確かめ、ssthresh を大きな値にします。印は立ったままです。
    fn first_rto_keep_slow_start(&mut self) {
        self.wait_rto(1);
        assert!(self.flag(), "the RTO raises the mark");
        let big = 100 * self.mss;
        self.set_ssthresh(big);
    }
}

// 1. ssthresh に届くと終わる

/// 窓が ssthresh に届いた ACK で slow start が終わります。窓が ssthresh に届いて終えた後に ssthresh を書き込んで
/// 作る slow start は、黙った後の再開ではなく HyStart++ の外なので、1 SMSS までです。
#[test]
fn reaching_ssthresh_ends_the_limit() {
    for cc in CCS {
        let mut r = Rig::new(cc, false, 10);
        r.wait_rto(1);
        assert!(r.flag(), "{cc:?}: raised");
        let ss = r.ssthresh();
        assert!(ss != u32::MAX && r.cwnd() < ss, "{cc:?}: slow start");
        r.settle(); // 元の segment は届かず、再送だけが確認される
        assert!(r.cwnd() >= ss, "{cc:?}: the window reached ssthresh");
        assert!(!r.flag(), "{cc:?}: the mark is down at ssthresh");
        // 黙って RTO を越え、後の slow start に置く。窓が ssthresh に届いていたので再開は HyStart++ を使わず、12 segment の
        // ACK は 1 SMSS
        r.n.advance(Duration::from_secs(60));
        let mss = r.mss;
        assert_eq!(r.probe(), mss, "{cc:?}");
    }
}

// 2. 黙っても変わらない

/// RTO の後の slow start の途中で黙って窓が IW に戻ると、再開は HyStart++ の中で動き、L = 2 です
/// (RFC 9406 4.3 の MAY)。
#[test]
fn idle_in_the_middle_restarts_under_hystart() {
    for cc in CCS {
        let mut r = Rig::new(cc, false, 10);
        r.first_rto_keep_slow_start();
        r.settle();
        assert!(r.flag(), "{cc:?}: still limited before the idle");
        r.n.advance(Duration::from_secs(60));
        assert_eq!(r.rtos(), 1, "{cc:?}: the idle raised no RTO");
        assert!(r.flag(), "{cc:?}: idle alone does not change the mark");
        let mss = r.mss;
        assert_eq!(
            r.probe(),
            2 * mss,
            "{cc:?}: HyStart++ after the idle restart"
        );
    }
}

// 3. 2 回目の RTO

/// 最初の RTO の回復で印が下りた後、2 回目の RTO が印を立て直します。
#[test]
fn a_second_rto_episode_sets_the_limit_again() {
    for cc in CCS {
        let mut r = Rig::new(cc, false, 10);
        r.wait_rto(1);
        r.settle();
        assert!(!r.flag(), "{cc:?}: the first episode ended at ssthresh");
        // 新しい送り残しをすべて失う
        let mss = r.mss;
        write_all(&mut r.n, r.c, 10 * mss as usize);
        let lost = r.take();
        assert!(!lost.is_empty());
        r.wait_rto(2);
        assert!(r.flag(), "{cc:?}: the second RTO raises the mark");
        r.set_ssthresh(100 * mss);
        r.settle();
        assert!(r.flag(), "{cc:?}: still limited");
        assert_eq!(r.probe(), mss, "{cc:?}: L = 1 in the second episode");
    }
}

// 4. 取り消し

/// 最初の slow start の不要な RTO を F-RTO が取り消すと、L = 2 に戻ります。
#[test]
fn spurious_rto_in_the_initial_slow_start_is_undone_to_l2() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 10);
        r.wait_rto(1);
        assert!(r.flag(), "{cc:?}: raised");
        r.take();
        r.deliver_originals();
        assert_eq!(r.n.s.stats().spurious_rtos, 1, "{cc:?}: undone");
        assert!(!r.flag(), "{cc:?}: the undo restores the initial mark");
        assert_eq!(r.ssthresh(), u32::MAX, "{cc:?}: ssthresh restored");
        let mss = r.mss;
        assert_eq!(r.probe_with(false), 2 * mss, "{cc:?}");
    }
}

/// F-RTO が使えない RTO (送り残しが 1 segment) を timestamp が取り消す経路も同じです。
#[test]
fn spurious_single_segment_rto_is_undone_to_l2() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 1);
        r.wait_rto(1);
        assert!(r.flag(), "{cc:?}: raised");
        assert_eq!(r.n.s.conn(r.c.slot).t.frto, 0, "{cc:?}: no F-RTO");
        r.take();
        r.n.advance(Duration::from_millis(1));
        let o = r.outs[0].clone();
        r.q.recv(&o);
        r.q.ack(&mut r.n);
        assert_eq!(r.n.s.stats().spurious_rtos, 1, "{cc:?}: undone");
        assert!(!r.flag(), "{cc:?}: the undo restores the initial mark");
        let mss = r.mss;
        assert_eq!(r.probe_with(false), 2 * mss, "{cc:?}");
    }
}

/// 最初の RTO の slow start の途中の 2 回目の RTO を取り消しても、先の slow start の L = 1 が続きます。
/// RTO の取り消しは SACK を交渉した接続だけにあります。
#[test]
fn spurious_rto_inside_the_limited_slow_start_keeps_l1() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 1);
        r.first_rto_keep_slow_start();
        r.settle(); // 再送が届き、確認される。元の segment への確認ではないので取り消しは起きない
        let mss = r.mss;
        assert!(r.flag(), "{cc:?}: still limited");
        assert_eq!(
            r.n.s.stats().spurious_rtos,
            0,
            "{cc:?}: the first RTO was real"
        );
        assert_eq!(r.n.s.conn(r.c.slot).t.backoff, 0, "{cc:?}: backoff reset");
        // 1 segment を送らせ、確認が遅れて 2 回目の RTO になる。1 segment なので F-RTO は使わず、遅れた確認が取り消す
        write_all(&mut r.n, r.c, mss as usize);
        let flight = r.take();
        assert_eq!(flight.len(), 1, "{cc:?}: one segment in flight");
        r.wait_rto(2);
        assert!(r.flag(), "{cc:?}: the second RTO keeps the mark");
        r.take();
        // 遅れた元の送り出しが届き、2 回目の RTO は不要だったと分かる
        r.n.advance(Duration::from_millis(1));
        r.q.deliver(&mut r.n, &flight);
        assert_eq!(r.n.s.stats().spurious_rtos, 1, "{cc:?}: undone");
        assert_eq!(r.probe(), mss, "{cc:?}: L = 1 goes on");
    }
}

/// 後の slow start の途中で入った高速の回復の取り消し (Eifel か D-SACK) は、入る前の印に戻します。
fn fast_recovery_in_limited_slow_start(cc: Congestion, dsack: bool) {
    let mut r = Rig::new(cc, true, 1);
    r.wait_rto(1);
    assert!(r.flag(), "{cc:?}: raised");
    r.set_ssthresh(100 * r.mss);
    r.settle();
    assert!(r.flag(), "{cc:?}: limited at the entry");
    let mss = r.mss;
    r.n.s.conn(r.c.slot).t.cwnd = 20 * mss;
    write_all(&mut r.n, r.c, 10 * mss as usize);
    let outs = take_with(&mut r);
    assert!(outs.len() >= 10, "{cc:?}: ten segments");
    r.n.advance(RTT);
    // 2 番目を遅らせて高速の回復に入る
    r.q.deliver_with(&mut r.n, &outs, |i, _| i == 1);
    assert!(r.n.s.conn(r.c.slot).t.in_recovery, "{cc:?}: in recovery");
    assert!(!r.flag(), "{cc:?}: fast recovery lowers the mark");
    let resent = take_with(&mut r);
    assert!(!resent.is_empty() && resent[0].seq == outs[1].seq);
    let before = r.n.s.stats().spurious_undos;
    if dsack {
        r.n.s.conn(r.c.slot).k.retrans_ts_ok = false; // timestamp による判定を使わない
        let mut s = r.q.p.seg(FLAG_ACK, &[]);
        let blk = |o: &Out| SackBlock {
            left: o.seq,
            right: o.seq.wrapping_add(o.payload.len() as u32),
        };
        let (b1, b9) = (blk(&outs[1]), blk(&outs[9]));
        s.sack = vec![
            b1,
            SackBlock {
                left: b1.left,
                right: b9.right,
            },
        ];
        r.n.inject(&s);
        r.q.deliver(&mut r.n, &outs[1..2]);
    } else {
        r.n.advance(Duration::from_millis(1));
        r.q.recv(&outs[1]);
        r.q.ack(&mut r.n);
    }
    assert_eq!(
        r.n.s.stats().spurious_undos,
        before + 1,
        "{cc:?} dsack {dsack}: undone"
    );
    assert!(
        r.flag(),
        "{cc:?} dsack {dsack}: the undo restores the mark as it was at the entry"
    );
    assert_eq!(r.probe(), mss, "{cc:?} dsack {dsack}: L = 1 goes on");
}

fn take_with(r: &mut Rig) -> Vec<Out> {
    r.take()
}

#[test]
fn eifel_undo_of_a_recovery_in_the_limited_slow_start_restores_the_mark() {
    for cc in CCS {
        fast_recovery_in_limited_slow_start(cc, false);
    }
}

#[test]
fn dsack_undo_of_a_recovery_in_the_limited_slow_start_restores_the_mark() {
    for cc in CCS {
        fast_recovery_in_limited_slow_start(cc, true);
    }
}

// 5. 高速の回復

/// 後の slow start の途中で高速の回復に入っても、取り消さなければ回復の後の slow start は HyStart++ の外で 1 SMSS です。
#[test]
fn fast_recovery_in_the_limited_slow_start_keeps_the_limit() {
    for cc in CCS {
        let mut r = Rig::new(cc, false, 10);
        r.first_rto_keep_slow_start();
        r.settle();
        assert!(r.flag(), "{cc:?}: limited at the entry");
        let mss = r.mss;
        // SND.UNA が RTO の recover を越えるまで 1 segment を確認させ、新しい送り残しを作る
        write_all(&mut r.n, r.c, mss as usize);
        r.settle();
        // 重複 ACK 3 つで回復に入る
        r.n.s.conn(r.c.slot).t.cwnd = 20 * mss;
        write_all(&mut r.n, r.c, 10 * mss as usize);
        let outs = r.take();
        assert!(outs.len() >= 5);
        let mut resent = Vec::new();
        for _ in 0..3 {
            r.q.p.rcv = r.n.s.conn(r.c.slot).t.snd_una;
            let s = r.q.p.seg(FLAG_ACK, &[]);
            r.n.inject(&s);
            resent.extend(r.take());
        }
        assert_eq!(r.n.s.stats().fast_recoveries, 1, "{cc:?}: entered");
        assert!(r.n.s.conn(r.c.slot).t.in_recovery, "{cc:?}: in recovery");
        // 失った分を再送で届けて回復を終える
        r.q.deliver(&mut r.n, &resent);
        r.settle();
        assert!(
            !r.n.s.conn(r.c.slot).t.in_recovery,
            "{cc:?}: recovery ended"
        );
        assert_eq!(r.n.s.stats().spurious_undos, 0);
        assert_eq!(r.probe(), mss, "{cc:?}: L = 1 after the recovery");
    }
}

// 6. TLP の縮小

/// TLP の probe が損失を直したと分かる縮小を後の slow start の途中で受けると、印が下ります。
fn tlp_cut_with_mark(cc: Congestion, by_hand: bool) {
    let mut r = Rig::new(cc, true, 1);
    let mss = r.mss;
    if by_hand {
        r.deliver_originals();
        r.n.s.conn(r.c.slot).t.ssthresh = 100 * mss;
    } else {
        r.wait_rto(1);
        assert!(r.flag(), "{cc:?}: raised");
        r.set_ssthresh(100 * mss);
        r.settle();
    }
    r.set_ssthresh(100 * mss);
    assert!(r.flag(), "{cc:?}: limited before the cut");
    r.n.advance(RTT);
    r.n.s.conn(r.c.slot).t.cwnd = 20 * mss;
    write_all(&mut r.n, r.c, 10 * mss as usize);
    let outs = r.take();
    assert!(outs.len() >= 10, "{cc:?}: ten segments");
    r.n.advance(RTT);
    for o in &outs[..8] {
        r.n.advance(Duration::from_millis(1));
        r.q.recv(o);
        r.q.ack(&mut r.n);
        r.n.drain();
    }
    assert!(r.flag(), "{cc:?}: the early ACKs keep the mark");
    // 末尾の 2 segment を失った所へ TLP が末尾を送り直す
    let tlp_at = r.n.s.conn(r.c.slot).t.tlp_at;
    assert!(tlp_at != 0, "{cc:?}: a PTO is armed");
    let wait = (tlp_at - crate::stack::ns(r.n.now)).max(0) + 2_000_000;
    r.n.advance(Duration::from_nanos(u64::try_from(wait).unwrap()));
    let probe = r.take();
    assert!(
        probe.len() == 1 && probe[0].seq == outs[9].seq,
        "{cc:?}: the probe resends the tail"
    );
    write_all(&mut r.n, r.c, 3 * mss as usize);
    let more = r.take();
    r.n.advance(Duration::from_millis(5));
    let before = r.n.s.stats().tlp_recoveries;
    r.q.recv(&outs[8]);
    r.q.recv(&probe[0]);
    for o in &more {
        r.q.recv(o);
    }
    r.q.ack(&mut r.n);
    assert_eq!(r.n.s.stats().tlp_recoveries, before + 1, "{cc:?}: TLP cut");
    assert!(!r.flag(), "{cc:?}: the TLP cut lowers the mark");
}

#[test]
fn tlp_cut_after_a_real_rto_lowers_the_mark() {
    for cc in CCS {
        tlp_cut_with_mark(cc, false);
    }
}

/// 同じ試験を、印を手で立てた接続でも行います。RTO の後では PTO が張られない場合の控えです。
#[test]
fn tlp_cut_with_the_mark_set_by_hand_lowers_the_mark() {
    for cc in CCS {
        tlp_cut_with_mark(cc, true);
    }
}

// 7 と 8. 最初の slow start

/// SYN-ACK を再送した接続の窓は 1 SMSS でも、続く最初の slow start は L = 2 です。
#[test]
fn syn_ack_retransmission_keeps_l2() {
    for cc in CCS {
        let config = Config {
            limits: small_limits(),
            congestion: cc,
            ..Config::new(DUT, TEST_MTU)
        };
        let mut n = TestNet::with_config(config, [7; 64]);
        let l = n.listen(80);
        let mut p = n.syn_sack(40000, 80, true, true, true);
        n.advance(Duration::from_secs(3));
        let again = n.drain();
        assert!(
            again
                .iter()
                .any(|o| o.flags == FLAG_ACK | crate::wire::FLAG_SYN),
            "{cc:?}: the SYN-ACK was retransmitted"
        );
        n.peer_ack(&mut p, &[]);
        let c = n.accept(l);
        n.drain();
        let mss = n.s.conn(c.slot).seg_mss();
        let cv = n.s.conn(c.slot);
        assert!(
            cv.hystart_on(),
            "{cc:?}: the SYN-ACK retransmission leaves the initial slow start"
        );
        let t = &*cv.t;
        assert_eq!(t.cwnd, mss, "{cc:?}: one segment after the retransmission");
        let mut r = Rig {
            n,
            c,
            q: SackPeer::new(p),
            mss,
            outs: Vec::new(),
        };
        assert_eq!(r.probe_with(false), 2 * mss, "{cc:?}");
    }
}

/// 損失の無い接続の最初の slow start は L = 2 で、印は立ちません。
#[test]
fn the_initial_slow_start_never_sees_l1() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 10);
        assert!(!r.flag());
        r.deliver_originals();
        assert!(!r.flag(), "{cc:?}: no loss, no mark");
        let mss = r.mss;
        assert_eq!(
            r.probe_with(false),
            2 * mss,
            "{cc:?}: ssthresh still initial"
        );
        assert_eq!(r.ssthresh(), u32::MAX);
        assert!(!r.flag());
    }
}
