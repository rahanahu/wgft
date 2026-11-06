//! slow start の 1 ACK の増分 L の試験です。
//!
//! 実装の担当とは別の担当が、`docs/design/v2/wgstack-rs.md` の「slow start の 1 ACK の増分」と RFC 5681 3.1 節、
//! RFC 3465、RFC 9406 から書きました。採る形は、黙った後の窓の育ちを HyStart++ の中で動かし (RFC 9406 4.3 節の
//! MAY)、HyStart++ の外の slow start (RTO の後、SACK を交渉しない接続の回復の終わり、取り消しの後) は 1 ACK の
//! 増分を 1 SMSS までにすることです。最初の slow start は今までどおり HyStart++ の中です。
//!
//! 増分は、本物の ACK で 2 segment を確認した時の窓の増分で見ます (1 SMSS なら L = 1、2 SMSS なら L = 2)。
//! 直す前の核で失敗する試験は `#[ignore]` を付けています。直す PR が外します。

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
use crate::{Config, Congestion, ConnId};
use core::time::Duration;

const CCS: [Congestion; 2] = [Congestion::NewReno, Congestion::Cubic];
const RTT: Duration = Duration::from_millis(20);
/// RFC 9406 の N_RTT_SAMPLE、CSS_GROWTH_DIVISOR、CSS_ROUNDS を核が採る値です。
const N_RTT_SAMPLE: usize = 8;
const CSS_GROWTH_DIVISOR: f64 = 4.0;
const CSS_ROUNDS: usize = 5;

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

impl Rig {
    /// timestamp を交渉し、`sack` なら SACK も交渉した接続に、RTT の標本を入れて、窓を `window` segment にして
    /// `segs` segment を送らせます。
    fn new(cc: Congestion, sack: bool, window: u32, segs: usize) -> Self {
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
            t.cwnd = window * mss;
            mss
        };
        let mut r = Self {
            n,
            c,
            q: SackPeer::new(p),
            mss,
            outs: Vec::new(),
        };
        r.write(segs * mss as usize);
        r.outs = r.take();
        r.n.advance(RTT);
        r
    }

    fn write(&mut self, len: usize) {
        let data = vec![0u8; len];
        let mut off = 0;
        while off < len {
            match self.n.s.write(self.n.now, self.c, &data[off..]) {
                Ok(k) if k > 0 => off += k,
                _ => break,
            }
        }
    }

    fn take(&mut self) -> Vec<Out> {
        payload(self.n.drain())
    }

    /// 最初に送った segment をすべて届けて確認させます。
    fn ack_originals(&mut self) {
        let outs = std::mem::take(&mut self.outs);
        self.q.deliver(&mut self.n, &outs);
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

    fn in_recovery(&mut self) -> bool {
        self.n.s.conn(self.c.slot).t.in_recovery
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

    /// 新しいデータを送らせ、先頭の 2 segment を 1 つの ACK で確認させて、窓の増分を返します。
    /// 確認の前に、回復の外で slow start (窓が ssthresh より小さい) にいることを確かめます。
    fn two_segment_ack(&mut self) -> u32 {
        // 窓を使い切らせる (窓を使い切っていない送り手の窓は増やさない)
        let fill = (self.cwnd() / self.mss + 8) as usize;
        self.write(fill * self.mss as usize);
        let outs = self.take();
        assert!(outs.len() >= 2, "{} segments in flight", outs.len());
        assert!(!self.in_recovery(), "outside recovery");
        let (cwnd, ssthresh) = (self.cwnd(), self.ssthresh());
        assert!(
            cwnd < ssthresh,
            "slow start: cwnd {cwnd} ssthresh {ssthresh}"
        );
        self.n.advance(Duration::from_millis(1));
        let una = self.n.s.conn(self.c.slot).t.snd_una;
        self.q.recv(&outs[0]);
        self.q.recv(&outs[1]);
        self.q.ack(&mut self.n);
        let t = &*self.n.s.conn(self.c.slot).t;
        assert_eq!(
            t.snd_una.wrapping_sub(una),
            2 * self.mss,
            "the ACK covers 2 segments"
        );
        assert!(!t.in_recovery, "outside recovery after the ACK");
        t.cwnd - cwnd
    }
}

// 1. HyStart++ の外の slow start は 1 ACK で 1 SMSS まで (RFC 5681 3.1 節、RFC 3465 2.3 節)

/// RTO の後の slow start: 2 segment を確認する ACK は窓を 1 SMSS だけ増やします (今の核もこうです)。
#[test]
fn slow_start_after_rto_grows_one_smss_per_ack() {
    for cc in CCS {
        let mut r = Rig::new(cc, false, 10, 10);
        r.wait_rto(1);
        let mss = r.mss;
        // 覚えた ssthresh を大きく取り、窓が届いて終わる経路を避ける
        r.set_ssthresh(100 * mss);
        r.settle();
        assert_eq!(r.two_segment_ack(), mss, "{cc:?}");
    }
}

/// SACK を交渉しない接続の高速の回復の終わりに窓が ssthresh より小さくなる時、続く slow start も 1 SMSS までです。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn slow_start_at_the_end_of_recovery_without_sack_grows_one_smss_per_ack() {
    for cc in CCS {
        let mut r = Rig::new(cc, false, 40, 40);
        let mss = r.mss;
        let outs = std::mem::take(&mut r.outs);
        assert!(outs.len() >= 20, "{} segments sent", outs.len());
        // 先頭の segment を失い、後ろの segment の重複 ACK で高速の回復に入る
        r.q.deliver_with(&mut r.n, &outs, |i, _| i == 0);
        let resent = r.take();
        assert_eq!(r.n.s.stats().fast_recoveries, 1, "{cc:?}: entered");
        assert!(r.in_recovery(), "{cc:?}: in recovery");
        assert!(!resent.is_empty() && resent[0].seq == outs[0].seq);
        // 再送が届いて回復が終わる
        r.n.advance(Duration::from_millis(1));
        r.q.deliver(&mut r.n, &resent[..1]);
        assert!(!r.in_recovery(), "{cc:?}: recovery ended");
        let (cwnd, ssthresh) = (r.cwnd(), r.ssthresh());
        assert!(
            cwnd < ssthresh && ssthresh != u32::MAX,
            "{cc:?}: slow start again; cwnd {cwnd} ssthresh {ssthresh}"
        );
        assert_eq!(r.two_segment_ack(), mss, "{cc:?}");
    }
}

/// 取り消しの後に戻した窓が ssthresh より小さい時、続く slow start も 1 SMSS までです。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn slow_start_after_an_undo_grows_one_smss_per_ack() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 20, 1);
        let mss = r.mss;
        r.set_ssthresh(100 * mss);
        r.ack_originals();
        r.settle();
        // 後の slow start の途中で、10 segment のうち 2 番目を遅らせて高速の回復に入る
        r.n.s.conn(r.c.slot).t.cwnd = 20 * mss;
        r.write(10 * mss as usize);
        let outs = r.take();
        assert!(outs.len() >= 10, "{cc:?}: ten segments");
        r.n.advance(RTT);
        r.q.deliver_with(&mut r.n, &outs, |i, _| i == 1);
        assert!(r.in_recovery(), "{cc:?}: in recovery");
        let resent = r.take();
        assert!(!resent.is_empty() && resent[0].seq == outs[1].seq);
        // 遅れた元の segment が届き、再送は不要だったと分かる (Eifel)
        let before = r.n.s.stats().spurious_undos;
        r.n.advance(Duration::from_millis(1));
        r.q.recv(&outs[1]);
        r.q.ack(&mut r.n);
        assert_eq!(r.n.s.stats().spurious_undos, before + 1, "{cc:?}: undone");
        assert!(!r.in_recovery(), "{cc:?}: recovery ended");
        assert!(
            r.cwnd() < r.ssthresh() && r.ssthresh() != u32::MAX,
            "{cc:?}: the undo leaves slow start; cwnd {} ssthresh {}",
            r.cwnd(),
            r.ssthresh()
        );
        assert_eq!(r.two_segment_ack(), mss, "{cc:?}");
    }
}

// 2. 黙った後の窓の育ちは HyStart++ の中 (RFC 9406 4.3 節の MAY)

/// 覚えた ssthresh (`ssthresh` segment) と `window` segment の窓を持つ接続を RTO より長く黙らせ、窓を IW に戻して
/// 再開させます。再開の最初の送り出しを返します。
fn idle_restart(cc: Congestion, window: u32, ssthresh: u32) -> (Rig, Vec<Out>) {
    idle_restart_with(cc, true, window, ssthresh, 400)
}

/// `idle_restart` と同じで、`sack` で SACK を交渉するかを選び、再開で書く量を `segs` segment にします。
fn idle_restart_with(
    cc: Congestion,
    sack: bool,
    window: u32,
    ssthresh: u32,
    segs: usize,
) -> (Rig, Vec<Out>) {
    let mut r = Rig::new(cc, sack, window, 1);
    let mss = r.mss;
    r.set_ssthresh(ssthresh * mss);
    r.ack_originals();
    r.settle();
    r.n.s.conn(r.c.slot).t.cwnd = window * mss;
    r.n.advance(Duration::from_secs(60));
    assert_eq!(r.rtos(), 0, "{cc:?}: the idle raised no RTO");
    r.write(segs * mss as usize);
    let outs = r.take();
    assert_eq!(
        outs.len() as u32,
        crate::tcp::INITIAL_WINDOW_SEGS,
        "{cc:?}: the idle restart returns the window to IW"
    );
    r.n.advance(RTT);
    (r, outs)
}

/// 黙った後の再開の最初の ACK の増分は、HyStart++ の中の slow start の L = 2 です (RFC 9406 4.2 節の min(N, L * SMSS))。
/// 今の核は HyStart++ の外の L = 2 なので通ります (統制)。
#[test]
fn idle_restart_first_ack_grows_by_the_hystart_limit() {
    for cc in CCS {
        let (mut r, outs) = idle_restart(cc, 40, 100_000);
        let mss = r.mss;
        let before = r.cwnd();
        for o in &outs {
            r.q.recv(o);
        }
        r.q.ack(&mut r.n);
        let t = &*r.n.s.conn(r.c.slot).t;
        assert_eq!(
            t.snd_una.wrapping_sub(outs[0].seq),
            outs.len() as u32 * mss,
            "{cc:?}: all acknowledged"
        );
        assert_eq!(t.cwnd - before, 2 * mss, "{cc:?}");
    }
}

/// 往復ごとに窓いっぱいを送り、往復の RTT を `rtt(round)` にして `rounds` 往復を進めます。往復ごとの窓 (segment) を
/// 返します。CSS を終えた往復で止めます。ACK は segment ごとに返します (往復の標本を `N_RTT_SAMPLE` 以上にするためです)。
fn hs_rounds(
    r: &mut Rig,
    first: Vec<Out>,
    rounds: usize,
    rtt: impl Fn(usize) -> Duration,
) -> Vec<u32> {
    let mss = r.mss;
    let mut windows = Vec::new();
    let mut flight = first;
    for round in 0..rounds {
        if flight.len() < N_RTT_SAMPLE {
            break;
        }
        // 最初の往復は、送り出しの後に RTT を進め済みの呼び出し側から始まる
        if round > 0 {
            r.n.advance(rtt(round));
        } else {
            r.n.advance(rtt(0).saturating_sub(RTT));
        }
        for o in &flight {
            r.q.recv(o);
            r.q.ack(&mut r.n);
        }
        windows.push(r.cwnd() / mss);
        if r.n.s.stats().hystart_exits > 0 {
            break; // 終えた直後の窓を呼び出し側が見る
        }
        flight = r.take();
    }
    windows
}

/// CSS を終えた直後は ssthresh が窓に揃っています。CUBIC は同じ ACK の続きで 1 SMSS に満たない分を足すことがあります。
fn assert_at_css_exit(r: &mut Rig, windows: &[u32]) {
    let (ssthresh, cwnd) = (r.ssthresh(), r.cwnd());
    assert!(
        ssthresh != u32::MAX && ssthresh <= cwnd && cwnd - ssthresh < r.mss,
        "ssthresh {ssthresh} cwnd {cwnd}; windows {windows:?}"
    );
}

fn rising_rtt(round: usize) -> Duration {
    // 20 ms の往復の後に 30 ms に上がる (閾値は max(4 ms, min(16 ms, 20 ms / 8)) = 4 ms)
    Duration::from_millis(if round >= 1 { 30 } else { 20 })
}

/// RTT が上がると、黙った後の窓の育ちも CSS に入り、CSS の間の窓は 1 往復で 1 + 1 / CSS_GROWTH_DIVISOR 倍ほどです。
/// RFC 9406 4.2 節: 往復の最小 RTT が前の往復より閾値以上増えると CSS に入ります。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn idle_restart_enters_css_when_rtt_rises() {
    for cc in CCS {
        let (mut r, outs) = idle_restart(cc, 40, 100_000);
        let w = hs_rounds(&mut r, outs, 5, rising_rtt);
        let st = r.n.s.stats();
        assert_eq!(st.hystart_css, 1, "{cc:?}: entered CSS; windows {w:?}");
        assert_eq!(st.hystart_exits, 0, "{cc:?}: not left yet; windows {w:?}");
        // 入った後は、1 往復の増えが slow start の 2 倍より遅い
        let k = w.len() - 1;
        let growth = f64::from(w[k]) / f64::from(w[k - 1]);
        assert!(
            growth <= 1.0 + 1.0 / CSS_GROWTH_DIVISOR + 0.05,
            "{cc:?}: windows {w:?}"
        );
    }
}

/// CSS に入って CSS_ROUNDS 往復を過ごすと、ssthresh を窓に揃えて CSS を終えます (RFC 9406 4.2 節)。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn idle_restart_leaves_css_after_five_rounds() {
    for cc in CCS {
        let (mut r, outs) = idle_restart(cc, 40, 100_000);
        let w = hs_rounds(&mut r, outs, 1 + 1 + CSS_ROUNDS + 1, rising_rtt);
        let st = r.n.s.stats();
        assert_eq!(st.hystart_css, 1, "{cc:?}: windows {w:?}");
        assert_eq!(st.hystart_exits, 1, "{cc:?}: windows {w:?}");
        // 入った往復の後、CSS_ROUNDS 往復で終える
        assert_eq!(w.len(), 1 + CSS_ROUNDS, "{cc:?}: windows {w:?}");
        assert_at_css_exit(&mut r, &w);
    }
}

// 2b. 黙った後の再開で動かした HyStart++ は、RTO や回復で終わる (出来事を本物の送り出しと ACK で起こす)

/// 黙った後の再開の送り出しをすべて失って RTO を起こすと、その後の slow start は HyStart++ の外で、1 ACK の増分は 1 SMSS
/// までです (RFC 3465 2.3 節の MUST)。RTO の後に ssthresh を大きく上げて (1000 SMSS) 落ち着かせても、再開で動かし始めた
/// HyStart++ が残って L = 2 に戻ってはいけません。
#[test]
fn rto_after_an_idle_restart_ends_the_hystart_limit() {
    for cc in CCS {
        let (mut r, lost) = idle_restart(cc, 40, 100_000);
        assert!(!lost.is_empty());
        // 再開の送り出しは届かない。RTO が起きる
        r.wait_rto(1);
        let mss = r.mss;
        r.set_ssthresh(1000 * mss);
        r.settle();
        assert_eq!(r.two_segment_ack(), mss, "{cc:?}");
    }
}

/// SACK を交渉しない接続が 60 s 黙った後、10 segment だけ送って先頭を失い、高速の回復が窓 < ssthresh で終わると、続く
/// slow start は HyStart++ の外で、1 ACK の増分は 1 SMSS までです (RFC 5681 3.1 節)。再開で動かし始めた HyStart++
/// が回復に入るときに終わらないと L = 2 に戻る。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn recovery_after_an_idle_restart_ends_the_hystart_limit() {
    for cc in CCS {
        let (mut r, outs) = idle_restart_with(
            cc,
            false,
            40,
            100_000,
            crate::tcp::INITIAL_WINDOW_SEGS as usize,
        );
        let mss = r.mss;
        assert_eq!(outs.len() as u32, crate::tcp::INITIAL_WINDOW_SEGS);
        // 先頭を失う。後ろの重複 ACK で高速の回復に入る
        r.q.deliver_with(&mut r.n, &outs, |i, _| i == 0);
        let resent = r.take();
        assert_eq!(r.n.s.stats().fast_recoveries, 1, "{cc:?}: entered");
        assert!(r.in_recovery(), "{cc:?}: in recovery");
        assert!(!resent.is_empty() && resent[0].seq == outs[0].seq);
        r.n.advance(Duration::from_millis(1));
        r.q.deliver(&mut r.n, &resent[..1]);
        assert!(!r.in_recovery(), "{cc:?}: recovery ended");
        let (cwnd, ssthresh) = (r.cwnd(), r.ssthresh());
        assert!(
            cwnd < ssthresh && ssthresh != u32::MAX,
            "{cc:?}: slow start again; cwnd {cwnd} ssthresh {ssthresh}"
        );
        assert_eq!(r.two_segment_ack(), mss, "{cc:?}");
    }
}

// 2c. 出来事で状態を作る (窓と ssthresh を書き換えて出来事の効果を消さない)

/// 最初の slow start の RTO の後、本物の高速の回復が窓 < 有限の ssthresh で終わると、続く slow start は HyStart++ の外で
/// 1 SMSS までです (RFC 5681 3.1 節)。回復の入口で ssthresh が決まり、窓は回復の出口で ssthresh より小さくなります。
/// 窓は、RTO の後に落ち着いてから 1 度だけ開けて (送り出しを作るため)、回復の後は触りません。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn slow_start_after_an_rto_and_a_real_recovery_grows_one_smss_per_ack() {
    for cc in CCS {
        let mut r = Rig::new(cc, false, 40, 40);
        let mss = r.mss;
        // 元の 40 segment をすべて失って RTO を起こし、再送で落ち着く
        r.wait_rto(1);
        r.settle();
        assert!(!r.in_recovery(), "{cc:?}: settled");
        // RTO の recover を SND.UNA が越えるまで、新しいデータを 1 segment 送って確認させる (RFC 6582 3.2 節)
        r.write(mss as usize);
        r.settle();
        // 窓を開けて 30 segment を送り、先頭を失って高速の回復に入る
        r.n.s.conn(r.c.slot).t.cwnd = 40 * mss;
        r.write(30 * mss as usize);
        let outs = r.take();
        assert!(outs.len() >= 20, "{cc:?}: {} segments", outs.len());
        r.n.advance(RTT);
        r.q.deliver_with(&mut r.n, &outs, |i, _| i == 0);
        let resent = r.take();
        assert_eq!(r.n.s.stats().fast_recoveries, 1, "{cc:?}: entered");
        assert!(r.in_recovery(), "{cc:?}: in recovery");
        assert!(!resent.is_empty() && resent[0].seq == outs[0].seq);
        r.n.advance(Duration::from_millis(1));
        r.q.deliver(&mut r.n, &resent[..1]);
        assert!(!r.in_recovery(), "{cc:?}: recovery ended");
        let (cwnd, ssthresh) = (r.cwnd(), r.ssthresh());
        assert!(
            cwnd < ssthresh && ssthresh != u32::MAX,
            "{cc:?}: slow start again; cwnd {cwnd} ssthresh {ssthresh}"
        );
        assert_eq!(r.two_segment_ack(), mss, "{cc:?}");
    }
}

/// 最初の slow start の不要な RTO が取り消されると、ssthresh は初期値に戻り (RFC 4015 の取り消し)、続く slow start は
/// 最初の slow start なので HyStart++ の中で L = 2 です (RFC 9406 4.2 節)。RTO の後の窓の戻しと取り消しは本物の
/// 再送と元の segment の確認で起こし、取り消しの後に窓も ssthresh も書き換えません。
#[test]
fn slow_start_after_a_spurious_rto_undo_in_the_initial_slow_start_keeps_l2() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 10, 10);
        let mss = r.mss;
        assert_eq!(r.ssthresh(), u32::MAX, "{cc:?}: the initial slow start");
        r.wait_rto(1);
        r.take(); // 再送
        // 遅れた元の segment が届いて確認される。RTO は不要だった
        r.ack_originals();
        assert_eq!(r.n.s.stats().spurious_rtos, 1, "{cc:?}: undone");
        assert_eq!(r.ssthresh(), u32::MAX, "{cc:?}: ssthresh restored");
        r.settle();
        assert!(!r.in_recovery());
        assert_eq!(r.two_segment_ack(), 2 * mss, "{cc:?}");
    }
}

// 3. 最初の slow start は今のまま

/// 最初の slow start (ssthresh が初期値) は HyStart++ の中で L = 2 です (統制)。
#[test]
fn the_initial_slow_start_keeps_l2() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 10, 10);
        let mss = r.mss;
        r.ack_originals();
        r.settle();
        r.n.s.conn(r.c.slot).t.cwnd = 40 * mss;
        assert_eq!(r.ssthresh(), u32::MAX);
        r.write(40 * mss as usize);
        let outs = r.take();
        assert!(outs.len() >= 12);
        let before = r.cwnd();
        r.n.advance(Duration::from_millis(1));
        for o in &outs[..12] {
            r.q.recv(o);
        }
        r.q.ack(&mut r.n);
        assert_eq!(r.cwnd() - before, 2 * mss, "{cc:?}");
        assert_eq!(
            r.ssthresh(),
            u32::MAX,
            "{cc:?}: still the initial slow start"
        );
    }
}

/// 最初の slow start でも RTT が上がると CSS に入り、CSS_ROUNDS 往復の後に終えます (統制。往復の駆動の確かめを兼ねます)。
#[test]
fn the_initial_slow_start_enters_and_leaves_css() {
    for cc in CCS {
        let mut r = Rig::new(cc, true, 10, 10);
        let mss = r.mss;
        let mut first = std::mem::take(&mut r.outs);
        r.write(400 * mss as usize);
        first.extend(r.take());
        let w = hs_rounds(&mut r, first, 1 + 1 + CSS_ROUNDS + 1, rising_rtt);
        let st = r.n.s.stats();
        assert_eq!(st.hystart_css, 1, "{cc:?}: windows {w:?}");
        assert_eq!(st.hystart_exits, 1, "{cc:?}: windows {w:?}");
        assert_eq!(w.len(), 1 + CSS_ROUNDS, "{cc:?}: windows {w:?}");
        assert_at_css_exit(&mut r, &w);
    }
}
