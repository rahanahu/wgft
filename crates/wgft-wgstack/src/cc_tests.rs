//! CUBIC と輻輳の事象 (Go の `cc_test.go`) の白箱の試験。窓の動きは核の関数を直接呼んで確かめます。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::float_cmp,
    clippy::many_single_char_names,
    reason = "test data"
)]

use crate::config::{Config, Congestion};
use crate::sack_tests::sack_conn;
use crate::tcp::cc::Cubic;
use crate::tcp::ctx::Conn;
use crate::testnet_tests::{DUT, PeerConn, TEST_MTU, TestNet, small_limits};
use core::time::Duration;
use std::collections::HashMap;

const CUBIC_BETA: f64 = 0.7;
const CUBIC_C: f64 = 0.4;
const MS: Duration = Duration::from_millis(1);
const SEC: i64 = 1_000_000_000;

fn config(cc: Congestion) -> Config {
    Config {
        limits: small_limits(),
        congestion: cc,
        ..Config::new(DUT, TEST_MTU)
    }
}

/// 輻輳の制御 `cc` の核で接続を 1 つ開きます (Go の `ccConn`)。
fn cc_conn(cc: Congestion) -> (TestNet, u32) {
    let mut n = TestNet::with_config(config(cc), [7; 64]);
    let (c, _) = n.accepted_sack(true, true);
    (n, c.slot)
}

/// 窓 `cwnd` の分の確認を RTT ごとに MSS ずつ受ける ACK の流れで、`d` の間の窓の変化を返します (Go の `runCubic`)。
/// 鍵は経過の時間を `rtt` の倍数に丸めた ns です。
fn run_cubic(c: &mut Conn<'_>, rtt: i64, d: i64, mut now: i64) -> HashMap<i64, f64> {
    let mss = c.seg_mss();
    let mut at = HashMap::new();
    let start = now;
    while now - start < d {
        let segs = c.t.cwnd / mss;
        for _ in 0..segs {
            now += rtt / i64::from(segs);
            c.cong_avoid(mss, now);
        }
        at.insert(
            round_to(now - start, rtt),
            f64::from(c.t.cwnd) / f64::from(mss),
        );
    }
    at
}

/// Go の `Duration.Round` です (正の値で、半分は切り上げます)。
fn round_to(d: i64, m: i64) -> i64 {
    (d + m / 2) / m * m
}

/// 輻輳の事象の ssthresh と fast convergence の試験です (Go の TestCubicLossThreshAndFastConvergence)。
#[test]
fn cubic_loss_thresh_and_fast_convergence() {
    let (mut n, i) = cc_conn(Congestion::Cubic);
    let mut c = n.s.conn(i);
    let mss = c.seg_mss();
    c.t.cwnd = 100 * mss;
    c.t.snd_max = c.t.snd_una.wrapping_add(100 * mss);
    let ss = c.loss_thresh();
    assert!(
        ss == 70 * mss && c.t.cubic.w_max == 100.0,
        "ssthresh {} segments, W_max {}",
        ss / mss,
        c.t.cubic.w_max
    );
    // 前の W_max より小さな窓での次の損失は、W_max を (1 + β) / 2 倍に縮める (fast convergence)
    c.t.cwnd = 80 * mss;
    c.t.snd_max = c.t.snd_una.wrapping_add(80 * mss);
    c.loss_thresh();
    let want = 80.0 * (1.0 + CUBIC_BETA) / 2.0;
    assert!(
        (c.t.cubic.w_max - want).abs() <= 1e-9 && c.t.cubic.cwnd_prior == 80.0,
        "W_max {}, want {want}",
        c.t.cubic.w_max
    );
}

/// 窓が 3 次の式に従うことの試験です (Go の TestCubicWindowFollowsTheCubicFunction)。
#[test]
fn cubic_window_follows_the_cubic_function() {
    let (mut n, i) = cc_conn(Congestion::Cubic);
    let mut c = n.s.conn(i);
    let mss = c.seg_mss();
    let rtt = 100 * MS.as_nanos() as i64;
    c.t.srtt = rtt;
    c.t.cwnd = 100 * mss;
    c.t.snd_max = c.t.snd_una.wrapping_add(100 * mss);
    c.t.ssthresh = c.loss_thresh();
    c.t.cwnd = c.t.ssthresh; // 回復の後の窓
    let now = 3600 * SEC;
    let k = ((100.0 - 70.0) / CUBIC_C).cbrt();
    let at = run_cubic(&mut c, rtt, 8 * SEC, now);
    let w = |t: f64| {
        let d = t - k;
        CUBIC_C * d * d * d + 100.0
    };
    let rtt_s = rtt as f64 / SEC as f64;
    for s in [1.0, 2.0, 3.0, k, 5.0, 6.0] {
        let got = at
            .get(&round_to((s * SEC as f64) as i64, rtt))
            .copied()
            .unwrap_or(0.0);
        // 窓は 1 RTT 先の W_cubic を目標にし、1 RTT ごとに近づくので、W_cubic(t) と W_cubic(t + RTT) の間にある
        let (lo, hi) = (w(s) - 2.0, w(s + rtt_s) + 2.0);
        assert!(
            got >= lo && got <= hi,
            "at {s:.2} s: cwnd {got:.1} segments, want within [{lo:.1}, {hi:.1}]"
        );
    }
    let got = at
        .get(&round_to((k * SEC as f64) as i64, rtt))
        .copied()
        .unwrap_or(0.0);
    assert!(
        (got - 100.0).abs() <= 3.0,
        "cwnd {got:.1} at K = {k:.2} s, want about W_max = 100"
    );
}

/// RTT が短く窓が小さいとき窓が Reno と公平な推定に従うことの試験です (Go の TestCubicRenoFriendlyRegion)。
#[test]
fn cubic_reno_friendly_region() {
    let (mut n, i) = cc_conn(Congestion::Cubic);
    let mut c = n.s.conn(i);
    let mss = c.seg_mss();
    let rtt = 2 * MS.as_nanos() as i64;
    c.t.srtt = rtt;
    c.t.cwnd = 20 * mss;
    c.t.snd_max = c.t.snd_una.wrapping_add(20 * mss);
    c.t.ssthresh = c.loss_thresh();
    c.t.cwnd = c.t.ssthresh;
    // 100 RTT の間、W_cubic は 0.2 秒しか進まないので W_max (20) に届かない。W_est は 14 から RTT ごとに約
    // 0.53 segment 増えて約 11 RTT で cwnd_prior (20) を超え、その後は RTT ごとに 1 segment 増えて約 109 になる
    let at = run_cubic(&mut c, rtt, 100 * rtt, 3600 * SEC);
    let got = at.get(&(100 * rtt)).copied().unwrap_or(0.0);
    assert!(
        (100.0..=112.0).contains(&got),
        "cwnd {got:.1} segments after 100 RTTs in the Reno-friendly region"
    );
    assert!(
        c.t.cubic.w_est >= c.t.cubic.cwnd_prior,
        "W_est {:.1} did not pass cwnd_prior {:.1}",
        c.t.cubic.w_est,
        c.t.cubic.cwnd_prior
    );
}

/// 黙った時間だけ epoch をずらすことの試験です (Go の TestCubicIdleShiftsTheEpoch)。
#[test]
fn cubic_idle_shifts_the_epoch() {
    let (mut n, i) = cc_conn(Congestion::Cubic);
    let mut c = n.s.conn(i);
    let mss = c.seg_mss();
    c.t.srtt = 100 * MS.as_nanos() as i64;
    c.t.cwnd = 50 * mss;
    c.t.snd_max = c.t.snd_una.wrapping_add(50 * mss);
    c.t.ssthresh = c.loss_thresh();
    c.t.cwnd = c.t.ssthresh;
    c.cong_avoid(mss, 3600 * SEC);
    let epoch = c.t.cubic.epoch;
    c.cc_on_idle(3 * SEC, 3610 * SEC);
    assert_eq!(
        c.t.cubic.epoch,
        epoch + 3 * SEC,
        "epoch after the idle shift"
    );
}

/// RTO で epoch を始め直すことの試験です (Go の TestCubicRTOResetsTheEpoch)。
#[test]
fn cubic_rto_resets_the_epoch() {
    let (mut n, i) = cc_conn(Congestion::Cubic);
    let mut c = n.s.conn(i);
    let mss = c.seg_mss();
    c.t.cwnd = 50 * mss;
    c.t.snd_max = c.t.snd_una.wrapping_add(50 * mss);
    c.loss_thresh();
    c.cc_on_rto();
    assert_eq!(c.t.cubic, Cubic::default(), "state after RTO");
}

/// NewReno を選べることの試験です (Go の TestNewRenoStaysSelectable)。
#[test]
fn new_reno_stays_selectable() {
    let (mut n, i) = cc_conn(Congestion::NewReno);
    {
        let mut c = n.s.conn(i);
        let mss = c.seg_mss();
        c.t.cwnd = 100 * mss;
        c.t.snd_max = c.t.snd_una.wrapping_add(100 * mss);
        let ss = c.loss_thresh();
        assert_eq!(ss, 50 * mss, "NewReno ssthresh {} segments", ss / mss);
        c.t.cwnd = 10 * mss;
        c.t.ca_acc = 0;
        for _ in 0..10 {
            c.cong_avoid(mss, 0);
        }
        assert_eq!(
            c.t.cwnd,
            11 * mss,
            "NewReno cwnd {} segments after one window of ACKs",
            c.t.cwnd / mss
        );
    }
    assert_eq!(
        n.s.config().congestion,
        Congestion::NewReno,
        "Config::congestion not applied"
    );
}

/// 送り残しが空になるたびに送り始める流れで epoch が今より先へずれないことの試験です (Go の TestCubicIdleShiftStaysBehindNow)。
#[test]
fn cubic_idle_shift_stays_behind_now() {
    let (mut n, i) = cc_conn(Congestion::Cubic);
    let mut c = n.s.conn(i);
    let mss = c.seg_mss();
    c.t.cwnd = 20 * mss;
    c.t.ssthresh = 10 * mss;
    c.t.srtt = 50 * MS.as_nanos() as i64;
    let mut now = 10 * SEC;
    for _ in 0..50 {
        let last = now; // 1 segment を送る
        now += 50 * MS.as_nanos() as i64; // 1 RTT の後に確認が届く
        c.cong_avoid(mss, now);
        now += 10 * MS.as_nanos() as i64; // 次の書き込み
        c.cc_on_idle(now - last, now); // 最後に送ってからの時間
    }
    assert!(
        c.t.cubic.epoch <= now,
        "epoch {} is {} ns after now",
        c.t.cubic.epoch,
        c.t.cubic.epoch - now
    );
}

/// 回復を終える ACK がそのまま次の回復に入る場合に窓が下がることの試験です (Go の TestRecoveryRightAfterRecoveryReducesTheWindow)。
#[test]
fn recovery_right_after_recovery_reduces_the_window() {
    for (cc, beta) in [(Congestion::Cubic, CUBIC_BETA), (Congestion::NewReno, 0.5)] {
        recovery_after_recovery(cc, beta);
        // 窓が 2 segment なら、β 倍は 2 SMSS の下限を下回るので ssthresh は下限になる
        let (mut n, i) = cc_conn(cc);
        let mut c = n.s.conn(i);
        let mss = c.seg_mss();
        c.t.cwnd = 2 * mss;
        c.t.snd_max = c.t.snd_una.wrapping_add(40 * mss);
        let ss = c.loss_thresh();
        assert_eq!(
            ss,
            2 * mss,
            "{cc:?}: ssthresh {ss} with a window of 2 segments, want the floor"
        );
    }
}

fn recovery_after_recovery(cc: Congestion, beta: f64) {
    let (mut n, c, mut q, outs) = sack_conn(150);
    let i = c.slot;
    n.s.conn(i).s.config.congestion = cc;
    assert_eq!(outs.len(), 10, "{cc:?}: IW10 sent");
    let mss = n.s.conn(i).seg_mss();
    // 先頭の segment を失い、残りの 9 つを SACK で知らせる:ssthresh が 10 segment の β 倍の回復に入る
    q.deliver_with(&mut n, &outs, |k, _| k == 0);
    assert!(n.s.conn(i).t.in_recovery, "{cc:?}: not in recovery");
    let (head, recover) = (outs[0].seq, n.s.conn(i).t.recover);
    // 先頭の再送を止めておく間に、回復の点より先の最初の新しい segment を失い、ほかはすべて届けて SACK で
    // 知らせる。PRR は SACK された分だけ新しいデータを送るので、穴の先の SACK 済みのデータが積もる
    let mut held = Vec::new();
    let (mut lost_seq, mut lost_set) = (0u32, false);
    for _ in 0..6 {
        n.advance(10 * MS);
        for o in n.drain() {
            if o.payload.is_empty() {
                continue;
            }
            let s = o.seq;
            if s == head {
                held.push(o);
            } else if !lost_set && crate::seq::ge(s, recover) {
                (lost_seq, lost_set) = (s, true);
            } else if lost_set && s == lost_seq {
                // 失った segment の再送も失う
            } else {
                q.recv(&o);
                q.ack(&mut n);
            }
        }
    }
    assert!(
        lost_set && !held.is_empty() && n.s.conn(i).t.in_recovery,
        "{cc:?}: setup: lost new segment {lost_set}, held {}, in recovery {}",
        held.len(),
        n.s.conn(i).t.in_recovery
    );
    let (ss, prior_una, prior_max, prior_sacked) = {
        let t = &*n.s.conn(i).t;
        (t.ssthresh, t.snd_una, t.snd_max, t.sacked)
    };
    // 先頭の再送を届ける。累積の確認は回復の点を越えて失った segment で止まり、回復を終えた同じ ACK で
    // 次の回復に入る
    q.recv(&held[0]);
    q.ack(&mut n);
    let t = *n.s.conn(i).t;
    let k = *n.s.conn(i).k;
    let flight = t.snd_max.wrapping_sub(t.snd_una);
    assert!(
        t.in_recovery && t.recover != recover,
        "{cc:?}: no new recovery: in recovery {}, recover {}",
        t.in_recovery,
        t.recover
    );
    assert!(
        flight > ss,
        "{cc:?}: setup: flight {flight} is not above the window {ss} at the second loss"
    );
    // 回復を終えた時の窓は ssthresh である。次の輻輳の事象は、その窓を β 倍に下げなければならない
    let want = (f64::from(ss) * beta) as u32;
    assert!(
        t.ssthresh <= want,
        "{cc:?}: ssthresh {} after a second loss, want at most {want}: beta times the window {ss}, not the flight {flight} ({} segments)",
        t.ssthresh,
        flight / mss
    );
    assert!(
        t.cwnd <= ss,
        "{cc:?}: cwnd {} above the window {ss} at the loss",
        t.cwnd
    );
    // RFC 9937 6.1:RecoverFS は ACK の前の送り残しから、ACK の前に SACK 済みの byte を引いた量である
    let want = prior_max.wrapping_sub(prior_una).wrapping_sub(prior_sacked);
    assert_eq!(
        k.recover_fs, want,
        "{cc:?}: RecoverFS: the flight before the ACK less the {prior_sacked} bytes SACKed before recovery"
    );
}

/// SACK による回復の中の RTO が回復の ssthresh を β 倍することの試験です (Go の TestRTODuringRecoveryKeepsTheRecoveryWindow)。
#[test]
fn rto_during_recovery_keeps_the_recovery_window() {
    let (mut n, c, mut q, outs) = sack_conn(150);
    let i = c.slot;
    assert_eq!(outs.len(), 10, "IW10 sent");
    // 先頭の 7 つを失い、残りの 3 つを SACK で知らせる:回復に入り、pipe はほぼ 0 になる
    q.deliver_with(&mut n, &outs, |k, _| k < 7);
    assert!(n.s.conn(i).t.in_recovery, "not in recovery");
    let (ss0, flight0) = {
        let t = &*n.s.conn(i).t;
        (t.ssthresh, t.snd_max.wrapping_sub(t.snd_una))
    };
    n.drain(); // 再送はすべて失う
    n.advance(Duration::from_secs(1)); // RTO
    assert_eq!(n.s.stats().rtos, 1, "RTOs after a second");
    let want = (f64::from(ss0.min(flight0)) * CUBIC_BETA) as u32;
    assert_eq!(
        n.s.conn(i).t.ssthresh,
        want,
        "ssthresh after an RTO in recovery: beta times the recovery's ssthresh {ss0}"
    );
    // RTO の後の回復の中で、先頭の再送だけが届く。累積の確認が進んで後退は 0 に戻るが、SND.UNA は RTO の時の
    // SND.MAX に届かない
    let ss1 = n.s.conn(i).t.ssthresh;
    let head = n
        .drain()
        .into_iter()
        .rfind(|o| o.seq == outs[0].seq && !o.payload.is_empty())
        .expect("no retransmission of the head after the RTO");
    q.recv(&head);
    q.ack(&mut n);
    let t = *n.s.conn(i).t;
    assert!(
        t.backoff == 0 && t.rto_episode && crate::seq::lt(t.snd_una, t.recover),
        "setup: backoff {}, RTO episode {}",
        t.backoff,
        t.rto_episode
    );
    let flight1 = t.snd_max.wrapping_sub(t.snd_una);
    n.drain();
    n.advance(Duration::from_secs(1)); // 2 回目の RTO。後退は 0 から数える
    assert!(n.s.stats().rtos >= 2, "RTOs {}", n.s.stats().rtos);
    let cs = n.s.conn(i);
    let want = ((f64::from(ss1.min(flight1)) * CUBIC_BETA) as u32).max(2 * cs.seg_mss());
    assert_eq!(
        cs.t.ssthresh, want,
        "ssthresh after an RTO in the RTO's recovery: beta times the ssthresh {ss1}"
    );
}

/// SACK を交渉しない接続でも RTO の後の回復の印を SND.UNA が recover に届いたら消すことの試験です (Go の TestRTOEpisodeEndsWithoutSACK)。
#[test]
fn rto_episode_ends_without_sack() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p): (_, PeerConn) = n.accepted_sack(true, false);
    let i = c.slot;
    let data = vec![0u8; 5 * crate::sack_tests::TEST_SEG_PAYLOAD];
    assert_eq!(n.s.write(n.now, c, &data).unwrap(), data.len());
    n.drain(); // すべて失う
    n.advance(Duration::from_secs(2));
    let rtos = n.s.stats().rtos;
    {
        let t = &*n.s.conn(i).t;
        assert!(
            rtos != 0 && t.rto_episode && !t.sack_ok,
            "setup: RTO episode {}, SACK {}",
            t.rto_episode,
            t.sack_ok
        );
    }
    let recover = n.s.conn(i).t.recover;
    for _ in 0..100 {
        let t = &*n.s.conn(i).t;
        if t.snd_una == t.snd_max {
            break;
        }
        let outs = n.drain();
        p.absorb(&outs);
        n.peer_ack(&mut p, &[]);
        n.advance(10 * MS);
    }
    let t = *n.s.conn(i).t;
    assert!(
        crate::seq::ge(t.snd_una, recover),
        "setup: SND.UNA {} short of recover {recover}",
        t.snd_una
    );
    assert!(
        !t.rto_episode,
        "RTO episode still marked after SND.UNA reached recover"
    );
}
