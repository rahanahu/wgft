//! RACK-TLP (Go の `rack_test.go`) の白箱の試験。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::float_cmp,
    clippy::many_single_char_names,
    reason = "test data follows the Go tests"
)]

use crate::buf::{BOOST_RECORDS, BOOST_SIZE, MIN_SEG_PAYLOAD};
use crate::config::{BoostPolicy, Config};
use crate::sack_tests::TEST_SEG_PAYLOAD;
use crate::sackpeer_tests::{SackPeer, check_scoreboard};
use crate::seq;
use crate::stack::{Error, ns};
use crate::tcp::TS_OPTION_LEN;
use crate::tcp::conn::{ConnId, TMR_RETRANS};
use crate::tcp::ctx::Conn;
use crate::tcp::rack::RACK_REO_PERSIST;
use crate::testnet_tests::{DUT, Out, TEST_MTU, TestNet, small_limits};
use crate::wire::{FLAG_ACK, SackBlock};
use core::time::Duration;

const TEST_RTT: Duration = Duration::from_millis(20);
const MS: i64 = 1_000_000;
/// Go の `rtoMin` です。
const RTO_MIN: i64 = 200 * MS;

fn cs(n: &mut TestNet, c: ConnId) -> Conn<'_> {
    n.s.conn(c.slot)
}

/// 時計を `ns` 進めます (負なら進めません)。
fn adv(n: &mut TestNet, ns: i64) {
    n.advance(Duration::from_nanos(ns.max(0) as u64));
}

/// 時刻 `at` (ns) まで時計を進めます。過ぎていれば進めません。
fn adv_to(n: &mut TestNet, at: i64) {
    let now = ns(n.now);
    adv(n, at - now);
}

fn write_all(n: &mut TestNet, c: ConnId, len: usize) {
    let data = vec![0u8; len];
    let mut off = 0;
    while off < len {
        match n.s.write(n.now, c, &data[off..]) {
            Ok(k) => off += k,
            Err(Error::WouldBlock) => panic!("the send buffer is full at {off} of {len}"),
            Err(e) => panic!("write failed: {e:?}"),
        }
    }
}

/// SACK を交渉した接続に RTT を与え、DUT に `segs` 個の segment を送らせて返します。手で進める時計の握手は RTT が
/// 0 なので、RTT の推定を直接与えます (Go の `rackConn`、`rackConnApp`)。
fn rack_conn(segs: usize) -> (TestNet, ConnId, SackPeer, Vec<Out>) {
    let mut n = TestNet::new(small_limits());
    let (c, p) = n.accepted_sack(true, true);
    let rtt = TEST_RTT.as_nanos() as i64;
    {
        let t = cs(&mut n, c).t;
        (t.srtt, t.rttvar, t.min_rtt) = (rtt, rtt / 2, rtt);
        (t.has_rtt, t.has_min_rtt) = (true, true);
        t.rto = RTO_MIN;
    }
    write_all(&mut n, c, segs * TEST_SEG_PAYLOAD);
    let outs = n.drain();
    n.advance(TEST_RTT);
    (n, c, SackPeer::new(p), outs)
}

/// 保持が上界の内側にあることを確かめます (Go の `checkHeld` のうち、表の大きさと保持の上界の部分)。
fn check_held(n: &TestNet) {
    let h = n.s.held();
    let b = n.s.bound();
    let lim = small_limits();
    assert!(
        h.syn_rows <= lim.syn_rows
            && h.tw_rows <= lim.tw_rows
            && h.accept_queued <= lim.accept_queue
            && h.ctl_queued <= lim.ctl_slots
            && h.conns <= lim.conns(),
        "a table exceeds its size: {h:?}"
    );
    let held = (h.chunk_bytes + h.record_bytes + h.interval_bytes) as u64;
    assert!(
        held <= b.floor_conn + b.boost,
        "held buffers {held} exceed the bound {}",
        b.floor_conn + b.boost
    );
}

#[test]
fn rack_marks_loss_after_the_reorder_window() {
    let (mut n, c, mut q, outs) = rack_conn(3);
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let got = n.drain();
    assert!(got.is_empty(), "resent {got:?} inside the reorder window");
    let (reo, retrans) = {
        let t = cs(&mut n, c).t;
        (t.reo_at, t.tdl[TMR_RETRANS])
    };
    assert!(
        reo != 0 && retrans == reo,
        "reorder deadline {reo}, retransmit node {retrans}"
    );
    adv_to(&mut n, reo);
    let got = n.drain();
    assert!(
        got.len() == 1 && got[0].seq == outs[1].seq,
        "after the reorder window sent {got:?}"
    );
    let st = n.s.stats();
    assert!(
        st.reorder_timeouts == 1
            && st.rack_lost == 1
            && st.rtos == 0
            && cs(&mut n, c).t.in_recovery,
        "stats {st:?}"
    );
    check_scoreboard(&mut cs(&mut n, c));
    q.deliver(&mut n, &got);
    let t = cs(&mut n, c).t;
    assert_eq!(t.snd_una, t.snd_max, "not repaired");
}

/// 再送も失われたとき、その後のデータの SACK で RACK が再送の損失を見つけます (Go の
/// `TestRACKFindsALostRetransmission`)。
#[test]
fn rack_finds_a_lost_retransmission() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    // 1 を失う。SACK で回復に入り、1 を再送するが、その再送も失う
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let resend = n.drain();
    assert!(
        !resend.is_empty() && resend[0].seq == outs[1].seq,
        "first resend {resend:?}"
    );
    // 再送の後に新しいデータを送り、それが届くと、RACK は再送も失われたとみなす
    n.advance(TEST_RTT / 2);
    write_all(&mut n, c, 4 * TEST_SEG_PAYLOAD);
    let fresh = n.drain();
    let newer: Vec<Out> = fresh
        .iter()
        .filter(|o| seq::ge(o.seq, outs[9].seq + TEST_SEG_PAYLOAD as u32))
        .cloned()
        .collect();
    assert!(!newer.is_empty(), "no new data after the resend: {fresh:?}");
    n.advance(TEST_RTT);
    q.deliver(&mut n, &newer);
    let mut again = false;
    for _ in 0..3 {
        for o in n.drain() {
            again = again || o.seq == outs[1].seq;
        }
        if again {
            break;
        }
        let reo = cs(&mut n, c).t.reo_at;
        let now = ns(n.now);
        adv(&mut n, (reo - now).max(MS));
    }
    assert!(
        again,
        "the lost retransmission was not resent; stats {:?}",
        n.s.stats()
    );
    let st = n.s.stats();
    assert!(st.rtos == 0 && st.rack_lost != 0, "stats {st:?}");
    check_scoreboard(&mut cs(&mut n, c));
}

/// 末尾の損失を TLP の probe が直します (Go の `TestTLPProbesATailLoss`)。
#[test]
fn tlp_probes_a_tail_loss() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    // 最後の 2 つを失い、残りを確認する
    q.deliver_with(&mut n, &outs, |i, _| i >= 8);
    let (tlp_at, srtt) = {
        let t = cs(&mut n, c).t;
        (t.tlp_at, t.srtt)
    };
    assert!(tlp_at != 0, "no PTO armed");
    let pto = tlp_at - ns(n.now);
    assert!(
        (2 * srtt - MS..=2 * srtt + MS).contains(&pto),
        "PTO {pto}, SRTT {srtt}"
    );
    adv(&mut n, pto);
    let got = n.drain();
    assert!(
        got.len() == 1 && got[0].seq == outs[9].seq,
        "probe {got:?}, want the last segment"
    );
    // probe の SACK がもう 1 つの損失を見せる
    n.advance(TEST_RTT);
    q.deliver(&mut n, &got);
    let mut got = n.drain();
    let reo = cs(&mut n, c).t.reo_at;
    let now = ns(n.now);
    adv(&mut n, reo - now);
    got.extend(n.drain());
    q.deliver(&mut n, &got);
    let st = n.s.stats();
    let t = cs(&mut n, c).t;
    assert!(
        t.snd_una == t.snd_max && st.rtos == 0 && st.tlp_probes == 1 && st.retrans[4] == 1,
        "una==max {} stats {st:?}",
        t.snd_una == t.snd_max
    );
    check_scoreboard(&mut cs(&mut n, c));
}

/// probe の後に相手が黙っても、重複した ACK だけを返し続けても、次の probe を送らずに RTO に移ります (Go の
/// `TestTLPOneProbePerTail`)。
#[test]
fn tlp_one_probe_per_tail() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver(&mut n, &outs[..8]);
    let tlp_at = cs(&mut n, c).t.tlp_at;
    adv_to(&mut n, tlp_at);
    let got = n.drain();
    assert_eq!(got.len(), 1, "probe {got:?}");
    for _ in 0..50 {
        n.advance(Duration::from_millis(10));
        n.drain();
        q.ack(&mut n); // 進まない ACK
    }
    for _ in 0..20 {
        n.advance(Duration::from_millis(500));
        n.drain();
    }
    let st = n.s.stats();
    assert!(st.tlp_probes == 1 && st.rtos != 0, "stats {st:?}");
    let mut k = cs(&mut n, c);
    assert!(
        k.t.tlp_at == 0 || k.tlp_eligible(),
        "PTO armed while not eligible"
    );
    check_scoreboard(&mut k);
}

/// 並べ替えの期限の処理が RTO の期限を動かさず、TLP の probe が RTO を probe の時刻から張り直します (Go の
/// `TestRTODeadlineIsNotPushedByReorderOrTLP`)。
#[test]
fn rto_deadline_is_not_pushed_by_reorder_or_tlp() {
    let (mut n, c, mut q, outs) = rack_conn(3);
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let (rto, reo) = {
        let t = cs(&mut n, c).t;
        (t.rto_at, t.reo_at)
    };
    assert!(reo != 0 && reo < rto, "reorder deadline {reo}, RTO {rto}");
    adv_to(&mut n, reo);
    let now_rto = cs(&mut n, c).t.rto_at;
    assert!(
        n.s.stats().reorder_timeouts == 1 && now_rto == rto,
        "after the reorder deadline: RTO {now_rto}, was {rto}"
    );

    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver(&mut n, &outs[..8]);
    let tlp_at = cs(&mut n, c).t.tlp_at;
    adv_to(&mut n, tlp_at);
    let got = n.drain();
    assert_eq!(got.len(), 1, "probe {got:?}");
    let now = ns(n.now);
    let k = cs(&mut n, c);
    let want = now + k.cur_rto();
    assert_eq!(k.t.rto_at, want, "RTO deadline after the probe");
}

/// SACK と累積の確認の洪水で、並べ替えの期限と TLP の probe が増え続けません (Go の
/// `TestRACKTimersStayBoundedUnderAdversarialACKs`)。Go の `rackChanges` は ACK の前後の RACK の状態の比較で
/// 数え直します。`scoreSteps` は試験 build だけの `tcp::sack::steps()` で数えます。
#[test]
fn rack_timers_stay_bounded_under_adversarial_acks() {
    // Go と同じ 4000 回です。
    const ROUNDS: usize = 4000;
    let config = Config {
        limits: small_limits(),
        boost: BoostPolicy::AtAccept,
        ..Config::new(DUT, TEST_MTU)
    };
    let mut n = TestNet::with_config(config, [7; 64]);
    let l = n.listen(80);
    let p = n.handshake_sack(40000, 80, true, true, true);
    let c = n.accept(l);
    assert!(cs(&mut n, c).b.boost.is_some(), "not boosted");
    n.drain();
    {
        let t = cs(&mut n, c).t;
        t.peer_mss = MIN_SEG_PAYLOAD as u32 + TS_OPTION_LEN; // segment の中身を MIN_SEG_PAYLOAD にする
        t.cwnd = 1 << 30;
        t.snd_wnd = 1 << 30;
        t.max_snd_wnd = 1 << 30;
    }
    write_all(&mut n, c, BOOST_SIZE as usize);
    for _ in 0..100 {
        if n.drain().is_empty() {
            break;
        }
    }
    assert_eq!(cs(&mut n, c).b.recs.len(), BOOST_RECORDS, "records");
    let mut q = SackPeer::new(p);

    let rtt = TEST_RTT.as_nanos() as i64;
    {
        let t = cs(&mut n, c).t;
        (t.srtt, t.min_rtt, t.has_rtt, t.has_min_rtt) = (rtt, rtt, true, true);
    }
    let nrec = cs(&mut n, c).b.recs.len();
    let steps0 = crate::tcp::sack::steps();
    let (mut acks, mut advances, mut rack_changes) = (0u64, 0u64, 0u64);
    for k in 0..ROUNDS {
        if k == ROUNDS / 2 {
            // 後半は RTT を長くし、並べ替えの期限が張られたまま ACK が続くようにする
            let t = cs(&mut n, c).t;
            (t.srtt, t.min_rtt) = (4_000_000_000, 4_000_000_000);
        }
        n.advance(Duration::from_millis(1 + (k % 7) as u64));
        let mut s = q.p.seg(FLAG_ACK, &[]);
        // 送り残しの先の記録を 1 つずつ SACK で知らせ、時々累積の確認を少し進める
        let v = cs(&mut n, c);
        let recs = v.b.recs.len();
        let i = 1 + (k * 7919) % recs.saturating_sub(1).max(1);
        if i < recs {
            let r = *v.b.recs.at(i);
            s.sack = vec![SackBlock {
                left: r.seq,
                right: r.seq + u32::from(r.length),
            }];
        }
        if k % 50 == 0 && recs > 2 {
            s.ack = v.b.recs.at(1).seq;
            advances += 1;
        } else {
            s.ack = v.t.snd_una;
        }
        let before = (v.t.rack_xmit, v.t.rack_end);
        n.inject(&s);
        acks += 1;
        let t = cs(&mut n, c).t;
        if t.sack_ok && (t.rack_xmit, t.rack_end) != before {
            rack_changes += 1;
        }
        n.drain();
        if k % 200 == 0 {
            check_scoreboard(&mut cs(&mut n, c));
            check_held(&n);
        }
    }
    let st = n.s.stats();
    assert!(
        st.reorder_timeouts <= st.rack_lost + rack_changes,
        "{} reorder timeouts for {} losses and {rack_changes} ACKs that changed the RACK state ({nrec} records, {acks} ACKs)",
        st.reorder_timeouts,
        st.rack_lost
    );
    assert!(
        st.tlp_probes <= advances + st.rtos + 1,
        "{} probes for {advances} advancing ACKs",
        st.tlp_probes
    );
    let steps = crate::tcp::sack::steps() - steps0;
    assert!(
        steps <= acks * 64 + nrec as u64 * 16,
        "{steps} scoreboard steps for {acks} ACKs and {nrec} records"
    );
    check_scoreboard(&mut cs(&mut n, c));
    check_held(&n);
}

/// RACK の待ち行列と損失の境目の両方に穴があるとき番号の小さい穴から送り直し、先頭の記録の再送が RTO を張り直します
/// (Go の `TestHolesResentInSequenceOrderAndHeadRearmsRTO`)。
#[test]
fn holes_resent_in_sequence_order_and_head_rearms_rto() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver_with(&mut n, &outs, |i, _| i == 0 || i == 6);
    let reo = cs(&mut n, c).t.reo_at;
    adv_to(&mut n, reo);
    let got = n.drain();
    assert!(
        !got.is_empty() && got[0].seq == outs[0].seq,
        "first resend {got:?}, want the head"
    );
    let now = ns(n.now);
    let mut k = cs(&mut n, c);
    let want = now + k.cur_rto();
    assert_eq!(k.t.rto_at, want, "RTO deadline after resending the head");
    check_scoreboard(&mut k);
}

/// 再送の probe の後に累積の確認が probe の手前まで進み続けても、probe の確認を待つ間は次の PTO を張らず、probe が
/// 1 つだけです (Go の `TestOneProbeWhileACKsAdvanceBelowTheProbe`)。
#[test]
fn one_probe_while_acks_advance_below_the_probe() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver(&mut n, &outs[..2]);
    let tlp_at = cs(&mut n, c).t.tlp_at;
    adv_to(&mut n, tlp_at);
    let probe = n.drain();
    {
        let t = cs(&mut n, c).t;
        assert!(
            probe.len() == 1 && probe[0].seq == outs[9].seq && t.tlp_active && t.tlp_retrans,
            "probe {probe:?} active {} retrans {}",
            t.tlp_active,
            t.tlp_retrans
        );
    }
    // 2 から 7 の確認が 1 つずつ遅れて届き、累積の確認は probe の手前で止まる
    for o in &outs[2..8] {
        let rto = cs(&mut n, c).cur_rto();
        adv(&mut n, 2 * rto / 10);
        q.recv(o);
        q.ack(&mut n);
        n.drain();
        let tlp_at = cs(&mut n, c).t.tlp_at;
        let now = ns(n.now);
        adv(&mut n, tlp_at - now);
        n.drain();
    }
    let st = n.s.stats();
    assert_eq!(
        st.tlp_probes, 1,
        "{} probes while ACKs advanced below the probe",
        st.tlp_probes
    );
}

/// RACK の状態を変えない重複した ACK を何度受けても、並べ替えの期限の処理が損失の印と RACK の状態を変えた ACK の数を
/// 超えて起きません (Go の `TestReorderTimeoutsNeedRACKProgress`)。`rackChanges` は ACK の前後の RACK の状態の比較で
/// 数え直します。
#[test]
fn reorder_timeouts_need_rack_progress() {
    let (mut n, c, mut q, outs) = rack_conn(3);
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let reo = cs(&mut n, c).t.reo_at;
    adv_to(&mut n, reo);
    n.drain(); // RACK が穴を失われたとみなして送り直す。送り直しも失う
    let mut rack_changes = 0u64;
    for _ in 0..300 {
        n.advance(Duration::from_millis(1));
        let t = cs(&mut n, c).t;
        let before = (t.rack_xmit, t.rack_end);
        q.ack(&mut n); // 同じ SACK の block を繰り返す
        let t = cs(&mut n, c).t;
        if (t.rack_xmit, t.rack_end) != before {
            rack_changes += 1;
        }
        n.drain();
    }
    let st = n.s.stats();
    assert!(
        st.reorder_timeouts <= st.rack_lost + rack_changes,
        "{} reorder timeouts for {} losses and {rack_changes} ACKs that changed the RACK state",
        st.reorder_timeouts,
        st.rack_lost
    );
    assert!(
        st.reorder_timeouts != 0 && st.rack_lost != 0,
        "stats {st:?}"
    );
}

/// D-SACK を受けた往復ごとに並べ替えの窓の倍率を 1 つ上げ、16 回の回復の後に 1 に戻します (Go の
/// `TestDSACKWidensTheReorderWindow`)。
#[test]
fn dsack_widens_the_reorder_window() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver(&mut n, &outs[..2]);
    cs(&mut n, c).t.reorder_seen = true;
    let w1 = cs(&mut n, c).reo_wnd();
    let dsack = |n: &mut TestNet, q: &mut SackPeer| {
        let mut s = q.p.seg(FLAG_ACK, &[]);
        s.sack = vec![SackBlock {
            left: outs[0].seq,
            right: outs[0].seq + TEST_SEG_PAYLOAD as u32,
        }]; // 確認済みの範囲
        n.inject(&s);
    };
    dsack(&mut n, &mut q); // 再送していないデータの D-SACK は疑わしいので使わない (Linux の tcp_dsack_seen)
    {
        let mult = cs(&mut n, c).t.reo_wnd_mult;
        assert!(
            mult <= 1 && n.s.stats().dsacks_in == 0,
            "a D-SACK with no retransmissions raised the multiplier to {mult}"
        );
    }
    cs(&mut n, c).k.total_retrans = 100; // 再送を送ったことにする
    dsack(&mut n, &mut q);
    {
        let k = cs(&mut n, c);
        let (mult, wnd, srtt) = (k.t.reo_wnd_mult, k.reo_wnd(), k.t.srtt);
        assert!(
            mult == 2 && wnd == (2 * w1).min(srtt),
            "after one D-SACK: mult {mult}, window {wnd}, was {w1}"
        );
    }
    assert_eq!(n.s.stats().dsacks_in, 1);
    dsack(&mut n, &mut q); // 同じ往復の 2 つ目は数えない
    assert_eq!(
        cs(&mut n, c).t.reo_wnd_mult,
        2,
        "second D-SACK in the round raised the multiplier"
    );
    q.deliver(&mut n, &outs[2..]); // 往復を終える
    n.drain();
    dsack(&mut n, &mut q);
    assert_eq!(cs(&mut n, c).t.reo_wnd_mult, 3, "D-SACK in the next round");
    let mut k = cs(&mut n, c);
    for _ in 0..RACK_REO_PERSIST {
        k.rack_recovery_done();
    }
    assert_eq!(
        k.t.reo_wnd_mult, 1,
        "multiplier after {RACK_REO_PERSIST} recoveries"
    );
}

/// 末尾の 2 segment を失った接続で TLP の probe に末尾を送り直させ、続けて新しいデータを `new_segs` segment 書かせます。
/// 返す `more` は probe の後に送った新しい segment です (Go の `tlpCutConn`)。
fn tlp_cut_conn(new_segs: usize) -> (TestNet, ConnId, SackPeer, Vec<Out>, Out, Vec<Out>) {
    let (mut n, c, mut q, outs) = rack_conn(10);
    for o in &outs[..8] {
        n.advance(Duration::from_millis(1));
        q.recv(o);
        q.ack(&mut n);
        n.drain();
    }
    let tlp_at = cs(&mut n, c).t.tlp_at;
    let now = ns(n.now);
    adv(&mut n, (tlp_at - now).max(0) + 2 * MS);
    let probe = n.drain();
    let retrans = cs(&mut n, c).t.tlp_retrans;
    assert!(
        probe.len() == 1 && retrans && probe[0].seq == outs[9].seq,
        "setup: probe {}, retransmission {retrans}",
        probe.len()
    );
    write_all(&mut n, c, new_segs * TEST_SEG_PAYLOAD);
    let more = n.drain();
    assert_eq!(more.len(), new_segs, "setup: new segments after the probe");
    n.advance(Duration::from_millis(5));
    (n, c, q, outs, probe[0].clone(), more)
}

/// ACK の前の送り残し `flight` と輻輳の窓 `w` で起きた輻輳の事象の ssthresh (CUBIC) です (Go の `tlpCutWant`)。
fn tlp_cut_want(k: &Conn<'_>, flight: u32, w: u32) -> u32 {
    ((f64::from(flight.min(w)) * 0.7) as u32).max(2 * k.seg_mss())
}

/// TLP の probe が損失を直したと分かる ACK が、probe の後に送ったデータの損失も RACK で知らせるとき、輻輳の窓を
/// 1 回だけ下げます (Go の `TestTLPRepairAndLossOnOneACKReduceOnce`)。
#[test]
fn tlp_repair_and_loss_on_one_ack_reduce_once() {
    let (mut n, c, mut q, outs, probe, more) = tlp_cut_conn(15);
    // 1 つの ACK:遅れた 8、probe、more[0] が届き、more[1] は失われ、残りは SACK される
    q.recv(&outs[8]);
    q.recv(&probe);
    q.recv(&more[0]);
    for o in &more[2..] {
        q.recv(o);
    }
    let (w, flight) = {
        let t = cs(&mut n, c).t;
        (t.cwnd, t.snd_max.wrapping_sub(t.snd_una))
    };
    let st0 = n.s.stats();
    q.ack(&mut n);
    let st = n.s.stats();
    let in_recovery = cs(&mut n, c).t.in_recovery;
    assert!(
        st.tlp_recoveries == st0.tlp_recoveries + 1
            && st.fast_recoveries == st0.fast_recoveries + 1
            && in_recovery,
        "setup: TLP reductions +{}, fast recoveries +{}, in recovery {in_recovery}",
        st.tlp_recoveries - st0.tlp_recoveries,
        st.fast_recoveries - st0.fast_recoveries
    );
    let k = cs(&mut n, c);
    let want = tlp_cut_want(&k, flight, w);
    assert_eq!(
        k.t.ssthresh, want,
        "ssthresh after one ACK, want one reduction from the window {w} and flight {flight} before the ACK"
    );
    // W_max は損失の前の窓で、この ACK の slow start の増分を含まない
    let want = f64::from(w) / f64::from(k.seg_mss());
    assert!(
        k.t.cubic.w_max == want && k.t.cubic.cwnd_prior == want,
        "W_max {}, cwnd_prior {}, want the window {want} before the ACK",
        k.t.cubic.w_max,
        k.t.cubic.cwnd_prior
    );
}

/// probe の縮小の後の ACK が、縮小の時までに送ったデータの損失で回復に入るとき、ssthresh を下げ直しません (Go の
/// `TestLossAfterTLPRepairInTheSameWindowReducesOnce`)。
#[test]
fn loss_after_tlp_repair_in_the_same_window_reduces_once() {
    let (mut n, c, mut q, outs, probe, more) = tlp_cut_conn(15);
    // probe の確認:累積の確認が probe と more[1] まで進み、窓を 1 回下げる
    q.recv(&outs[8]);
    q.recv(&probe);
    q.recv(&more[0]);
    q.recv(&more[1]);
    let tlp0 = n.s.stats().tlp_recoveries;
    q.ack(&mut n);
    let in_recovery = cs(&mut n, c).t.in_recovery;
    let tlp = n.s.stats().tlp_recoveries;
    assert!(
        tlp == tlp0 + 1 && !in_recovery,
        "setup: TLP reductions +{}, in recovery {in_recovery}",
        tlp - tlp0
    );
    let ss = cs(&mut n, c).t.ssthresh;
    // 次の ACK 群:more[2] が失われ、残りは SACK される。どれも縮小の前に送ったデータである
    let fast0 = n.s.stats().fast_recoveries;
    q.deliver(&mut n, &more[3..]);
    let fast = n.s.stats().fast_recoveries;
    let t = cs(&mut n, c).t;
    assert!(
        fast == fast0 + 1 && t.in_recovery,
        "setup: fast recoveries +{}, in recovery {}",
        fast - fast0,
        t.in_recovery
    );
    assert!(
        t.ssthresh == ss && t.recover == t.tlp_cut_seq,
        "ssthresh {}, recover {} after a loss in the window the probe's reduction covers, want {ss} and the cut point {}",
        t.ssthresh,
        t.recover,
        t.tlp_cut_seq
    );
    // 穴の再送が届き、累積の確認が縮小の時の SND.MAX を越えると、縮小の印は消える
    for o in n.drain() {
        q.recv(&o);
    }
    q.ack(&mut n);
    let t = cs(&mut n, c).t;
    assert!(
        seq::ge(t.snd_una, t.tlp_cut_seq) && !t.tlp_cut,
        "after the window is acknowledged: SND.UNA {}, cut at {}, mark {}",
        t.snd_una,
        t.tlp_cut_seq,
        t.tlp_cut
    );
}

/// 縮小の時までのデータの損失で入った回復が縮小の時の SND.MAX で終わり、その先に送ったデータの損失が次の回復で窓を
/// 下げます (RFC 6582 の 1 つの窓に 1 回の縮小。Go の `TestLossBeyondTheTLPCutReducesAgain`)。
#[test]
fn loss_beyond_the_tlp_cut_reduces_again() {
    let (mut n, c, mut q, outs, probe, more) = tlp_cut_conn(15);
    q.recv(&outs[8]);
    q.recv(&probe);
    q.recv(&more[0]);
    q.ack(&mut n);
    let (ss, cut, mark) = {
        let t = cs(&mut n, c).t;
        (t.ssthresh, t.tlp_cut_seq, t.tlp_cut)
    };
    let last = more.last().unwrap();
    assert!(
        mark && cut == last.seq + last.payload.len() as u32,
        "setup: mark {mark} at {cut}"
    );
    write_all(&mut n, c, 20 * TEST_SEG_PAYLOAD);
    // more[1..7] の確認が順に届き、窓が開いて縮小の後のデータ post が出る
    let mut post: Vec<Out> = Vec::new();
    for o in &more[1..8] {
        q.recv(o);
        q.ack(&mut n);
        post.extend(n.drain());
    }
    assert!(
        post.len() >= 5,
        "setup: {} segments after the cut",
        post.len()
    );
    // 縮小の前の more[8] と縮小の後の post[1] を失い、残りを SACK で知らせる
    let fast0 = n.s.stats().fast_recoveries;
    let lost_post = post[1].seq;
    for o in &more[9..] {
        q.recv(o);
        q.ack(&mut n);
    }
    for (i, o) in post.iter().enumerate() {
        if i != 1 {
            q.recv(o);
            q.ack(&mut n);
        }
    }
    {
        let t = cs(&mut n, c).t;
        assert!(
            t.in_recovery && t.ssthresh == ss && t.recover == cut,
            "held recovery: in recovery {}, ssthresh {} want {ss}, recover {} want the cut point {cut}",
            t.in_recovery,
            t.ssthresh,
            t.recover
        );
    }
    // more[8] の再送だけが届く。post[1] は送り直しも失う。累積の確認は縮小の時の SND.MAX を越えて回復が終わり、
    // 同じ ACK で post[1] の損失の回復に入って窓を下げる
    let mut held: Option<Out> = None;
    for _ in 0..4 {
        for o in n.drain() {
            if o.seq == more[8].seq && !o.payload.is_empty() {
                held = Some(o);
            }
        }
        if held.is_some() {
            break;
        }
        n.advance(Duration::from_millis(5));
    }
    let held = held.expect("setup: no retransmission of more[8]");
    q.recv(&held);
    q.ack(&mut n);
    let fast = n.s.stats().fast_recoveries - fast0;
    let t = cs(&mut n, c).t;
    assert!(
        fast == 2 && t.in_recovery && seq::gt(t.recover, cut) && t.snd_una == lost_post,
        "no second recovery for the loss beyond the cut: fast recoveries +{fast}, in recovery {}, recover {}, SND.UNA {} at {lost_post}",
        t.in_recovery,
        t.recover,
        t.snd_una
    );
    assert!(
        t.ssthresh < ss,
        "ssthresh {} after a loss beyond the cut, want below {ss}",
        t.ssthresh
    );
}

/// probe の確認が probe の後のデータまで確認するとき、縮小が ACK の前の窓で決まり、ACK の後の送り残し (0) で下限に
/// 落ちません。続けて、縮小がすべてを確認した後に送った最初の segment を失うと、縮小の窓の外の損失として窓を下げ直し
/// ます (Go の `TestTLPCutUsesTheWindowBeforeTheACK`)。
#[test]
fn tlp_cut_uses_the_window_before_the_ack() {
    let (mut n, c, mut q, outs, probe, more) = tlp_cut_conn(3);
    let mss = cs(&mut n, c).seg_mss();
    q.recv(&outs[8]);
    q.recv(&probe);
    for o in &more {
        q.recv(o);
    }
    let (w, flight) = {
        let t = cs(&mut n, c).t;
        (t.cwnd, t.snd_max.wrapping_sub(t.snd_una))
    };
    let tlp0 = n.s.stats().tlp_recoveries;
    q.ack(&mut n);
    let tlp = n.s.stats().tlp_recoveries;
    {
        let t = cs(&mut n, c).t;
        assert!(
            tlp == tlp0 + 1 && t.snd_una == t.snd_max,
            "setup: TLP reductions +{}, flight {}",
            tlp - tlp0,
            t.snd_max.wrapping_sub(t.snd_una)
        );
    }
    let ss = cs(&mut n, c).t.ssthresh;
    let want = tlp_cut_want(&cs(&mut n, c), flight, w);
    assert!(
        ss == want && ss > 2 * mss,
        "ssthresh {ss} after an ACK that covers everything, want {want} from the flight {flight} and window {w} before it"
    );
    // 縮小の時の SND.MAX はすべて確認された。その後に送った最初の segment を失い、残りを SACK で知らせる
    write_all(&mut n, c, 10 * TEST_SEG_PAYLOAD);
    let post = n.drain();
    assert!(
        post.len() >= 3,
        "setup: {} segments after the cut",
        post.len()
    );
    let fast0 = n.s.stats().fast_recoveries;
    for o in &post[1..] {
        q.recv(o);
        q.ack(&mut n);
    }
    let reo = cs(&mut n, c).t.reo_at;
    let now = ns(n.now);
    adv(&mut n, (reo - now).max(0) + MS);
    let fast = n.s.stats().fast_recoveries - fast0;
    let t = cs(&mut n, c).t;
    assert!(
        fast == 1 && t.in_recovery,
        "setup: fast recoveries +{fast}, in recovery {}",
        t.in_recovery
    );
    assert!(
        t.ssthresh < ss,
        "ssthresh {} after a loss in data sent after the cut, want below {ss}",
        t.ssthresh
    );
}

/// probe の確認を待つ間に RACK が回復に入ったとき、回復を終える ACK が probe の先まで確認しても TLP の縮小を重ねません
/// (RFC 8985 7.4.1。Go の `TestRecoveryDuringAProbeIsTheOnlyCut`)。
#[test]
fn recovery_during_a_probe_is_the_only_cut() {
    let (mut n, c, mut q, outs, probe, more) = tlp_cut_conn(12);
    // outs[8] を失ったまま、probe と新しい 12 segment を届ける。RACK が回復に入る
    q.recv(&probe);
    q.ack(&mut n);
    q.deliver(&mut n, &more);
    {
        let t = cs(&mut n, c).t;
        assert!(
            t.in_recovery && t.tlp_active,
            "setup: in recovery {}, probe outstanding {}",
            t.in_recovery,
            t.tlp_active
        );
    }
    let ss = cs(&mut n, c).t.ssthresh;
    let st0 = n.s.stats();
    // outs[8] の再送が届き、累積の確認が probe と回復の点を越える
    let mut rtx: Option<Out> = None;
    for _ in 0..4 {
        for o in n.drain() {
            if o.seq == outs[8].seq && !o.payload.is_empty() {
                rtx = Some(o);
            }
        }
        if rtx.is_some() {
            break;
        }
        n.advance(Duration::from_millis(5));
    }
    let rtx = rtx.expect("setup: no retransmission of outs[8]");
    q.recv(&rtx);
    q.ack(&mut n);
    let t = cs(&mut n, c).t;
    assert!(
        !t.in_recovery && seq::gt(t.snd_una, t.tlp_end),
        "setup: in recovery {}, SND.UNA {}, probe end {}",
        t.in_recovery,
        t.snd_una,
        t.tlp_end
    );
    let ssthresh = t.ssthresh;
    let st = n.s.stats();
    let got = st.tlp_recoveries - st0.tlp_recoveries;
    assert!(
        got == 0 && ssthresh == ss,
        "TLP reductions +{got}, ssthresh {ssthresh} after the recovery ended past the probe, want no TLP cut and {ss}"
    );
    assert_eq!(
        st.fast_recoveries, st0.fast_recoveries,
        "fast recoveries changed"
    );
}
