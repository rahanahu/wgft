//! 不要な再送の取り消しと F-RTO (Go の `undo_test.go`) の白箱の試験。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "test data"
)]

use crate::sack_tests::TEST_SEG_PAYLOAD;
use crate::sackpeer_tests::SackPeer;
use crate::stack::Error;
use crate::tcp::RTO_MIN;
use crate::testnet_tests::{Out, TSeg, TestNet, small_limits};
use crate::wire::{FLAG_ACK, SackBlock};
use core::time::Duration;

const MS: Duration = Duration::from_millis(1);
const TEST_RTT: Duration = Duration::from_millis(20);

/// 接続 `id` に `len` byte を書けるだけ書きます。
fn write_zeros(n: &mut TestNet, id: crate::ConnId, len: usize) {
    let data = vec![0u8; len];
    let mut off = 0;
    while off < len {
        match n.s.write(n.now, id, &data[off..]) {
            Ok(k) => off += k,
            Err(Error::WouldBlock) => break,
            Err(e) => panic!("write: {e:?}"),
        }
    }
    assert_eq!(off, len, "the send buffer took only {off} of {len} bytes");
}

/// SACK と timestamp を交渉した接続に RTT の標本を入れ、`segs` 個の segment を送らせて 1 RTT 進めます
/// (Go の `rackConnApp`)。
fn rack_conn(segs: usize) -> (TestNet, crate::ConnId, SackPeer, Vec<Out>) {
    let mut n = TestNet::new(small_limits());
    let (c, p) = n.accepted_sack(true, true);
    {
        let t = n.s.conn(c.slot).t;
        let rtt = TEST_RTT.as_nanos() as i64;
        (t.srtt, t.rttvar, t.min_rtt, t.has_rtt, t.has_min_rtt) = (rtt, rtt / 2, rtt, true, true);
        t.rto = RTO_MIN;
    }
    write_zeros(&mut n, c, segs * TEST_SEG_PAYLOAD);
    let outs = n.drain();
    n.advance(TEST_RTT);
    (n, c, SackPeer::new(p), outs)
}

fn blk(o: &Out) -> SackBlock {
    SackBlock {
        left: o.seq,
        right: o.seq.wrapping_add(o.payload.len() as u32),
    }
}

/// 1 を遅らせて回復に入れ、再送を送らせる。返り値は回復の前の輻輳の窓です (Go の `spuriousRecovery`)。
fn spurious_recovery(n: &mut TestNet, c: crate::ConnId, q: &mut SackPeer, outs: &[Out]) -> u32 {
    let before = n.s.conn(c.slot).t.cwnd;
    q.deliver_with(n, outs, |i, _| i == 1);
    let t = *n.s.conn(c.slot).t;
    assert!(
        t.in_recovery && t.cwnd < before,
        "not in recovery with a reduced window: {} {}",
        t.in_recovery,
        t.cwnd
    );
    let resent = n.drain();
    assert!(
        !resent.is_empty() && resent[0].seq == outs[1].seq,
        "resend {}",
        crate::testnet_tests::show(&resent)
    );
    before
}

/// 並べ替えを見た後は DupThresh で回復に入らないことの試験です (Go の TestNoDupThreshRecoveryAfterReorderingSeen)。
#[test]
fn no_dup_thresh_recovery_after_reordering_seen() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    n.s.conn(c.slot).t.reorder_seen = true;
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let got = n.drain();
    assert!(
        got.is_empty() && !n.s.conn(c.slot).t.in_recovery,
        "resent {}, in recovery {}, inside the reorder window",
        crate::testnet_tests::show(&got),
        n.s.conn(c.slot).t.in_recovery
    );
    n.advance(MS);
    q.deliver(&mut n, &outs[1..2]);
    let st = n.s.stats();
    let t = *n.s.conn(c.slot).t;
    assert!(
        st.fast_recoveries == 0 && st.retrans[0] == 0 && t.snd_una == t.snd_max,
        "stats {st:?}"
    );
}

/// Eifel で窓を戻すことの試験です (Go の TestEifelUndoRestoresTheWindow)。
#[test]
fn eifel_undo_restores_the_window() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    let before = spurious_recovery(&mut n, c, &mut q, &outs);
    n.advance(MS);
    q.recv(&outs[1]); // 元の segment が届き、TSecr はその TSval になる
    q.ack(&mut n);
    let t = *n.s.conn(c.slot).t;
    let st = n.s.stats();
    assert!(
        !t.in_recovery && t.cwnd >= before && st.spurious_undos == 1 && t.reorder_seen,
        "after the original arrived: recovery {} cwnd {} (was {before}) stats {st:?}",
        t.in_recovery,
        t.cwnd
    );
}

/// D-SACK で窓を戻すことの試験です (Go の TestDSACKUndoRestoresTheWindow)。
#[test]
fn dsack_undo_restores_the_window() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    spurious_recovery(&mut n, c, &mut q, &outs);
    n.s.conn(c.slot).k.retrans_ts_ok = false; // timestamp による判定を使わない
    q.deliver(&mut n, &outs[1..2]); // 元の segment が累積の確認を進める
    assert!(!n.s.conn(c.slot).t.in_recovery, "still in recovery");
    assert_eq!(n.s.stats().spurious_undos, 0, "undid without evidence");
    // 回復の終わりの前の D-SACK を確かめる
    let (mut n2, c2, mut q2, outs2) = rack_conn(10);
    let before = spurious_recovery(&mut n2, c2, &mut q2, &outs2);
    n2.s.conn(c2.slot).k.retrans_ts_ok = false;
    let mut s = q2.p.seg(FLAG_ACK, &[]); // 再送が届いた重複への D-SACK (2 つ目の block の内側)
    let (b1, b9) = (blk(&outs2[1]), blk(&outs2[9]));
    s.sack = vec![
        b1,
        SackBlock {
            left: b1.left,
            right: b9.right,
        },
    ];
    n2.inject(&s);
    q2.deliver(&mut n2, &outs2[1..2]);
    let t = *n2.s.conn(c2.slot).t;
    let st = n2.s.stats();
    assert!(
        !t.in_recovery && t.cwnd >= before && st.spurious_undos == 1,
        "D-SACK undo: recovery {} cwnd {} (was {before}) stats {st:?}",
        t.in_recovery,
        t.cwnd
    );
}

/// 不要な RTO を F-RTO が取り消すことの試験です (Go の TestFRTOUndoesASpuriousRTO)。
#[test]
fn frto_undoes_a_spurious_rto() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    let (before, ss_before) = {
        let t = n.s.conn(c.slot).t;
        (t.cwnd, t.ssthresh)
    };
    for _ in 0..1000 {
        if n.s.stats().rtos != 0 {
            break;
        }
        n.advance(5 * MS);
    }
    let cs = n.s.conn(c.slot);
    let mss = cs.seg_mss();
    assert!(
        cs.t.frto != 0 && cs.t.cwnd == mss,
        "F-RTO {} cwnd {} after the RTO",
        cs.t.frto,
        cs.t.cwnd
    );
    let resent = n.drain();
    assert!(
        resent.len() == 1 && resent[0].seq == outs[0].seq,
        "after the RTO sent {}, want only the head",
        crate::testnet_tests::show(&resent)
    );
    // 元の segment がすべて遅れて届く
    q.deliver(&mut n, &outs);
    let st = n.s.stats();
    let t = *n.s.conn(c.slot).t;
    assert!(
        st.spurious_rtos == 1 && t.cwnd >= before && t.ssthresh >= ss_before && t.frto == 0,
        "after the originals: cwnd {} (was {before}) ssthresh {} stats {st:?}",
        t.cwnd,
        t.ssthresh
    );
    assert_eq!(st.retrans[2], 1, "resent segments for a spurious RTO");
}

/// 本当の損失なら F-RTO が通常の RTO の回復に戻ることの試験です (Go の TestFRTOFallsBackOnRealLoss)。
#[test]
fn frto_falls_back_on_real_loss() {
    let (mut n, c, mut q, _outs) = rack_conn(10);
    write_zeros(&mut n, c, 10 * TEST_SEG_PAYLOAD); // 送り残しの後に新しいデータがある
    for _ in 0..1000 {
        if n.s.stats().rtos != 0 {
            break;
        }
        n.advance(5 * MS);
    }
    let resent = n.drain();
    q.deliver(&mut n, &resent); // 先頭の再送だけが届く:SND.UNA が進む
    let fresh = n.drain();
    assert!(n.s.conn(c.slot).t.frto != 0, "F-RTO left before step 2");
    // 新しいデータが届き、その SACK は 1 から 9 が失われたままであることを示す
    q.deliver(&mut n, &fresh);
    n.drain();
    let st = n.s.stats();
    let t = *n.s.conn(c.slot).t;
    assert!(
        st.spurious_rtos == 0 && t.frto == 0 && st.retrans[2] >= 2,
        "real loss after F-RTO: frto {} stats {st:?} (fresh {})",
        t.frto,
        fresh.len()
    );
}

/// 再送していない確認済みのデータの D-SACK では窓を戻さないことの試験です (Go の TestForgedDSACKDoesNotUndoARealLoss)。
#[test]
fn forged_dsack_does_not_undo_a_real_loss() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    assert!(n.s.conn(c.slot).t.in_recovery, "not in recovery");
    let resent = n.drain();
    n.advance(TEST_RTT);
    // 再送が届く前の重複した ACK に、確認済みの segment 0 の D-SACK を偽って載せ、続けて再送を届ける
    // (元の segment は失われた)
    let mut s = q.p.seg(FLAG_ACK, &[]);
    s.sack = vec![blk(&outs[0])];
    s.sack.extend(q.blocks(2));
    n.inject(&s);
    n.drain();
    q.recv(&resent[0]);
    q.ack(&mut n);
    let t = *n.s.conn(c.slot).t;
    assert!(
        !t.in_recovery && n.s.stats().spurious_undos == 0,
        "a D-SACK for data that was never retransmitted undid the reduction of a real loss: cwnd {}",
        t.cwnd
    );
}

/// SND.UNA より先の再送していない記録の D-SACK では窓を戻さないことの試験です (Go の TestForgedDSACKAboveTheAckDoesNotUndo)。
#[test]
fn forged_dsack_above_the_ack_does_not_undo() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let resent = n.drain();
    n.advance(TEST_RTT);
    n.s.conn(c.slot).k.retrans_ts_ok = false; // timestamp による判定を使わない
    // SACK 済みで再送していない segment 5 の D-SACK (2 つ目の block の内側) を偽って載せる
    let mut s = q.p.seg(FLAG_ACK, &[]);
    s.sack = vec![blk(&outs[5])];
    s.sack.extend(q.blocks(2));
    n.inject(&s);
    n.drain();
    q.recv(&resent[0]);
    q.ack(&mut n);
    let t = *n.s.conn(c.slot).t;
    assert!(
        !t.in_recovery && n.s.stats().spurious_undos == 0,
        "a D-SACK for a record that was never retransmitted undid a real loss: cwnd {}",
        t.cwnd
    );
}

/// 前の回復への遅れた D-SACK で次の回復を取り消さないことの試験です (Go の TestStaleDSACKDoesNotUndoALaterRecovery)。
#[test]
fn stale_dsack_does_not_undo_a_later_recovery() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    write_zeros(&mut n, c, 10 * TEST_SEG_PAYLOAD);
    // 1 回目の回復:segment 1 が遅れ、再送は不要だった。遅れた D-SACK のために再送の範囲を覚えておく
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let resent = n.drain();
    let stale = blk(&outs[1]);
    q.deliver(&mut n, &outs[1..2]);
    q.deliver_with(&mut n, &resent, |_, o| o.seq == stale.left); // 再送は届かない (重複の知らせも無い)
    assert!(
        !n.s.conn(c.slot).t.in_recovery,
        "first recovery did not end"
    );
    let undos = n.s.stats().spurious_undos;
    // 2 回目の回復:本当の損失
    n.advance(TEST_RTT);
    let outs2 = n.drain();
    assert!(outs2.len() >= 4, "only {} new segments", outs2.len());
    q.deliver_with(&mut n, &outs2, |i, _| i == 0);
    assert!(n.s.conn(c.slot).t.in_recovery, "not in the second recovery");
    let resent2 = n.drain();
    n.s.conn(c.slot).k.retrans_ts_ok = false; // timestamp による判定を使わない
    // 1 回目の回復の再送への遅れた D-SACK が届き、続けて 2 回目の回復の再送が届く
    let mut s = q.p.seg(FLAG_ACK, &[]);
    s.sack = vec![stale];
    s.sack.extend(q.blocks(2));
    n.inject(&s);
    n.drain();
    q.deliver(&mut n, &resent2[..1]);
    let now_undos = n.s.stats().spurious_undos;
    let rec = n.s.conn(c.slot).t.in_recovery;
    assert!(
        !rec && now_undos == undos,
        "a stale D-SACK from an earlier recovery undid a real loss: recovery {rec} undos {now_undos} (was {undos})"
    );
}

/// TLP の probe の D-SACK を再送に数えないことの試験です (Go の TestTLPProbeDSACKIsNotCounted)。
#[test]
fn tlp_probe_dsack_is_not_counted() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    n.s.conn(c.slot).t.reorder_seen = true;
    // 最後の 2 つの segment の確認が遅れ、TLP が最後の segment を再送する
    q.deliver(&mut n, &outs[..8]);
    assert!(n.s.conn(c.slot).t.tlp_at != 0, "no PTO armed");
    let mut probe = Vec::new();
    for _ in 0..1000 {
        if !probe.is_empty() {
            break;
        }
        n.advance(MS);
        probe = n.drain();
    }
    assert!(
        n.s.stats().tlp_probes == 1 && probe.len() == 1 && probe[0].seq == outs[9].seq,
        "probe {}, stats {:?}",
        crate::testnet_tests::show(&probe),
        n.s.stats()
    );
    {
        // probe より前に取り消しの印を付け、印の後の再送が 1 つあるとする
        let mut cs = n.s.conn(c.slot);
        cs.init_undo();
        cs.k.undo_retrans = 1;
    }
    q.deliver(&mut n, &outs[8..]); // 元の segment が届く
    let mult = n.s.conn(c.slot).t.reo_wnd_mult;
    let mut s = q.p.seg(FLAG_ACK, &[]);
    s.sack = vec![blk(&outs[9])];
    n.inject(&s); // probe への D-SACK
    assert!(
        n.s.conn(c.slot).t.reo_wnd_mult == mult && n.s.stats().dsacks_in == 0,
        "a TLP probe's D-SACK widened the reorder window: mult {} (was {mult})",
        n.s.conn(c.slot).t.reo_wnd_mult
    );
    let k = *n.s.conn(c.slot).k;
    assert_eq!(
        k.undo_retrans, 1,
        "a TLP probe's D-SACK was counted as a spurious retransmission"
    );
    assert!(k.dsack_dups != 0, "the probe's D-SACK was not seen");
}

/// 1 つの ACK が RTO の時の SND.MAX を越えたら F-RTO を終えることの試験です (Go の TestFRTOEndsWhenOneAckPassesRecover)。
#[test]
fn frto_ends_when_one_ack_passes_recover() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    for o in &outs[1..] {
        q.recv(o); // 相手は 1 から 9 を受けたが、その ACK は失われた
    }
    for _ in 0..1000 {
        if n.s.stats().rtos != 0 {
            break;
        }
        n.advance(5 * MS);
    }
    assert_eq!(n.s.conn(c.slot).t.frto, 1, "F-RTO state after the RTO");
    let resent = n.drain();
    q.deliver(&mut n, &resent); // 先頭の再送が届き、1 つの ACK がすべてを確認する
    let cs = n.s.conn(c.slot);
    assert!(
        cs.t.snd_una == cs.t.snd_max && cs.t.frto == 0 && !cs.t.rto_episode && !cs.k.undo_marker,
        "after one ACK past recover: una {} max {} frto {} episode {} marker {}",
        cs.t.snd_una.wrapping_sub(cs.t.iss),
        cs.t.snd_max.wrapping_sub(cs.t.iss),
        cs.t.frto,
        cs.t.rto_episode,
        cs.k.undo_marker
    );
    let cs = n.s.conn(c.slot);
    let (cwnd, mss) = (cs.t.cwnd, cs.seg_mss());
    let st = n.s.stats();
    assert!(
        st.spurious_rtos == 0 && st.spurious_undos == 0 && cwnd <= 4 * mss,
        "a real loss was undone: cwnd {cwnd} stats {st:?}"
    );
}

/// 片付いた probe の後の同じ範囲の D-SACK を probe のものとみなさないことの試験です (Go の TestTLPProbeEndIsForgottenOnceResolved)。
#[test]
fn tlp_probe_end_is_forgotten_once_resolved() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver(&mut n, &outs[..8]);
    let mut probe = Vec::new();
    for _ in 0..1000 {
        if !probe.is_empty() {
            break;
        }
        n.advance(MS);
        probe = n.drain();
    }
    assert!(
        probe.len() == 1 && probe[0].seq == outs[9].seq,
        "probe {}",
        crate::testnet_tests::show(&probe)
    );
    q.deliver(&mut n, &outs[8..]);
    let b = blk(&outs[9]);
    let dsack = |n: &mut TestNet, q: &mut SackPeer| {
        let mut s: TSeg = q.p.seg(FLAG_ACK, &[]);
        s.sack = vec![b];
        n.inject(&s);
    };
    dsack(&mut n, &mut q); // probe への D-SACK:probe が片付く
    let t = *n.s.conn(c.slot).t;
    assert!(
        !t.tlp_active && !t.tlp_retrans && n.s.stats().dsacks_in == 0,
        "after the probe's D-SACK: active {} retrans {} stats {:?}",
        t.tlp_active,
        t.tlp_retrans,
        n.s.stats()
    );
    n.s.conn(c.slot).k.total_retrans = 10; // 後の再送を送ったことにする
    dsack(&mut n, &mut q); // 同じ範囲で終わる後の D-SACK は probe のものではない
    assert_eq!(
        n.s.stats().dsacks_in,
        1,
        "a later D-SACK ending at an old probe's end was taken for the probe's"
    );
}

/// 相手の窓の最大より広い D-SACK の block を使わないことの試験です (Go の TestDSACKWiderThanTheWindowIsIgnored)。
#[test]
fn dsack_wider_than_the_window_is_ignored() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver(&mut n, &outs[..2]);
    let b = {
        let cs = n.s.conn(c.slot);
        cs.k.total_retrans = 1 << 20; // 再送の累計の上限には掛からない
        SackBlock {
            left: cs.t.snd_una.wrapping_sub(cs.t.max_snd_wnd),
            right: cs.t.snd_una.wrapping_add(TEST_SEG_PAYLOAD as u32),
        }
    };
    let mut s = q.p.seg(FLAG_ACK, &[]);
    s.sack = vec![b, b]; // 2 つ目の block の内側なので D-SACK
    n.inject(&s);
    let dups = n.s.conn(c.slot).k.dsack_dups;
    assert!(
        n.s.stats().dsacks_in == 0 && dups == 0,
        "a D-SACK wider than the peer's largest window was used: dups {dups} stats {:?}",
        n.s.stats()
    );
}

/// 再送を送る前に回復が終わっても数による取り消しをしないことの試験です (Go の TestNoUndoBeforeARetransmission)。
#[test]
fn no_undo_before_a_retransmission() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver_with(&mut n, &outs, |i, _| i == 1);
    let (rec, cnt) = {
        let cs = n.s.conn(c.slot);
        (cs.t.in_recovery, cs.k.undo_retrans)
    };
    assert!(rec && cnt == -1, "recovery {rec}, count {cnt}");
    q.deliver(&mut n, &outs[1..2]); // 再送を作る前に元の segment が届き、回復が終わる
    let st = n.s.stats();
    assert!(
        !n.s.conn(c.slot).t.in_recovery && st.retrans[0] == 0 && st.spurious_undos == 0,
        "stats {st:?}"
    );
}

/// 同じ ACK が確認するデータの D-SACK を数えないことの試験です (Go の TestDSACKOfDataThisAckAcknowledgesIsNotCounted)。
#[test]
fn dsack_of_data_this_ack_acknowledges_is_not_counted() {
    let (mut n, c, mut q, outs) = rack_conn(10);
    q.deliver_with(&mut n, &outs, |i, _| i == 1 || i == 3);
    let resent = n.drain();
    let cnt = n.s.conn(c.slot).k.undo_retrans;
    assert!(
        resent.len() >= 2 && cnt == 2,
        "resent {}, count {cnt}",
        resent.len()
    );
    q.recv(&resent[0]); // 再送が最初の穴を埋める。その ACK に、埋めた segment の D-SACK を偽って載せる
    let mut s = q.p.seg(FLAG_ACK, &[]);
    s.sack = vec![blk(&outs[1])];
    s.sack.extend(q.blocks(2));
    n.inject(&s);
    let cs = n.s.conn(c.slot);
    assert!(
        cs.t.snd_una == outs[3].seq && cs.t.in_recovery,
        "una {}, recovery {}",
        cs.t.snd_una.wrapping_sub(cs.t.iss),
        cs.t.in_recovery
    );
    assert_eq!(
        cs.k.undo_retrans, 2,
        "a D-SACK of data the same ACK acknowledges was counted"
    );
}
