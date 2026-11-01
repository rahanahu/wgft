//! SACK の scoreboard と回復と PRR、D-SACK、窓の使用の判定 (Go の `sack_test.go`、`scoreboard_test.go`、`prr_test.go`、`lostq_audit_test.go`、`dsack_test.go`、`cwndval_test.go`、`lazyegress_test.go`、`tlp_rto_test.go`) の白箱の試験。
#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect segments"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::naive_bytecount,
    clippy::many_single_char_names,
    reason = "tests follow the Go names and small sizes"
)]

use crate::buf::{BOOST_RECORDS, BOOST_SIZE, MIN_SEG_PAYLOAD};
use crate::sackpeer_tests::{SackPeer, check_scoreboard};
use crate::seq;
use crate::stack::ns;
use crate::tcp::RTO_MIN;
use crate::tcp::TS_OPTION_LEN;
use crate::tcp::conn::{State, TMR_RETRANS};
use crate::tcp::sack::steps;
use crate::testnet_tests::{DUT, Out, TEST_MTU, TestNet, parse_out, small_limits};
use crate::wire::{FLAG_ACK, SackBlock};
use crate::{BoostPolicy, Config, Congestion, ConnId};
use core::time::Duration;
use std::collections::HashMap;

/// timestamp を付けた segment の中身です。
pub(crate) const TEST_SEG_PAYLOAD: usize = TEST_MTU - 40 - 12;

/// SACK と timestamp を交渉した接続を開き、DUT に `segs` 個の segment を送らせて返します (Go の `sackConn`)。
pub(crate) fn sack_conn(segs: usize) -> (TestNet, crate::ConnId, SackPeer, Vec<Out>) {
    let mut n = TestNet::new(small_limits());
    let (c, p) = n.accepted_sack(true, true);
    let data = vec![0u8; segs * TEST_SEG_PAYLOAD];
    let mut off = 0;
    while off < data.len() {
        off += n.s.write(n.now, c, &data[off..]).unwrap();
    }
    let outs = n.drain();
    (n, c, SackPeer::new(p), outs)
}

/// segment の開始の番号の集合です (Go の `seqSet`)。
pub(crate) fn seq_set(outs: &[Out]) -> HashMap<u32, usize> {
    let mut m = HashMap::new();
    for o in outs.iter().filter(|o| !o.payload.is_empty()) {
        *m.entry(o.seq).or_insert(0) += 1;
    }
    m
}

#[test]
fn sack_recovery_repairs_several_holes_without_rto() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    assert_eq!(outs.len(), 10, "IW10");
    let lost = [outs[1].seq, outs[4].seq, outs[7].seq];
    q.deliver_with(&mut n, &outs, |_, o| lost.contains(&o.seq));
    let i = c.slot;
    check_scoreboard(&mut n.s.conn(i));
    assert!(
        n.s.conn(i).t.in_recovery,
        "not in recovery after three holes"
    );
    let mut resent = Vec::new();
    for _ in 0..20 {
        let got = n.drain();
        let mut cs = n.s.conn(i);
        check_scoreboard(&mut cs);
        let pipe = cs.pipe();
        assert!(
            !(cs.t.in_recovery && pipe > cs.t.cwnd && !got.is_empty()),
            "pipe {pipe} above cwnd {} after sending",
            cs.t.cwnd
        );
        if got.is_empty() {
            break;
        }
        resent.extend(got.iter().cloned());
        q.deliver(&mut n, &got);
    }
    let set = seq_set(&resent);
    for s in set.keys() {
        assert!(
            lost.contains(s),
            "resent {}, which the peer SACKed",
            s - outs[0].seq
        );
    }
    for s in lost {
        assert_eq!(set.get(&s), Some(&1), "hole {} resent", s - outs[0].seq);
    }
    let st = n.s.stats();
    let cs = n.s.conn(i);
    assert!(
        st.rtos == 0
            && st.fast_recoveries == 1
            && st.retrans[0] == 3
            && !cs.t.in_recovery
            && cs.t.snd_una == cs.t.snd_max,
        "{st:?}"
    );
    assert_eq!(cs.t.cwnd, cs.t.ssthresh, "cwnd after recovery");
}

/// RTT の推定に使う値です (Go の `testRTT`)。
const TEST_RTT: Duration = Duration::from_millis(20);

/// 書ける分だけ書いて、書いた byte 数を返します。いっぱいなら 0 です。
fn write_some(n: &mut TestNet, c: ConnId, data: &[u8]) -> usize {
    n.s.write(n.now, c, data).unwrap_or(0)
}

/// `sack_conn` と同じで、RTT の推定を直接与えて 1 RTT 進めた接続です (Go の `rackConnApp`)。手で進める時計の
/// 握手は RTT が 0 なので、RTT の推定を直接与えます。
fn rack_conn_app(segs: usize) -> (TestNet, ConnId, SackPeer, Vec<Out>) {
    let mut n = TestNet::new(small_limits());
    let (c, p) = n.accepted_sack(true, true);
    set_rtt(&mut n, c, TEST_RTT);
    n.s.conn(c.slot).t.rto = RTO_MIN;
    let data = vec![0u8; segs * TEST_SEG_PAYLOAD];
    assert_eq!(n.s.write(n.now, c, &data), Ok(data.len()));
    let outs = n.drain();
    n.advance(TEST_RTT);
    (n, c, SackPeer::new(p), outs)
}

fn set_rtt(n: &mut TestNet, c: ConnId, rtt: Duration) {
    let r = i64::try_from(rtt.as_nanos()).unwrap();
    let t = &mut *n.s.conn(c.slot).t;
    (t.srtt, t.min_rtt, t.has_rtt, t.has_min_rtt) = (r, r, true, true);
    t.rttvar = if rtt == TEST_RTT {
        r / 2
    } else {
        i64::try_from(Duration::from_millis(5).as_nanos()).unwrap()
    };
}

fn stats_rtos(n: &mut TestNet) -> u64 {
    n.s.stats().rtos
}

/// RTO の後も SACK 済みの範囲を保ち、送り直さないことを確かめます (Go の `TestRTOKeepsSACKedRangesAndSkipsThem`)。
#[test]
fn rto_keeps_sacked_ranges_and_skips_them() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    let i = c.slot;
    // 1 と 2 を失い、残りを SACK で知らせます。回復の再送も失います。
    q.deliver_with(&mut n, &outs, |k, _| k == 1 || k == 2);
    n.drain();
    loop {
        n.advance(Duration::from_millis(10));
        if stats_rtos(&mut n) > 0 {
            break;
        }
        n.drain();
    }
    check_scoreboard(&mut n.s.conn(i));
    assert_eq!(
        n.s.conn(i).t.sacked,
        7 * TEST_SEG_PAYLOAD as u32,
        "SACKed bytes after the RTO"
    );
    let mut resent = Vec::new();
    for _ in 0..20 {
        let got = n.drain();
        if got.is_empty() {
            break;
        }
        resent.extend(got.iter().cloned());
        q.deliver(&mut n, &got);
        check_scoreboard(&mut n.s.conn(i));
    }
    for s in seq_set(&resent).keys() {
        assert!(
            *s == outs[1].seq || *s == outs[2].seq,
            "resent {} after the RTO, which the peer SACKed",
            (s - outs[0].seq) / TEST_SEG_PAYLOAD as u32
        );
    }
    let t = n.s.conn(i).t.snd_una;
    assert_eq!(t, n.s.conn(i).t.snd_max, "not everything acknowledged");
}

/// SACK 済みを相手が捨てたとき、RTO の経路で印を消すことを確かめます (Go の
/// `TestSACKRenegingClearsMarksOnTheRTOPath`)。
#[test]
fn sack_reneging_clears_marks_on_the_rto_path() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    let i = c.slot;
    // 3 から 9 を SACK で知らせた後、相手が 0 から 2 だけを累積で確認し、SACK した 3 から先を捨てます。
    q.deliver_with(&mut n, &outs, |k, _| k < 3);
    n.drain();
    q.ivs.clear();
    q.p.rcv = outs[3].seq;
    q.ack(&mut n);
    let now = ns(n.now);
    // 取り消しの疑いの期限の下限は 10 ms です (Go の `renegeDelayMin`)。
    let want = now + (n.s.conn(i).t.srtt / 2).max(10_000_000);
    assert_eq!(
        n.s.conn(i).t.tdl[TMR_RETRANS] - now,
        want - now,
        "retransmit timer offset"
    );
    n.drain();
    n.advance(Duration::from_nanos(u64::try_from(want - now).unwrap()));
    let st = n.s.stats();
    let sacked = n.s.conn(i).t.sacked;
    assert!(
        st.sack_reneging == 1 && st.rtos == 1 && sacked == 0,
        "{st:?} sacked {sacked}"
    );
    check_scoreboard(&mut n.s.conn(i));
    let mut got = n.drain();
    assert!(
        got.len() == 1 && got[0].seq == outs[3].seq,
        "after reneging sent {} segments, want the first reneged one",
        got.len()
    );
    for _ in 0..50 {
        q.deliver(&mut n, &got);
        got = n.drain();
        if got.is_empty() {
            break;
        }
    }
    let t = &n.s.conn(i).t;
    assert_eq!(
        t.snd_una, t.snd_max,
        "did not resend the reneged data up to the cumulative ACK"
    );
}

/// 期限の前に相手が SACK 済みの記録を累積で確認すれば、取り消しの扱いにしないことを確かめます (Go の
/// `TestSACKRenegeSuspicionClearedByTheNextACK`)。
#[test]
fn sack_renege_suspicion_cleared_by_the_next_ack() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    q.deliver_with(&mut n, &outs, |k, _| k < 3);
    n.drain();
    q.p.rcv = outs[3].seq;
    q.ack(&mut n); // 0 から 2 を確認し、3 から 9 は SACK のまま
    q.p.rcv = outs[9].seq + TEST_SEG_PAYLOAD as u32;
    q.ivs.clear();
    q.ack(&mut n);
    n.advance(Duration::from_secs(1));
    let st = n.s.stats();
    let t = &n.s.conn(c.slot).t;
    assert!(
        st.sack_reneging == 0 && st.rtos == 0 && t.snd_una == t.snd_max,
        "{st:?}"
    );
}

/// 同じ SND.UNA での 2 度目の RTO が SACK の印を消すことを確かめます (Go の `TestSecondRTOAtTheSameUnaClearsSACK`)。
#[test]
fn second_rto_at_the_same_una_clears_sack() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    let i = c.slot;
    q.deliver_with(&mut n, &outs, |k, _| k == 0);
    n.drain();
    while stats_rtos(&mut n) < 1 {
        n.advance(Duration::from_millis(10));
        n.drain();
    }
    assert!(
        n.s.conn(i).t.sacked != 0 && n.s.stats().sack_reneging == 0,
        "the first RTO cleared the SACK marks"
    );
    while stats_rtos(&mut n) < 2 {
        n.advance(Duration::from_millis(10));
        n.drain();
    }
    let sacked = n.s.conn(i).t.sacked;
    assert!(
        sacked == 0 && n.s.stats().sack_reneging == 1,
        "the second RTO at the same SND.UNA kept {sacked} SACKed bytes"
    );
    check_scoreboard(&mut n.s.conn(i));
}

/// 重複した ACK 1 つずつに新しい segment を 1 つ送ることを確かめます (Go の `TestLimitedTransmit`)。
#[test]
fn limited_transmit() {
    for sack in [false, true] {
        let mut n = TestNet::new(small_limits());
        let l = n.listen(80);
        let p = n.handshake_sack(40000, 80, true, sack, true);
        let c = n.accept(l);
        n.drain();
        n.s.write(n.now, c, &vec![0; 20 * TEST_SEG_PAYLOAD])
            .unwrap();
        let mut outs = n.drain();
        // RTT を 20 ms にします。手で進める時計の握手は RTT が 0 で、RACK の並べ替えの窓が 0 になります。
        n.advance(Duration::from_millis(20));
        set_rtt(&mut n, c, TEST_RTT);
        let mut q = SackPeer::new(p);
        // 1 つ目を確認します。slow start でさらに 2 つ送ります。
        q.recv(&outs[0]);
        q.ack(&mut n);
        outs.extend(n.drain());
        // 2 つ目を失い、3 つ目と 4 つ目への重複した ACK で 1 つずつ新しい segment を送ります。
        for k in 2..=3 {
            q.recv(&outs[k]);
            q.ack(&mut n);
            let got = n.drain();
            assert!(
                got.len() == 1 && got[0].seq == outs[outs.len() - 1].seq + TEST_SEG_PAYLOAD as u32,
                "sack {sack}: duplicate ACK {} sent {} segments, want one new segment",
                k - 1,
                got.len()
            );
            outs.extend(got);
        }
        assert!(
            !n.s.conn(c.slot).t.in_recovery && n.s.stats().retrans[0] == 0,
            "sack {sack}: recovery before the third duplicate ACK"
        );
    }
}

/// 多くの損失のある窓の回復の間、送った後の pipe が輻輳の窓を超えず、PRR が送る量を抑えることを確かめます
/// (Go の `TestRecoveryStaysWithinCwnd`)。
#[test]
fn recovery_stays_within_cwnd() {
    let mut n = TestNet::new(small_limits());
    let (c, p) = n.accepted_sack(true, true);
    let i = c.slot;
    let seg = TEST_SEG_PAYLOAD as u64;
    n.s.write(n.now, c, &vec![0; 150 * TEST_SEG_PAYLOAD])
        .unwrap();
    let mut q = SackPeer::new(p);
    let mut outs = n.drain();
    // slow start で窓を広げます。
    for _ in 0..3 {
        let mut next = Vec::new();
        for o in &outs {
            q.recv(o);
            q.ack(&mut n);
            next.extend(n.drain());
        }
        outs = next;
    }
    // 1 つおきに失います。
    let mut max_out = 0u32;
    for (k, o) in outs.iter().enumerate() {
        if k % 2 == 1 {
            continue;
        }
        q.recv(o);
        q.ack(&mut n);
        let got = n.drain();
        let mut cs = n.s.conn(i);
        check_scoreboard(&mut cs);
        if cs.t.in_recovery {
            let pipe = cs.pipe();
            assert!(
                got.is_empty() || u64::from(pipe) <= u64::from(cs.t.cwnd) + seg,
                "pipe {pipe} above cwnd {}",
                cs.t.cwnd
            );
            let fs = u64::from(cs.k.recover_fs.max(1));
            let lim = (u64::from(cs.k.prr_delivered) * u64::from(cs.t.ssthresh)).div_ceil(fs) + seg;
            assert!(
                !(pipe > cs.t.ssthresh && u64::from(cs.k.prr_out) > lim),
                "PRR sent {} with {} delivered, limit {lim}",
                cs.k.prr_out,
                cs.k.prr_delivered
            );
            max_out = max_out.max(cs.k.prr_out);
        }
    }
    assert!(max_out != 0, "no sending during recovery");
    assert_eq!(n.s.stats().rtos, 0, "RTO during recovery");
}

/// 欠けた segment の再送だけを届けても、PRR の届いた量が受け手に届いた量を超えないことを確かめます
/// (Go の `TestPRRDeliveredDataCountsSACKedBytesOnce`)。
#[test]
fn prr_delivered_data_counts_sacked_bytes_once() {
    let (mut n, c, mut q, outs) = sack_conn(10);
    let i = c.slot;
    // 2 つの穴: segment 0 と 5。ほかは届いて SACK されます。
    q.deliver_with(&mut n, &outs, |k, _| k == 0 || k == 5);
    assert!(n.s.conn(i).t.in_recovery, "not in recovery");
    // 最初の穴の再送だけを届けます (部分の確認が SACK 済みの 1-4 を累積で覆います)。
    let got = n.drain();
    assert!(
        !got.is_empty() && got[0].seq == outs[0].seq,
        "first resend is not the head"
    );
    q.recv(&got[0]);
    q.ack(&mut n);
    assert!(n.s.conn(i).t.in_recovery, "recovery ended at a partial ACK");
    // 回復の間に受け手に届いたのは 9 segment (8 つの SACK 済みと再送した 0) です。
    let delivered = 9 * TEST_SEG_PAYLOAD as u32;
    let got = n.s.conn(i).k.prr_delivered;
    assert!(
        got <= delivered,
        "prr_delivered {got} counts SACKed bytes again when the cumulative ACK covers them; RFC 6937 DeliveredData gives {delivered}"
    );
}

/// 分けて送っている途中の損失の待ち行列の先頭が SACK で外れたとき、分けた位置を次の記録に持ち越さないことを
/// 確かめます (Go の `TestLostQueueSplitEndsWhenTheHeadIsSACKed`)。
#[test]
fn lost_queue_split_ends_when_the_head_is_sacked() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    // 別の接続のデータが、置き場に返る chunk を通ります。
    let mut pa = n.handshake_sack(41000, 80, true, true, true);
    let ca = n.accept(l);
    let secret = vec![0x5au8; 8000];
    n.s.write(n.now, ca, &secret).unwrap();
    for _ in 0..20 {
        let outs = n.drain();
        pa.absorb(&outs);
        n.peer_ack(&mut pa, &[]);
    }
    let ta = n.s.conn(ca.slot).t.una_off == n.s.conn(ca.slot).t.tail_off;
    assert!(ta, "A not acked");
    let p = n.handshake_sack(40000, 80, true, true, true);
    let c = n.accept(l);
    n.drain();
    let i = c.slot;
    {
        let t = &mut *n.s.conn(i).t;
        let rtt = i64::try_from(TEST_RTT.as_nanos()).unwrap();
        (t.srtt, t.rttvar, t.min_rtt, t.has_rtt, t.has_min_rtt) = (rtt, rtt / 2, rtt, true, true);
        t.rto = RTO_MIN;
    }
    let mut recs = Vec::new();
    for sz in [TEST_SEG_PAYLOAD, TEST_SEG_PAYLOAD, 100, TEST_SEG_PAYLOAD] {
        n.s.write(n.now, c, &vec![0; sz]).unwrap();
        let o = n.drain();
        assert_eq!(o.len(), 1, "write {sz} sent {} segments", o.len());
        recs.push(o[0].clone());
    }
    n.advance(TEST_RTT);
    let mut q = SackPeer::new(p);
    // 相手は R3 だけを受けて SACK します。
    q.recv(&recs[3]);
    q.ack(&mut n);
    n.drain();
    // DUT が順序外のデータを持つようにして、DUT の segment が SACK の block を載せるようにします。
    let mut s = q.p.seg(FLAG_ACK, &[0; 10]);
    s.seq += 50;
    n.inject(&s);
    n.advance(Duration::from_millis(10)); // 並べ替えの窓を過ぎ、R0..R2 が損失になります。
    n.s.conn(i).t.cwnd = 1 << 20;
    let mut buf = vec![0u8; 65536];
    for _ in 0..3 {
        let k = n.s.poll_transmit(n.now, &mut buf).expect("a packet");
        parse_out(&buf[..k]);
    }
    // R1 の元の segment が遅れて届きます: R1 と R3 を SACK し、累積の確認は R0 のままです。
    q.recv(&recs[1]);
    q.ack(&mut n);
    let (q_mid, q_off) = {
        let t = &n.s.conn(i).t;
        (t.q_mid, t.q_off)
    };
    assert!(
        !q_mid && q_off == 0,
        "the split position {q_off} of the SACKed head was kept for the next record"
    );
    let max = n.s.conn(i).t.snd_max;
    for o in n.drain() {
        let e = o.seq.wrapping_add(o.payload.len() as u32);
        if seq::gt(e, max) {
            let leak = o.payload.iter().filter(|&&x| x == 0x5a).count();
            panic!(
                "segment ends {} bytes past SND.MAX; payload holds {leak} bytes of the other connection's data",
                e.wrapping_sub(max)
            );
        }
    }
    assert_eq!(
        n.s.stats().accounting_faults,
        0,
        "accounting faults: the check closed the connection instead of the fix"
    );
}

/// 重複の部分を先頭の block にした D-SACK を返し、次の ACK には載せないことを確かめます (Go の
/// `TestDSACKBlocksForDuplicateParts`)。
#[test]
fn dsack_blocks_for_duplicate_parts() {
    let mut n = TestNet::new(small_limits());
    let (_, mut p) = n.accepted_sack(true, true);
    let base = p.snd;
    n.peer_ack(&mut p, &[0; 1000]); // [0, 1000)
    n.drain();
    let blk = |l: u32, r: u32| SackBlock {
        left: base + l,
        right: base + r,
    };
    // 1. RCV.NXT より前の重複
    let mut s = p.seg(FLAG_ACK, &[0; 500]);
    s.seq = base + 200;
    n.inject(&s);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && !outs[0].sack.is_empty() && outs[0].sack[0] == blk(200, 700),
        "duplicate below RCV.NXT: {}",
        crate::testnet_tests::show(&outs)
    );
    // 2. 順序外の区間の内側の重複: 先頭は D-SACK、2 つ目はそれを含む区間
    let mut s = p.seg(FLAG_ACK, &[0; 1000]);
    s.seq = base + 3000; // [3000, 4000)
    n.inject(&s);
    let mut s = p.seg(FLAG_ACK, &[0; 300]);
    s.seq = base + 6000; // 別の区間 [6000, 6300)
    n.inject(&s);
    n.drain();
    let mut s = p.seg(FLAG_ACK, &[0; 200]);
    s.seq = base + 3200;
    n.inject(&s);
    let outs = n.drain();
    assert_eq!(outs.len(), 1, "dup in interval");
    let o = &outs[0].sack;
    assert!(
        o.len() >= 2 && o[0] == blk(3200, 3400) && o[1] == blk(3000, 4000),
        "want D-SACK [3200,3400) then [3000,4000), got {o:?}"
    );
    // 3. 前半が重複で後半が新しい segment (重複の部分を D-SACK で知らせます)
    let mut s = p.seg(FLAG_ACK, &[0; 600]);
    s.seq = base + 700; // [700,1300)、700-1000 は重複
    n.inject(&s);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && !outs[0].sack.is_empty() && outs[0].sack[0] == blk(700, 1000),
        "partial overlap: want D-SACK [700,1000)"
    );
    // 4. 次の ACK には D-SACK を載せない
    p.snd = base + 1300;
    n.peer_ack(&mut p, &[]);
    let mut s = p.seg(FLAG_ACK, &[0; 10]);
    s.seq = base + 6300;
    n.inject(&s);
    for x in n.drain() {
        for b in &x.sack {
            assert!(
                *b != blk(3200, 3400) && *b != blk(200, 700),
                "D-SACK repeated: {x}"
            );
        }
    }
}

/// 2 つ目の重複が接していれば D-SACK の block を広げ、quickack の数を上げるだけで下げないことを確かめます
/// (Go の `TestDSACKExtendsAndQuickackOnlyRises`)。`raise_quickack` は module の外から呼べないので、
/// 同じ道を通る `note_duplicate` で数が下がらないことを見ます。
#[test]
fn dsack_extends_and_quickack_only_rises() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted_sack(true, true);
    let mut cs = n.s.conn(c.slot);
    cs.t.pingpong = true;
    cs.t.quick_acks = 0;
    cs.note_duplicate(100, 50);
    cs.note_duplicate(150, 50);
    let blk = SackBlock {
        left: 100,
        right: 200,
    };
    assert_eq!(cs.t.dsack, blk, "D-SACK [100,200)");
    cs.note_duplicate(500, 10); // 接しない重複は最初の block を保つ
    assert_eq!(cs.t.dsack, blk, "D-SACK after a separate duplicate");
    // quickack の数の上限は 16 です (Linux の TCP_MAX_QUICKACKS)。
    assert!(
        !cs.t.pingpong && cs.t.quick_acks == 16,
        "pingpong {} quick_acks {} after a duplicate",
        cs.t.pingpong,
        cs.t.quick_acks
    );
    cs.t.quick_acks = 16;
    cs.t.rcv_mss_est = 1 << 20; // 窓に対して大きな MSS: 窓から求める数は 2
    cs.note_duplicate(600, 10);
    assert_eq!(
        cs.t.quick_acks, 16,
        "raising lowered a running count to {}",
        cs.t.quick_acks
    );
}

/// RTT ごとに 2 segment ずつしか送らない stream で、輻輳の窓が使わないまま育たないことを確かめます
/// (Go の `TestCwndDoesNotGrowWhileAppLimited`)。
#[test]
fn cwnd_does_not_grow_while_app_limited() {
    for cc in [Congestion::Cubic, Congestion::NewReno] {
        let rtt = Duration::from_millis(50);
        let mut n = TestNet::with_config(
            Config {
                congestion: cc,
                limits: small_limits(),
                ..Config::new(DUT, TEST_MTU)
            },
            [7; 64],
        );
        let (c, p) = n.accepted_sack(true, true);
        {
            let cs = n.s.conn(c.slot);
            let mss = cs.seg_mss();
            let t = cs.t;
            t.srtt = i64::try_from(rtt.as_nanos()).unwrap();
            t.rttvar = 5_000_000;
            t.has_rtt = true;
            t.ssthresh = 10 * mss; // 輻輳の回避から始める
            t.cwnd = t.ssthresh;
        }
        let mut q = SackPeer::new(p);
        for _ in 0..1200 {
            // 60 秒
            write_some(&mut n, c, &vec![0; 2 * TEST_SEG_PAYLOAD]);
            let outs = n.drain();
            n.advance(rtt / 2);
            q.deliver(&mut n, &outs);
            n.drain();
            n.advance(rtt / 2);
        }
        let cs = n.s.conn(c.slot);
        assert!(
            cs.t.cwnd <= 4 * cs.t.ssthresh,
            "{cc:?}: cwnd grew to {} segments while only 2 were ever in flight",
            cs.t.cwnd / cs.seg_mss()
        );
    }
}

/// 窓に 1 segment の余地も無い間は窓が増えることを確かめます (Go の `TestCwndGrowsWhenTheWindowIsFull`)。
#[test]
fn cwnd_grows_when_the_window_is_full() {
    for cc in [Congestion::Cubic, Congestion::NewReno] {
        let rtt = Duration::from_millis(50);
        let mut n = TestNet::with_config(
            Config {
                congestion: cc,
                limits: small_limits(),
                ..Config::new(DUT, TEST_MTU)
            },
            [7; 64],
        );
        let (c, p) = n.accepted_sack(true, true);
        let (mss, start) = {
            let cs = n.s.conn(c.slot);
            let mss = cs.seg_mss();
            let t = cs.t;
            t.srtt = i64::try_from(rtt.as_nanos()).unwrap();
            t.rttvar = 5_000_000;
            t.has_rtt = true;
            t.ssthresh = 4 * mss;
            t.cwnd = 4 * mss + 100; // segment の倍数でない窓
            (mss, t.cwnd)
        };
        let mut q = SackPeer::new(p);
        let data = vec![0u8; 200 * mss as usize];
        let mut off = write_some(&mut n, c, &data);
        for _ in 0..40 {
            let outs = n.drain();
            n.advance(rtt / 2);
            q.deliver(&mut n, &outs);
            n.advance(rtt / 2);
            off += write_some(&mut n, c, &data[off..]);
        }
        let cwnd = n.s.conn(c.slot).t.cwnd;
        assert!(
            cwnd > start + mss,
            "{cc:?}: cwnd {cwnd} bytes after 40 RTTs of a full window, started at {start}"
        );
    }
}

/// まとめて届いた ACK で往復が終わったとき、次の往復の終わりが ACK が許した segment の後ろになることを
/// 確かめます (Go の `TestHyStartRoundEndsAfterWhatTheBurstLetsOut`)。
#[test]
fn hystart_round_ends_after_what_the_burst_lets_out() {
    let (mut n, c, mut q, mut outs) = rack_conn_app(10);
    let i = c.slot;
    n.s.write(n.now, c, &vec![0; 100 * TEST_SEG_PAYLOAD])
        .unwrap(); // 窓に制限される
    q.deliver(&mut n, &outs); // 最初の往復が始まる
    outs = n.drain();
    n.advance(TEST_RTT);
    q.deliver(&mut n, &outs); // 最初の往復が終わり、次の往復が始まる
    let cs = n.s.conn(i);
    assert!(
        cs.hystart_on() && cs.t.hs.started && !seq::lt(cs.t.snd_una, cs.t.snd_max),
        "HyStart++ on {} started {}, flight {}",
        cs.hystart_on(),
        cs.t.hs.started,
        cs.t.snd_max.wrapping_sub(cs.t.snd_una)
    );
    let (end, mss) = (cs.t.hs.window_end, cs.seg_mss());
    let sent = n.drain();
    let t = &n.s.conn(i).t;
    let (una, nxt, iss) = (t.snd_una, t.snd_nxt, t.iss);
    assert!(
        sent.len() >= 2
            && seq::gt(end, una)
            && !seq::gt(end, nxt)
            && nxt.wrapping_sub(end) <= 8 * mss,
        "round ends at {} after ACKs to {} that let out data to {}",
        end.wrapping_sub(iss),
        una.wrapping_sub(iss),
        nxt.wrapping_sub(iss)
    );
}

/// 送り残しを空にした ACK の後の送りを、黙った後の送り始めとみなさないことを確かめます (Go の
/// `TestBurstThatDrainsTheFlightIsNotIdle`)。
#[test]
fn burst_that_drains_the_flight_is_not_idle() {
    let (mut n, c, mut q, outs) = rack_conn_app(10);
    let i = c.slot;
    {
        let t = &mut *n.s.conn(i).t;
        t.ssthresh = t.cwnd; // 輻輳の回避から始める
    }
    n.s.write(n.now, c, &vec![0; 200 * TEST_SEG_PAYLOAD])
        .unwrap();
    q.deliver(&mut n, &outs); // epoch はこの ACK の時刻から始まる
    let epoch = n.s.conn(i).t.cubic.epoch;
    assert!(
        epoch != 0,
        "no CUBIC epoch after the first ACKs in congestion avoidance"
    );
    let outs = n.drain();
    n.advance(TEST_RTT);
    q.deliver(&mut n, &outs);
    // 往復より短い RTO: 黙った後の規則が働けば窓を初めの窓に戻します。
    n.s.conn(i).t.rto = i64::try_from(TEST_RTT.as_nanos()).unwrap() / 2;
    let cwnd = n.s.conn(i).t.cwnd;
    n.drain();
    let cs = n.s.conn(i);
    assert_eq!(cs.t.cubic.epoch, epoch, "epoch moved after a burst");
    assert!(
        cs.t.cwnd >= cwnd,
        "cwnd fell from {cwnd} to {} after a burst",
        cs.t.cwnd
    );
}

/// probe の後に RTO を張り直さないと、probe の ACK が返る前に RTO が起きることを確かめます (Go の
/// `TestNoRTOBeforeTheProbeCanBeAcked`)。
#[test]
fn no_rto_before_the_probe_can_be_acked() {
    let rtt = Duration::from_millis(80);
    let mut n = TestNet::new(small_limits());
    let (c, p) = n.accepted_sack(true, true);
    let i = c.slot;
    set_rtt(&mut n, c, rtt);
    n.s.conn(i).t.rto = RTO_MIN;
    let mut q = SackPeer::new(p);
    n.s.write(n.now, c, &vec![0; 10 * TEST_SEG_PAYLOAD])
        .unwrap();
    let outs = n.drain();
    n.advance(rtt);
    q.deliver_with(&mut n, &outs, |k, _| k >= 8);
    assert!(n.s.conn(i).t.tlp_at != 0, "no PTO armed");
    let start = n.now;
    let mut probe = Vec::new();
    while probe.is_empty() && n.now - start < Duration::from_secs(1) {
        n.advance(Duration::from_millis(1));
        probe = n.drain();
    }
    let at = n.now - start;
    // probe は 1 RTT で届き、その SACK が返る前に RTO が起きるかを見ます。
    while n.now - start < at + rtt {
        n.advance(Duration::from_millis(1));
        n.drain();
    }
    let rto_at = n.s.conn(i).t.rto_at - ns(start);
    assert_eq!(
        n.s.stats().rtos,
        0,
        "RTO (deadline +{rto_at} ns) fired after the probe at +{at:?}, before its ACK could return one RTT later"
    );
}

/// SACK の無い接続で高速の再送を作る前に RTO が来ても、先頭の segment を 1 度だけ送り直すことを確かめます
/// (Go の `TestRTOWithAPendingFastRetransmitSendsTheHeadOnce`)。
#[test]
fn rto_with_a_pending_fast_retransmit_sends_the_head_once() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted_sack(true, false);
    let i = c.slot;
    n.s.write(n.now, c, &vec![0; 10 * TEST_SEG_PAYLOAD])
        .unwrap();
    let outs = n.drain();
    assert!(outs.len() >= 5, "sent {} segments", outs.len());
    let head = outs[0].seq;
    for _ in 0..3 {
        n.peer_ack(&mut p, &[]); // 先頭が失われた重複の ACK
    }
    assert!(
        n.s.conn(i).t.fast_rtx,
        "no fast retransmit pending after three duplicate ACKs"
    );
    let at = n.s.conn(i).t.rto_at;
    n.advance(
        Duration::from_nanos(u64::try_from(at - ns(n.now)).unwrap()) + Duration::from_millis(1),
    );
    let heads = n
        .drain()
        .iter()
        .filter(|o| o.seq == head && !o.payload.is_empty())
        .count();
    assert_eq!(heads, 1, "the head was sent {heads} times after the RTO");
}

/// 試験の乱数です (splitmix64)。
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// `0..n` の値です。
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

/// 境目より先の SACK 済みの記録の数と byte が、境目の記録を損失とみなす RFC 6675 の閾値に届いていないことを
/// 確かめます (Go の `checkLossFrontier`)。
fn check_loss_frontier(c: &mut crate::tcp::ctx::Conn<'_>) {
    let i = crate::tcp::sack::idx(c.t.loss_idx);
    let n = c.b.recs.len();
    if i >= n || c.t.reorder_seen {
        return; // 並べ替えを見た後は RACK だけが損失を決める
    }
    let (mut cnt, mut by) = (0i64, 0i64);
    for k in i + 1..n {
        if c.is_sacked(k) {
            cnt += 1;
            by += i64::from(c.b.recs.at(k).length);
        }
    }
    let thresh = crate::tcp::sack::DUP_THRESH;
    assert!(
        !(cnt >= thresh || by > (thresh - 1) * i64::from(c.seg_mss())),
        "loss frontier at record {i} of {n} stays behind {cnt} SACKed records of {by} bytes"
    );
}

/// 損失、並べ替え、SACK の取り消し、RTO を無作為に起こす相手に対して、scoreboard の欄が記録を数え直した値と
/// 一致し続け、境目が RFC 6675 の範囲より手前に留まらないことを確かめます (Go の
/// `TestScoreboardAgainstRecount`)。Go の PMTU の引き下げの手順は PR 6 の段で足すので、この試験の乱数の分岐からは
/// 外れています。
#[test]
fn scoreboard_against_recount() {
    for seed in 1..=40u64 {
        scoreboard_recount_seed(seed);
    }
}

fn scoreboard_recount_seed(seed: u64) {
    let mut rng = Rng(seed ^ 99 << 32);
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let p = n.handshake_sack(40000, 80, true, true, true);
    let c = n.accept(l);
    let i = c.slot;
    let mut q = SackPeer::new(p);
    let total = 300 * TEST_SEG_PAYLOAD;
    let mut written = 0;
    let mut net: Vec<Out> = Vec::new();
    let done = |n: &mut TestNet, written: usize| {
        let t = &n.s.conn(i).t;
        written >= total && t.snd_una == t.snd_max
    };
    let mut step = 0;
    while step < 20000 && !done(&mut n, written) {
        let r = rng.below(100);
        if r < 15 {
            if written < total {
                let k = (1 + rng.below(30000)).min(total - written);
                written += write_some(&mut n, c, &vec![0; k]);
            }
        } else if r < 40 {
            for o in n.drain() {
                if rng.below(100) >= 8 {
                    net.push(o);
                }
            }
        } else if r < 80 {
            if !net.is_empty() {
                let k = if rng.below(4) == 0 {
                    rng.below(net.len())
                } else {
                    0
                };
                let o = net.remove(k);
                q.recv(&o);
                if rng.below(100) >= 5 {
                    q.ack(&mut n);
                }
            }
        } else if r < 82 {
            // 相手が順序外のデータを捨てます (SACK の取り消し)。
            q.ivs.clear();
            q.ack(&mut n);
        } else if r < 83 {
            // Go ではここで PMTU を引き下げます。
        } else {
            n.advance(Duration::from_millis(1 + rng.below(60) as u64));
        }
        let mut cs = n.s.conn(i);
        assert!(
            cs.t.state != State::Free && cs.t.state != State::Closed,
            "seed {seed}: connection ended at step {step}"
        );
        check_scoreboard(&mut cs);
        check_loss_frontier(&mut cs);
        step += 1;
    }
    let t = &n.s.conn(i).t;
    assert!(
        written >= total && t.snd_una == t.snd_max,
        "seed {seed}: sent {written} of {total}, una {} max {}",
        t.snd_una,
        t.snd_max
    );
}

/// 洪水の試験の ACK の数です。Go は 20000 ですが、それでは試験が 18 秒かかるので減らします。上界は ACK の数に
/// 比例し、ACK 1 つの手間の上界も確かめるので、確かめる比は同じです。
const ACKS: usize = 5000;

/// boost を持ち、boost の記録の輪を満たすほど小さな segment で送った接続です (Go の `floodConn`)。
fn flood_conn() -> (TestNet, ConnId, SackPeer) {
    let mut n = TestNet::with_config(
        Config {
            boost: BoostPolicy::AtAccept,
            limits: small_limits(),
            ..Config::new(DUT, TEST_MTU)
        },
        [7; 64],
    );
    let l = n.listen(80);
    let p = n.handshake_sack(40000, 80, true, true, true);
    let c = n.accept(l);
    assert!(n.s.conn(c.slot).b.boost.is_some(), "not boosted");
    n.drain();
    {
        let t = &mut *n.s.conn(c.slot).t;
        t.peer_mss = u32::try_from(MIN_SEG_PAYLOAD).unwrap() + TS_OPTION_LEN; // segment の中身を最小にする
        t.cwnd = 1 << 30;
        t.snd_wnd = 1 << 30;
        t.max_snd_wnd = 1 << 30;
    }
    let data = vec![0u8; usize::try_from(BOOST_SIZE).unwrap()];
    let mut off = 0;
    for _ in 0..100 {
        off += write_some(&mut n, c, &data[off..]);
        n.drain();
    }
    assert_eq!(off, data.len(), "the boosted ring took all the data");
    for _ in 0..100 {
        if n.drain().is_empty() {
            break;
        }
    }
    assert_eq!(n.s.conn(c.slot).b.recs.len(), BOOST_RECORDS, "records");
    (n, c, SackPeer::new(p))
}

/// 記録 `k` の `[開始, 終わり)` です。
fn rec_range(n: &mut TestNet, c: ConnId, k: usize) -> (u32, u32) {
    let r = *n.s.conn(c.slot).b.recs.at(k);
    (r.seq, r.seq + u32::from(r.length))
}

/// 相手が選ぶ SACK の block の洪水で、ACK 1 つの scoreboard の手間が block の数 x log(記録の数) と印付けの均した
/// 手間の和に留まることを確かめます (Go の `TestPerACKCostUnderSACKFlood`)。手間は試験の build の `steps()` で数えます。
#[test]
fn per_ack_cost_under_sack_flood() {
    let acks: usize = ACKS;
    for pattern in 0..4 {
        let (mut n, c, mut q) = flood_conn();
        let mut rng = Rng(1 ^ 2 << 32);
        let nrec = n.s.conn(c.slot).b.recs.len();
        let log_n = u64::from(nrec.bit_width());
        let per_block = 3 * (log_n + 3);
        let mut worst_excess = 0u64;
        let start = steps();
        for k in 0..acks {
            let sack_max = n.s.conn(c.slot).t.snd_max;
            let mut bs = Vec::new();
            match pattern {
                0 => {
                    let (l, _) = rec_range(&mut n, c, 1);
                    bs = vec![
                        SackBlock {
                            left: l,
                            right: sack_max
                        };
                        3
                    ];
                }
                1 => {
                    for j in 0..3 {
                        let (l, r) = rec_range(&mut n, c, 1 + (2 * (3 * k + j)) % (nrec - 1));
                        bs.push(SackBlock { left: l, right: r });
                    }
                }
                2 => {
                    for _ in 0..3 {
                        let (l, r) = rec_range(&mut n, c, 1 + rng.below(nrec - 1));
                        bs.push(SackBlock {
                            left: l + 1,
                            right: r - 1,
                        });
                    }
                }
                _ => {
                    for _ in 0..3 {
                        let (a, b) = (1 + rng.below(nrec - 1), 1 + rng.below(nrec - 1));
                        let (a, b) = (a.min(b), a.max(b));
                        let (l, _) = rec_range(&mut n, c, a);
                        let (_, r) = rec_range(&mut n, c, b);
                        bs.push(SackBlock { left: l, right: r });
                    }
                }
            }
            let mut s = q.p.seg(FLAG_ACK, &[]);
            s.sack = bs;
            let (before, marked) = (steps(), n.s.conn(c.slot).t.sacked);
            n.inject(&s);
            n.drain();
            let spent = steps() - before;
            let newly = u64::from(n.s.conn(c.slot).t.sacked.wrapping_sub(marked)) / MIN_SEG_PAYLOAD;
            // 印を付けた記録と境目を進めた記録の分を除いた手間が、block ごとの上限を超えないこと
            let fixed = 3 * per_block;
            if spent > fixed + 4 * newly {
                worst_excess = worst_excess.max(spent - fixed - 4 * newly);
            }
        }
        // ACK 1 つの手間は、block ごとの定数と、新しく印を付けた記録の数に比例する分を超えません。
        assert_eq!(
            worst_excess, 0,
            "pattern {pattern}: an ACK spent more than its per-block and per-record share"
        );
        let total = steps() - start;
        // 均した手間: 記録ごとの印付け、境目の通過、再送の手がかりの通過、経路の圧縮
        let budget = acks as u64 * 3 * per_block * 3 + nrec as u64 * 8 * log_n;
        assert!(
            total <= budget,
            "pattern {pattern}: total steps {total} exceed the amortized budget {budget}"
        );
        check_scoreboard(&mut n.s.conn(c.slot));
    }
}

/// SACK した範囲を取り消しては知らせ直す相手が、ACK 1 つの手間を上界の外へ押し出せないことを確かめます (Go の
/// `TestPerACKCostUnderRenegeFlapping`)。
#[test]
fn per_ack_cost_under_renege_flapping() {
    let (mut n, c, mut q) = flood_conn();
    let i = c.slot;
    let nrec = n.s.conn(i).b.recs.len();
    let log_n = u64::from(nrec.bit_width());
    let mut worst = 0u64;
    let mut first = rec_range(&mut n, c, 1).0;
    let mut ack_to = n.s.conn(i).t.snd_una;
    for k in 0..300 {
        // 全体を SACK で知らせ、次の ACK で先頭の記録の内側まで累積で確認して SACK を外します。
        let mut s = q.p.seg(FLAG_ACK, &[]);
        s.ack = ack_to;
        s.sack = vec![SackBlock {
            left: first,
            right: n.s.conn(i).t.snd_max,
        }];
        let before = steps();
        n.inject(&s);
        n.drain();
        if k > 0 {
            worst = worst.max(steps() - before);
        }
        if n.s.conn(i).b.recs.len() > 2 {
            ack_to = rec_range(&mut n, c, 1).0 + 1; // SACK 済みの記録の内側
            let mut s = q.p.seg(FLAG_ACK, &[]);
            s.ack = ack_to;
            let before = steps();
            n.inject(&s);
            n.drain();
            worst = worst.max(steps() - before);
            first = rec_range(&mut n, c, 1).0;
        }
        // 取り消しを疑った期限まで進めて RTO の処理に入ります。
        let d = n.s.conn(i).t.tdl[TMR_RETRANS] - ns(n.now);
        n.advance(Duration::from_nanos(u64::try_from(d).unwrap_or(0)) + Duration::from_millis(1));
        n.drain();
        check_scoreboard(&mut n.s.conn(i));
    }
    let st = n.s.stats();
    assert!(
        st.sack_reneging >= 290,
        "{} renegings in 300 rounds",
        st.sack_reneging
    );
    // 1 回目より後の ACK は、印の付いていない記録をすべて印付けし直す手間 (記録の数) と block の手間を超えない
    assert!(
        worst <= nrec as u64 * 4 + 8 * log_n,
        "worst per-ACK steps {worst} with {nrec} records"
    );
    check_scoreboard(&mut n.s.conn(i));
}
