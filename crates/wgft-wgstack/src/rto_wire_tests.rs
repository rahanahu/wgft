//! RTO の後の slow start の 1 ACK の増分 (L = 1、RFC 3465 2.3) を、packet の入出力だけで守る試験です。
//!
//! 核の内部の状態を読まず、相手の側から segment を入れ、時計を進め、核が出した segment の数だけを見ます。
//! 窓は「ACK の後に核が出し終えた時の、確認されていない byte の数」で見ます。送るデータはいつも十分に有り、
//! 受信窓は大きいので、核が出せる量は窓が決めます。相手は、損失の無い経路の受信側として振る舞います。
//! 元の segment はすべて届いたものとし、確認だけを遅らせます。再送の後に累積の確認が何 segment も進む形です。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "test helpers"
)]
#![expect(clippy::cast_possible_truncation, reason = "test data")]

use crate::testnet_tests::{DUT, Out, PeerConn, TEST_MTU, TestNet, small_limits};
use crate::wire::FLAG_ACK;
use crate::{Config, Congestion, ConnId};
use core::time::Duration;

const RTT: Duration = Duration::from_millis(20);

/// 相手の側から見た 1 つの接続です。番号は核の最初の byte からの offset で持ちます。
struct Wire {
    n: TestNet,
    c: ConnId,
    p: PeerConn,
    base: u32,
    mss: u32,
    /// 相手が累積で確認した offset です。
    ack: u32,
    /// 核が出した最も先の offset の終わりです。
    hi: u32,
    /// 最後に出した segment の終わりの offset です。
    tail: u32,
    /// 出した segment の `(offset, TSval)` です。
    sent_ts: Vec<(u32, u32)>,
    /// 書いた byte の数です。
    written: u64,
    /// 確認された範囲の先に置くデータの segment 数の上限です。`u32::MAX` なら書けるだけ書きます。
    ahead: u32,
}

impl Wire {
    fn new(cc: Congestion, ts: bool, sack: bool) -> Self {
        Self::with_ahead(cc, ts, sack, u32::MAX)
    }

    fn with_ahead(cc: Congestion, ts: bool, sack: bool, ahead: u32) -> Self {
        let config = Config {
            limits: small_limits(),
            congestion: cc,
            ..Config::new(DUT, TEST_MTU)
        };
        let mut n = TestNet::with_config(config, [7; 64]);
        // SACK を交渉しない接続では F-RTO が働かず、RTO の後は SND.UNA から順に送り直す形になります。
        let (c, p) = n.accepted_sack(ts, sack);
        let base = p.dut_iss.wrapping_add(1);
        let mut w = Self {
            n,
            c,
            p,
            base,
            // 最初の segment の中身の大きさです。IPv4 と TCP の header と timestamp option を引きます。
            mss: (TEST_MTU - 40 - if ts { 12 } else { 0 }) as u32,
            ack: 0,
            hi: 0,
            tail: 0,
            sent_ts: Vec::new(),
            written: 0,
            ahead,
        };
        w.feed();
        w.pull();
        assert!(w.hi != 0, "the core sent no data");
        w
    }

    /// 送るデータを書きます。`ahead` が有限なら、確認された範囲の先に `ahead` segment 置くところまでです。
    fn feed(&mut self) {
        let data = vec![0u8; 1 << 16];
        for _ in 0..256 {
            let mut len = data.len();
            if self.ahead != u32::MAX && self.mss != 0 {
                let want = u64::from(self.ack) + u64::from(self.ahead) * u64::from(self.mss);
                let Some(room) = want.checked_sub(self.written).filter(|&r| r > 0) else {
                    return;
                };
                len = len.min(room as usize);
            }
            match self.n.s.write(self.n.now, self.c, &data[..len]) {
                Ok(k) if k > 0 => self.written += k as u64,
                _ => return,
            }
        }
    }

    /// 核が今出す、中身のある segment を読みます。
    fn pull(&mut self) -> Vec<Out> {
        let outs: Vec<Out> = self
            .n
            .drain()
            .into_iter()
            .filter(|o| !o.payload.is_empty())
            .collect();
        for o in &outs {
            let off = o.seq.wrapping_sub(self.base);
            assert!(
                off < 1 << 30,
                "unexpected segment {o} at ack {} hi {}",
                self.ack,
                self.hi
            );
            let end = off + o.payload.len() as u32;
            if self.hi == 0 {
                assert_eq!(self.mss, o.payload.len() as u32, "segment size");
            }
            self.hi = self.hi.max(end);
            self.tail = end;
            if let Some((v, _)) = o.ts {
                self.sent_ts.push((off, v));
                self.p.dut_ts = v;
            }
        }
        outs
    }

    /// offset `to` までの累積の確認を送ります。`echo` があれば、それを TSecr にします。確認の後に核が出す
    /// segment を返します。
    fn ack_to(&mut self, to: u32, echo: Option<u32>) -> Vec<Out> {
        assert!(to <= self.hi, "acking {to} beyond the {} sent", self.hi);
        self.p.rcv = self.base.wrapping_add(to);
        if let Some(e) = echo {
            self.p.dut_ts = e;
        }
        let seg = self.p.seg(FLAG_ACK, &[]);
        self.n.inject(&seg);
        self.ack = self.ack.max(to);
        self.feed();
        self.pull()
    }

    fn ack(&mut self, to: u32) -> Vec<Out> {
        self.ack_to(to, None)
    }

    /// ACK の後に核が出し終えた時の、確認されていない segment の数です。
    fn flight(&self) -> u32 {
        let b = self.tail.saturating_sub(self.ack);
        assert_eq!(b % self.mss, 0, "flight of {b} bytes is not whole segments");
        b / self.mss
    }

    /// 損失の無い経路で `target` segment を送り出した状態にします。確認は 2 segment ごとに返します。
    /// 通常の slow start では 1 ACK で 2 SMSS 増えるので、確認し終えるごとに窓は倍になります。
    fn grow_to(&mut self, target: u32) {
        while self.hi - self.ack < target * self.mss {
            self.n.advance(RTT);
            let end = self.hi;
            let mut to = self.ack;
            while to + 2 * self.mss <= end {
                to += 2 * self.mss;
                self.ack(to);
            }
        }
        assert_eq!(self.hi - self.ack, target * self.mss, "grow_to overshoot");
    }

    /// 確認が来ないまま再送の timer が切れるのを待ち、再送された segment を返します。確認されていない先頭からの
    /// 再送が出るまで待つので、SACK を交渉した接続の tail loss probe は読み飛ばします。
    fn wait_rto(&mut self) -> Vec<Out> {
        let mut all = Vec::new();
        for _ in 0..4000 {
            self.n.advance(Duration::from_millis(5));
            all.extend(self.pull());
            if all
                .iter()
                .any(|o| o.seq.wrapping_sub(self.base) == self.ack)
            {
                return all;
            }
        }
        panic!("no retransmission of the head");
    }

    /// 先頭の再送が 1 segment だけで、窓が 1 segment に落ちたことを確かめます。
    fn rto_to_one_segment(&mut self) {
        let outs = self.wait_rto();
        assert_eq!(
            outs.len(),
            1,
            "the RTO sends one segment: {}",
            crate::testnet_tests::show(&outs)
        );
        assert_eq!(outs[0].seq.wrapping_sub(self.base), self.ack);
        assert_eq!(self.flight(), 1);
    }

    /// 同じ確認を `n` 回送ります。
    fn dup_acks(&mut self, n: u32) {
        for _ in 0..n {
            self.ack(self.ack);
        }
    }

    /// `n_segs` segment の確認を `k` segment ずつ送り、ACK ごとの窓を返します。
    fn ack_by(&mut self, k: u32, n_acks: u32) -> Vec<u32> {
        let mut v = Vec::new();
        for _ in 0..n_acks {
            let to = self.ack + k * self.mss;
            self.ack(to);
            v.push(self.flight());
        }
        v
    }
}

const CCS: [Congestion; 2] = [Congestion::NewReno, Congestion::Cubic];
const KS: [u32; 3] = [2, 4, 8];
const ACKS: u32 = 5;

/// 40 segment を出して確認が来ないまま RTO が起き、先頭が再送された状態です。
fn after_rto(cc: Congestion) -> Wire {
    let mut w = Wire::new(cc, false, false);
    w.grow_to(40);
    w.rto_to_one_segment();
    w
}

// 1. RTO の後は、1 つの ACK がいくつの segment を確認しても窓は 1 SMSS しか増えない

#[test]
fn after_rto_each_ack_releases_one_extra_segment() {
    for cc in CCS {
        for k in KS {
            let mut w = after_rto(cc);
            let got = w.ack_by(k, ACKS);
            let want: Vec<u32> = (2..2 + ACKS).collect();
            assert_eq!(got, want, "{cc:?}: ACKs of {k} segments after an RTO");
        }
    }
}

// 2. 通常の slow start では同じ ACK で 2 SMSS 増える

#[test]
fn normal_slow_start_releases_two_extra_segments() {
    for cc in CCS {
        for k in KS {
            let mut w = Wire::new(cc, false, false);
            let iw = w.flight();
            assert!(iw >= 8, "initial window of {iw} segments");
            w.n.advance(RTT);
            let got = w.ack_by(k, ACKS);
            let want: Vec<u32> = (1..=ACKS).map(|i| iw + 2 * i).collect();
            assert_eq!(
                got, want,
                "{cc:?}: ACKs of {k} segments in the first slow start"
            );
        }
    }
}

// 3. 窓が ssthresh に届くと限りは終わり、輻輳回避になる

#[test]
fn reaching_ssthresh_ends_the_limit_and_congestion_avoidance_follows() {
    // NewReno の ssthresh は RTO の時の送り残しの半分で、40 segment なら 20 segment です。
    let mut w = after_rto(Congestion::NewReno);
    let got = w.ack_by(2, 19);
    let want: Vec<u32> = (2..=20).collect();
    assert_eq!(
        got, want,
        "slow start after the RTO grows 1 segment per ACK up to ssthresh"
    );
    // 20 segment を確認する間に増えるのは、輻輳回避の 1 segment 程度です。
    let tail = w.ack_by(2, 10);
    assert!(
        tail.iter().all(|&f| (20..=21).contains(&f)),
        "congestion avoidance after ssthresh: {tail:?}"
    );
}

// 4. 高速の再送に入ると RTO の後の限りは終わる

/// RTO の後の slow start を続け、RTO の時に出していた範囲 (recover) を確認し終えた状態にします。重複した確認で
/// 高速の再送に入れるのは、その先からです (RFC 6582 3.2)。返す値は、その時の窓 (segment) です。
fn past_recover(w: &mut Wire) -> u32 {
    let got = w.ack_by(8, 5);
    assert_eq!(got, [2, 3, 4, 5, 6], "limited growth up to the old SND.MAX");
    let got = w.ack_by(2, 1);
    assert_eq!(got, [7]);
    7
}

#[test]
fn fast_recovery_after_rto_keeps_the_limit() {
    for cc in CCS {
        let mut w = after_rto(cc);
        past_recover(&mut w);
        // 3 つの重複した確認で高速の回復に入ります。
        w.n.advance(RTT);
        w.dup_acks(3);
        // 回復を終える確認。送り残しが無くなるので、窓は 2 segment (RFC 6582 3.2) まで下がり、ssthresh より低いまま
        // slow start に戻ります。
        w.n.advance(RTT);
        let hi = w.hi;
        w.ack_to(hi, None);
        assert_eq!(w.flight(), 2, "{cc:?}: window after the recovery");
        let got = w.ack_by(2, 1);
        assert_eq!(
            got,
            [3],
            "{cc:?}: slow start after a fast recovery is outside HyStart++, so L = 1"
        );
    }
}

// 5. 不要な RTO の取り消しは、前の状態の増分に戻す

#[test]
fn spurious_rto_undo_restores_the_first_slow_start_increment() {
    for cc in CCS {
        let mut w = Wire::new(cc, true, true);
        w.grow_to(40);
        let orig_ts = w.sent_ts.last().expect("timestamps").1;
        let outs = w.wait_rto();
        assert!(!outs.is_empty());
        // 再送より前の TSval を返す確認で、RTO は不要だったと分かります。窓は RTO の前に戻ります。
        // 出した範囲のすべてを確認します。残りが無いので、RACK が元の segment を損失とみなして窓を下げ直すことは
        // ありません。確認が返すのは再送より前の TSval で、核は RTO が不要だったと分かって窓を戻し、戻した窓の分の
        // 新しいデータを出します。
        let hi = w.hi;
        w.ack_to(hi, Some(orig_ts));
        let back = w.flight();
        assert!(
            back >= 35,
            "{cc:?}: the undo restores the window; {back} segments sent"
        );
        // 戻した後は最初の slow start と同じ 2 SMSS 増えます。
        w.n.advance(RTT);
        let got = w.ack_by(4, 3);
        let want: Vec<u32> = (1..=3).map(|i| back + 2 * i).collect();
        assert_eq!(got, want, "{cc:?}: slow start after the undo");
    }
}

#[test]
fn undo_inside_an_earlier_rto_slow_start_keeps_the_limit() {
    for cc in CCS {
        let mut w = Wire::new(cc, true, false);
        w.grow_to(40);
        w.rto_to_one_segment();
        w.n.advance(RTT);
        past_recover(&mut w);
        // 回復に入る直前の元の送信の TSval です。回復の再送はこれより新しくなります。
        let orig_ts = w.sent_ts.last().expect("timestamps").1;
        w.n.advance(RTT);
        w.dup_acks(3);
        // 元の TSval を返す確認で回復を終えると、回復は不要だったと分かり、RTO の後の slow start に戻ります。
        w.n.advance(RTT);
        let hi = w.hi;
        w.ack_to(hi, Some(orig_ts));
        assert_eq!(w.flight(), 7, "{cc:?}: the undo restores the window");
        w.n.advance(RTT);
        let got = w.ack_by(2, 3);
        assert_eq!(
            got,
            [8, 9, 10],
            "{cc:?}: the RTO slow start continues at 1 segment per ACK"
        );
    }
}

// 6. 2 度目の RTO はまた限りをかける

#[test]
fn second_rto_limits_again() {
    for cc in CCS {
        let mut w = after_rto(cc);
        // 窓が増えなくなるまで確認し、ssthresh に届いて限りが終わったことにします。
        let mut prev = 1;
        let mut n = 0;
        loop {
            let f = w.ack_by(2, 1)[0];
            n += 1;
            assert!(n < 80, "{cc:?}: window never stopped growing");
            if f != prev + 1 {
                assert!(n > 10, "{cc:?}: the growth stopped early at ACK {n}");
                break;
            }
            prev = f;
        }
        w.n.advance(RTT);
        w.rto_to_one_segment();
        let got = w.ack_by(4, 3);
        assert_eq!(
            got,
            [2, 3, 4],
            "{cc:?}: the second RTO limits the increase again"
        );
    }
}

// 3b. 窓が ssthresh にちょうど届いた時に限りが終わっていること

/// 窓が ssthresh にちょうど届くと RTO の後の slow start は終わり、その後の ACK は輻輳回避で窓を増やしません
/// (残りのデータが窓の 20 segment に満たないので、増やすには窓の分の byte の確認が要ります)。
/// 終わるのは「窓が ssthresh 以上」の時で、`>` の比べでは終わりません (RFC 5681 3.1 は「超えた時、または任意で届いた時」)。
/// 遊びの後の再開で窓が ssthresh より低い slow start に戻ると、それは HyStart++ の中の再開なので、2 SMSS ずつ増えます。
#[test]
fn limit_ends_when_the_window_equals_ssthresh() {
    let mut w = Wire::with_ahead(Congestion::NewReno, false, false, 40);
    w.grow_to(40);
    w.rto_to_one_segment();
    // ssthresh は 20 segment です。データは窓の先に 19 segment しか置かないので、窓が 19 から 20 になる ACK の後も
    // 送り手は窓に止められません。窓が 20 に届いたことは、ACK 19 回の +1 ずつから分かります。
    w.ahead = 19;
    let got = w.ack_by(2, 19);
    let want: Vec<u32> = (2..=19).chain([19]).collect();
    assert_eq!(got, want);
    // 残りを確認して黙らせ、遊びを置きます。
    w.ahead = 0;
    while w.hi > w.ack {
        let hi = w.hi;
        w.ack_to(hi, None);
    }
    w.n.advance(Duration::from_secs(5));
    w.ahead = 100;
    w.feed();
    let burst = w.pull().len() as u32;
    assert!(
        (1..20).contains(&burst),
        "restart window of {burst} segments"
    );
    w.n.advance(RTT);
    let got = w.ack_by(2, 3);
    let want: Vec<u32> = (1..=3).map(|i| burst + 2 * i).collect();
    assert_eq!(
        got, want,
        "slow start after the idle restart is not RTO limited"
    );
}
