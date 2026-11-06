//! RFC 6191 2 節の試験:TIME_WAIT の 4 つ組への SYN を受けて開き直す比べを、製品の packet 列で固定します。
//!
//! RFC 6191 2 節 (BCP, SHOULD) の規則は次のとおりです。
//!
//! - 前の接続が timestamp を使い、新しい接続も使うなら、SYN の TSval が前の接続の最後の TSval より大きければ受ける
//! - 同じく、TSval が最後の値に等しく、SYN の番号が "greater than the last sequence number seen on the previous
//!   incarnation" なら受ける
//! - 新しい接続が timestamp を使わず、SYN の番号が同じ基準より大きければ受ける
//! - それ以外は SYN を黙って捨て、TIME_WAIT を残す
//!
//! 注記は "last sequence number" を "the last sequence number used by the previous incarnation" と説明します。
//! 前の接続の最後の番号は相手の FIN の番号 (核の RCV.NXT - 1) なので、「より大きい」は `SEG.SEQ >= RCV.NXT` です。
//!
//! 前の接続が timestamp を使わず、新しい SYN が使う場合 (RFC 6191 の (b)) は、記録した外れとして残すので、この
//! ファイルの試験は触れません。
//!
//! 修正の前に落ちる試験は `#[ignore]` を付けています。対照の試験は今の main で通ります。
//! `handle_packet` に渡る packet は WireGuard が認証した後のものなので、遅れて着いた前の接続の segment も
//! トンネルは防ぎません。守るのは PAWS と番号の検査だけです。

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]
#![expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "test data"
)]

use crate::stack::Error;
use crate::tcp::conn::State;
use crate::testnet_tests::{Out, PeerConn, TSeg, TestNet, show, small_limits};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use crate::{ConnId, ListenerId};

/// 相手の ISN です。`ISS_WRAP` では FIN の次の番号 (核の RCV.NXT) が 0 に回り込みます。
const ISS_PLAIN: u32 = 1000;
const ISS_WRAP: u32 = u32::MAX - 1;

struct Tw {
    n: TestNet,
    l: ListenerId,
    c: ConnId,
    /// 前の接続の相手の側です。`snd` は核の RCV.NXT、`ts_val` は核の TS.Recent です。
    p: PeerConn,
    row: bool,
}

/// 核が先に閉じ、相手の FIN で TIME_WAIT に入った状態を作ります。`row` が真なら行に移します。
fn tw_setup(row: bool, ts: bool, iss: u32) -> Tw {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut p = PeerConn {
        sport: 40000,
        dport: 80,
        iss,
        snd: 0,
        rcv: 0,
        dut_iss: 0,
        ts,
        ts_val: 5000,
        dut_ts: 0,
        wnd: 65535,
    };
    n.inject(&TSeg {
        sport: 40000,
        dport: 80,
        seq: iss,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        ts: ts.then_some((p.ts_val, 0)),
        ..TSeg::default()
    });
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
        "{}",
        show(&outs)
    );
    p.dut_iss = outs[0].seq;
    p.snd = iss.wrapping_add(1);
    p.rcv = outs[0].seq.wrapping_add(1);
    p.dut_ts = outs[0].ts.map_or(0, |(v, _)| v);
    n.peer_ack(&mut p, &[]);
    let c = n.accept(l);
    n.drain();
    if row {
        n.s.close_conn(n.now, c);
    } else {
        n.s.close_write(n.now, c).unwrap();
    }
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    n.peer_fin(&mut p);
    n.drain();
    let tw = Tw { n, l, c, p, row };
    assert!(tw.alive(), "no TIME_WAIT to start with");
    if row {
        assert_eq!(tw.n.s.held().tw_rows, 1);
    }
    tw
}

impl Tw {
    fn alive(&self) -> bool {
        if self.row {
            self.n.s.held().tw_rows == 1
        } else {
            self.n.s.conns.tcb(self.c.slot).state == State::TimeWait
        }
    }

    /// 前の接続の核の RCV.NXT です。
    fn rcv_nxt(&self) -> u32 {
        self.p.snd
    }

    /// 前の接続の核の TS.Recent です。
    fn recent(&self) -> u32 {
        self.p.ts_val
    }
}

fn new_syn(seq: u32, ts_val: Option<u32>) -> TSeg {
    TSeg {
        sport: 40000,
        dport: 80,
        seq,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws: Some(7),
        ts: ts_val.map(|v| (v, 0)),
        ..TSeg::default()
    }
}

/// SYN を送り、握手を始めたか (SYN-ACK を 1 つだけ返したか) を返します。始めなかった時は、SYN-ACK が無く
/// TIME_WAIT が残ることも確かめます。
fn try_syn(tw: &mut Tw, syn: &TSeg) -> (bool, Vec<Out>) {
    tw.n.inject(syn);
    let outs = tw.n.drain();
    let began = outs.iter().any(|o| o.has(FLAG_SYN));
    if began {
        assert!(
            outs.len() == 1
                && outs[0].flags == FLAG_SYN | FLAG_ACK
                && outs[0].ack == syn.seq.wrapping_add(1),
            "want exactly one SYN-ACK for the new SYN, got {}",
            show(&outs)
        );
    } else {
        assert!(
            tw.alive(),
            "the SYN was dropped but TIME_WAIT went away: {}",
            show(&outs)
        );
        assert_eq!(tw.n.s.held().syn_rows, 0);
    }
    (began, outs)
}

/// 比べの 1 件です。`rfc_only` が真なら、今の main が RFC と食い違う件です。
struct Case {
    name: &'static str,
    prev_ts: bool,
    /// SYN の TSval の TS.Recent との差です。`None` なら SYN は TSopt を持ちません。
    ts_delta: Option<i64>,
    /// SYN の番号の RCV.NXT との差です。
    seq_off: i64,
    accept: bool,
    rfc_only: bool,
}

const fn case(
    name: &'static str,
    prev_ts: bool,
    ts_delta: Option<i64>,
    seq_off: i64,
    accept: bool,
    rfc_only: bool,
) -> Case {
    Case {
        name,
        prev_ts,
        ts_delta,
        seq_off,
        accept,
        rfc_only,
    }
}

fn cases() -> Vec<Case> {
    vec![
        // 前の接続が timestamp を使い、SYN も TSopt を持つ。1 つ目の規則:TSval が大きければ番号は問わない。
        case(
            "tsval +1, seq far ahead",
            true,
            Some(1),
            100_000,
            true,
            false,
        ),
        case(
            "tsval +1, seq equal to RCV.NXT",
            true,
            Some(1),
            0,
            true,
            false,
        ),
        case(
            "tsval +1, seq behind the old space",
            true,
            Some(1),
            -1000,
            true,
            false,
        ),
        // TSval が小さければ番号が大きくても受けない。
        case(
            "tsval -1, seq far ahead",
            true,
            Some(-1),
            100_000,
            false,
            false,
        ),
        case(
            "tsval -1, seq equal to RCV.NXT",
            true,
            Some(-1),
            0,
            false,
            false,
        ),
        case(
            "tsval -1000, seq one ahead",
            true,
            Some(-1000),
            1,
            false,
            false,
        ),
        // 2 つ目の規則 (a):TSval が等しく番号が最後の番号より大きければ受ける。
        case(
            "tsval equal, seq far ahead",
            true,
            Some(0),
            100_000,
            true,
            true,
        ),
        case(
            "tsval equal, seq one more than RCV.NXT",
            true,
            Some(0),
            1,
            true,
            true,
        ),
        case(
            "tsval equal, seq equal to RCV.NXT",
            true,
            Some(0),
            0,
            true,
            true,
        ),
        // 最後の番号 (FIN の番号) 以下は受けない。
        case(
            "tsval equal, seq one less than RCV.NXT",
            true,
            Some(0),
            -1,
            false,
            false,
        ),
        case(
            "tsval equal, seq two less than RCV.NXT",
            true,
            Some(0),
            -2,
            false,
            false,
        ),
        case(
            "tsval equal, seq far behind",
            true,
            Some(0),
            -100_000,
            false,
            false,
        ),
        // 3 つ目の規則 (c):新しい接続が timestamp を使わなければ、番号だけで決める。
        case("no TSopt, seq far ahead", true, None, 100_000, true, false),
        case(
            "no TSopt, seq one more than RCV.NXT",
            true,
            None,
            1,
            true,
            false,
        ),
        case("no TSopt, seq equal to RCV.NXT", true, None, 0, true, true),
        case(
            "no TSopt, seq one less than RCV.NXT",
            true,
            None,
            -1,
            false,
            false,
        ),
        case(
            "no TSopt, seq far behind",
            true,
            None,
            -100_000,
            false,
            false,
        ),
        // 前の接続が timestamp を使わず、SYN も使わない:番号だけで決める。
        case(
            "prev no ts, no TSopt, seq far ahead",
            false,
            None,
            100_000,
            true,
            false,
        ),
        case(
            "prev no ts, no TSopt, seq one more",
            false,
            None,
            1,
            true,
            false,
        ),
        case(
            "prev no ts, no TSopt, seq equal to RCV.NXT",
            false,
            None,
            0,
            true,
            true,
        ),
        case(
            "prev no ts, no TSopt, seq one less",
            false,
            None,
            -1,
            false,
            false,
        ),
        case(
            "prev no ts, no TSopt, seq far behind",
            false,
            None,
            -100_000,
            false,
            false,
        ),
    ]
}

fn run_cases(row: bool, rfc_only: bool, with_tsopt: bool) {
    for iss in [ISS_PLAIN, ISS_WRAP] {
        for c in cases()
            .iter()
            .filter(|c| c.rfc_only == rfc_only && (!rfc_only || c.ts_delta.is_some() == with_tsopt))
        {
            let mut tw = tw_setup(row, c.prev_ts, iss);
            if iss == ISS_WRAP {
                assert_eq!(tw.rcv_nxt(), 0, "the sequence space did not wrap");
            }
            let ts = c.ts_delta.map(|d| tw.recent().wrapping_add(d as u32));
            let seq = tw.rcv_nxt().wrapping_add(c.seq_off as u32);
            let (began, outs) = try_syn(&mut tw, &new_syn(seq, ts));
            assert_eq!(
                began,
                c.accept,
                "{} (row {row}, iss {iss}): want accept={}, got {}",
                c.name,
                c.accept,
                show(&outs)
            );
        }
    }
}

#[test]
fn rfc6191_slot_comparisons_that_main_already_follows() {
    run_cases(false, false, true);
}

#[test]
fn rfc6191_row_comparisons_that_main_already_follows() {
    run_cases(true, false, true);
}

#[test]
#[ignore = "fixed by the follow-up PR"]
fn rfc6191_slot_accepts_equal_tsval_and_greater_seq() {
    run_cases(false, true, true);
}

#[test]
#[ignore = "fixed by the follow-up PR"]
fn rfc6191_row_accepts_equal_tsval_and_greater_seq() {
    run_cases(true, true, true);
}

#[test]
#[ignore = "fixed by the follow-up PR"]
fn rfc6191_slot_accepts_a_syn_without_tsopt_at_rcv_nxt() {
    run_cases(false, true, false);
}

#[test]
#[ignore = "fixed by the follow-up PR"]
fn rfc6191_row_accepts_a_syn_without_tsopt_at_rcv_nxt() {
    run_cases(true, true, false);
}

/// 遅れて着く前の接続の segment です。
#[derive(Clone, Copy, Debug)]
enum Old {
    /// 前の番号の範囲のデータで、TSval は前の接続の最後の値と同じです。
    DataSameTs,
    /// 前の番号の範囲のデータで、TSval は前の接続の最後の値より古いものです。
    DataOlderTs,
    /// 前の接続の FIN の写しです。
    Fin,
    /// 前の番号の範囲の RST です。
    Rst,
    /// 新しい接続の窓の中の番号を持つが、TSval が古いデータです。番号の検査が働かなくても PAWS が止めます。
    NewSeqOlderTs,
}

const OLD_KINDS: [Old; 5] = [
    Old::DataSameTs,
    Old::DataOlderTs,
    Old::Fin,
    Old::Rst,
    Old::NewSeqOlderTs,
];

/// 前の接続の TIME_WAIT へ新しい SYN を送って開き直し、新しい接続を返します。`early` が真なら最後の ACK の前
/// (SYN-RECEIVED) に、偽なら後 (ESTABLISHED) に、遅れた segment を 1 つ入れて、新しい接続が無事なことを確かめます。
/// `equal` が真なら、規則の最も狭い受け入れ (TSval が前と等しく、番号が RCV.NXT) で開き直します。
fn mixing(row: bool, equal: bool, early: bool, old: Old) {
    let ctx = format!("row {row}, equal {equal}, early {early}, {old:?}");
    let mut tw = tw_setup(row, true, ISS_PLAIN);
    let (old_snd, old_rcv, recent) = (tw.p.snd, tw.p.rcv, tw.recent());
    let (syn_ts, syn_seq) = if equal {
        (recent, old_snd)
    } else {
        (recent + 1, old_snd.wrapping_add(100_000))
    };
    let syn = new_syn(syn_seq, Some(syn_ts));
    let (began, outs) = try_syn(&mut tw, &syn);
    assert!(began, "the reuse was not accepted ({ctx}): {}", show(&outs));
    let sa = &outs[0];
    let mut np = PeerConn {
        sport: 40000,
        dport: 80,
        iss: syn_seq,
        snd: syn_seq.wrapping_add(1),
        rcv: sa.seq.wrapping_add(1),
        dut_iss: sa.seq,
        ts: true,
        ts_val: syn_ts,
        dut_ts: sa.ts.map_or(0, |(v, _)| v),
        wnd: 65535,
    };
    let n = &mut tw.n;
    let l = tw.l;

    let delayed = |np: &PeerConn| -> TSeg {
        let mut s = TSeg {
            sport: 40000,
            dport: 80,
            ack: old_rcv,
            flags: FLAG_ACK,
            wnd: 65535,
            ..TSeg::default()
        };
        match old {
            Old::DataSameTs => {
                s.seq = old_snd.wrapping_sub(50);
                s.ts = Some((recent, np.dut_ts));
                s.payload = b"OLD-OLD-OLD-OLD-OLD!".to_vec();
            }
            Old::DataOlderTs => {
                s.seq = old_snd.wrapping_sub(50);
                s.ts = Some((recent.wrapping_sub(1000), np.dut_ts));
                s.payload = b"OLD-OLD-OLD-OLD-OLD!".to_vec();
            }
            Old::Fin => {
                s.seq = old_snd.wrapping_sub(1);
                s.flags = FLAG_ACK | FLAG_FIN;
                s.ts = Some((recent.wrapping_sub(1000), np.dut_ts));
            }
            Old::Rst => {
                s.seq = old_snd.wrapping_sub(1);
                s.flags = FLAG_RST | FLAG_ACK;
                s.ts = Some((recent.wrapping_sub(1000), np.dut_ts));
            }
            Old::NewSeqOlderTs => {
                s.seq = np.snd;
                s.ack = np.rcv;
                s.ts = Some((syn_ts.wrapping_sub(1000), np.dut_ts));
                s.payload = b"OLD-OLD-OLD-OLD-OLD!".to_vec();
            }
        }
        s
    };

    if early {
        n.inject(&delayed(&np));
        let outs = n.drain();
        // SYN-RECEIVED で受け入れられない ACK には、RFC 9293 が RST を送ることを許します。それは相手への応答で、
        // 接続は残ります。
        assert!(
            outs.iter().all(|o| !o.has(FLAG_SYN)),
            "{ctx}: {}",
            show(&outs)
        );
        assert_eq!(
            n.s.accept(n.now, l).err(),
            Some(Error::WouldBlock),
            "{ctx}: the old segment completed the handshake"
        );
    }
    let fin = np.seg(FLAG_ACK, &[]);
    n.inject(&fin);
    n.drain();
    let c2 =
        n.s.accept(n.now, l)
            .unwrap_or_else(|e| panic!("{ctx}: the new connection never came up: {e:?}"))
            .0;
    n.drain();
    n.events();
    if !early {
        n.inject(&delayed(&np));
        let outs = n.drain();
        assert!(
            outs.iter().all(|o| !o.has(FLAG_RST) && !o.has(FLAG_SYN)),
            "{ctx}: {}",
            show(&outs)
        );
    }
    let mut buf = [0u8; 64];
    assert_eq!(
        n.s.read(n.now, c2, &mut buf),
        Err(Error::WouldBlock),
        "{ctx}: the delayed segment reached the new connection (data, EOF or reset)"
    );
    // 新しい接続は生きていて、新しい番号の中身だけを受ける。
    n.peer_ack(&mut np, b"hello");
    let outs = n.drain();
    np.absorb(&outs);
    assert_eq!(n.read_all(c2), b"hello", "{ctx}");
    assert!(
        outs.iter().all(|o| !o.has(FLAG_RST)),
        "{ctx}: {}",
        show(&outs)
    );
    let w =
        n.s.write(n.now, c2, b"world")
            .unwrap_or_else(|e| panic!("{ctx}: write failed: {e:?}"));
    assert_eq!(w, 5, "{ctx}");
    let outs = n.drain();
    assert!(
        outs.iter()
            .any(|o| o.payload == b"world" && o.seq == np.rcv),
        "{ctx}: the reply did not leave on the new sequence space: {}",
        show(&outs)
    );
}

fn mixing_all(equal: bool) {
    for row in [false, true] {
        for early in [false, true] {
            for old in OLD_KINDS {
                mixing(row, equal, early, old);
            }
        }
    }
}

/// 対照:TSval が大きい SYN で開き直した後、前の接続の遅れた segment は新しい接続に入らず、接続も壊さない。
#[test]
fn rfc6191_old_segments_do_not_enter_a_connection_reused_by_a_newer_tsval() {
    mixing_all(false);
}

/// 同じことを、規則が最も狭く受ける SYN (TSval が等しく番号が RCV.NXT) で開き直した接続について確かめる。
/// 前の接続の番号の範囲は新しい ISN の直前まで届き、PAWS の TSval も等しいので、守るのは番号の検査と PAWS の
/// 境目だけである。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn rfc6191_old_segments_do_not_enter_a_connection_reused_by_an_equal_tsval() {
    mixing_all(true);
}
