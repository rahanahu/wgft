//! DNAT のルールで相手が一般のクライアントになる時の反例の試験です。
//!
//! カーネルモードの server は、DNAT のルールでインターネットのクライアントの packet をそのままトンネルへ転送します
//! (docs/design/spec/tunnel.md の「server から agent への通信」)。核の TCP の相手は一般の OS で、クライアントの
//! アドレスを偽る経路の外の第三者の segment も server の転送を通って核に届きます。WireGuard の認証は、正しい相手の
//! 古い segment も、転送された偽の segment も止めません。ここでは `handle_packet` に渡る packet の列だけで、
//! timestamp、RST、challenge ACK、TIME_WAIT の使い直しの挙動を確かめます。
//!
//! 安全な今の挙動を確かめる試験は通ります。欠陥を示す試験は `defect`、RFC の範囲の危険を示す試験は `hazard`、
//! 所有者が残している既知の外れを示す試験は `known deviation` の理由で ignore にしてあります。各件の説明は PR の
//! 本文にあります。

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

use crate::stack::ListenerId;
use crate::tcp::conn::{ConnId, State};
use crate::testnet_tests::{Out, PeerConn, TSeg, TestNet, show, small_limits};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use core::time::Duration;

/// 正しいクライアントのポートです。TIME_WAIT の試験では、前の接続のクライアント A と、同じトンネルの側の 4 つ組を
/// 使う後のクライアント B が共に使います。
const VICTIM: u16 = 40000;
/// 偽の segment を送る第三者が、自分で開いた接続のポートです。
const ATTACKER: u16 = 50000;
/// 1 秒の challenge ACK の予算の最大 (`Shared::challenge_allowed` の 3*LIMIT/2) を超える数です。
const FLOOD: usize = 1600;

fn seg(sport: u16, seq: u32, ack: u32, flags: u8, ts: Option<(u32, u32)>, payload: &[u8]) -> TSeg {
    TSeg {
        sport,
        dport: 80,
        seq,
        ack,
        flags,
        wnd: 65535,
        ts,
        payload: payload.to_vec(),
        ..TSeg::default()
    }
}

/// 80 番で待ち受け、`ports` の各ポートから timestamp と窓の scale を付けて接続を開きます。
fn established(ports: &[u16]) -> (TestNet, ListenerId, Vec<(ConnId, PeerConn)>) {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut v = Vec::new();
    for &port in ports {
        let p = n.handshake(port, 80, true, true);
        let c = n.accept(l);
        v.push((c, p));
    }
    n.drain();
    (n, l, v)
}

fn to(outs: &[Out], port: u16) -> Vec<&Out> {
    outs.iter().filter(|o| o.rport == port).collect()
}

fn state(n: &TestNet, c: ConnId) -> State {
    n.s.conns.tcb(c.slot).state
}

/// 第三者が自分の接続に SYN を `FLOOD` 回送り、返った challenge ACK の数を返します。確立した接続への SYN には、
/// 番号を問わず challenge ACK を返す決まりです (RFC 5961 4.2)。
fn attacker_flood(n: &mut TestNet, pa: &mut PeerConn) -> usize {
    let mut got = 0;
    for _ in 0..FLOOD {
        let s = pa.seg(FLAG_SYN, &[]);
        n.inject(&s);
        got += to(&n.drain(), ATTACKER)
            .iter()
            .filter(|o| o.flags == FLAG_ACK)
            .count();
    }
    got
}

// ---- 古い segment と TSopt ----

/// 窓の内に届いた古い TSval の segment (番号の一周か前の接続の古い写し) を PAWS が捨て、後から届く本当のデータを
/// 受けます (RFC 7323 5.3 の R1)。
#[test]
fn paws_drops_an_old_duplicate_with_tsopt_inside_the_window() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, mut p) = v[0];
    let old = seg(
        VICTIM,
        p.snd,
        p.rcv,
        FLAG_ACK,
        Some((p.ts_val - 100, p.dut_ts)),
        b"OLD",
    );
    n.inject(&old);
    let outs = n.drain();
    assert!(
        to(&outs, VICTIM).iter().any(|o| o.ack == p.snd),
        "PAWS answers with an ACK for RCV.NXT: {}",
        show(&outs)
    );
    assert!(n.read_all(c).is_empty(), "PAWS let the old bytes in");
    n.peer_ack(&mut p, b"NEW");
    assert_eq!(n.read_all(c), b"NEW");
}

/// 同じ古い segment が TSopt を持たなければ、RFC 7323 3.2 の SHOULD では黙って捨てます。核は TSopt の無い segment
/// の PAWS を飛ばすので古い bytes を受け、後から届く本当のデータを重複として捨てます。正しい相手は交渉の後に
/// すべての segment に TSopt を付けるので (MUST)、起きるのは途中で TSopt を外された segment と偽の segment です。
#[test]
#[ignore = "known deviation: see PR body"]
fn an_old_duplicate_without_tsopt_does_not_replace_the_real_bytes() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, mut p) = v[0];
    n.inject(&seg(VICTIM, p.snd, p.rcv, FLAG_ACK, None, b"OLD"));
    n.drain();
    n.peer_ack(&mut p, b"NEW");
    assert_eq!(
        n.read_all(c),
        b"NEW",
        "a TSopt-less old segment replaced the stream"
    );
}

/// TSopt の無い segment で接続を切らず (RFC 7323 3.2 の MUST NOT)、TS.Recent も動かしません。
#[test]
fn a_segment_without_tsopt_neither_aborts_nor_moves_ts_recent() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, mut p) = v[0];
    n.peer_ack(&mut p, b"a");
    let recent = n.s.conn(c.slot).t.ts_recent;
    n.inject(&seg(VICTIM, p.snd, p.rcv, FLAG_ACK, None, b"b"));
    p.snd += 1;
    n.drain();
    assert_eq!(state(&n, c), State::Established);
    assert_eq!(n.s.conn(c.slot).t.ts_recent, recent);
    n.peer_ack(&mut p, b"c");
    assert_eq!(n.read_all(c), b"abc");
}

// ---- 偽の RST と偽のデータ ----

/// 偽の RST の扱いは TSopt の有無と値に依りません。RST は PAWS にかけない決まりで (RFC 7323 5.2 の MUST NOT)、
/// 窓の外の RST は黙って捨て、窓の内で RCV.NXT と違う RST には challenge ACK を返します (RFC 5961 3.2)。
#[test]
fn spoofed_rst_handling_does_not_depend_on_tsopt() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, p) = v[0];
    let (snd_nxt, rcv_nxt) = {
        let t = &n.s.conn(c.slot).t;
        (t.snd_nxt, t.rcv_nxt)
    };
    for ts in [
        None,
        Some((p.ts_val - 1000, 0)),
        Some((p.ts_val + (1 << 30), 0)),
    ] {
        n.inject(&seg(
            VICTIM,
            rcv_nxt.wrapping_add(1 << 31),
            0,
            FLAG_RST,
            ts,
            b"",
        ));
        let outs = n.drain();
        assert!(outs.is_empty(), "out-of-window RST {ts:?}: {}", show(&outs));
        n.inject(&seg(VICTIM, rcv_nxt.wrapping_add(1), 0, FLAG_RST, ts, b""));
        let outs = n.drain();
        assert!(
            outs.len() == 1
                && outs[0].flags == FLAG_ACK
                && (outs[0].seq, outs[0].ack) == (snd_nxt, rcv_nxt),
            "in-window RST {ts:?} wants one challenge ACK: {}",
            show(&outs)
        );
        assert_eq!(state(&n, c), State::Established);
    }
}

/// 番号が RCV.NXT と一致する RST は、TSopt が無くても古い TSval でも接続を閉じます (RFC 7323 5.2、RFC 5961 3.2)。
#[test]
fn exact_rst_resets_with_or_without_tsopt() {
    for ts in [None, Some((1, 0))] {
        let (mut n, _, v) = established(&[VICTIM]);
        let (c, p) = v[0];
        n.inject(&seg(VICTIM, p.snd, 0, FLAG_RST, ts, b""));
        assert_eq!(state(&n, c), State::Closed, "exact RST {ts:?}");
    }
}

/// 窓の内の番号を当てた偽のデータでも、ACK の値が受け入れの範囲の外なら challenge ACK を返して捨てます
/// (RFC 5961 5.2)。TSopt の有無に依りません。
#[test]
fn blind_data_with_an_ack_outside_the_range_gets_a_challenge_ack() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, p) = v[0];
    let bad_ack = p.rcv.wrapping_add(1 << 31);
    for ts in [None, Some((p.ts_val + 1, p.dut_ts))] {
        n.inject(&seg(VICTIM, p.snd, bad_ack, FLAG_ACK, ts, b"EVIL"));
        let outs = n.drain();
        assert!(
            outs.len() == 1 && outs[0].flags == FLAG_ACK && outs[0].ack == p.snd,
            "ACK check {ts:?}: {}",
            show(&outs)
        );
    }
    assert_eq!(n.read_all(c), b"");
}

/// 窓の内の番号と範囲の内の ACK を当てた偽のデータは、TSopt を持てば TSval の比べ (PAWS) も通る必要があります。
/// TSopt を持たなければ PAWS を飛ばすので、当てずっぽうの TSval で半分が落ちる分 (1 bit) だけ偽のデータが通り
/// やすくなります。RFC 7323 3.2 の SHOULD どおりなら TSopt の無いデータは捨てます。
#[test]
#[ignore = "known deviation: see PR body"]
fn blind_data_without_tsopt_is_dropped() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, p) = v[0];
    // TSopt を持ち、TSval が TS.Recent より古い偽のデータは PAWS で落ちます。
    n.inject(&seg(
        VICTIM,
        p.snd,
        p.rcv,
        FLAG_ACK,
        Some((p.ts_val - 1, 0)),
        b"EVIL",
    ));
    n.drain();
    assert_eq!(n.read_all(c), b"");
    // TSopt を持たない同じ番号の偽のデータです。
    n.inject(&seg(VICTIM, p.snd, p.rcv, FLAG_ACK, None, b"EVIL"));
    n.drain();
    assert!(
        n.read_all(c).is_empty(),
        "TSopt-less blind data was delivered"
    );
}

// ---- 核の全体の challenge ACK の予算 ----

/// 第三者が自分の接続で数える challenge ACK の数は、他人の接続に送った偽の segment が challenge ACK を引いたかに
/// 依ってはいけません (RFC 5961 の Errata ID 4772、CVE-2016-5696)。核の予算は全体で 1 つなので、窓の内に当たった
/// 偽の RST を同じ秒に予算の最大より多く送ると、第三者が数える数は 0 になり、外れなら 500 以上になります。第三者は
/// 1 秒に 1 回、被害者の接続の窓の位置を確かめられます。
#[test]
#[ignore = "defect: see PR body"]
fn attacker_cannot_observe_whether_a_spoofed_rst_hit_the_window() {
    let observe = |hit: bool| {
        let (mut n, _, v) = established(&[VICTIM, ATTACKER]);
        let (_, pv) = v[0];
        let (_, mut pa) = v[1];
        n.advance(Duration::from_secs(2));
        n.drain();
        let guess = if hit {
            pv.snd.wrapping_add(100)
        } else {
            pv.snd.wrapping_add(1 << 31)
        };
        for _ in 0..FLOOD {
            n.inject(&seg(VICTIM, guess, 0, FLAG_RST, None, b""));
            n.drain();
        }
        attacker_flood(&mut n, &mut pa)
    };
    let (hit, miss) = (observe(true), observe(false));
    assert_eq!(
        hit, miss,
        "the attacker's own challenge ACK count reveals the victim's window ({hit} on a hit, {miss} on a miss)"
    );
}

/// 第三者が自分の接続への SYN で予算を使い切っても、被害者の接続の challenge ACK は返ります。クライアントが再起動して
/// 同じポートから新しい SYN を送る半開きの回復は、この challenge ACK に RST を返すことで進みます (RFC 5961 4.2)。
#[test]
#[ignore = "defect: see PR body"]
fn a_challenge_ack_flood_does_not_silence_another_connection() {
    let (mut n, _, v) = established(&[VICTIM, ATTACKER]);
    let (c, pv) = v[0];
    let (_, mut pa) = v[1];
    n.advance(Duration::from_secs(2));
    n.drain();
    assert!(attacker_flood(&mut n, &mut pa) > 0);
    // 再起動したクライアントの新しい SYN です。番号と TSval は前の接続と関係ありません。TSval が TS.Recent より
    // 小さい SYN は PAWS の ACK (接続ごとの 500 ms の制限) を受けるので、大きい TSval と TSopt の無い SYN を見ます。
    for ts in [Some((pv.ts_val.wrapping_add(1 << 20), 0)), None] {
        let syn = TSeg {
            mss: 1380,
            ws: Some(7),
            ..seg(
                VICTIM,
                pv.snd.wrapping_add(0x4000_0000),
                0,
                FLAG_SYN,
                ts,
                b"",
            )
        };
        n.inject(&syn);
        let outs = n.drain();
        assert_eq!(state(&n, c), State::Established);
        assert!(
            to(&outs, VICTIM).iter().any(|o| o.flags == FLAG_ACK),
            "the half-open connection sent no challenge ACK to a SYN {ts:?} under the flood ({} limited): {}",
            n.s.stats().challenge_limited,
            show(&outs)
        );
    }
}

// ---- TIME_WAIT の 4 つ組の使い直し ----

/// 核が先に閉じ、相手 A の FIN で TIME_WAIT に入った状態です。`row` なら接続を手放して行に移します。返す
/// `PeerConn` の `snd` は前の接続の RCV.NXT、`ts_val` は TS.Recent、`rcv` は前の接続の核の SND.NXT です。
fn time_wait(
    row: bool,
    extra: &[u16],
) -> (
    TestNet,
    ListenerId,
    ConnId,
    PeerConn,
    Vec<(ConnId, PeerConn)>,
) {
    let mut ports = vec![VICTIM];
    ports.extend_from_slice(extra);
    let (mut n, l, mut v) = established(&ports);
    let (c, mut p) = v.remove(0);
    n.peer_ack(&mut p, b"A's request");
    n.drain();
    assert_eq!(n.read_all(c), b"A's request");
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
    if row {
        assert_eq!(n.s.held().tw_rows, 1);
    } else {
        assert_eq!(state(&n, c), State::TimeWait);
    }
    (n, l, c, p, v)
}

fn new_syn(seq: u32, ts_val: u32) -> TSeg {
    TSeg {
        mss: 1380,
        ws: Some(7),
        ..seg(VICTIM, seq, 0, FLAG_SYN, Some((ts_val, 0)), b"")
    }
}

/// SYN-ACK に最後の ACK を返し、新しい接続を受け取ります。最後の ACK の TSval は `ts_val` です。
fn finish(n: &mut TestNet, l: ListenerId, syn: &TSeg, sa: &Out, ts_val: u32) -> ConnId {
    let sa_ts = sa.ts.map_or(0, |(v, _)| v);
    n.inject(&seg(
        VICTIM,
        syn.seq.wrapping_add(1),
        sa.seq.wrapping_add(1),
        FLAG_ACK,
        Some((ts_val, sa_ts)),
        b"",
    ));
    n.drain();
    let c =
        n.s.accept(n.now, l)
            .expect("the reused 4-tuple was not accepted")
            .0;
    n.drain();
    c
}

/// RFC 6191 の 1 つ目の規則で使い直した 4 つ組です。SYN の TSval は TS.Recent より 1 大きく、番号は前の接続の
/// RCV.NXT より 1000 前にあります (RFC 6191 はこの時に番号を問いません)。前の接続の古い segment の `old_ts` を
/// TSval に持つ写しが、新しい接続の RCV.NXT に届いた時に読める bytes を返します。
fn rule1_reuse_then_old_segment(row: bool, old_ts: impl Fn(u32) -> u32) -> Vec<u8> {
    let (mut n, l, _, p, _) = time_wait(row, &[]);
    let syn_ts = p.ts_val + 1;
    let syn = new_syn(p.snd.wrapping_sub(1000), syn_ts);
    n.inject(&syn);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
        "RFC 6191 rule 1 reuse: {}",
        show(&outs)
    );
    let c2 = finish(&mut n, l, &syn, &outs[0], syn_ts);
    // 前の接続の写しです。ACK の値は前の接続の核の SND.NXT のままで、使い直しの ISN の下限 (前の SND.NXT の
    // 65537 先) は相手の窓 (MAX.SND.WND) より近いので、RFC 5961 5.2 の範囲に入ります。
    n.inject(&seg(
        VICTIM,
        syn.seq.wrapping_add(1),
        p.rcv,
        FLAG_ACK,
        Some((old_ts(syn_ts), p.dut_ts)),
        b"OLD-DATA",
    ));
    n.drain();
    n.read_all(c2)
}

/// 相手の timestamp の時計が刻んでいれば、使い直しの前に送った古い写しの TSval は新しい TS.Recent より小さく、
/// PAWS が捨てます。
#[test]
fn rfc6191_rule1_old_segment_from_an_earlier_tick_is_dropped() {
    for row in [false, true] {
        let got = rule1_reuse_then_old_segment(row, |syn_ts| syn_ts - 1);
        assert!(
            got.is_empty(),
            "row={row}: {:?}",
            String::from_utf8_lossy(&got)
        );
    }
}

/// 古い写しが新しい SYN と同じ時計の刻みで送られた (TSval が等しい) なら、PAWS は捨てず、番号の空間が重なった分の
/// 古い bytes を新しい接続のデータとして受けます。RFC 6191 は相手の時計が刻むことに頼るので RFC の範囲の挙動です。
#[test]
#[ignore = "hazard: see PR body"]
fn rfc6191_rule1_old_segment_from_the_same_tick_is_dropped() {
    for row in [false, true] {
        let got = rule1_reuse_then_old_segment(row, |syn_ts| syn_ts);
        assert!(
            got.is_empty(),
            "row={row}: {:?}",
            String::from_utf8_lossy(&got)
        );
    }
}

/// 別のクライアント B が、TIME_WAIT の行の 4 つ組を使い直す SYN を送ります。B の番号と TSval は A と関係が無いので、
/// RFC 6191 の比べに落ちることがあります。その時は速さを抑えた ACK を返し、B の RST (番号は ACK の値) で行が外れ、
/// B の SYN の再送で接続が開きます。拒まれるのは 60 秒でなく、B の SYN の再送の間隔だけです。
#[test]
fn another_client_refused_by_rfc6191_connects_on_its_syn_retransmission() {
    let (mut n, l, _, p, _) = time_wait(true, &[]);
    let syn = new_syn(p.snd.wrapping_sub(5000), 3);
    n.inject(&syn);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_ACK && outs[0].ack == p.snd,
        "a refused reuse SYN gets the TIME_WAIT ACK: {}",
        show(&outs)
    );
    // B は SYN-SENT で受けた受け入れられない ACK に、番号を ACK の値にした RST を返します (RFC 9293 3.10.7.3)。
    n.inject(&seg(VICTIM, outs[0].ack, 0, FLAG_RST, None, b""));
    assert_eq!(n.s.held().tw_rows, 0, "B's RST removes the row");
    n.advance(Duration::from_secs(1));
    n.inject(&syn);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
        "B's retransmitted SYN opens the connection: {}",
        show(&outs)
    );
    finish(&mut n, l, &syn, &outs[0], 4);
}

/// 上の続きで、B の接続が開いた後に、A の遅れた segment が同じトンネルの側の 4 つ組で届き、番号が B の窓に入る
/// とします。A の時計は B と関係が無いので TSval は B の TS.Recent より大きいことがあり、核の ISN は同じ 4 つ組の
/// 鍵付きの hash と時計で作るので、A の ACK の値も B の接続の受け入れの範囲に入ります。核はこの segment を B の
/// データとして受けます。server の NAT がこの写しを B の 4 つ組に写すかは PR の本文で扱います。
#[test]
#[ignore = "hazard: see PR body"]
fn another_clients_stream_does_not_take_old_bytes_of_the_previous_client() {
    let (mut n, l, _, p, _) = time_wait(true, &[]);
    let syn = new_syn(p.snd.wrapping_sub(5000), 3);
    n.inject(&syn);
    let outs = n.drain();
    n.inject(&seg(VICTIM, outs[0].ack, 0, FLAG_RST, None, b""));
    n.advance(Duration::from_secs(1));
    n.inject(&syn);
    let outs = n.drain();
    let c2 = finish(&mut n, l, &syn, &outs[0], 4);
    n.inject(&seg(
        VICTIM,
        syn.seq.wrapping_add(1),
        p.rcv,
        FLAG_ACK,
        Some((p.ts_val - 10, p.dut_ts)),
        b"A's old bytes",
    ));
    n.drain();
    let got = n.read_all(c2);
    assert!(
        got.is_empty(),
        "B's stream took {:?}",
        String::from_utf8_lossy(&got)
    );
}

/// 上の回復は、TIME_WAIT の行が返す ACK に頼ります。この ACK は challenge ACK と同じ核の全体の予算から取るので、
/// 第三者が自分の接続への SYN で予算を使い切り続けると、B の SYN には何も返らず、B は行の期限 (60 秒) まで開けません。
#[test]
#[ignore = "defect: see PR body"]
fn a_challenge_ack_flood_does_not_block_time_wait_reuse() {
    let (mut n, _, _, p, mut v) = time_wait(true, &[ATTACKER]);
    let (_, mut pa) = v.remove(0);
    n.advance(Duration::from_secs(2));
    n.drain();
    assert!(attacker_flood(&mut n, &mut pa) > 0);
    n.inject(&new_syn(p.snd.wrapping_sub(5000), 3));
    let outs = n.drain();
    assert_eq!(n.s.held().tw_rows, 1);
    assert!(
        !to(&outs, VICTIM).is_empty(),
        "B's SYN got nothing while the budget was spent ({} limited)",
        n.s.stats().challenge_limited
    );
}

/// 使い直した接続の相手 (新しい番号) が `len` byte を順に送り、核が読ませた bytes と接続の状態を返します。
fn new_peer_sends(
    n: &mut TestNet,
    c2: ConnId,
    syn: &TSeg,
    ack: u32,
    ts_val: u32,
    sizes: &[usize],
) -> (Vec<u8>, State) {
    let mut got = Vec::new();
    let mut seq = syn.seq.wrapping_add(1);
    for &k in sizes {
        n.inject(&seg(
            VICTIM,
            seq,
            ack,
            FLAG_ACK,
            Some((ts_val, 0)),
            &vec![b'n'; k],
        ));
        seq = seq.wrapping_add(k as u32);
        n.drain();
        got.extend(n.read_all(c2));
    }
    (got, state(n, c2))
}

/// RFC 6191 の 1 つ目の規則で使い直した接続に、前の接続の FIN の写し (番号は前の RCV.NXT - 1 で、新しい接続の
/// 窓の内の 998 byte 先) が `old_ts` の TSval で届いた後、新しい相手が 998 byte と 1002 byte の segment を送ります。
/// 新しい相手の segment の境目が古い FIN の番号に重なる場合です。
fn rule1_reuse_then_old_fin(row: bool, old_ts: impl Fn(u32) -> u32) -> (Vec<u8>, State) {
    let (mut n, l, _, p, _) = time_wait(row, &[]);
    let syn_ts = p.ts_val + 1;
    let syn = new_syn(p.snd.wrapping_sub(1000), syn_ts);
    n.inject(&syn);
    let outs = n.drain();
    let sa = outs[0].clone();
    let c2 = finish(&mut n, l, &syn, &sa, syn_ts);
    n.inject(&seg(
        VICTIM,
        p.snd.wrapping_sub(1),
        p.rcv,
        FLAG_ACK | FLAG_FIN,
        Some((old_ts(syn_ts), p.dut_ts)),
        b"",
    ));
    n.drain();
    new_peer_sends(
        &mut n,
        c2,
        &syn,
        sa.seq.wrapping_add(1),
        syn_ts,
        &[998, 1002],
    )
}

/// 時計が刻む相手なら、前の接続の FIN の写しは PAWS で落ち、新しい接続の stream を途中で終えません。
#[test]
fn rfc6191_rule1_old_fin_from_an_earlier_tick_does_not_end_the_new_stream() {
    for row in [false, true] {
        let (got, st) = rule1_reuse_then_old_fin(row, |syn_ts| syn_ts - 1);
        assert_eq!((got.len(), st), (2000, State::Established), "row={row}");
    }
}

/// 同じ時計の刻みの FIN の写しは PAWS を通り、窓の内の順序外の FIN として残ります。新しい相手のデータの境目が
/// その番号に重なると、核は stream を前の接続の FIN の位置で終えます。
#[test]
#[ignore = "hazard: see PR body"]
fn rfc6191_rule1_old_fin_from_the_same_tick_does_not_end_the_new_stream() {
    for row in [false, true] {
        let (got, st) = rule1_reuse_then_old_fin(row, |syn_ts| syn_ts);
        assert_eq!((got.len(), st), (2000, State::Established), "row={row}");
    }
}
