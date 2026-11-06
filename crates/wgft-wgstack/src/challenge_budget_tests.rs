//! challenge ACK の予算を接続、TIME_WAIT の行、握手の途中の行ごとに分ける直しの受け入れの試験です。
//!
//! 接続、TIME_WAIT の行、握手の途中の行は、それぞれ独立した速さの制限を持ちます (直す前の核は、全体で 1 つの
//! 予算 `Shared::challenge_allowed` を持っていました)。1 つの流れ (接続か行) の間隔は固定の [`PER_FLOW_INTERVAL`]
//! (500 ms) で、他の流れの状態や流れの数で変わりません。核の全体の資源は、上限のある制御の輪、接続と行の数の上限、メモリの予算が
//! 守ります。challenge ACK だけの全体の上限は置きません。
//!
//! 全体の上限を置かない理由は 3 つです。共有の数え (流れの数を含む) は新しい観測の経路になります。流れの数で
//! 間隔を伸ばすと、多くの接続の下で正しい相手への返事が数十秒遅れます。間隔を伸ばしても、同時に求める N 個の
//! 流れの山は N のままで、守りとしては大きすぎます。
//!
//! 直しが別の間隔を選ぶなら、[`PER_FLOW_INTERVAL`] を合わせます。直す前の核で落ちる試験は
//! `fixed by the follow-up PR` の理由で ignore にしてあります。今も直しの後も通るべき試験は ignore にしていません。

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

use crate::config::Limits;
use crate::dnat_peer_tests::{
    PER_FLOW_INTERVAL, VICTIM, established, finish, new_syn, seg, state, time_wait, to,
};
use crate::tcp::conn::State;
use crate::testnet_tests::{Out, PeerConn, TSeg, TestNet, build_peer, parse_out, show};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use core::time::Duration;

/// 直す前の核が持っていた全体の challenge ACK の予算の 1 秒あたりの最大です。第三者の需要が、全体で 1 つの予算なら
/// 使い切る大きさであることを確かめるのに使います。
const CORE_BUDGET_MAX: usize = 1500;

/// 1 回の試しで同じ segment を送る数です。接続ごとの制限が無ければ、この数の ACK が返ります。
const BURST: usize = 5;

fn acks_to(outs: &[Out], port: u16) -> usize {
    to(outs, port)
        .iter()
        .filter(|o| o.flags == FLAG_ACK)
        .count()
}

/// `seg` を `BURST` 回送り、`port` へ返った ACK の数を返します。
fn burst(n: &mut TestNet, s: &TSeg, port: u16) -> usize {
    let mut got = 0;
    for _ in 0..BURST {
        n.inject(s);
        got += acks_to(&n.drain(), port);
    }
    got
}

// ---- 正しい回復 ----

/// 再起動したクライアントの SYN は半開きの接続から challenge ACK を受け、その ACK の値を番号にした RST で古い接続を
/// 閉じ、SYN の再送で新しい接続を開きます (RFC 5961 4.2、RFC 9293 3.10.7.3)。
#[test]
fn a_rebooted_client_recovers_a_half_open_connection() {
    let (mut n, l, v) = established(&[VICTIM]);
    let (c, p) = v[0];
    n.advance(Duration::from_secs(2));
    let syn = new_syn(
        p.snd.wrapping_add(0x4000_0000),
        p.ts_val.wrapping_add(1 << 20),
    );
    n.inject(&syn);
    let outs = n.drain();
    let (snd_nxt, rcv_nxt) = {
        let t = &n.s.conn(c.slot).t;
        (t.snd_nxt, t.rcv_nxt)
    };
    assert!(
        outs.len() == 1
            && outs[0].flags == FLAG_ACK
            && (outs[0].seq, outs[0].ack) == (snd_nxt, rcv_nxt),
        "the SYN wants one challenge ACK: {}",
        show(&outs)
    );
    n.inject(&seg(VICTIM, outs[0].ack, 0, FLAG_RST, None, b""));
    assert_eq!(state(&n, c), State::Closed, "the client's RST closes it");
    n.advance(Duration::from_secs(1));
    n.inject(&syn);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
        "the retransmitted SYN opens a new connection: {}",
        show(&outs)
    );
    let ts = syn.ts.map_or(0, |(v, _)| v);
    let c2 = finish(&mut n, l, &syn, &outs[0], ts);
    assert_eq!(state(&n, c2), State::Established);
}

/// 窓の内で番号の合わない RST には challenge ACK を返し、その直後 (制限の間隔の内) でも番号の合う RST は接続を
/// 閉じます。番号の合う RST を速さの制限に掛けてはいけません。
#[test]
fn an_exact_rst_resets_right_after_a_challenge_ack() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, p) = v[0];
    n.advance(Duration::from_secs(2));
    n.inject(&seg(VICTIM, p.snd.wrapping_add(1), 0, FLAG_RST, None, b""));
    assert_eq!(acks_to(&n.drain(), VICTIM), 1);
    n.inject(&seg(VICTIM, p.snd, 0, FLAG_RST, None, b""));
    assert_eq!(state(&n, c), State::Closed);
}

// ---- 接続と行ごとの速さ ----

/// 1 つの接続の challenge ACK は `PER_FLOW_INTERVAL` に 1 回です。同じ時刻の RST と SYN と範囲の外の ACK の山には
/// 1 つだけ返し、間隔の手前では返さず、間隔の後に再び 1 つ返します。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn challenge_acks_on_one_connection_follow_the_per_connection_rate() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (_, p) = v[0];
    n.advance(Duration::from_secs(2));
    let rst = seg(VICTIM, p.snd.wrapping_add(1), 0, FLAG_RST, None, b"");
    let syn = new_syn(
        p.snd.wrapping_add(0x4000_0000),
        p.ts_val.wrapping_add(1 << 20),
    );
    let bad_ack = seg(
        VICTIM,
        p.snd,
        p.rcv.wrapping_add(1 << 31),
        FLAG_ACK,
        None,
        b"",
    );
    let first =
        burst(&mut n, &rst, VICTIM) + burst(&mut n, &syn, VICTIM) + burst(&mut n, &bad_ack, VICTIM);
    assert_eq!(first, 1, "one challenge ACK for a burst of {}", 3 * BURST);
    n.advance(PER_FLOW_INTERVAL.saturating_sub(Duration::from_millis(1)));
    assert_eq!(
        burst(&mut n, &rst, VICTIM),
        0,
        "none before the interval ends"
    );
    n.advance(Duration::from_millis(1));
    assert_eq!(
        burst(&mut n, &rst, VICTIM),
        1,
        "one again after the interval"
    );
}

/// TIME_WAIT の行の ACK (使い直しを拒んだ SYN と窓の内の RST への ACK) も行ごとに `PER_FLOW_INTERVAL` に 1 回です。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn time_wait_row_acks_follow_the_per_row_rate() {
    let (mut n, _, _, p, _) = time_wait(true, &[]);
    n.advance(Duration::from_secs(2));
    let refused = new_syn(p.snd.wrapping_sub(5000), 3);
    let rst = seg(VICTIM, p.snd.wrapping_add(1), 0, FLAG_RST, None, b"");
    let first = burst(&mut n, &refused, VICTIM) + burst(&mut n, &rst, VICTIM);
    assert_eq!(first, 1, "one ACK for a burst of {}", 2 * BURST);
    n.advance(PER_FLOW_INTERVAL.saturating_sub(Duration::from_millis(1)));
    assert_eq!(burst(&mut n, &refused, VICTIM), 0);
    n.advance(Duration::from_millis(1));
    assert_eq!(burst(&mut n, &refused, VICTIM), 1);
    assert_eq!(n.s.held().tw_rows, 1);
}

/// 握手の途中の行の ACK (別の番号の SYN と窓の外の segment への ACK) も行ごとに `PER_FLOW_INTERVAL` に 1 回です。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn half_open_row_acks_follow_the_per_row_rate() {
    let mut n = TestNet::new(crate::testnet_tests::small_limits());
    n.listen(80);
    n.advance(Duration::from_secs(2));
    let irs = 1000;
    n.inject(&new_syn(irs, 5000));
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK);
    assert_eq!(n.s.held().syn_rows, 1);
    let other_syn = new_syn(irs.wrapping_add(1 << 31), 5001);
    assert_eq!(
        burst(&mut n, &other_syn, VICTIM),
        1,
        "one ACK for a burst of {BURST}"
    );
    n.advance(PER_FLOW_INTERVAL.saturating_sub(Duration::from_millis(1)));
    n.drain();
    assert_eq!(burst(&mut n, &other_syn, VICTIM), 0);
    n.advance(Duration::from_millis(1));
    n.drain();
    assert_eq!(burst(&mut n, &other_syn, VICTIM), 1);
    assert_eq!(n.s.held().syn_rows, 1);
}

// ---- 流れの受け継ぎと枠の使い直し ----

/// 被害者の接続の 4 つ組です。
fn tuple(port: u16) -> crate::wire::Tuple {
    crate::wire::Tuple {
        laddr: crate::testnet_tests::DUT.to_bits(),
        raddr: crate::testnet_tests::PEER.to_bits(),
        lport: 80,
        rport: port,
    }
}

/// 窓の内で番号の合わない RST を 1 つ送り、`port` へ返った ACK の数を返します。
fn rst_probe(n: &mut TestNet, port: u16, rcv_nxt: u32) -> usize {
    n.inject(&seg(port, rcv_nxt.wrapping_add(1), 0, FLAG_RST, None, b""));
    acks_to(&n.drain(), port)
}

/// 接続が TIME_WAIT の行に移っても、接続の速さの制限は行に受け継がれます。時刻 T の challenge ACK の後、行は
/// T + 100 ms の RST に返さず、T + 500 ms の RST に返します。受け継がなければ、接続を閉じるだけで制限を外せます。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn the_limit_carries_from_a_connection_to_its_time_wait_row() {
    let (mut n, _, v) = established(&[VICTIM]);
    let (c, mut p) = v[0];
    n.advance(Duration::from_secs(2));
    assert_eq!(
        rst_probe(&mut n, VICTIM, p.snd),
        1,
        "the challenge ACK at T"
    );
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    n.peer_fin(&mut p);
    n.drain();
    assert_eq!(n.s.held().tw_rows, 1);
    n.advance(Duration::from_millis(100));
    assert_eq!(
        rst_probe(&mut n, VICTIM, p.snd),
        0,
        "the row inherits the limit"
    );
    n.advance(PER_FLOW_INTERVAL.saturating_sub(Duration::from_millis(100)));
    assert_eq!(
        rst_probe(&mut n, VICTIM, p.snd),
        1,
        "one again after the interval"
    );
}

/// 握手の途中の行が接続になっても、行の速さの制限は接続に受け継がれます。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn the_limit_carries_from_a_half_open_row_to_its_connection() {
    let mut n = TestNet::new(crate::testnet_tests::small_limits());
    let l = n.listen(80);
    n.advance(Duration::from_secs(2));
    let irs = 1000;
    let syn = new_syn(irs, 5000);
    n.inject(&syn);
    let outs = n.drain();
    assert!(outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK);
    let sa = outs[0].clone();
    assert_eq!(
        burst(&mut n, &new_syn(irs.wrapping_add(1 << 31), 5001), VICTIM),
        1,
        "the row ACK at T"
    );
    let c = finish(&mut n, l, &syn, &sa, 5002);
    assert_eq!(state(&n, c), State::Established);
    let rcv_nxt = irs.wrapping_add(1);
    n.advance(Duration::from_millis(100));
    assert_eq!(
        rst_probe(&mut n, VICTIM, rcv_nxt),
        0,
        "the connection inherits the limit"
    );
    n.advance(PER_FLOW_INTERVAL.saturating_sub(Duration::from_millis(100)));
    assert_eq!(
        rst_probe(&mut n, VICTIM, rcv_nxt),
        1,
        "one again after the interval"
    );
}

/// 被害者の TIME_WAIT の行が ACK を返してから外れ、第三者の新しい行が同じ枠を使っても (空きの枠は決まった順の
/// LIFO です)、新しい行はすぐに ACK を返します。枠が前の流れの時刻を受け継げば、第三者は他人の行が最近 ACK を
/// 返したかを観測できます。
#[test]
fn a_reused_time_wait_slot_does_not_inherit_the_previous_rows_limit() {
    let (mut n, l, _, p, _) = time_wait(true, &[]);
    n.advance(Duration::from_secs(2));
    let victim_id = n.s.s.tw.find(tuple(VICTIM)).expect("the victim's row");
    assert_eq!(
        rst_probe(&mut n, VICTIM, p.snd),
        1,
        "the victim's row ACK at T"
    );
    n.inject(&seg(VICTIM, p.snd, 0, FLAG_RST, None, b""));
    assert_eq!(
        n.s.held().tw_rows,
        0,
        "the exact RST removes the victim's row"
    );
    n.advance(Duration::from_millis(100));
    let mut pa = n.handshake(crate::dnat_peer_tests::ATTACKER, 80, true, true);
    let ca = n.accept(l);
    n.drain();
    n.s.close_conn(n.now, ca);
    let outs = n.drain();
    pa.absorb(&outs);
    n.peer_ack(&mut pa, &[]);
    n.peer_fin(&mut pa);
    n.drain();
    let id = n.s.s.tw.find(tuple(crate::dnat_peer_tests::ATTACKER));
    assert_eq!(
        id,
        Some(victim_id),
        "the attacker's row takes the victim's slot"
    );
    assert_eq!(
        rst_probe(&mut n, crate::dnat_peer_tests::ATTACKER, pa.snd),
        1,
        "the new row answers at once"
    );
}

/// 握手の途中の行の枠の使い直しも、前の行の時刻を受け継ぎません。
#[test]
fn a_reused_half_open_slot_does_not_inherit_the_previous_rows_limit() {
    let attacker = crate::dnat_peer_tests::ATTACKER;
    let mut n = TestNet::new(crate::testnet_tests::small_limits());
    n.listen(80);
    n.advance(Duration::from_secs(2));
    let irs = 1000;
    n.inject(&new_syn(irs, 5000));
    n.drain();
    let victim_id = n.s.s.syn.find(tuple(VICTIM)).expect("the victim's row");
    n.inject(&new_syn(irs.wrapping_add(1 << 31), 5001));
    assert_eq!(acks_to(&n.drain(), VICTIM), 1, "the victim's row ACK at T");
    n.inject(&seg(VICTIM, irs.wrapping_add(1), 0, FLAG_RST, None, b""));
    assert_eq!(
        n.s.held().syn_rows,
        0,
        "the exact RST removes the victim's row"
    );
    n.advance(Duration::from_millis(100));
    n.inject(&new_syn(irs, 5000).with_port(attacker));
    n.drain();
    assert_eq!(
        n.s.s.syn.find(tuple(attacker)),
        Some(victim_id),
        "the attacker's row takes the victim's slot"
    );
    n.inject(&new_syn(irs.wrapping_add(1 << 31), 5001).with_port(attacker));
    assert_eq!(
        acks_to(&n.drain(), attacker),
        1,
        "the new row answers at once"
    );
}

/// 接続の枠の使い直しも、前の接続の時刻を受け継ぎません。
#[test]
fn a_reused_connection_slot_does_not_inherit_the_previous_connections_limit() {
    let attacker = crate::dnat_peer_tests::ATTACKER;
    let (mut n, l, v) = established(&[VICTIM]);
    let (c, p) = v[0];
    n.advance(Duration::from_secs(2));
    assert_eq!(
        rst_probe(&mut n, VICTIM, p.snd),
        1,
        "the victim's challenge ACK at T"
    );
    n.inject(&seg(VICTIM, p.snd, 0, FLAG_RST, None, b""));
    assert_eq!(state(&n, c), State::Closed);
    n.s.close_conn(n.now, c);
    n.drain();
    n.advance(Duration::from_millis(100));
    let pa = n.handshake(attacker, 80, true, true);
    let ca = n.accept(l);
    n.drain();
    assert_eq!(
        ca.slot, c.slot,
        "the attacker's connection takes the victim's slot"
    );
    assert_eq!(
        rst_probe(&mut n, attacker, pa.snd),
        1,
        "the new connection answers at once"
    );
}

/// 接続の中身の無い窓の外の segment への ACK は、challenge ACK と 1 つの速さの制限を分け合います。どちらを先に
/// 返しても、もう一方は `PER_FLOW_INTERVAL` の間は返らず、その後に返ります。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn out_of_window_acks_share_the_limit_with_challenge_acks() {
    for challenge_first in [true, false] {
        let (mut n, _, v) = established(&[VICTIM]);
        let (_, mut p) = v[0];
        n.advance(Duration::from_secs(2));
        let rcv_nxt = p.snd;
        let mut oow = |n: &mut TestNet| {
            let mut s = p.seg(FLAG_ACK, &[]);
            s.seq = s.seq.wrapping_add(1 << 31);
            n.inject(&s);
            acks_to(&n.drain(), VICTIM)
        };
        let first = if challenge_first {
            rst_probe(&mut n, VICTIM, rcv_nxt)
        } else {
            oow(&mut n)
        };
        assert_eq!(
            first, 1,
            "challenge_first={challenge_first}: the first ACK at T"
        );
        n.advance(Duration::from_millis(100));
        let second = if challenge_first {
            oow(&mut n)
        } else {
            rst_probe(&mut n, VICTIM, rcv_nxt)
        };
        assert_eq!(
            second, 0,
            "challenge_first={challenge_first}: the other kind shares the limit"
        );
        n.advance(PER_FLOW_INTERVAL.saturating_sub(Duration::from_millis(100)));
        let third = if challenge_first {
            oow(&mut n)
        } else {
            rst_probe(&mut n, VICTIM, rcv_nxt)
        };
        assert_eq!(
            third, 1,
            "challenge_first={challenge_first}: one again after the interval"
        );
    }
}

// ---- 核の全体の守り ----

/// 全体の守りの試験の表の大きさです。第三者は被害者の接続のほかのすべての枠と行を使い、接続と行ごとの速さの
/// 制限の内でも、需要が [`CORE_BUDGET_MAX`] を超えるようにします。
fn guard_limits() -> Limits {
    Limits {
        max_flows: 64,
        accept_queue: 16,
        syn_rows: 256,
        tw_rows: 2048,
        ..Limits::default()
    }
}

/// 第三者の手元の 1 つです。
#[derive(Clone, Copy)]
enum Endpoint {
    /// 確立した接続です。SYN で challenge ACK を引きます。
    Conn(PeerConn),
    /// TIME_WAIT の行のポートです。TS.Recent より古い TSval の SYN (使い直しの拒み) で ACK を引きます。
    Tw(u16),
    /// 握手の途中の行のポートと相手の ISN です。別の番号の SYN で ACK を引きます。
    Half(u16, u32),
}

impl Endpoint {
    fn port(&self) -> u16 {
        match *self {
            Self::Conn(p) => p.sport,
            Self::Tw(port) | Self::Half(port, _) => port,
        }
    }
}

/// 不変条件の確かめを省いて packet を渡し、出力を読みます。行と枠が多いので、確かめを毎回すると遅すぎます。
fn raw(n: &mut TestNet, s: &TSeg) -> Vec<Out> {
    n.s.handle_packet(n.now, &build_peer(s));
    raw_drain(n)
}

fn raw_drain(n: &mut TestNet) -> Vec<Out> {
    let mut b = vec![0u8; 2048];
    let mut v = Vec::new();
    while let Some(k) = n.s.poll_transmit(n.now, &mut b) {
        v.push(parse_out(&b[..k]));
    }
    v
}

fn raw_advance_to(n: &mut TestNet, at: Duration) {
    n.now = crate::time::Time::ZERO + at;
    n.s.handle_timeout(n.now);
    raw_drain(n);
}

/// `port` から接続を開いて受け取り、相手の側を返します。開けなければ `None` です。
fn raw_open(
    n: &mut TestNet,
    l: crate::stack::ListenerId,
    port: u16,
) -> Option<(crate::ConnId, PeerConn)> {
    let mut p = PeerConn {
        sport: port,
        dport: 80,
        iss: 1000,
        snd: 1001,
        rcv: 0,
        dut_iss: 0,
        ts: true,
        ts_val: 5000,
        dut_ts: 0,
        wnd: 65535,
    };
    let outs = raw(n, &new_syn(p.iss, p.ts_val).with_port(port));
    let sa = outs
        .iter()
        .find(|o| o.rport == port && o.flags == FLAG_SYN | FLAG_ACK)?;
    p.dut_iss = sa.seq;
    p.rcv = sa.seq.wrapping_add(1);
    p.dut_ts = sa.ts.map_or(0, |(v, _)| v);
    let s = p.seg(FLAG_ACK, &[]);
    raw(n, &s);
    let c = n.s.accept(n.now, l).ok()?.0;
    raw_drain(n);
    Some((c, p))
}

/// 被害者の 1 つの接続と、残りのすべての枠と行を第三者の手元にした核です。どの呼び出しも同じ核を作ります。
fn guard_net() -> (TestNet, PeerConn, Vec<Endpoint>) {
    let limits = guard_limits();
    let mut n = TestNet::with_seed(limits, [7; 64]);
    let l = n.listen(80);
    let (_, victim) = raw_open(&mut n, l, VICTIM).expect("the victim's connection");
    let mut eps = Vec::new();
    // TIME_WAIT の行:接続を開き、手放し、相手の FIN で行に移します。
    for i in 0..limits.tw_rows {
        let port = 1024 + i as u16;
        let Some((c, mut p)) = raw_open(&mut n, l, port) else {
            panic!(
                "no connection for TIME_WAIT row {i}: held {:?} stats {:?}",
                n.s.held(),
                n.s.stats()
            );
        };
        n.s.close_conn(n.now, c);
        let outs = raw_drain(&mut n);
        p.absorb(&outs);
        let s = p.seg(FLAG_ACK, &[]);
        raw(&mut n, &s);
        let s = p.seg(FLAG_ACK | FLAG_FIN, &[]);
        raw(&mut n, &s);
        eps.push(Endpoint::Tw(port));
    }
    assert_eq!(n.s.held().tw_rows, limits.tw_rows);
    // 確立した接続:被害者の分を除いた枠のすべてです。
    for i in 0..limits.max_flows - 1 {
        let port = 20000 + i as u16;
        match raw_open(&mut n, l, port) {
            Some((_, p)) => eps.push(Endpoint::Conn(p)),
            None => break,
        }
    }
    // 握手の途中の行:最後の ACK を返さない SYN です。行を作れた分だけ数えます。
    for i in 0..limits.syn_rows {
        let port = 30000 + i as u16;
        let before = n.s.held().syn_rows;
        raw(&mut n, &new_syn(7000, 5000).with_port(port));
        if n.s.held().syn_rows == before {
            break;
        }
        eps.push(Endpoint::Half(port, 7000));
    }
    let count = |f: fn(&Endpoint) -> bool| eps.iter().filter(|e| f(e)).count();
    assert_eq!(
        (
            count(|e| matches!(e, Endpoint::Tw(_))),
            count(|e| matches!(e, Endpoint::Conn(_))),
            count(|e| matches!(e, Endpoint::Half(..))),
        ),
        (limits.tw_rows, limits.max_flows - 1, limits.syn_rows / 2),
        "the attacker's TIME_WAIT rows, connections and half-open rows"
    );
    n.check();
    (n, victim, eps)
}

trait WithPort {
    fn with_port(self, port: u16) -> Self;
}

impl WithPort for TSeg {
    fn with_port(mut self, port: u16) -> Self {
        self.sport = port;
        self
    }
}

/// 第三者が手元のすべてで ACK を 1 つずつ引こうとし、返った ACK の数を返します。
fn attacker_round(n: &mut TestNet, eps: &mut [Endpoint]) -> usize {
    let mut got = 0;
    for e in eps.iter_mut() {
        let port = e.port();
        let s = match e {
            Endpoint::Conn(p) => p.seg(FLAG_SYN, &[]),
            Endpoint::Tw(port) => new_syn(1, 1).with_port(*port),
            Endpoint::Half(port, irs) => new_syn(irs.wrapping_add(1 << 31), 5000).with_port(*port),
        };
        got += acks_to(&raw(n, &s), port);
    }
    got
}

/// 守りが試しの始めに使う時刻です。表を作る間の時刻と別の秒にします。
const START: Duration = Duration::from_secs(10);

/// 第三者が手元のすべてを使って全体の守りを働かせても、他人の接続に送った偽の RST が challenge ACK を引いたか
/// どうかは、第三者が自分の手元で数える ACK の数に現れてはいけません。全体の守りが、第三者が使い切って数えられる
/// 1 つの決まった数えなら、被害者の接続が使った 1 つの差が現れてこの試験は落ちます。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn the_global_guard_does_not_reveal_another_connections_window() {
    let observe = |hit: bool| {
        let (mut n, victim, mut eps) = guard_net();
        assert!(
            2 * eps.len() > CORE_BUDGET_MAX,
            "the attacker's demand must exceed the guard"
        );
        raw_advance_to(&mut n, START);
        let guess = if hit {
            victim.snd.wrapping_add(100)
        } else {
            victim.snd.wrapping_add(1 << 31)
        };
        for _ in 0..BURST {
            raw(&mut n, &seg(VICTIM, guess, 0, FLAG_RST, None, b""));
        }
        let mut got = attacker_round(&mut n, &mut eps);
        raw_advance_to(&mut n, START + PER_FLOW_INTERVAL);
        got += attacker_round(&mut n, &mut eps);
        got
    };
    let (hit, miss) = (observe(true), observe(false));
    assert_eq!(
        hit, miss,
        "the attacker's count reveals the victim's window through the global guard ({hit} on a hit, {miss} on a miss)"
    );
}

/// 第三者が手元のすべてで全体の守りを働かせ続けても、しばらく challenge ACK を返していない被害者の接続は、再起動
/// したクライアントの SYN に challenge ACK を返します。全体の守りが他人の接続の回復を止めてはいけません。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn the_global_guard_does_not_silence_an_idle_connection() {
    let (mut n, victim, mut eps) = guard_net();
    raw_advance_to(&mut n, START);
    attacker_round(&mut n, &mut eps);
    raw_advance_to(&mut n, START + PER_FLOW_INTERVAL);
    attacker_round(&mut n, &mut eps);
    let syn = new_syn(
        victim.snd.wrapping_add(0x4000_0000),
        victim.ts_val.wrapping_add(1 << 20),
    );
    let got = acks_to(&raw(&mut n, &syn), VICTIM);
    assert_eq!(
        got, 1,
        "the victim's half-open recovery got no challenge ACK under the guard"
    );
}

/// 試しの刻みです。第三者は刻みごとに手元のすべてで ACK を引こうとします。
const TICK: Duration = Duration::from_millis(100);
/// 大量の試しを続ける刻みの数 (3 秒) です。
const MASS_TICKS: u32 = 30;
/// 待ち受けの無いポートです。ここへの SYN には制御の輪から RST を返します。
const CLOSED_PORT: u16 = 81;
/// 刻みごとに待ち受けの無いポートへ送る SYN と、echo request の数です。合わせて制御の輪の枠より多くします。
const RSTS_PER_TICK: usize = 300;
const ECHOS_PER_TICK: usize = 100;

/// 刻み `k` の時刻です。
fn tick_at(k: u32) -> Duration {
    START + TICK * k
}

/// 不変条件の確かめも出力の読み出しもせずに packet を渡します。出力は刻みの終わりにまとめて読みます。
fn push(n: &mut TestNet, pkt: &[u8]) {
    n.s.handle_packet(n.now, pkt);
}

/// 第三者の手元 `e` の ACK を引く segment です。
fn trigger(e: &mut Endpoint) -> TSeg {
    match e {
        Endpoint::Conn(p) => p.seg(FLAG_SYN, &[]),
        Endpoint::Tw(port) => new_syn(1, 1).with_port(*port),
        Endpoint::Half(port, irs) => new_syn(irs.wrapping_add(1 << 31), 5000).with_port(*port),
    }
}

/// この thread の CPU の時間 (/proc/thread-self/stat の utime と stime、clock tick の単位) です。読めなければ
/// `None` です。
fn thread_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").ok()?;
    let rest = stat.rsplit_once(") ")?.1;
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// 大量の試しの測った値です。
#[derive(Debug, Default)]
struct Mass {
    /// 1 秒ごとの、第三者と被害者への ACK の数です。
    acks_per_sec: Vec<usize>,
    /// 刻みの終わり (読み出しの前) の制御の輪の枠の数の最大です。
    ring_max: usize,
    ring_slots: usize,
    /// 刻みごとに返った RST の数の最小と、echo の応答の数の最大です。
    rst_min: usize,
    echo_max: usize,
    /// 捨てた数の差分です:(合計、TCP の制御、ICMP の誤り、echo の応答)。
    drops: (u64, u64, u64, u64),
    /// 1 つの流れが `PER_FLOW_INTERVAL` より短い間に返した ACK の数です。
    interval_violations: usize,
    /// 0 刻みから `PER_FLOW_INTERVAL` ごとの刻みに ACK を 1 つずつ受けた、という予定から外れた流れの数です。
    off_schedule: usize,
    /// 刻みの中で、流れが受けた segment より多く返した ACK の数です。
    amplified: usize,
    /// 刻みの外 (タイマー) で第三者と被害者へ返した ACK だけの segment の数です。
    timer_acks: usize,
    wall: Duration,
    cpu_ticks: Option<u64>,
}

/// 第三者の手元のすべてと被害者が刻みごとに同時に ACK を引こうとし、同じ刻みに制御の輪を満たす RST と echo を
/// 混ぜます。出力は刻みの終わりにまとめて読みます。
fn mass_run() -> Mass {
    use std::collections::HashMap;
    let (mut n, victim, mut eps) = guard_net();
    let mut m = Mass {
        ring_slots: guard_limits().ctl_slots,
        rst_min: usize::MAX,
        ..Mass::default()
    };
    let flows: Vec<u16> = eps.iter().map(Endpoint::port).chain([VICTIM]).collect();
    let mut acked: HashMap<u16, Vec<u32>> = HashMap::new();
    let before = n.s.stats();
    let victim_rst = seg(VICTIM, victim.snd.wrapping_add(1), 0, FLAG_RST, None, b"");
    let echo = {
        let mut msg = vec![0u8; 64];
        msg[0] = crate::icmp::ECHO;
        msg
    };
    let every_echo = eps.len() / ECHOS_PER_TICK;
    let every_rst = eps.len() / RSTS_PER_TICK;
    let cpu0 = thread_cpu_ticks();
    let t0 = std::time::Instant::now();
    for k in 0..MASS_TICKS {
        n.now = crate::time::Time::ZERO + tick_at(k);
        n.s.handle_timeout(n.now);
        // 刻みの外の出力 (握手の途中の行の SYN-ACK の再送など) を読みます。
        for o in raw_drain(&mut n) {
            if o.flags == FLAG_ACK && flows.contains(&o.rport) {
                m.timer_acks += 1;
            }
        }
        for (i, e) in eps.iter_mut().enumerate() {
            push(&mut n, &build_peer(&trigger(e)));
            if i % every_echo == 0 {
                push(
                    &mut n,
                    &crate::testnet_tests::build_icmp(crate::testnet_tests::PEER, &echo),
                );
            }
            if i % every_rst == 0 {
                let mut s = new_syn(9, 9).with_port(60000 + (i / every_rst) as u16);
                s.dport = CLOSED_PORT;
                push(&mut n, &build_peer(&s));
            }
        }
        push(&mut n, &build_peer(&victim_rst));
        m.ring_max = m.ring_max.max(n.s.held().ctl_queued);
        let mut per_flow: HashMap<u16, usize> = HashMap::new();
        let (mut rsts, mut echos) = (0, 0);
        let mut b = vec![0u8; 2048];
        while let Some(len) = n.s.poll_transmit(n.now, &mut b) {
            let ip = crate::wire::parse_ipv4(&b[..len]).expect("a bad IPv4 packet");
            if ip.proto == crate::wire::PROTO_ICMP {
                echos += 1;
                continue;
            }
            let o = parse_out(&b[..len]);
            if o.lport == CLOSED_PORT && o.has(FLAG_RST) {
                rsts += 1;
            } else if o.flags == FLAG_ACK && flows.contains(&o.rport) {
                *per_flow.entry(o.rport).or_default() += 1;
            }
        }
        for (&port, &c) in &per_flow {
            // 刻みの中で、どの流れも segment を 1 つだけ受けました。
            m.amplified += c.saturating_sub(1);
            let ticks = acked.entry(port).or_default();
            if let Some(&j) = ticks.last()
                && TICK * (k - j) < PER_FLOW_INTERVAL
            {
                m.interval_violations += c;
            }
            ticks.push(k);
        }
        let acks: usize = per_flow.values().sum();
        let sec = (TICK * k).as_secs() as usize;
        if m.acks_per_sec.len() <= sec {
            m.acks_per_sec.push(0);
        }
        m.acks_per_sec[sec] += acks;
        m.rst_min = m.rst_min.min(rsts);
        m.echo_max = m.echo_max.max(echos);
        n.s.check_invariants().unwrap();
    }
    m.wall = t0.elapsed();
    let per = (PER_FLOW_INTERVAL.as_millis() / TICK.as_millis()) as usize;
    let want: Vec<u32> = (0..MASS_TICKS).step_by(per).collect();
    m.off_schedule = flows.iter().filter(|p| acked.get(p) != Some(&want)).count();
    m.cpu_ticks = cpu0.zip(thread_cpu_ticks()).map(|(a, b)| b - a);
    let after = n.s.stats();
    m.drops = (
        after.ctl_dropped - before.ctl_dropped,
        after.ctl_dropped_tcp - before.ctl_dropped_tcp,
        after.ctl_dropped_icmp_error - before.ctl_dropped_icmp_error,
        after.ctl_dropped_echo - before.ctl_dropped_echo,
    );
    println!(
        "mass: {} flows, {MASS_TICKS} ticks of {TICK:?}; ACKs per second {:?}; ring max {} of {}; \
         RSTs per tick >= {}; echo replies per tick <= {}; drops (total, tcp, icmp_error, echo) {:?}; \
         interval violations {}; flows off the per-flow schedule {}; amplified {}; timer ACKs {}; loop wall {:?}, thread CPU {:?} clock ticks",
        flows.len(),
        m.acks_per_sec,
        m.ring_max,
        m.ring_slots,
        m.rst_min,
        m.echo_max,
        m.drops,
        m.interval_violations,
        m.off_schedule,
        m.amplified,
        m.timer_acks,
        m.wall,
        m.cpu_ticks
    );
    m
}

/// 大量の試しの下でも、設計が保証することを確かめます。ACK は受けた segment への返事だけで増えず (刻みの中で
/// 流れごとに 1 つまで、刻みの外では返さない)、制御の輪は枠の数を超えず、捨てた数は種類ごとに数えて合計に合い、
/// echo の洪水の下でも RST は echo の上限の外の枠 (`ctl_slots` - `ctl_slots / 4`) を使えます。RST が捨てられない
/// ことは求めません。測った値は `--nocapture` で表示します。
#[test]
fn mass_requests_keep_the_ring_rules_and_never_amplify() {
    let m = mass_run();
    assert_eq!(m.amplified, 0, "more ACKs than received segments");
    assert_eq!(m.timer_acks, 0, "ACK-only segments sent from timers");
    assert!(
        m.ring_max <= m.ring_slots,
        "ring {} of {}",
        m.ring_max,
        m.ring_slots
    );
    let (total, tcp, icmp_error, echo) = m.drops;
    assert_eq!(
        total,
        tcp + icmp_error + echo,
        "drops by kind {:?}",
        m.drops
    );
    let echo_cap = (m.ring_slots / 4).max(1);
    let reserved = m.ring_slots - echo_cap;
    assert!(
        m.rst_min >= RSTS_PER_TICK.min(reserved),
        "only {} RSTs in a tick; the ring promises {reserved} slots outside the echo cap",
        m.rst_min
    );
    assert!(
        m.echo_max <= echo_cap,
        "{} echo replies in a tick",
        m.echo_max
    );
}

/// 大量の試しの下でも、1 つの流れは `PER_FLOW_INTERVAL` に ACK を 1 つまでしか返さず、他の流れの数に関わらず
/// `PER_FLOW_INTERVAL` ごとに必ず 1 つ返します (0、5、10 … 刻み)。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn mass_requests_get_one_ack_per_flow_per_interval() {
    let m = mass_run();
    assert_eq!(m.interval_violations, 0, "ACKs inside a flow's interval");
    assert_eq!(m.off_schedule, 0, "flows not answered once per interval");
}

/// 被害者の接続が 100 ms ごとに窓の内の RST を受けた時に ACK を返した刻みを返します。`others` なら、同じ刻みに
/// 第三者の手元のすべても ACK を引こうとします。
fn victim_ack_ticks(others: bool) -> Vec<u32> {
    let (mut n, victim, mut eps) = if others {
        guard_net()
    } else {
        let mut n = TestNet::with_seed(guard_limits(), [7; 64]);
        let l = n.listen(80);
        let (_, victim) = raw_open(&mut n, l, VICTIM).expect("the victim's connection");
        (n, victim, Vec::new())
    };
    let rst = seg(VICTIM, victim.snd.wrapping_add(1), 0, FLAG_RST, None, b"");
    let mut got = Vec::new();
    for k in 0..MASS_TICKS {
        raw_advance_to(&mut n, tick_at(k));
        attacker_round(&mut n, &mut eps);
        if acks_to(&raw(&mut n, &rst), VICTIM) > 0 {
            got.push(k);
        }
    }
    got
}

/// 1 つの流れの間隔は、他の流れが 0 でも、2000 を超える流れが同じ刻みに求めていても同じです。100 ms ごとの
/// 試しで、ACK は 500 ms ごと (5 刻みごと) に返ります。
#[test]
#[ignore = "fixed by the follow-up PR"]
fn one_flows_interval_does_not_depend_on_other_flows() {
    let per = (PER_FLOW_INTERVAL.as_millis() / TICK.as_millis()) as usize;
    let want: Vec<u32> = (0..MASS_TICKS).step_by(per).collect();
    let alone = victim_ack_ticks(false);
    let crowded = victim_ack_ticks(true);
    assert_eq!(alone, want, "alone");
    assert_eq!(crowded, want, "with 2239 other flows");
}
