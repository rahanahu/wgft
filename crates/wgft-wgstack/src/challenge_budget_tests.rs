//! challenge ACK の予算を接続、TIME_WAIT の行、握手の途中の行ごとに分ける直しの受け入れの試験です。
//!
//! 直しは、核の全体で 1 つの予算 (`Shared::challenge_allowed`) を、接続、TIME_WAIT の行、握手の途中の行のそれぞれ
//! の独立した速さの制限に替え、多くの接続で出力を使い切る攻撃に備える核の全体の守り (Resource Guard) を残します。
//! 全体の守りは、接続をまたぐ側路も、他人の接続の回復を止める DoS も作ってはいけません。
//!
//! 仮定する値は 2 つです。直しが別の値を選ぶなら、定数を合わせます。
//!
//! - [`PER_FLOW_INTERVAL`]:1 つの接続か行が ACK を返した後に、次の ACK を返すまでの間隔 (500 ms) です
//! - [`GUARD_MAX_PER_SEC`]:核の全体の challenge ACK の出力の 1 秒あたりの上限 (今の予算の最大と同じ 1500) です
//!
//! 今の main で落ちる試験は `fixed by the follow-up PR` の理由で ignore にしてあります。今も直しの後も通るべき
//! 試験は ignore にしていません。

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

/// 核の全体の challenge ACK の出力の 1 秒あたりの上限として試験が仮定する値です。
const GUARD_MAX_PER_SEC: usize = 1500;

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

// ---- 核の全体の守り ----

/// 全体の守りの試験の表の大きさです。第三者は被害者の接続のほかのすべての枠と行を使い、接続と行ごとの速さの
/// 制限の内でも、需要が [`GUARD_MAX_PER_SEC`] を超えるようにします。
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
            2 * eps.len() > GUARD_MAX_PER_SEC,
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

/// 第三者が手元のすべてで 100 ms ごとに ACK を引こうとしても、核の全体の challenge ACK の出力は 1 秒に
/// [`GUARD_MAX_PER_SEC`] を超えません。
#[test]
fn the_global_guard_bounds_the_total_output() {
    let (mut n, _, mut eps) = guard_net();
    for sec in 0..2u32 {
        let mut total = 0;
        for tick in 0..10u32 {
            raw_advance_to(
                &mut n,
                START
                    + Duration::from_secs(sec.into())
                    + Duration::from_millis(100 * u64::from(tick)),
            );
            total += attacker_round(&mut n, &mut eps);
        }
        assert!(
            total <= GUARD_MAX_PER_SEC,
            "{total} challenge ACKs in second {sec} for {} endpoints",
            eps.len()
        );
    }
    n.check();
}
