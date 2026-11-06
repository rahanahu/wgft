//! 整数の溢れの監査 (RTT の標本と回復の窓) の反例の試験です。
//!
//! どちらも呼び手や相手が起こせる入力で、overflow-checks の有無の両方で同じ主張になるよう、panic を期待せず、
//! 安全側の結果 (値が範囲に収まる、早すぎる再送が起きない) を確かめます。
//!
//! - 握手の RTT を測らなかった接続 (SYN-ACK を再送した) に、呼び手が時計を `Time::MAX` に跳ばして ACK を渡す
//! - SACK の無い接続の回復の間に、同じ重複 ACK を 300 万回以上受ける (窓が `u32` を回る)

#![expect(
    clippy::disallowed_macros,
    clippy::many_single_char_names,
    reason = "test helpers and test data"
)]

use crate::stack::{MAX_NOW, ns};
use crate::tcp::{RTO_MAX, RTO_MIN};
use crate::testnet_tests::{DUT, TEST_MTU, TestNet, build_peer, small_limits};
use crate::{Config, Congestion, ConnId, Time};
use core::time::Duration;

/// 窓の上限です。核が許す最大の窓 (`1 << 30`) です。
const CWND_MAX: u32 = 1 << 30;

fn net(cc: Congestion) -> TestNet {
    let config = Config {
        limits: small_limits(),
        congestion: cc,
        ..Config::new(DUT, TEST_MTU)
    };
    TestNet::with_config(config, [7; 64])
}

/// SYN-ACK を再送させて握手の RTT を測らせない接続です。
fn unmeasured_handshake(n: &mut TestNet, ts: bool) -> (ConnId, crate::testnet_tests::PeerConn) {
    let l = n.listen(80);
    let mut p = n.syn_sack(40000, 80, ts, true, true);
    n.advance(Duration::from_millis(1500));
    n.drain();
    n.peer_ack(&mut p, &[]);
    let c = n.accept(l);
    n.drain();
    (c, p)
}

/// 1000 byte を書いて送らせ、相手が受けた分を確認する ACK を渡します。
fn send_and_ack(n: &mut TestNet, c: ConnId, p: &mut crate::testnet_tests::PeerConn) {
    assert_eq!(n.s.write(n.now, c, &[0u8; 1000]).unwrap(), 1000);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(p, &[]);
}

/// 時計が `Time::MAX` に跳んだ後の RTT の推定と期限が範囲に収まり、跳んだ時刻で早すぎる再送が起きません。
fn clock_jump_to_max(cc: Congestion, ts: bool) {
    let mut n = net(cc);
    let (c, mut p) = unmeasured_handshake(&mut n, ts);
    // 跳ぶ前に送った segment を、跳んだ時刻の ACK が確認する。これが握手の後の最初の標本になる
    assert_eq!(n.s.write(n.now, c, &[0u8; 1000]).unwrap(), 1000);
    let outs = n.drain();
    p.absorb(&outs);
    n.now = Time::MAX;
    n.peer_ack(&mut p, &[]);
    // その後に跳んだ時刻でもう一度送って 2 つ目の標本を取る
    for round in 0..2 {
        if round > 0 {
            send_and_ack(&mut n, c, &mut p);
        }
        let t = &*n.s.conn(c.slot).t;
        let (srtt, rttvar, rto) = (t.srtt, t.rttvar, t.rto);
        assert!(
            srtt >= 0 && rttvar >= 0,
            "{cc:?} ts {ts} round {round}: srtt {srtt} rttvar {rttvar}"
        );
        assert!(
            srtt <= RTO_MAX && rttvar <= RTO_MAX,
            "{cc:?} ts {ts} round {round}: srtt {srtt} rttvar {rttvar} beyond RTO_MAX"
        );
        assert!(
            (RTO_MIN..=RTO_MAX).contains(&rto),
            "{cc:?} ts {ts} round {round}: rto {rto}"
        );
        assert!(
            t.rack_rtt >= 0,
            "{cc:?} ts {ts} round {round}: rack_rtt {}",
            t.rack_rtt
        );
    }
    // もう一度送り、同じ時刻のままタイマーを回しても、RTO、TLP、RACK のどれも再送しない
    assert_eq!(n.s.write(n.now, c, &[0u8; 1000]).unwrap(), 1000);
    let first = n.drain();
    assert!(
        first.iter().any(|o| !o.payload.is_empty()),
        "{cc:?} ts {ts}: the data goes out"
    );
    n.s.handle_timeout(n.now);
    let again = n.drain();
    assert!(
        again.iter().all(|o| o.payload.is_empty()),
        "{cc:?} ts {ts}: a retransmission fired at the instant of the send: {}",
        crate::testnet_tests::show(&again)
    );
    let t = &*n.s.conn(c.slot).t;
    assert!(
        t.tlp_at == 0 || t.tlp_at >= ns(n.now).min(MAX_NOW),
        "{cc:?} ts {ts}: the tail loss probe is due at {} before now {}",
        t.tlp_at,
        ns(n.now).min(MAX_NOW)
    );
}

#[test]
fn clock_jump_to_max_keeps_the_rtt_estimate_in_range() {
    for cc in [Congestion::NewReno, Congestion::Cubic] {
        for ts in [false, true] {
            clock_jump_to_max(cc, ts);
        }
    }
}

/// 時計が `Time::MAX` に跳んでも、ほどほどの跳び (25 日) は今の実装でも範囲に収まります。
#[test]
fn clock_jump_of_days_keeps_the_rtt_estimate_in_range() {
    let mut n = net(Congestion::NewReno);
    let (c, mut p) = unmeasured_handshake(&mut n, false);
    send_and_ack(&mut n, c, &mut p);
    n.advance(Duration::from_hours(25 * 24));
    for _ in 0..2 {
        send_and_ack(&mut n, c, &mut p);
        let t = &*n.s.conn(c.slot).t;
        assert!(
            t.srtt >= 0 && t.rttvar >= 0,
            "srtt {} rttvar {}",
            t.srtt,
            t.rttvar
        );
        assert!((RTO_MIN..=RTO_MAX).contains(&t.rto), "rto {}", t.rto);
    }
}

/// SACK の無い接続の回復の間に同じ重複 ACK を `count` 回受け、窓が範囲に収まり、回復の後も送れることを確かめます。
fn dup_ack_flood(cc: Congestion, count: u32) {
    let mut n = net(cc);
    let (c, mut p) = n.accepted_sack(false, false);
    assert_eq!(n.s.write(n.now, c, &vec![0u8; 20_000]).unwrap(), 20_000);
    let outs = n.drain();
    p.absorb(&outs);
    // 何も確認しない ACK です。
    let pkt = {
        let seg = p.seg(crate::wire::FLAG_ACK, &[]);
        build_peer(&seg)
    };
    let mut out = vec![0u8; TEST_MTU];
    let mut max_cwnd = 0u32;
    for i in 0..count {
        n.s.handle_packet(n.now, &pkt);
        while n.s.poll_transmit(n.now, &mut out).is_some() {}
        if i % 4096 == 0 || i + 1 == count {
            let cw = n.s.conn(c.slot).t.cwnd;
            max_cwnd = max_cwnd.max(cw);
            assert!(
                cw <= CWND_MAX,
                "{cc:?}: cwnd {cw} after {i} duplicate ACKs (largest seen {max_cwnd})"
            );
        }
    }
    n.check();
    let cw = n.s.conn(c.slot).t.cwnd;
    assert!(
        (1..=CWND_MAX).contains(&cw),
        "{cc:?}: cwnd {cw} after {count} duplicate ACKs"
    );
    // 回復から抜けても接続は生きていて、送れる
    n.drain();
    let ack = p.seg(crate::wire::FLAG_ACK, &[]);
    n.inject(&ack);
    n.advance(Duration::from_secs(1));
    assert!(
        n.s.write(n.now, c, &[0u8; 100]).is_ok(),
        "{cc:?}: the connection still accepts data"
    );
}

/// 重複 ACK が少ない間の窓の増え方は今の実装でも範囲に収まります (流れの確かめ)。
#[test]
fn dup_ack_flood_of_thousands_keeps_cwnd_bounded() {
    dup_ack_flood(Congestion::NewReno, 10_000);
}

/// NewReno の回復の間に 3,200,000 回の重複 ACK を受けても、窓は回り込みません。
#[test]
fn dup_ack_flood_of_millions_keeps_cwnd_bounded() {
    dup_ack_flood(Congestion::NewReno, 3_200_000);
}

/// 網が作れる timestamp の標本は切りません。TSecr が 200 s 前の TSval を指す ACK の標本は、RTO の上限 (120 s) を超えて
/// いても、そのまま SRTT に入ります (RFC 6298 2.3 は網の標本に上限を課さない。標本を `RTO_MAX` で切り直すと
/// この試験が落ちる)。
#[test]
fn timestamp_sample_of_200_seconds_reaches_srtt_unchanged() {
    use crate::tcp::{SEC, ts_clock};
    for cc in [Congestion::NewReno, Congestion::Cubic] {
        let mut n = net(cc);
        let (c, _p) = n.accepted(true);
        n.advance(Duration::from_secs(300));
        let now = ns(n.now);
        let mut v = n.s.conn(c.slot);
        assert!(v.t.ts_ok, "{cc:?}: timestamps are on");
        v.t.has_rtt = false;
        let ecr = ts_clock(now)
            .wrapping_add(v.t.ts_offset)
            .wrapping_sub(200_000);
        let r = v.ts_rtt_sample(ecr, now);
        assert_eq!(r, 200 * SEC, "{cc:?}: the sample returned");
        let t = &*v.t;
        assert_eq!(t.srtt, 200 * SEC, "{cc:?}: srtt");
        assert_eq!(t.rttvar, 100 * SEC, "{cc:?}: rttvar");
        assert_eq!(t.rto, RTO_MAX, "{cc:?}: rto is still capped");
        // 2 つ目の標本も同じ式で入る
        let r = v.ts_rtt_sample(ecr, now);
        assert_eq!(r, 200 * SEC);
        assert_eq!(v.t.srtt, 200 * SEC, "{cc:?}: srtt after a second sample");
    }
}

/// 握手の RTT の標本 (timestamp が無く、自分の時計で測る) も、ACK の経路と同じく `RTO_MAX` で切ります。SYN-ACK を
/// 送った後に呼び手の時計が `Time::MAX` に跳んでも、SRTT と RTTVAR は `0..=RTO_MAX` に収まり、RTO は
/// `RTO_MIN..=RTO_MAX` に収まります。
#[test]
fn handshake_own_clock_sample_is_capped_like_the_ack_path() {
    for cc in [Congestion::NewReno, Congestion::Cubic] {
        let mut n = net(cc);
        let l = n.listen(80);
        let mut p = n.syn_sack(40000, 80, false, true, true);
        n.now = Time::MAX;
        n.peer_ack(&mut p, &[]);
        let c = n.accept(l);
        let t = &*n.s.conn(c.slot).t;
        assert!(t.has_rtt, "{cc:?}: the handshake took a sample");
        assert!(
            (0..=RTO_MAX).contains(&t.srtt) && (0..=RTO_MAX).contains(&t.rttvar),
            "{cc:?}: srtt {} rttvar {}",
            t.srtt,
            t.rttvar
        );
        assert!(
            (RTO_MIN..=RTO_MAX).contains(&t.rto),
            "{cc:?}: rto {}",
            t.rto
        );
        assert_eq!(t.srtt, RTO_MAX, "{cc:?}: the sample is cut at RTO_MAX");
    }
}
