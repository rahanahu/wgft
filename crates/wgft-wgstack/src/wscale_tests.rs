//! RFC 7323 2.3 の試験:14 を超える窓の scale を示す SYN を、14 で扱い (MUST)、記録する (SHOULD)。
//!
//! RFC 7323 2.3 は次のとおりです。
//! "If a Window Scale option is received with a shift.cnt value larger than 14, the TCP SHOULD log the error but
//! MUST use 14 instead of the specified value."
//!
//! 核にはこの記録の道が今ありません。`Stats` に欄が無く、`LogKind` に種類が無いためです。そのため記録の試験は
//! 新しい名前を使わず、今ある公開の道だけで確かめます。`Stack::stats()` の全体が scale 14 以下の SYN の後と
//! 変わり、`Stack::poll_log()` が 1 分に 1 回の門を通った行を新しく 1 つ返し、その行の `count` が核を作ってから
//! の数であること、です。修正は `Stats` に 1 欄、`LogKind` に 1 つを足せば、この試験を変えずに通ります。
//!
//! 核は待ち受け側しか持たず、能動的な接続 (SYN-ACK の受信) の経路はありません。
//!

#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests build data and format failures"
)]

use crate::listen_tests::flooded;
use crate::stack::{LogLine, Stats};
use crate::testnet_tests::{PeerConn, TSeg, TestNet, show, small_limits};
use crate::wire::{FLAG_ACK, FLAG_SYN};
use core::time::Duration;

fn syn(sport: u16, ws: Option<u8>) -> TSeg {
    TSeg {
        sport,
        dport: 80,
        seq: 1000,
        flags: FLAG_SYN,
        wnd: 65535,
        mss: 1380,
        ws,
        ..TSeg::default()
    }
}

/// 核が今出したい記録の行をすべて取り出します。
fn logs(n: &mut TestNet) -> Vec<LogLine> {
    let mut v = Vec::new();
    while let Some(l) = n.s.poll_log() {
        v.push(l);
    }
    v
}

/// SYN を送って握手を終え、受け取った接続の SYN で示された窓の scale (核が使う値) を返します。
fn open(n: &mut TestNet, l: crate::ListenerId, sport: u16, ws: Option<u8>) -> u8 {
    n.inject(&syn(sport, ws));
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
        "want one SYN-ACK, got {}",
        show(&outs)
    );
    let mut p = PeerConn {
        sport,
        dport: 80,
        iss: 1000,
        snd: 1001,
        rcv: outs[0].seq.wrapping_add(1),
        dut_iss: outs[0].seq,
        ts: false,
        ts_val: 0,
        dut_ts: 0,
        wnd: 65535,
    };
    n.peer_ack(&mut p, &[]);
    let c = n.accept(l);
    n.s.conns.tcb(c.slot).snd_wscale
}

// MUST:14 を超える scale は 14 で扱います。今の main で通ります。

#[test]
fn wscale_above_14_is_used_as_14_on_a_listener_row() {
    for (ws, want) in [
        (Some(0), 0),
        (Some(13), 13),
        (Some(14), 14),
        (Some(15), 14),
        (Some(16), 14),
        (Some(255), 14),
    ] {
        let mut n = TestNet::new(small_limits());
        let l = n.listen(80);
        assert_eq!(open(&mut n, l, 40000, ws), want, "scale {ws:?}");
    }
}

#[test]
fn wscale_above_14_is_used_as_14_on_the_cookie_path() {
    for (ws, want) in [(13, 13), (14, 14), (15, 14), (255, 14)] {
        let (mut n, l) = flooded();
        // cookie は timestamp を示す相手の分だけ窓の scale を運びます。
        n.inject(&TSeg {
            ts: Some((5000, 0)),
            ..syn(41000, Some(ws))
        });
        let outs = n.drain();
        assert!(
            outs.len() == 1 && outs[0].flags == FLAG_SYN | FLAG_ACK,
            "scale {ws}: want one cookie SYN-ACK, got {}",
            show(&outs)
        );
        let mut p = PeerConn {
            sport: 41000,
            dport: 80,
            iss: 1000,
            snd: 1001,
            rcv: outs[0].seq.wrapping_add(1),
            dut_iss: outs[0].seq,
            ts: true,
            ts_val: 5000,
            dut_ts: outs[0].ts.map_or(0, |(v, _)| v),
            wnd: 65535,
        };
        let before = n.s.stats().syn_cookies_accepted;
        n.peer_ack(&mut p, &[]);
        assert_eq!(n.s.stats().syn_cookies_accepted, before + 1, "scale {ws}");
        let c = n.accept(l);
        assert_eq!(n.s.conns.tcb(c.slot).snd_wscale, want, "scale {ws}");
    }
}

// 対照:14 以下の scale と、option の無い SYN では何も記録しません。今の main で通ります。

#[test]
fn wscale_up_to_14_adds_no_log_and_no_count_on_a_listener_row() {
    let mut n0 = TestNet::new(small_limits());
    let l0 = n0.listen(80);
    open(&mut n0, l0, 40000, None);
    let base: Stats = n0.s.stats();
    assert_eq!(logs(&mut n0), Vec::<LogLine>::new());
    for ws in [0, 1, 13, 14] {
        let mut n = TestNet::new(small_limits());
        let l = n.listen(80);
        open(&mut n, l, 40000, Some(ws));
        assert_eq!(n.s.stats(), base, "scale {ws} changed a count");
        assert!(logs(&mut n).is_empty(), "scale {ws} logged");
    }
}

#[test]
fn wscale_up_to_14_adds_no_log_and_no_count_on_the_cookie_path() {
    let (mut base_net, _) = flooded();
    logs(&mut base_net);
    base_net.inject(&syn(41000, None));
    base_net.drain();
    let base = base_net.s.stats();
    let base_logs = logs(&mut base_net);
    for ws in [13, 14] {
        let (mut n, _) = flooded();
        logs(&mut n);
        n.inject(&syn(41000, Some(ws)));
        n.drain();
        assert_eq!(n.s.stats(), base, "scale {ws} changed a count");
        assert_eq!(logs(&mut n), base_logs, "scale {ws} logged");
    }
}

// SHOULD:14 を超える scale は数え、1 分に 1 回の門を通して記録します。修正の前に落ちます。

#[test]
fn wscale_above_14_is_counted_and_logged_on_a_listener_row() {
    let mut n0 = TestNet::new(small_limits());
    let l0 = n0.listen(80);
    open(&mut n0, l0, 40000, Some(14));
    let base = n0.s.stats();
    for ws in [15, 16, 255] {
        let mut n = TestNet::new(small_limits());
        let l = n.listen(80);
        let before = n.s.stats().wscale_clamped;
        open(&mut n, l, 40000, Some(ws));
        assert_ne!(n.s.stats(), base, "scale {ws} was not counted");
        assert_eq!(n.s.stats().wscale_clamped, before + 1, "scale {ws}");
        let lines = logs(&mut n);
        assert_eq!(
            lines.len(),
            1,
            "scale {ws}: want one log line, got {lines:?}"
        );
        assert_eq!(lines[0].count, 1, "scale {ws}");
        assert_eq!(lines[0].kind, crate::LogKind::WscaleClamped, "scale {ws}");
    }
}

#[test]
fn wscale_above_14_is_counted_and_logged_on_the_cookie_path() {
    let (mut base_net, _) = flooded();
    logs(&mut base_net);
    base_net.inject(&syn(41000, Some(14)));
    base_net.drain();
    let base = base_net.s.stats();
    for ws in [15, 255] {
        let (mut n, _) = flooded();
        logs(&mut n);
        let before = n.s.stats().wscale_clamped;
        n.inject(&syn(41000, Some(ws)));
        n.drain();
        assert_ne!(n.s.stats(), base, "scale {ws} was not counted");
        assert_eq!(n.s.stats().wscale_clamped, before + 1, "scale {ws}");
        let lines = logs(&mut n);
        assert_eq!(
            lines.len(),
            1,
            "scale {ws}: want one log line, got {lines:?}"
        );
        assert_eq!(lines[0].count, 1, "scale {ws}");
        assert_eq!(lines[0].kind, crate::LogKind::WscaleClamped, "scale {ws}");
    }
}

/// 門は 1 分に 1 回です。1 分の内の 2 つ目は数えるだけで行を足さず、1 分の後の次の SYN で、核を作ってからの数を
/// 持つ行が出ます。
#[test]
fn wscale_log_passes_the_once_a_minute_gate_and_keeps_the_count() {
    let mut n = TestNet::new(small_limits());
    n.listen(80);
    n.inject(&syn(40001, Some(15)));
    n.drain();
    let first = logs(&mut n);
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(first[0].count, 1);
    let kind = first[0].kind;
    assert_eq!(kind, crate::LogKind::WscaleClamped);
    assert_eq!(n.s.stats().wscale_clamped, 1);

    n.inject(&syn(40002, Some(15)));
    n.drain();
    assert!(logs(&mut n).is_empty(), "a second line inside the minute");
    assert_eq!(
        n.s.stats().wscale_clamped,
        2,
        "the second SYN was not counted"
    );

    n.advance(Duration::from_secs(61));
    n.drain();
    logs(&mut n); // 時間の経過で出る別の種類の行は読み捨てます。
    n.inject(&syn(40003, Some(15)));
    n.drain();
    let third = logs(&mut n);
    assert_eq!(
        third
            .iter()
            .filter(|l| l.kind == kind)
            .map(|l| l.count)
            .collect::<Vec<_>>(),
        vec![3],
        "{third:?}"
    );
    assert_eq!(n.s.stats().wscale_clamped, 3);
}

/// 14 を超える scale は握手を止めません (SYN-ACK を返し、接続を作ります)。記録のための失敗や遅れが無いことの対照
/// で、今の main で通ります。
#[test]
fn wscale_above_14_does_not_refuse_the_syn() {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    open(&mut n, l, 40000, Some(15));
    assert_eq!(n.s.held().conns, 1);
}
