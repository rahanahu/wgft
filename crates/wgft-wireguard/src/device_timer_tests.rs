//! timer の時刻を固定する試験。2 つの Device を、どちらかの `poll_timeout` の時刻か台本の次の時刻へ
//! 偽の時計を飛ばして回し、各段の timer の呼び出し、運んだ datagram、event、次の期限を 1 行ずつ書く。
//! 書いた記録を `testdata/timer-trace.txt` と照らす。ハンドシェイク、鍵の更新、persistent keepalive と
//! passive keepalive、再試行の打ち切りと期限切れ、endpoint の移動の時刻が、記録を作った版から 1 ns も
//! 動かないことを確かめる。
//!
//! 振る舞いを意図して変えたときだけ、`WGFT_UPDATE_TIMER_TRACE=1 cargo test -p wgft-wireguard
//! timer_trace` で記録を書き直し、差分を確かめてから入れる。

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::*;

const TRACE: &str = include_str!("../testdata/timer-trace.txt");

#[derive(Clone, Copy, Debug)]
enum Act {
    /// A がデータを送る。
    ASends,
    /// B がデータを送る。
    BSends,
    /// B が落ちる。B へ向かう datagram を捨てる。
    BDown,
    /// B が戻る。
    BUp,
    /// agent のデータプレーンのように、セッションが無ければ A にハンドシェイクを始めさせる。
    AStarts,
    /// A の送信元のアドレスが変わる (NAT の付け替え)。
    ARoams,
    /// 制御の層が B の名前を引き直し、A の endpoint を新しいアドレスへ移す。
    BMoves,
}

fn at(secs: f64, act: Act) -> (Duration, Act) {
    (Duration::from_secs_f64(secs), act)
}

fn offset(n: &Net, t: Option<Instant>) -> String {
    t.map_or_else(
        || "-".to_owned(),
        |t| t.saturating_duration_since(n.base).as_nanos().to_string(),
    )
}

fn kind(payload: &[u8]) -> String {
    match (payload.first(), payload.len()) {
        (Some(1), _) => "init".to_owned(),
        (Some(2), _) => "resp".to_owned(),
        (Some(3), _) => "cookie".to_owned(),
        (Some(4), 32) => "keepalive".to_owned(),
        (Some(4), len) => format!("data/{len}"),
        _ => format!("other/{}", payload.len()),
    }
}

fn event(e: &Event) -> String {
    match e {
        Event::HandshakeAccepted { .. } => "handshake-accepted".to_owned(),
        Event::SessionEstablished { took, .. } => format!("established took={}", took.as_nanos()),
        Event::EndpointChanged { endpoint, .. } => format!("endpoint {endpoint}"),
        Event::PeerExpired { .. } => "expired".to_owned(),
    }
}

/// 出たものが無くなるまで datagram を運び、1 つずつ記録する。
fn carry(n: &mut Net, out: &mut String) {
    let now = n.now();
    let t = n.t.as_nanos();
    loop {
        let mut moved = false;
        while let Some(tx) = n.a.poll_transmit() {
            moved = true;
            let reached = n.b_up && tx.to == n.b_addr;
            let _ = writeln!(
                out,
                "{t} a>b {} to={}{}",
                kind(&tx.payload),
                tx.to,
                if reached { "" } else { " lost" }
            );
            if reached {
                n.b_got.extend(n.b.recv(now, n.a_addr, &tx.payload));
            }
        }
        while let Some(tx) = n.b.poll_transmit() {
            moved = true;
            let reached = tx.to == n.a_addr;
            let _ = writeln!(
                out,
                "{t} b>a {} to={}{}",
                kind(&tx.payload),
                tx.to,
                if reached { "" } else { " lost" }
            );
            if reached {
                n.a_got.extend(n.a.recv(now, n.b_addr, &tx.payload));
            }
        }
        if !moved {
            break;
        }
    }
    while let Some(e) = n.a.poll_event() {
        let _ = writeln!(out, "{t} a {}", event(&e));
    }
    while let Some(e) = n.b.poll_event() {
        let _ = writeln!(out, "{t} b {}", event(&e));
    }
}

fn apply(n: &mut Net, act: Act) {
    let now = n.now();
    match act {
        Act::ASends => {
            let packet = ipv4_packet(AGENT_IP, SERVER_IP, b"from a");
            n.a.send(now, &packet);
        }
        Act::BSends => {
            let packet = ipv4_packet(SERVER_IP, AGENT_IP, b"from b");
            n.b.send(now, &packet);
        }
        Act::BDown => n.b_up = false,
        Act::BUp => n.b_up = true,
        Act::AStarts => {
            let b = n.b_pub();
            if !n.a.has_session(&b, now) {
                n.a.start_handshake(now, &b);
            }
        }
        Act::ARoams => {
            let port = n.a_addr.port() + 1;
            n.a_addr = SocketAddr::new(n.a_addr.ip(), port);
        }
        Act::BMoves => {
            let port = n.b_addr.port() + 1;
            n.b_addr = SocketAddr::new(n.b_addr.ip(), port);
            let (b, to) = (n.b_pub(), n.b_addr);
            n.a.set_endpoint(now, &b, to);
        }
    }
}

/// 台本を `end` まで流した記録。
fn run(name: &str, mut n: Net, script: &[(Duration, Act)], end: Duration, out: &mut String) {
    let _ = writeln!(out, "# {name}");
    let mut i = 0;
    let mut same_time = 0;
    loop {
        let (da, db) = (n.a.poll_timeout(), n.b.poll_timeout());
        let device = match (da, db) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
        .map(|t| t.saturating_duration_since(n.base));
        let scripted = script.get(i).map(|s| s.0);
        let next = match (device, scripted) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => break,
        };
        if next > end {
            break;
        }
        // 過ぎた期限は今の時刻で扱う。同じ時刻に回り続けたら期限が進んでいない
        let next = next.max(n.t);
        same_time = if next == n.t { same_time + 1 } else { 0 };
        assert!(
            same_time < 16,
            "{name}: a deadline does not move at {next:?}"
        );
        n.t = next;
        let now = n.now();
        let t = n.t.as_nanos();
        if da.is_some_and(|d| d <= now) {
            let _ = writeln!(out, "{t} a timeout");
            n.a.handle_timeout(now);
        }
        if db.is_some_and(|d| d <= now) {
            let _ = writeln!(out, "{t} b timeout");
            n.b.handle_timeout(now);
        }
        while let Some(&(when, act)) = script.get(i)
            && when <= n.t
        {
            let _ = writeln!(out, "{t} {act:?}");
            apply(&mut n, act);
            i += 1;
        }
        carry(&mut n, out);
        let (da, db) = (n.a.poll_timeout(), n.b.poll_timeout());
        let _ = writeln!(out, "{t} next a={} b={}", offset(&n, da), offset(&n, db));
    }
}

fn trace() -> String {
    let mut out = String::new();

    // agent (A) は persistent keepalive を持つ。始めの接触、両向きのデータ、片向きのデータへの passive
    // keepalive (両向き)、送信元の移動、REKEY_AFTER_TIME の後の送信による鍵の更新、endpoint の付け替え、
    // B が落ちた間の再送と打ち切りと休止、B が戻った後の再接続、idle の間の keepalive とセッションの寿命
    let mut script = vec![at(1.0, Act::ASends), at(1.5, Act::BSends)];
    script.extend((2..=40).map(|s| at(f64::from(s), Act::ASends)));
    script.extend((0..18).map(|k| at(45.0 + 2.0 * f64::from(k), Act::BSends)));
    script.extend([
        at(100.0, Act::ARoams),
        at(100.0, Act::ASends),
        at(130.0, Act::ASends),
        at(131.0, Act::BSends),
        at(140.0, Act::BMoves),
        at(140.5, Act::ASends),
        at(200.0, Act::BDown),
        at(201.0, Act::ASends),
    ]);
    script.extend((202..=330).map(|s| at(f64::from(s), Act::AStarts)));
    script.extend([at(340.0, Act::BUp), at(345.0, Act::ASends)]);
    run(
        "agent with a persistent keepalive",
        Net::new(),
        &script,
        Duration::from_secs(1300),
        &mut out,
    );

    // persistent keepalive の無い A。データの後に両方が黙り、セッションの寿命 (180 秒) と接続の寿命
    // (540 秒) が切れる。その後のデータは新しいハンドシェイクを始める
    let script = [
        at(0.0, Act::AStarts),
        at(1.0, Act::ASends),
        at(2.0, Act::BSends),
        at(700.0, Act::ASends),
        at(701.0, Act::BSends),
    ];
    run(
        "agent without a keepalive",
        Net::with(|a| a.peers[0].persistent_keepalive = None, |_| {}),
        &script,
        Duration::from_secs(1300),
        &mut out,
    );

    // 経路が両向きとも切れる。A は再送を打ち切り、B は何も受けないまま接続の寿命 (540 秒) が切れる
    let script = [
        at(0.0, Act::AStarts),
        at(1.0, Act::ASends),
        at(2.0, Act::BSends),
        at(3.0, Act::BDown),
        at(3.0, Act::ARoams),
        at(4.0, Act::BSends),
    ];
    run(
        "a link cut both ways",
        Net::with(|a| a.peers[0].persistent_keepalive = None, |_| {}),
        &script,
        Duration::from_secs(800),
        &mut out,
    );

    // 縮めた timer。B が落ちたまま、再送と打ち切りが縮めた値で回る
    let mut script = vec![at(0.0, Act::BDown), at(0.5, Act::ASends)];
    script.extend((1..=20).map(|s| at(f64::from(s), Act::AStarts)));
    script.push(at(30.0, Act::BUp));
    run(
        "shortened timers",
        Net::with(
            |a| {
                a.timers.rekey_timeout = Some(Duration::from_secs(1));
                a.timers.rekey_attempt_time = Some(Duration::from_secs(4));
                a.timers.keepalive_timeout = Some(Duration::from_secs(3));
            },
            |_| {},
        ),
        &script,
        Duration::from_secs(120),
        &mut out,
    );
    out
}

#[test]
fn timer_trace_matches_the_recorded_trace() {
    let got = trace();
    if std::env::var_os("WGFT_UPDATE_TIMER_TRACE").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/timer-trace.txt");
        std::fs::write(path, &got).unwrap();
        return;
    }
    assert!(got == TRACE, "{}", trace_difference(&got, TRACE));
}

/// Where two traces differ. Lines are split at `\n` only, so that a `\r` the checkout added (a
/// CRLF conversion of the file) shows in the quoted lines instead of hiding the difference.
fn trace_difference(got: &str, want: &str) -> String {
    let (g, w): (Vec<&str>, Vec<&str>) = (got.split('\n').collect(), want.split('\n').collect());
    match g.iter().zip(&w).position(|(a, b)| a != b) {
        Some(i) => format!(
            "the timer trace differs from testdata/timer-trace.txt at line {}:\n  got:  {:?}\n  want: {:?}{}",
            i + 1,
            g[i],
            w[i],
            if w[i].ends_with('\r') {
                "\n  the file has CRLF line ends; it must keep LF (.gitattributes)"
            } else {
                ""
            },
        ),
        None => format!(
            "the timer trace has {} lines ({} bytes) and testdata/timer-trace.txt has {} lines ({} bytes); the common lines are equal",
            g.len(),
            got.len(),
            w.len(),
            want.len(),
        ),
    }
}

#[test]
fn a_trace_difference_names_crlf_and_length() {
    let crlf = trace_difference("a\nb\n", "a\r\nb\r\n");
    assert!(crlf.contains("line 1") && crlf.contains("CRLF"), "{crlf}");
    // 片方が行の単位で他方の前の部分のときだけ、共通の行が等しい
    let short = trace_difference("a\nb", "a\nb\nc");
    assert!(
        short.contains("2 lines") && short.contains("3 lines"),
        "{short}"
    );
}
