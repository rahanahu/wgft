//! UDP の中継の試験。agent の側は本物のデータプレーンと Rust の wgstack の核で、server の側は試験の相手
//! ([`super::testpeer`]) が台本の UDP の endpoint を動かす。宛先はループバックのカーネルの UDP のソケット
//! である。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket as LanSocket;
use wgft_proto::{AgentRule, Proto};

use super::replies::Replies;
use super::testpeer::{Peer, UdpClient};
use super::tests::{free_port, rule, targets, wait_for};
use super::{Key, Kind, ListenerStat, Manager};
use crate::flowpool::{self, Limits};

const WAIT: Duration = Duration::from_secs(5);

/// 試験の相手と agent を立て、トンネルのハンドシェイクが済むまで待つ。台本の UDP は送り直さないので、
/// ハンドシェイクの前の datagram は server の device で落ちうる。待ち受けの無いポートへの SYN に RST が
/// 返れば、トンネルは通っている。
async fn start() -> Peer {
    let peer = Peer::start().await;
    assert_eq!(
        peer.connect(1).await.err(),
        Some(super::testpeer::Outcome::Reset)
    );
    peer
}

fn udp(id: &str, port: u16, target: &str) -> [AgentRule; 1] {
    [rule(id, Proto::Udp, &port.to_string(), target, true)]
}

fn manager_with(peer: &Peer, limits: Limits, idle: Duration) -> Manager {
    Manager::new(
        super::testpeer::AGENT_IP,
        peer.agent().handle(),
        targets("", vec![]),
        limits,
        idle,
    )
}

fn manager(peer: &Peer) -> Manager {
    manager_with(peer, Limits::default(), super::DEFAULT_UDP_IDLE)
}

/// 受けた datagram をそのまま返し、送信元を数える宛先。
async fn echo() -> (SocketAddr, tokio::sync::watch::Receiver<Vec<SocketAddr>>) {
    let s = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(Vec::new());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, from)) = s.recv_from(&mut buf).await else {
                continue;
            };
            tx.send_modify(|v| {
                if !v.contains(&from) {
                    v.push(from);
                }
            });
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    (a, rx)
}

async fn round_trip(c: &mut UdpClient, port: u16, msg: &[u8]) -> Option<Vec<u8>> {
    c.send(port, msg);
    let (from, data) = c.recv(WAIT).await?;
    assert_eq!(from, port, "the reply leaves from the listener's port");
    Some(data)
}

fn stat(m: &Manager, port: u16) -> ListenerStat {
    m.listener_stats()
        .into_iter()
        .find(|s| {
            s.key
                == Key {
                    kind: Kind::Udp,
                    port,
                }
        })
        .expect("the udp listener")
}

#[tokio::test]
async fn relays_both_ways_with_a_session_per_source() {
    let peer = start().await;
    let (target, sources) = echo().await;
    let mut m = manager(&peer);
    assert_eq!(m.apply(&udp("r_u", 2456, &target.to_string())).await, 1);
    assert_eq!(m.listening(), 1);
    let mut a = peer.udp();
    let mut b = peer.udp();
    assert_eq!(round_trip(&mut a, 2456, b"hello").await.unwrap(), b"hello");
    assert_eq!(round_trip(&mut b, 2456, b"world").await.unwrap(), b"world");
    // 同じ送信元はセッションを使い続け、宛先から見た送信元も変わらない
    assert_eq!(round_trip(&mut a, 2456, b"again").await.unwrap(), b"again");
    assert_eq!(sources.borrow().len(), 2);
    let s = stat(&m, 2456);
    assert_eq!((s.sessions, s.flows), (2, 2));
    assert_eq!(s.name(), "udp/2456");
    assert_eq!(m.udp_pool().in_use(), 2);
    // ルールを消すと、セッションと予算の枠が戻る
    m.apply(&[]).await;
    assert_eq!(m.udp_pool().in_use(), 0);
    assert_eq!(m.udp_pool().rules(), 0);
    m.close().await;
}

#[tokio::test]
async fn a_datagram_larger_than_the_mtu_goes_both_ways() {
    let peer = start().await;
    let (target, _) = echo().await;
    let mut m = manager(&peer);
    m.apply(&udp("r_u", 2456, &target.to_string())).await;
    let mut a = peer.udp();
    // トンネルの中の datagram は試験の相手が組み立てないので、MTU に収まる最大の大きさで確かめる
    let big = vec![7u8; 1392];
    assert_eq!(round_trip(&mut a, 2456, &big).await.unwrap(), big);
}

#[tokio::test]
async fn an_idle_session_closes_between_the_timeout_and_a_quarter_more() {
    let peer = start().await;
    let (target, sources) = echo().await;
    let idle = Duration::from_millis(400);
    let mut m = manager_with(&peer, Limits::default(), idle);
    m.apply(&udp("r_u", 2456, &target.to_string())).await;
    let mut a = peer.udp();
    // 最後の datagram は送る時刻より後に届くので、その前に測れば閉じるまでの時間を短く見積もらない
    let last = Instant::now();
    round_trip(&mut a, 2456, b"x").await.unwrap();
    // 期限の前には閉じない。応答の向きも期限を延ばす
    tokio::time::sleep(idle / 2).await;
    assert_eq!(stat(&m, 2456).sessions, 1);
    wait_for("the idle session to close", || stat(&m, 2456).sessions == 0).await;
    let took = last.elapsed();
    assert!(took >= idle, "closed after {took:?}");
    // 点検の間隔と試験の待ちの粒度の分だけ余裕を見る
    assert!(
        took < idle * 5 / 4 + Duration::from_millis(150),
        "closed after {took:?}"
    );
    assert_eq!(stat(&m, 2456).flows, 0);
    // 同じ送信元の次の datagram は新しいセッションを作る
    round_trip(&mut a, 2456, b"y").await.unwrap();
    assert_eq!(sources.borrow().len(), 2);
}

/// 受けるだけで応答しない宛先。受けた送信元と、受けた datagram の数を返す。
async fn sink() -> (
    SocketAddr,
    tokio::sync::watch::Receiver<(Vec<SocketAddr>, usize)>,
) {
    let s = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel((Vec::new(), 0));
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((_, from)) = s.recv_from(&mut buf).await {
            tx.send_modify(|(v, n)| {
                if !v.contains(&from) {
                    v.push(from);
                }
                *n += 1;
            });
        }
    });
    (a, rx)
}

/// 片方の向きだけの datagram がセッションを保つ試験の間隔。datagram は前のものが届いてからこの間をおいて
/// 送り、この間に届かなければ送り直す (ループバックとトンネルでも datagram は落ちうる)。点検の間隔の半分で、
/// 届いた datagram の間は無通信の期限よりずっと短い。保つことを確かめる長さは期限の 3 倍である。
fn keep_spacing(idle: Duration) -> Duration {
    super::sweep_interval(idle) / 2
}

#[tokio::test]
async fn datagrams_toward_the_target_alone_keep_the_session() {
    let peer = start().await;
    let (target, mut seen) = sink().await;
    let idle = Duration::from_millis(300);
    let spacing = keep_spacing(idle);
    let mut m = manager_with(&peer, Limits::default(), idle);
    m.apply(&udp("r_u", 2456, &target.to_string())).await;
    let a = peer.udp();
    // 期限の 3 倍の間、トンネルの側からだけ送る。応答は無い
    let began = Instant::now();
    let mut last = began;
    let mut longest = Duration::ZERO;
    while began.elapsed() < 3 * idle {
        let before = seen.borrow().1;
        let give_up = Instant::now() + WAIT;
        loop {
            a.send(2456, b"k");
            let arrived = seen.wait_for(|(_, n)| *n > before);
            if tokio::time::timeout(spacing, arrived).await.is_ok() {
                break;
            }
            assert!(
                Instant::now() < give_up,
                "no datagram reached the target for {WAIT:?}; sessions {}",
                stat(&m, 2456).sessions
            );
        }
        longest = longest.max(last.elapsed());
        last = Instant::now();
        tokio::time::sleep(spacing).await;
    }
    assert_eq!(stat(&m, 2456).sessions, 1);
    assert_eq!(
        seen.borrow().0.len(),
        1,
        "the session was rebuilt; the longest gap between datagrams at the target was {longest:?}, the idle timeout is {idle:?}"
    );
}

#[tokio::test]
async fn datagrams_from_the_target_alone_keep_the_session() {
    let peer = start().await;
    let s = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let target = s.local_addr().unwrap();
    let idle = Duration::from_millis(300);
    let spacing = keep_spacing(idle);
    let mut m = manager_with(&peer, Limits::default(), idle);
    m.apply(&udp("r_u", 2456, &target.to_string())).await;
    let mut a = peer.udp();
    a.send(2456, b"hello");
    let mut buf = [0u8; 16];
    let (_, session) = tokio::time::timeout(WAIT, s.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    // 期限の 3 倍の間、宛先からだけ送る。トンネルの側は送らない。閉じたセッションへは宛先から作り直せない
    // ので、最後まで届けばセッションは保たれている
    let began = Instant::now();
    let mut last = began;
    let mut longest = Duration::ZERO;
    let mut i = 0u8;
    while began.elapsed() < 3 * idle {
        let give_up = Instant::now() + WAIT;
        loop {
            s.send_to(&[i], session).await.unwrap();
            if let Some((_, d)) = a.recv(spacing).await {
                // 送り直した datagram の遅れた写しは前の番号で届く
                assert!(d.len() == 1 && d[0] <= i, "{d:?}");
                if d[0] == i {
                    break;
                }
            }
            assert!(
                Instant::now() < give_up,
                "no datagram from the target came through for {WAIT:?}; sessions {}, the longest gap so far {longest:?}, the idle timeout {idle:?}",
                stat(&m, 2456).sessions
            );
        }
        longest = longest.max(last.elapsed());
        last = Instant::now();
        i += 1;
        tokio::time::sleep(spacing).await;
    }
    assert_eq!(stat(&m, 2456).sessions, 1);
}

#[tokio::test]
async fn a_port_unreachable_target_closes_the_session_without_icmp_into_the_tunnel() {
    let peer = start().await;
    let target = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap();
    let mut m = manager(&peer);
    m.apply(&udp("r_u", 2456, &addr.to_string())).await;
    let a = peer.udp();
    a.send(2456, b"x");
    let mut buf = [0u8; 16];
    let (_, first) = tokio::time::timeout(WAIT, target.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stat(&m, 2456).sessions, 1);
    // 宛先が消えると、次の datagram への ICMP の拒否でセッションが閉じ、枠が戻る
    drop(target);
    a.send(2456, b"z");
    wait_for("the refused session to close", || {
        let s = stat(&m, 2456);
        s.sessions == 0 && s.flows == 0
    })
    .await;
    // 同じ送信元の次の datagram は新しいセッション (宛先から見て別のポート) で届く
    let back = LanSocket::bind(addr).await.unwrap();
    a.send(2456, b"y");
    let (n, second) = tokio::time::timeout(WAIT, back.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"y");
    assert_ne!(first.port(), second.port(), "the old session carried it");
    assert_eq!(peer.icmp_errors(), 0);
}

/// 書き込みの失敗で閉じる道の試験。Linux と macOS のカーネルは、接続した UDP のソケットに残った ICMP の
/// 拒否を次の書き込みの誤りとして返す。Windows の Winsock は拒否を次の受信の `WSAECONNRESET` として
/// 渡し、CI の Windows では書き込みは失敗しなかった。そこでは応答の task が受信の誤りでセッションを閉じ、
/// その道は [`a_port_unreachable_target_closes_the_session_without_icmp_into_the_tunnel`] が全 OS で
/// 確かめる。書き込みの失敗を Windows で起こす手段が無いので、この試験は Windows では走らせない。
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Winsock reports an ICMP refusal on the next receive, not on the next send"
)]
async fn a_failed_write_to_the_target_closes_the_session() {
    let peer = start().await;
    let dead = free_port();
    let mut m = manager(&peer);
    m.apply(&udp("r_u", 2456, &format!("127.0.0.1:{dead}")))
        .await;
    // 最初の datagram の ICMP の拒否が残っている間に次の datagram を書くと、書き込みが拒否で失敗する。
    // 応答の task が先に拒否を取り出すこともあるので、書き込みの側で閉じるまで送信元を替えて試す
    for _ in 0..50 {
        let a = peer.udp();
        for _ in 0..4 {
            a.send(2456, b"z");
        }
        if m.write_closes() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(m.write_closes() > 0, "no failed write closed a session");
    wait_for("the sessions to close", || {
        let s = stat(&m, 2456);
        s.sessions == 0 && s.flows == 0
    })
    .await;
    assert_eq!(peer.icmp_errors(), 0);
}

#[tokio::test]
async fn the_flow_budget_drops_new_sources_silently_and_keeps_existing_ones() {
    let peer = start().await;
    let (target, _) = echo().await;
    // 予算 16 でルールが 1 本なら、予備の 4 を除いた 12 まで
    let mut m = manager_with(&peer, Limits { udp: 16, tcp: 16 }, super::DEFAULT_UDP_IDLE);
    m.apply(&udp("r_u", 2456, &target.to_string())).await;
    let mut held = Vec::new();
    for _ in 0..12 {
        let mut c = peer.udp();
        assert_eq!(round_trip(&mut c, 2456, b"x").await.unwrap(), b"x");
        held.push(c);
    }
    let mut over = peer.udp();
    over.send(2456, b"x");
    assert!(over.recv(Duration::from_millis(300)).await.is_none());
    assert_eq!(m.udp_pool().in_use(), 12);
    assert_eq!(
        m.udp_pool().refusals()["r_u"][flowpool::Reason::Spare as usize],
        1
    );
    // 拒んだ datagram に ICMP は返さない
    assert_eq!(peer.icmp_errors(), 0);
    // 既存のセッションは残る
    assert_eq!(round_trip(&mut held[0], 2456, b"y").await.unwrap(), b"y");
    let d = m.udp_pool().reading();
    assert_eq!(d.in_use, 12);
}

#[tokio::test]
async fn closing_the_listener_releases_a_reply_waiting_for_a_slot() {
    let peer = start().await;
    let (target, _) = echo().await;
    let replies: &'static Replies = Box::leak(Box::new(Replies::new(1)));
    let mut m = manager(&peer).with_replies(replies);
    m.apply(&udp("r_u", 2456, &target.to_string())).await;
    // 枠を外で持ち続け、応答の task を枠の待ちにする
    let held = replies.acquire().await;
    let mut a = peer.udp();
    a.send(2456, b"x");
    wait_for("a reply to wait for the slot", || {
        replies.waits().count == 1
    })
    .await;
    assert!(a.recv(Duration::from_millis(100)).await.is_none());
    // 待ち受けを閉じると待ちが解け、取り消しとして数える
    m.apply(&[]).await;
    wait_for("the wait to be cancelled", || {
        replies.waits().cancelled == 1
    })
    .await;
    drop(held);
    assert_eq!(replies.available(), 1);
}

#[tokio::test]
async fn the_reply_slots_bound_the_buffers_across_sessions() {
    let peer = start().await;
    let (target, _) = echo().await;
    let replies: &'static Replies = Box::leak(Box::new(Replies::new(2)));
    let mut m = manager(&peer).with_replies(replies);
    m.apply(&udp("r_u", 2456, &target.to_string())).await;
    let mut cs: Vec<UdpClient> = (0..6).map(|_| peer.udp()).collect();
    for round in 0..3u8 {
        for c in &cs {
            c.send(2456, &[round]);
        }
        for c in &mut cs {
            let (_, d) = c.recv(WAIT).await.expect("every reply arrives");
            assert_eq!(d, [round]);
        }
    }
    // 作ったバッファは枠の数を超えない
    assert_eq!(replies.available(), 2);
    assert!(replies.spare() <= 2);
}

#[tokio::test]
async fn tcp_and_udp_rules_share_a_port_and_sort_like_go() {
    let peer = start().await;
    let (target, _) = echo().await;
    let mut m = manager(&peer);
    // TCP の宛先は試し接続がすぐ拒まれる宛先にする
    let dead = format!("127.0.0.1:{}", free_port());
    m.apply(&[
        rule("r_u", Proto::Udp, "9-10", &target.to_string(), true),
        rule("r_t", Proto::Tcp, "9", &dead, true),
    ])
    .await;
    let names: Vec<String> = m.listener_stats().iter().map(ListenerStat::name).collect();
    assert_eq!(names, ["tcp/9", "udp/10", "udp/9"]);
    let mut a = peer.udp();
    // 範囲のルールは宛先のポートもずらすので、範囲の最初のポートが echo に届く
    assert_eq!(round_trip(&mut a, 9, b"x").await.unwrap(), b"x");
}

#[tokio::test]
async fn an_ip_literal_target_outside_the_allow_list_keeps_the_listener_closed() {
    let peer = start().await;
    let mut m = Manager::new(
        super::testpeer::AGENT_IP,
        peer.agent().handle(),
        targets("10.0.0.0/8", vec![]),
        Limits::default(),
        super::DEFAULT_UDP_IDLE,
    );
    m.apply(&udp("r_u", 2456, "192.0.2.1:2456")).await;
    assert_eq!(m.listening(), 0);
    let st = m.status();
    assert_eq!(st[0].state, "error");
    assert!(st[0].reason.starts_with("udp/2456: "), "{st:?}");
    assert_eq!(m.udp_pool().rules(), 0);
}

#[tokio::test]
async fn a_host_name_denied_at_dial_time_is_reported_and_dropped() {
    let peer = start().await;
    let mut m = Manager::new(
        super::testpeer::AGENT_IP,
        peer.agent().handle(),
        targets("10.0.0.0/8", vec![("game.lan", "192.0.2.1")]),
        Limits::default(),
        super::DEFAULT_UDP_IDLE,
    );
    m.apply(&udp("r_u", 2456, "game.lan:2456")).await;
    assert_eq!(m.listening(), 1);
    let a = peer.udp();
    a.send(2456, b"x");
    wait_for("the denial to show", || stat(&m, 2456).err.is_some()).await;
    let s = stat(&m, 2456);
    assert!(s.listening && s.sessions == 0 && s.flows == 0, "{s:?}");
    assert_eq!(m.status()[0].state, "error");
}

#[test]
fn the_idle_timeout_and_the_sweep_follow_the_fixture() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../testdata/spec/tunnel/relay-timing.json"
    ))
    .unwrap();
    let def = fixture["default_udp_idle_seconds"].as_u64().unwrap();
    let div = u32::try_from(fixture["udp_sweep_divisor"].as_u64().unwrap()).unwrap();
    assert_eq!(super::DEFAULT_UDP_IDLE, Duration::from_secs(def));
    for bad in [0, -1, i64::from(i32::MAX) + 1, i64::MAX] {
        assert_eq!(super::udp_idle_timeout(bad), Duration::from_secs(def));
    }
    assert_eq!(super::udp_idle_timeout(30), Duration::from_secs(30));
    assert_eq!(
        super::udp_idle_timeout(i64::from(i32::MAX)),
        Duration::from_secs(u64::from(i32::MAX.unsigned_abs()))
    );
    let idle = Duration::from_secs(def);
    assert_eq!(super::sweep_interval(idle), idle / div);
    assert_eq!(
        super::sweep_interval(Duration::from_millis(40)),
        super::MIN_SWEEP
    );
}
