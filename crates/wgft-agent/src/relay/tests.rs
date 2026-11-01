//! 中継の試験。agent の側は本物のデータプレーンと Rust の wgstack の核で、server の側は試験の相手
//! ([`super::testpeer`]) が WireGuard の device と台本の TCP の client を動かす。宛先はループバックの
//! カーネルの TCP の待ち受けである。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as LanListener;
use wgft_netstack::TcpListener;
use wgft_proto::{AgentRule, Proto, RuleStatus};

use super::testpeer::{AGENT_IP, Client, Outcome, Peer, SERVER_IP};
use super::{ListenerStat, Manager};
use crate::flowpool::{self, Limits};
use crate::targets::Targets;

fn rule(id: &str, proto: Proto, port: &str, target: &str, enabled: bool) -> AgentRule {
    AgentRule {
        id: id.into(),
        proto,
        listen_port: port.parse().unwrap(),
        target: target.into(),
        enabled,
    }
}

fn tcp(id: &str, port: u16, target: &str) -> [AgentRule; 1] {
    [rule(id, Proto::Tcp, &port.to_string(), target, true)]
}

/// 今は空いていて、試験が手放した後に他が取りにくいポート。ポート 0 の bind が割り当てる一時の
/// ポートの範囲 (Linux の既定は 32768 から、macOS と Windows は 49152 から) の下から選ぶ。一時の
/// ポートを手放して使い直すと、並行に走る試験のポート 0 の bind が間で同じポートを取りうるためである。
/// 始まりの位置はプロセスごとに乱し、nextest の別のプロセスと重なりにくくする。
fn free_port() -> u16 {
    use std::hash::{BuildHasher, RandomState};
    use std::sync::atomic::{AtomicU16, Ordering};
    const LOW: u16 = 20000;
    const SPAN: u16 = 10000;
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let seed = RandomState::new().hash_one(std::process::id());
    for _ in 0..SPAN {
        let i = NEXT.fetch_add(1, Ordering::Relaxed);
        let offset = seed.wrapping_add(u64::from(i)) % u64::from(SPAN);
        let port = LOW + u16::try_from(offset).unwrap_or(0);
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port below the ephemeral range");
}

/// 試験の宛先の規則。ホストのインタフェースは読まず、名前は `names` の表で引く。
fn targets(allow: &str, names: Vec<(&'static str, &'static str)>) -> Arc<Targets> {
    use crate::targets::resolve::Resolver;
    use crate::targets::unicast::Unicast;
    let allow = crate::config::allow_targets::parse(allow).unwrap();
    let resolver = Resolver::with_lookup(
        8,
        1,
        Arc::new(move |h: &str, _| {
            names
                .iter()
                .find(|(n, _)| *n == h)
                .map(|(_, a)| vec![a.parse().unwrap()])
                .ok_or_else(|| std::io::Error::other("Name or service not known"))
        }),
    );
    Arc::new(Targets::with(
        allow,
        Unicast::new(Box::new(|| Ok(Vec::new()))),
        Arc::new(resolver),
    ))
}

/// 接続ごとに読んだものを返す echo の宛先。
async fn echo() -> SocketAddr {
    let l = LanListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    a
}

/// 接続を受けるたびに `blob` を書いて閉じる宛先。
async fn sender(blob: Vec<u8>) -> SocketAddr {
    let l = LanListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let blob = Arc::new(blob);
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let blob = Arc::clone(&blob);
            tokio::spawn(async move {
                let _ = s.write_all(&blob).await;
            });
        }
    });
    a
}

async fn round_trip(c: &mut Client, msg: &[u8]) -> Result<Vec<u8>, Outcome> {
    c.send(msg);
    c.read_exact(msg.len()).await
}

fn manager_with(peer: &Peer, targets: Arc<Targets>, limits: Limits) -> Manager {
    Manager::new(AGENT_IP, peer.agent().handle(), targets, limits)
}

fn manager(peer: &Peer) -> Manager {
    manager_with(peer, targets("", vec![]), Limits::default())
}

/// `f` が真を返すまで待つ。5 秒で諦める。
async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..250 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn relays_and_cuts_the_flow_when_the_rule_is_disabled() {
    let peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager(&peer);
    assert_eq!(m.apply(&tcp("r_a", 80, &target.to_string())).await, 1);
    assert_eq!(m.listening(), 1);
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(round_trip(&mut c, b"hello").await.unwrap(), b"hello");
    // ルールを無効にすると、中継の接続はトンネルの側に RST で切られる
    let mut off = tcp("r_a", 80, &target.to_string());
    off[0].enabled = false;
    assert_eq!(m.apply(&off).await, 1);
    assert_eq!(m.listening(), 0);
    assert_eq!(c.outcome(Duration::from_secs(5)).await, Outcome::Reset);
    // 待ち受けの無いポートへの SYN には RST が返る
    assert_eq!(peer.connect(80).await.err(), Some(Outcome::Reset));
    m.close().await;
}

#[tokio::test]
async fn a_target_change_rebinds_at_once() {
    let peer = Peer::start().await;
    let first = echo().await;
    let second = echo().await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &first.to_string())).await;
    assert_eq!(m.apply(&tcp("r_b", 80, &second.to_string())).await, 2);
    assert_eq!(m.listening(), 1);
    assert_eq!(
        m.status(),
        vec![RuleStatus {
            id: "r_b".into(),
            state: "ok".into(),
            reason: String::new()
        }]
    );
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
}

#[tokio::test]
async fn a_new_rule_id_with_the_same_target_keeps_the_listener() {
    let peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(m.apply(&tcp("r_b", 80, &target.to_string())).await, 0);
    assert_eq!(m.status()[0].id, "r_b");
    assert_eq!(round_trip(&mut c, b"still").await.unwrap(), b"still");
}

#[tokio::test]
async fn closes_with_fin_when_the_target_refuses_and_returns_the_flow() {
    let peer = Peer::start().await;
    // 待ち受けの無い宛先
    let dead = free_port();
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &format!("127.0.0.1:{dead}"))).await;
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(c.outcome(Duration::from_secs(5)).await, Outcome::Eof);
    wait_for("the flow to come back", || {
        let s = m.listener_stats()[0].clone();
        (s.sessions, s.flows) == (0, 0)
    })
    .await;
}

#[tokio::test]
async fn reports_unsupported_unusable_and_failed_listeners() {
    let peer = Peer::start().await;
    let target = echo().await;
    // 核のポート 80 を先に取っておく
    let addr = std::net::SocketAddrV4::new(AGENT_IP, 80);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    peer.agent()
        .call(move |net| {
            let l = TcpListener::bind(net, addr).unwrap();
            tokio::task::spawn_local(async move {
                let _ = stopped.await;
                drop(l);
            });
        })
        .await
        .unwrap();
    let mut m = manager(&peer);
    m.apply(&[
        rule("r_u", Proto::Udp, "27015", "192.0.2.1:27015", true),
        rule("r_t", Proto::Tcp, "80", &target.to_string(), true),
        rule("r_x", Proto::Tcp, "40000-40001", "192.0.2.1:65535", true),
    ])
    .await;
    let st = m.status();
    assert_eq!(st.len(), 3);
    assert!(st.iter().all(|s| s.state == "error"), "{st:?}");
    let t = st.iter().find(|s| s.id == "r_t").unwrap();
    assert!(
        t.reason.starts_with("tcp/80: bind tcp 10.200.0.2:80: "),
        "{t:?}"
    );
    assert_eq!(m.listening(), 0);
    drop(stop);
    // 手放した核のポートは、次の見回りで開き直す
    tokio::time::sleep(Duration::from_millis(50)).await;
    m.retry().await;
    assert_eq!(m.listening(), 1);
    assert_eq!(m.tcp_pool().rules(), 1);
}

#[tokio::test]
async fn the_flow_budget_resets_new_connections_and_keeps_existing_ones() {
    let peer = Peer::start().await;
    let target = echo().await;
    // 予算 16 でルールが 1 本なら、予備の 4 を除いた 12 本まで
    let mut m = manager_with(&peer, targets("", vec![]), Limits { udp: 16, tcp: 16 });
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let mut held = Vec::new();
    for _ in 0..12 {
        let mut c = peer.connect(80).await.unwrap();
        assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
        held.push(c);
    }
    // 上限を超えた接続は握手の後に RST で閉じる
    let mut over = peer.connect(80).await.unwrap();
    assert_eq!(over.outcome(Duration::from_secs(5)).await, Outcome::Reset);
    assert_eq!(m.tcp_pool().in_use(), 12);
    assert_eq!(
        m.tcp_pool().refusals()["r_a"][flowpool::Reason::Spare as usize],
        1
    );
    // 既存の接続は残る。1 本閉じれば新しい接続が通る
    assert_eq!(round_trip(&mut held[0], b"y").await.unwrap(), b"y");
    let mut last = held.pop().unwrap();
    last.finish();
    assert_eq!(last.outcome(Duration::from_secs(5)).await, Outcome::Eof);
    wait_for("a flow to come back", || m.tcp_pool().in_use() == 11).await;
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(round_trip(&mut c, b"z").await.unwrap(), b"z");
    // ルールを無効にすると予算からも外れる
    m.apply(&[]).await;
    assert_eq!(m.tcp_pool().rules(), 0);
}

/// ルールの ID だけが変わると、待ち受けと接続は残り、予算の枠は新しいルールに付け替わる。
#[tokio::test]
async fn a_relabel_keeps_the_flows_and_moves_them_to_the_new_rule() {
    let peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let mut held = Vec::new();
    for _ in 0..3 {
        let mut c = peer.connect(80).await.unwrap();
        assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
        held.push(c);
    }
    assert_eq!(m.tcp_pool().rule_flows("r_a"), 3);
    assert_eq!(m.apply(&tcp("r_b", 80, &target.to_string())).await, 0);
    assert_eq!(m.tcp_pool().rules(), 1);
    assert_eq!(m.tcp_pool().rule_flows("r_a"), 0);
    assert_eq!(m.tcp_pool().rule_flows("r_b"), 3);
    assert_eq!(m.tcp_pool().ledger().reg_flows["r_b"], 3);
    for c in &mut held {
        assert_eq!(round_trip(c, b"y").await.unwrap(), b"y");
    }
    assert_eq!(m.status()[0].id, "r_b");
}

/// 中継の接続はトンネルの側と宛先の側を 1 本ずつ数え、予算の枠はトンネルの側の 1 本だけを数える
/// (Go の `Status.Sessions` と `Status.Flows`)。両方の向きを閉じ、届け終えれば両方とも戻る。
#[tokio::test]
async fn listener_stats_count_sessions_and_flows() {
    let peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let stat = |m: &Manager| m.listener_stats()[0].clone();
    assert_eq!((stat(&m).sessions, stat(&m).flows), (0, 0));
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
    let s = stat(&m);
    assert!(s.listening && s.err.is_none(), "{s:?}");
    assert_eq!((s.sessions, s.flows), (2, 1));
    // FIN は宛先に伝わり、宛先が閉じると FIN が返る
    c.finish();
    assert_eq!(c.outcome(Duration::from_secs(5)).await, Outcome::Eof);
    wait_for("the counts to come back", || {
        let s = stat(&m);
        (s.sessions, s.flows) == (0, 0)
    })
    .await;
}

/// 中継が終わった時にトンネルの側がまだ届けていない末尾は、RST で捨てずに届け、FIN で終える。中継は
/// 届け終えるまで枠を持ち、その後に返す。
#[tokio::test]
async fn the_tail_is_delivered_before_the_flow_returns() {
    let peer = Peer::start().await;
    let blob: Vec<u8> = (0..48_000u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let target = sender(blob.clone()).await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let mut c = peer.connect(80).await.unwrap();
    // 先に FIN を送り、読まずに待つ。宛先が書いて閉じると両方の向きが終わり、中継はトンネルの側に ACK
    // されていないデータを残したまま終わる
    c.finish();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        m.tcp_pool().in_use(),
        1,
        "the flow is held while the tail is in flight"
    );
    let (got, end) = c.read_to_end(Duration::from_secs(5)).await;
    assert_eq!(end, Outcome::Eof);
    assert_eq!(got.len(), blob.len());
    assert!(got == blob, "the bytes differ");
    wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
}

/// 届けている途中でルールを無効にすると、待ちを打ち切ってトンネルの側を RST で切り、枠を返す。
#[tokio::test]
async fn disabling_the_rule_resets_a_relay_that_is_still_delivering() {
    let peer = Peer::start().await;
    let blob: Vec<u8> = (0..48_000u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let target = sender(blob).await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let mut c = peer.connect(80).await.unwrap();
    // 読まずに待ち、中継を末尾の配送の待ちに入れる
    c.finish();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(m.tcp_pool().in_use(), 1, "the relay waits for the tail");
    let mut off = tcp("r_a", 80, &target.to_string());
    off[0].enabled = false;
    m.apply(&off).await;
    assert_eq!(
        m.tcp_pool().in_use(),
        0,
        "closing the listener returns the lease"
    );
    let (_, end) = c.read_to_end(Duration::from_secs(5)).await;
    assert_eq!(end, Outcome::Reset);
}

/// リスナーは Go の `Manager.Status` と同じく名前の文字列の順に並べ、ルールの状態の理由はその順で
/// 最初の誤りから取る。ポート 10 の名前はポート 9 の名前より前である。
#[tokio::test]
async fn listener_stats_and_rule_reasons_follow_go_s_key_order() {
    let peer = Peer::start().await;
    let mut m = manager_with(&peer, targets("10.0.0.0/8", vec![]), Limits::default());
    m.apply(&[rule("r_a", Proto::Tcp, "9-10", "192.0.2.1:80", true)])
        .await;
    let st = m.listener_stats();
    let keys: Vec<String> = st.iter().map(ListenerStat::key).collect();
    assert_eq!(keys, ["tcp/10", "tcp/9"]);
    assert!(st.iter().all(|s| !s.listening && s.err.is_some()));
    let rs = m.status();
    assert!(rs[0].reason.starts_with("tcp/10: "), "{rs:?}");
    assert_eq!(m.status_of(&st), rs);
}

#[tokio::test]
async fn an_ip_literal_outside_the_allowlist_is_not_opened() {
    let peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager_with(&peer, targets("10.0.0.0/8", vec![]), Limits::default());
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    assert_eq!(m.listening(), 0);
    assert_eq!(m.tcp_pool().rules(), 0);
    let st = m.status();
    assert_eq!(st[0].state, "error");
    assert_eq!(
        st[0].reason,
        format!("tcp/80: target {target} is not in WGFT_AGENT_ALLOW_TARGETS")
    );
    // 開き直しでも同じ判定
    m.retry().await;
    assert_eq!(m.listening(), 0);
}

#[tokio::test]
async fn a_hostname_the_allowlist_refuses_is_reset_at_connect_and_reported() {
    let peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager_with(
        &peer,
        targets("10.0.0.0/8", vec![("nas.lan", "127.0.0.1")]),
        Limits::default(),
    );
    m.apply(&tcp("r_a", 80, &format!("nas.lan:{}", target.port())))
        .await;
    // 待ち受けは開き、試し接続が拒否を状態に載せる
    assert_eq!(m.listening(), 1);
    let want = format!(
        "tcp/80: target 127.0.0.1:{} is not in WGFT_AGENT_ALLOW_TARGETS",
        target.port()
    );
    assert_eq!(m.status()[0].reason, want);
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(c.outcome(Duration::from_secs(5)).await, Outcome::Reset);
    assert_eq!(m.status()[0].reason, want);
    // 拒んだ接続は枠を返す
    wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
}

#[tokio::test]
async fn probes_report_an_unreachable_target_and_its_recovery() {
    let peer = Peer::start().await;
    let dead = free_port();
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &format!("127.0.0.1:{dead}"))).await;
    assert_eq!(m.listening(), 1);
    let st = m.status();
    assert_eq!(st[0].state, "error");
    // Windows はループバックの拒否にも SYN を送り直すので、2 秒の期限に届くことがある
    #[cfg(not(windows))]
    assert_eq!(
        st[0].reason,
        format!("tcp/80: dial tcp 127.0.0.1:{dead}: connect: connection refused")
    );
    // 宛先が戻れば、次の見回りで誤りが消える
    let up = LanListener::bind(("127.0.0.1", dead)).await.unwrap();
    m.retry().await;
    assert_eq!(m.status()[0].state, "ok");
    drop(up);
}

/// keepalive の ping は wgstack の ping の endpoint から送り、server の答えで往復時間を返す。
#[tokio::test]
async fn the_keepalive_ping_goes_through_the_core() {
    let peer = Peer::start().await;
    let rtt = crate::tunnel::ping(&peer.agent().handle(), SERVER_IP, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(rtt < Duration::from_secs(5));
    // 答えない宛先は期限で終わり、文は `timed out` で終わる
    let e = crate::tunnel::ping(
        &peer.agent().handle(),
        std::net::Ipv4Addr::new(10, 200, 0, 9),
        Duration::from_millis(200),
    )
    .await
    .unwrap_err();
    assert!(e.ends_with("timed out"), "{e}");
}

/// トンネルの側の client が RST で切ると、中継は終わり、枠を返す。
#[tokio::test]
async fn a_reset_from_the_tunnel_side_ends_the_relay() {
    let peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
    c.reset();
    wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
}

/// データプレーンを止めると、中継の接続は RST で切られ、その RST は止まる前に送り出される。
#[tokio::test]
async fn stopping_the_data_plane_resets_the_relayed_connections() {
    let mut peer = Peer::start().await;
    let target = echo().await;
    let mut m = manager(&peer);
    m.apply(&tcp("r_a", 80, &target.to_string())).await;
    let mut c = peer.connect(80).await.unwrap();
    assert_eq!(round_trip(&mut c, b"x").await.unwrap(), b"x");
    // 中継を閉じずにデータプレーンを止める
    peer.stop_agent().await;
    assert_eq!(c.outcome(Duration::from_secs(5)).await, Outcome::Reset);
    drop(m);
}
