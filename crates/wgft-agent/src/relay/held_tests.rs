//! メモリの上界と実際の保持の比較 (agent-parity.md の「メモリの上界の行」)。
//!
//! 小さい上限の agent のデータプレーンと中継を試験の相手と組み、段ごとに生きている確保のバイトを測って、
//! 上界の項と比べる。
//!
//! - 作成:核、表、device と待ち受けを作った後の保持が、作成の時に作る項 (核の固定の部分、表、駆動、
//!   device) に収まる
//! - 応答のバッファ:枠をすべて同時に貸させた後の育ちが、枠の数の UDP のバッファに収まる
//! - UDP:予算が拒むまでセッションを作った後の育ちが、セッションの数とセッションの項の積に収まる
//! - TCP:予算が拒むまで中継を開き、両向きに大きいバッファを借りさせた後の育ちが、中継の数と中継の項の積と、
//!   生きている大きいバッファの和に収まる。データが止まった中継は大きいバッファを返し、生きている大きい
//!   バッファは置き場に残す数までになる
//! - 閉じた後:UDP のセッションが無通信の期限で閉じた後と、すべてを閉じた後の保持が、作成の時の保持と、
//!   使い回しのために残す応答のバッファと大きいバッファの和に収まる。閉じた流れの漏れはここで見える
//!
//! 試験の側の持ち物は見積もらずに測る。server の側の device は agent 無しで立てて測る。台本の client は
//! 落としても agent に何も送らないので、落とす前後の差を試験の側とする。TCP の宛先の echo の接続は、
//! agent 無しの普通の TCP の client で同じ量を往復させて測る。この測りは client の側のソケットの登録も
//! 含むので、試験の側を少し多めに数え、その分だけ agent の側を少なめに数える。核の保持は核が数えて返す
//! 値 (`Stack::held`) を差し引く。核の保持が核の項に収まることは wgstack の試験が確かめる。
//!
//! 生きている確保の最大値は比べない。最大値には試験の側の一時の確保 (台本の client のチャネルに溜まる
//! segment など) が混ざり、差し引けないためである。比べるのは各段の後の落ち着いた保持である。
//!
//! 数えはプロセスで 1 つなので、試験ごとにプロセスを分けて流す cargo-nextest の下でだけ測る。
//! `cargo test` のように他の試験と同じプロセスで流れるときは、その旨を書いて測らずに終わる。

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as LanListener, TcpStream as LanStream, UdpSocket as LanSocket};
use wgft_alloc_count::live_bytes;
use wgft_proto::Proto;

use super::pipe::BULK_ALIVE;
use super::pipe::BULK_WAIT;
use super::replies::{REPLIES, REPLY_SLOTS, UDP_BUF};
use super::testpeer::{self, Outcome, Peer};
use super::tests::{rule, targets, wait_for};
use super::{BULK_BUF, BULK_KEEP, Kind, Manager};
use crate::flowpool::Limits;
use crate::memory::{MemoryBound, TCP_RELAY_CONN, UDP_SESSION};

/// 測りの誤差として認める量。実行環境と台本の通信路が測りの間に一時に持つもの (ログの行、チャネルの
/// block、タイマー) のためで、流れの数に比例しない。
const SLACK: usize = 64 << 10;

/// UDP のセッションの無通信の期限。セッションを作って測り終えるまでより十分長く、閉じるのを待つ時間が
/// 試験を長くしすぎない長さにする。
const UDP_IDLE: Duration = Duration::from_secs(2);

/// 他の試験と同じプロセスで流れていないか。cargo-nextest は試験ごとにプロセスを分け、そのことを
/// `NEXTEST_EXECUTION_MODE` で示す。古い版はこの変数を持たず、`NEXTEST` だけを置く。
fn counted_alone() -> bool {
    match std::env::var_os("NEXTEST_EXECUTION_MODE") {
        Some(mode) => mode == "process-per-test",
        None => std::env::var_os("NEXTEST").is_some(),
    }
}

/// 生きている確保が落ち着くのを待って返す。20 ミリ秒ごとに読み、続けて 3 回同じなら落ち着いたとする。
/// 落ち着かなければ 2 秒で最後の値を返す。
async fn settled() -> usize {
    let mut last = live_bytes();
    let mut same = 0;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let now = live_bytes();
        if now == last {
            same += 1;
            if same == 3 {
                break;
            }
        } else {
            same = 0;
            last = now;
        }
    }
    last
}

/// 受けたものをそのまま返す TCP の宛先。接続ごとに task と 4 KiB の読みのバッファを持つ。
async fn tcp_echo() -> std::net::SocketAddr {
    let l = LanListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
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

/// 核が自分で数える可変の保持のバイト。接続の枠に残る floor の記録の輪と区間の表、輪と置き場の chunk、
/// 再組み立ての表、UDP の datagram である。核の保持が核の項に収まることは核の試験が確かめるので、この試験は
/// 核の分を差し引いて中継の保持を見る。
async fn core_bytes(peer: &Peer) -> usize {
    let h = peer
        .agent()
        .handle()
        .call(|net| net.with(|s| s.core().held()))
        .await
        .unwrap();
    // `Held` の文書の式。借りている boost の配列は Budget が先に確保したものなので引く
    (h.record_bytes
        + h.interval_bytes
        + h.chunk_bytes
        + h.pool_bytes
        + h.frag_bytes
        + h.udp_rx_bytes
        + h.udp_tx_bytes)
        - h.lent_array_bytes
}

fn sessions(m: &Manager) -> usize {
    m.listener_stats()
        .iter()
        .filter(|s| s.key.kind == Kind::Udp)
        .map(|s| s.sessions)
        .sum()
}

#[tokio::test]
async fn the_relays_hold_what_the_terms_of_the_memory_bound_count() {
    if !counted_alone() {
        eprintln!(
            "skipped: the allocation count is per process, so this test measures only under cargo-nextest, which runs each test in its own process"
        );
        return;
    }
    let limits = Limits { udp: 128, tcp: 24 };
    let bound = MemoryBound::with_core(limits, testpeer::limits());
    let chunk = vec![7u8; 2 * BULK_BUF.min(8 << 10)];

    // 試験の側:server の側の device を agent 無しで立てて測る
    let t0 = settled().await;
    let (server, _) = Peer::server().await;
    let server_side = settled().await.saturating_sub(t0);
    drop(server);

    // 試験の側:TCP の宛先の接続 1 本の持ち物を、普通の client で同じ量を往復させて測る
    let ttarget = tcp_echo().await;
    let t1 = settled().await;
    let mut plain = Vec::new();
    let mut back = vec![0u8; chunk.len()];
    for _ in 0..limits.tcp {
        let mut s = LanStream::connect(ttarget).await.unwrap();
        s.write_all(&chunk).await.unwrap();
        s.read_exact(&mut back).await.unwrap();
        plain.push(s);
    }
    let echo_conn = settled().await.saturating_sub(t1).div_ceil(limits.tcp);
    drop(plain);

    // UDP の echo の宛先
    let usock = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let utarget = usock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF];
        while let Ok((n, from)) = usock.recv_from(&mut buf).await {
            let _ = usock.send_to(&buf[..n], from).await;
        }
    });

    // 作成:agent のデータプレーンと核、待ち受け
    let t2 = settled().await;
    let peer = Peer::start().await;
    assert_eq!(peer.connect(1).await.err(), Some(Outcome::Reset));
    let mut m = Manager::new(
        testpeer::AGENT_IP,
        peer.agent().handle(),
        targets("", vec![]),
        limits,
        UDP_IDLE,
    );
    m.apply(&[
        rule("r_u", Proto::Udp, "2456", &utarget.to_string(), true),
        rule("r_t", Proto::Tcp, "80", &ttarget.to_string(), true),
    ])
    .await;
    let setup = settled().await;
    let agent_setup = setup.saturating_sub(t2).saturating_sub(server_side);
    let made_at_setup = bound.core_fixed + bound.tables + bound.driver + bound.device;
    eprintln!(
        "setup: the agent holds {agent_setup} bytes against the terms made at creation, {made_at_setup}; the test side: the server device {server_side}, one echo connection {echo_conn}"
    );
    assert!(
        agent_setup <= made_at_setup + SLACK,
        "the agent holds {agent_setup} bytes after setup, above the terms made at creation, {made_at_setup}"
    );

    // 応答のバッファ:枠をすべて同時に貸させる。以後の段は作ったバッファを使い回す
    {
        let mut held = Vec::with_capacity(REPLY_SLOTS);
        for _ in 0..REPLY_SLOTS {
            held.push(REPLIES.acquire().await);
        }
    }
    let after_replies = settled().await;
    let replies = after_replies.saturating_sub(setup);
    eprintln!("replies: {replies} bytes for {REPLY_SLOTS} buffers of {UDP_BUF}");
    assert!(
        (REPLY_SLOTS * UDP_BUF..=REPLY_SLOTS * UDP_BUF + SLACK).contains(&replies),
        "the reply buffers grew the heap by {replies} bytes"
    );

    // UDP:予算が新しい送信元を拒むまでセッションを作る
    let core_udp = core_bytes(&peer).await;
    let mut sources = Vec::new();
    loop {
        let mut c = peer.udp();
        c.send(2456, b"u");
        if c.recv(Duration::from_millis(300)).await.is_none() {
            break;
        }
        sources.push(c);
        assert!(sources.len() <= limits.udp, "the UDP budget did not refuse");
    }
    let n_udp = sources.len();
    assert!(n_udp >= limits.udp / 2, "{n_udp} UDP sessions");
    let with_sources = settled().await;
    drop(sources);
    let after_udp = settled().await;
    assert_eq!(
        sessions(&m),
        n_udp,
        "UDP sessions closed while they were measured; the idle timeout is too short for this machine"
    );
    let udp_core = core_bytes(&peer).await.saturating_sub(core_udp);
    let udp_test_side = with_sources.saturating_sub(after_udp);
    let udp_growth = after_udp
        .saturating_sub(after_replies)
        .saturating_sub(udp_core);
    let udp_allowed = n_udp * UDP_SESSION + SLACK;
    eprintln!(
        "udp: {n_udp} sessions grew the relay by {udp_growth} bytes against {udp_allowed}, the core by {udp_core}; the scripted sources held {udp_test_side}"
    );
    assert!(
        udp_growth <= udp_allowed,
        "{n_udp} UDP sessions grew the relay by {udp_growth} bytes, above {udp_allowed}"
    );

    // UDP のセッションが無通信の期限で閉じた後は、段の前の保持に戻る
    wait_for("the UDP sessions to close", || sessions(&m) == 0).await;
    let udp_closed = settled().await;
    let udp_left = udp_closed.saturating_sub(after_replies);
    eprintln!("udp closed: {udp_left} bytes above the start of the stage");
    assert!(
        udp_left <= SLACK,
        "the closed UDP sessions left {udp_left} bytes"
    );

    // TCP:予算が拒むまで中継を開き、両向きに大きいバッファを借りさせる量を往復させる
    let core_tcp = core_bytes(&peer).await;
    let mut conns = Vec::new();
    loop {
        let Ok(mut c) = peer.connect(80).await else {
            break;
        };
        c.send(&chunk);
        match c.read_exact(chunk.len()).await {
            Ok(d) => assert_eq!(d.len(), chunk.len()),
            Err(Outcome::Reset) => break,
            Err(o) => panic!("the relay ended with {o:?}"),
        }
        conns.push(c);
        assert!(conns.len() <= limits.tcp, "the TCP budget did not refuse");
    }
    let n_tcp = conns.len();
    assert!(n_tcp >= limits.tcp / 2, "{n_tcp} TCP relays");
    // データが止まった中継が大きいバッファを返すまで待つ
    tokio::time::sleep(2 * BULK_WAIT).await;
    let with_clients = settled().await;
    drop(conns);
    let after_tcp = settled().await;
    let bulk = BULK_ALIVE.load(Ordering::Relaxed);
    let tcp_core = core_bytes(&peer).await.saturating_sub(core_tcp);
    let tcp_test_side = with_clients.saturating_sub(after_tcp) + n_tcp * echo_conn;
    let tcp_growth = after_tcp
        .saturating_sub(udp_closed)
        .saturating_sub(n_tcp * echo_conn)
        .saturating_sub(tcp_core);
    let tcp_allowed = n_tcp * TCP_RELAY_CONN + bulk * BULK_BUF + SLACK;
    eprintln!(
        "tcp: {n_tcp} relays grew the relay by {tcp_growth} bytes with {bulk} bulk buffers alive against {tcp_allowed}, the core by {tcp_core}; the scripted clients and the echo connections held {tcp_test_side}"
    );
    assert!(
        bulk <= BULK_KEEP,
        "{bulk} bulk buffers are alive after the data stopped, above the {BULK_KEEP} kept for reuse"
    );
    assert!(
        tcp_growth <= tcp_allowed,
        "{n_tcp} TCP relays grew the relay by {tcp_growth} bytes, above {tcp_allowed}"
    );

    // すべてを閉じた後は、作成の時の保持と、使い回しに残す応答のバッファと大きいバッファまでに戻る
    m.close().await;
    let closed = settled().await;
    let left = closed
        .saturating_sub(setup)
        .saturating_sub(core_bytes(&peer).await);
    let kept = REPLY_SLOTS * UDP_BUF + BULK_KEEP * BULK_BUF;
    eprintln!("closed: {left} bytes above setup besides the core's, against {kept} kept for reuse");
    assert!(
        left <= kept + SLACK,
        "closing every flow left {left} bytes above setup, above the {kept} kept for reuse"
    );
}
