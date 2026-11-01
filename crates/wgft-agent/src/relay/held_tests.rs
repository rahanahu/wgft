//! メモリの上界と実際の保持の比較 (agent-parity.md の「メモリの上界の行」)。
//!
//! 小さい上限の agent のデータプレーンと中継を試験の相手と組み、UDP のセッションを上限まで作り、応答の
//! バッファの枠をすべて作らせ、TCP の中継を上限まで開いて両向きに大きいバッファを借りさせる。その間の
//! 生きている確保の最大値が、上界の式のうちヒープの項 (固定の基礎と名前の解決のスレッドを除く) と、
//! 試験の側が持つものの見積もりの和を超えないことを確かめる。数えはプロセスで 1 つなので、cargo-nextest
//! のように試験ごとにプロセスを分けて流す。

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as LanListener, UdpSocket as LanSocket};
use wgft_alloc_count::{live_bytes, peak_bytes, reset_peak};
use wgft_proto::Proto;

use super::replies::{REPLIES, REPLY_SLOTS, UDP_BUF};
use super::testpeer::{self, Outcome, Peer};
use super::tests::{rule, targets};
use super::{BULK_BUF, Manager};
use crate::flowpool::Limits;
use crate::memory::{MemoryBound, device_bytes};

/// 試験の側の 1 つの TCP の接続が持つもの (台本の client の受けた segment の列、echo の task とその
/// 4 KiB の読みのバッファ、宛先のソケット) の見積もり。
const TEST_TCP_CONN: usize = 64 << 10;
/// 試験の側の 1 つの UDP の送信元 (台本の endpoint の受け取りの列と表の項) の見積もり。
const TEST_UDP_SOURCE: usize = 4 << 10;
/// 試験の側の固定の持ち物 (server の側の device の受け取りのバッファ、宛先の受け取りのバッファ、実行環境の
/// 余り) の見積もり。server の側の device のキューは別に [`device_bytes`] で足す。
const TEST_FIXED: usize = 2 * UDP_BUF + (1 << 20);

#[tokio::test]
async fn the_relays_hold_less_than_the_heap_terms_of_the_memory_bound() {
    let before = live_bytes();
    reset_peak();
    let peer = Peer::start().await;
    assert_eq!(peer.connect(1).await.err(), Some(Outcome::Reset));

    // UDP の echo と TCP の echo の宛先
    let usock = LanSocket::bind("127.0.0.1:0").await.unwrap();
    let utarget = usock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF];
        while let Ok((n, from)) = usock.recv_from(&mut buf).await {
            let _ = usock.send_to(&buf[..n], from).await;
        }
    });
    let tl = LanListener::bind("127.0.0.1:0").await.unwrap();
    let ttarget = tl.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tl.accept().await {
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

    // 核の表は試験の相手の大きさ (接続の枠 64) で、TCP の上限はそれより小さくする
    let limits = Limits { udp: 128, tcp: 24 };
    let mut m = Manager::new(
        testpeer::AGENT_IP,
        peer.agent().handle(),
        targets("", vec![]),
        limits,
        super::DEFAULT_UDP_IDLE,
    );
    m.apply(&[
        rule("r_u", Proto::Udp, "2456", &utarget.to_string(), true),
        rule("r_t", Proto::Tcp, "80", &ttarget.to_string(), true),
    ])
    .await;

    // ここから中継の流れの分だけが育つ。核と表は作成の時に確保してある
    let setup = live_bytes();
    let setup_peak = peak_bytes();
    reset_peak();

    // 応答のバッファの枠をすべて同時に貸させ、作るバッファを上限まで作らせる
    {
        let mut held = Vec::with_capacity(REPLY_SLOTS);
        for _ in 0..REPLY_SLOTS {
            held.push(REPLIES.acquire().await);
        }
    }

    // UDP のセッションを、予算が新しい送信元を拒むまで作る
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
    assert!(
        m.udp_pool().in_use() >= limits.udp / 2,
        "{}",
        m.udp_pool().in_use()
    );

    // TCP の中継を、予算が拒むまで開き、両向きに大きいバッファを借りさせる量を流す
    let chunk = vec![7u8; 2 * BULK_BUF.min(8 << 10)];
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
    assert!(
        m.tcp_pool().in_use() >= limits.tcp / 2,
        "{}",
        m.tcp_pool().in_use()
    );

    let flows = conns.len() * TEST_TCP_CONN + sources.len() * TEST_UDP_SOURCE;
    let peak = peak_bytes().max(setup_peak).saturating_sub(before);
    let growth = peak_bytes().saturating_sub(setup);
    let bound = MemoryBound::with_core(limits, testpeer::limits());
    let allowed = bound.heap_terms() + device_bytes() + TEST_FIXED + flows;
    let allowed_growth = bound.relays() + flows;
    eprintln!(
        "held peak {peak} bytes (heap terms {} + test side = {allowed}); growth under the flows {growth} bytes (relay terms {} + test side = {allowed_growth}); {} UDP sessions, {} TCP relays",
        bound.heap_terms(),
        bound.relays(),
        sources.len(),
        conns.len()
    );
    assert!(peak <= allowed, "held {peak} bytes, above {allowed}");
    // 流れの分の育ちは中継の項に収まる。核が流れの間に足す保持もこの育ちに入り、この量の流れでは余りに収まる
    assert!(
        growth <= allowed_growth,
        "the flows grew the heap by {growth} bytes, above {allowed_growth}"
    );
    m.close().await;
}
