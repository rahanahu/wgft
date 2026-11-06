//! 中継の読みの待ちと大きいバッファの返却の、外から見える挙動の試験。
//!
//! 内部の実装 (読みを何回呼ぶか、タイマーをどう置くか) には触れず、次の 2 つを固定する。
//!
//! - 短い読みの後の待ち:LAN の側の読みがバッファより少ない byte で返った後に届く byte は、順序どおり、
//!   止まらずに届く。短い読みと次の待ちの間に届く byte も含む。短い読みの後の EOF は反対側の送信を
//!   閉じ、RST は接続を終える。両方の向きで見る
//! - 大きいバッファの返却:無通信が `BULK_WAIT` を超えるまで返さず、超えたら返す。間隔が `BULK_WAIT`
//!   より短い通信は持ち続ける。返却と借り直しをまたいでも byte は欠けず、順序も変わらない
//!
//! 大きいバッファの貸出数は `BULK_LENT` (cfg(test) の数え) で見る。数えはプロセスで 1 つなので、貸出数を
//! 読む試験は cargo-nextest の下でだけ流す (`held_tests` と同じ)。

#![expect(
    clippy::many_single_char_names,
    reason = "m, c, s are the manager, the tunnel client and the LAN stream, as in the neighbouring tests"
)]

use std::time::Duration;

use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as LanListener, TcpStream as LanStream};
use tokio::time::Instant;
use wgft_proto::Proto;

use super::Manager;
use super::held_tests::counted_alone;
use super::pipe::{BULK_LENT, BULK_WAIT};
use super::testpeer::{Client, Outcome, Peer};
use super::tests::{rule, targets, wait_for};
use crate::flowpool::Limits;

const WAIT: Duration = Duration::from_secs(5);

fn lent() -> usize {
    BULK_LENT.load(std::sync::atomic::Ordering::Relaxed)
}

/// 位置と種から決まる byte 列。順序と欠けを比べるため、周期を素数にして位置がずれると一致しない。
fn pattern(seed: u8, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap()))
        .collect()
}

/// 試験の宛先の待ち受け、中継、台本の接続、宛先の側の接続を用意する。
async fn setup(peer: &Peer) -> (Manager, Client, LanStream) {
    let lan = LanListener::bind("127.0.0.1:0").await.unwrap();
    let mut m = Manager::new(
        super::testpeer::AGENT_IP,
        peer.agent().handle(),
        targets("", vec![]),
        Limits::default(),
        super::DEFAULT_UDP_IDLE,
    );
    let rules = [rule(
        "r_t",
        Proto::Tcp,
        "80",
        &lan.local_addr().unwrap().to_string(),
        true,
    )];
    assert_eq!(m.apply(&rules).await, 1);
    // ルールを適用した時の試し接続を受けて捨てる
    while let Ok(probe) = tokio::time::timeout(Duration::from_millis(300), lan.accept()).await {
        drop(probe.unwrap());
    }
    let client = peer.connect(80).await.unwrap();
    let (stream, _) = tokio::time::timeout(WAIT, lan.accept())
        .await
        .unwrap()
        .unwrap();
    (m, client, stream)
}

async fn read_lan(s: &mut LanStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(WAIT, s.read_exact(&mut buf))
        .await
        .expect("the relay stalled: the bytes never reached the LAN side")
        .unwrap();
    buf
}

async fn read_tun(c: &mut Client, n: usize) -> Vec<u8> {
    c.read_exact(n)
        .await
        .expect("the relay stalled or ended: the bytes never reached the tunnel side")
}

/// 書き込みの長さ。小さい読み、バッファの大きさの前後、複数回の読みになる長さを含む。
const SIZES: [usize; 9] = [1, 2, 100, 1000, 2047, 2048, 2049, 3000, 1];

/// 小さい待ち。0 は他の task に譲るだけ、残りは短い実時間で、短い読みと次の待ちの間に byte が届く
/// 並びを広く踏む。
async fn nap(i: usize) {
    match i % 4 {
        0 => tokio::task::yield_now().await,
        1 => tokio::time::sleep(Duration::from_micros(200)).await,
        2 => tokio::time::sleep(Duration::from_millis(2)).await,
        _ => {}
    }
}

/// LAN からトンネルへ:短い読みの後に届く byte も、順序どおり止まらずに届く。
#[tokio::test]
async fn bytes_after_a_short_read_from_the_lan_arrive_in_order() {
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    // 1 回ずつ書いて、届くのを待つ:毎回、中継は短い読みの後に待ちへ戻っている
    for i in 0..120 {
        let msg = pattern(u8::try_from(i).unwrap(), SIZES[i % SIZES.len()]);
        s.write_all(&msg).await.unwrap();
        assert!(read_tun(&mut c, msg.len()).await == msg, "round {i}");
        nap(i).await;
    }
    // 競り合い:書いて、短い待ちの後にもう 1 byte。短い読みの後の待ちに入る前後に 2 つ目が届く並びを、
    // 毎回、2 つとも届くまで待って確かめる。途中で 1 つでも取りこぼせば、次の書き込みまで届かず止まる
    for i in 0..300 {
        let first = pattern(u8::try_from(i % 200).unwrap(), 1 + i % 50);
        let second = [u8::try_from(i % 251).unwrap()];
        s.write_all(&first).await.unwrap();
        nap(i).await;
        s.write_all(&second).await.unwrap();
        let mut want = first.clone();
        want.extend_from_slice(&second);
        assert!(read_tun(&mut c, want.len()).await == want, "race round {i}");
    }
    // 待たずに続けて書く:短い読みと次の待ちの間に byte が届く並びを含む
    let mut sent = Vec::new();
    for i in 0..400 {
        let msg = pattern(u8::try_from(i % 200).unwrap(), 1 + i % 7);
        s.write_all(&msg).await.unwrap();
        sent.extend(msg);
        nap(i).await;
    }
    // 最後の 1 byte が単独で届いても、止まらない
    s.write_all(b"Z").await.unwrap();
    sent.push(b'Z');
    let got = read_tun(&mut c, sent.len()).await;
    assert!(got == sent, "bytes were lost or reordered");
    m.close().await;
}

/// トンネルから LAN へ:同じことを反対の向きで。
#[tokio::test]
async fn bytes_after_a_short_read_from_the_tunnel_arrive_in_order() {
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    for i in 0..120 {
        let msg = pattern(u8::try_from(i).unwrap(), SIZES[i % SIZES.len()]);
        c.send(&msg);
        assert!(read_lan(&mut s, msg.len()).await == msg, "round {i}");
        nap(i).await;
    }
    // 競り合い:書いて、短い待ちの後にもう 1 byte。短い読みの後の待ちに入る前後に 2 つ目が届く並びを、
    // 毎回、2 つとも届くまで待って確かめる。途中で 1 つでも取りこぼせば、次の書き込みまで届かず止まる
    for i in 0..300 {
        let first = pattern(u8::try_from(i % 200).unwrap(), 1 + i % 50);
        let second = [u8::try_from(i % 251).unwrap()];
        c.send(&first);
        nap(i).await;
        c.send(&second);
        let mut want = first.clone();
        want.extend_from_slice(&second);
        assert!(read_lan(&mut s, want.len()).await == want, "race round {i}");
    }
    let mut sent = Vec::new();
    for i in 0..400 {
        let msg = pattern(u8::try_from(i % 200).unwrap(), 1 + i % 7);
        c.send(&msg);
        sent.extend(msg);
        nap(i).await;
    }
    c.send(b"Z");
    sent.push(b'Z');
    let got = read_lan(&mut s, sent.len()).await;
    assert!(got == sent, "bytes were lost or reordered");
    m.close().await;
}

/// 両方の向きを同時に流しても、それぞれの向きの順序と欠けは保たれる。
#[tokio::test]
async fn short_reads_in_both_directions_at_once_stay_ordered() {
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let (mut up, mut down) = (Vec::new(), Vec::new());
    for i in 0..300 {
        let a = pattern(u8::try_from(i % 100).unwrap(), 1 + (i * 37) % 300);
        let b = pattern(u8::try_from(100 + i % 100).unwrap(), 1 + (i * 53) % 300);
        s.write_all(&a).await.unwrap();
        c.send(&b);
        down.extend(a);
        up.extend(b);
        nap(i).await;
    }
    assert!(read_tun(&mut c, down.len()).await == down, "LAN to tunnel");
    assert!(read_lan(&mut s, up.len()).await == up, "tunnel to LAN");
    m.close().await;
}

/// LAN の側の EOF は、短い読みの後でも、トンネルの側の送信を閉じる。反対の向きは開いたまま続く。
#[tokio::test]
async fn eof_from_the_lan_after_a_short_read_half_closes_the_tunnel() {
    for (n, pause) in [(100, false), (100, true), (1, false), (2047, true)] {
        let peer = Peer::start().await;
        let (mut m, mut c, mut s) = setup(&peer).await;
        let msg = pattern(9, n);
        s.write_all(&msg).await.unwrap();
        if pause {
            // 中継が短い読みの後の待ちに入ってから閉じる
            assert!(read_tun(&mut c, n).await == msg, "the bytes differ");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        s.shutdown().await.unwrap();
        let (got, end) = c.read_to_end(WAIT).await;
        assert_eq!(end, Outcome::Eof, "n={n} pause={pause}");
        let mut all = if pause { msg.clone() } else { Vec::new() };
        all.extend(got);
        assert!(all == msg, "n={n} pause={pause}: the data before the FIN");
        // 半分閉じた後も、トンネルから LAN へは流れる
        let back = pattern(5, 300);
        c.send(&back);
        assert!(read_lan(&mut s, 300).await == back, "the bytes differ");
        c.finish();
        let mut tail = [0u8; 1];
        let r = tokio::time::timeout(WAIT, s.read(&mut tail)).await.unwrap();
        assert_eq!(r.unwrap(), 0, "the FIN reaches the LAN side");
        wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
        m.close().await;
    }
}

/// トンネルの側の EOF は、短い読みの後でも、LAN の側の送信を閉じる。反対の向きは開いたまま続く。
#[tokio::test]
async fn eof_from_the_tunnel_after_a_short_read_half_closes_the_lan() {
    for (n, pause) in [(100, false), (100, true), (1, false), (2047, true)] {
        let peer = Peer::start().await;
        let (mut m, mut c, mut s) = setup(&peer).await;
        let msg = pattern(3, n);
        c.send(&msg);
        if pause {
            assert!(read_lan(&mut s, n).await == msg, "the bytes differ");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        c.finish();
        let mut got = if pause { msg.clone() } else { Vec::new() };
        let mut buf = [0u8; 4096];
        loop {
            let r = tokio::time::timeout(WAIT, s.read(&mut buf))
                .await
                .expect("the FIN never reached the LAN side")
                .unwrap();
            if r == 0 {
                break;
            }
            got.extend_from_slice(&buf[..r]);
        }
        assert!(got == msg, "n={n} pause={pause}: the data before the FIN");
        let back = pattern(8, 300);
        s.write_all(&back).await.unwrap();
        assert!(read_tun(&mut c, 300).await == back, "the bytes differ");
        s.shutdown().await.unwrap();
        assert_eq!(c.outcome(WAIT).await, Outcome::Eof);
        wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
        m.close().await;
    }
}

/// 短い読みの後に LAN の側が RST で切ると、中継が終わってトンネルの側が閉じ、枠が戻る。製品は読みの誤りの後、
/// トンネルの側を FIN で閉じる (Go の PipeHold の規則)。ここでは閉じ方を RST と FIN のどちらでも認める。
#[tokio::test]
async fn a_reset_from_the_lan_after_a_short_read_ends_the_tunnel_side() {
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let msg = pattern(1, 100);
    s.write_all(&msg).await.unwrap();
    assert!(read_tun(&mut c, 100).await == msg, "the bytes differ");
    tokio::time::sleep(Duration::from_millis(30)).await;
    SockRef::from(&s).set_linger(Some(Duration::ZERO)).unwrap();
    drop(s);
    // 今の挙動では、中継は読みの誤りで終わり、トンネルの側は FIN で閉じられる。RST でも構わないが、
    // 開いたまま (Timeout) は許さない
    let end = c.outcome(WAIT).await;
    assert!(
        matches!(end, Outcome::Reset | Outcome::Eof),
        "the tunnel side was left open: {end:?}"
    );
    wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
    m.close().await;
}

/// 書いてすぐ RST で切る:データが届くかは決まらないが、接続は RST で終わり、枠が戻る。
#[tokio::test]
async fn a_reset_right_after_a_short_write_from_the_lan_still_ends_the_relay() {
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    s.write_all(&pattern(2, 100)).await.unwrap();
    SockRef::from(&s).set_linger(Some(Duration::ZERO)).unwrap();
    drop(s);
    let (got, end) = c.read_to_end(WAIT).await;
    assert!(
        matches!(end, Outcome::Reset | Outcome::Eof),
        "the relay did not end: {end:?}"
    );
    assert!(got.len() <= 100 && got == pattern(2, got.len()));
    wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
    m.close().await;
}

/// 短い読みの後にトンネルの側が RST で切ると、LAN の側の接続が終わり、枠が戻る。
#[tokio::test]
async fn a_reset_from_the_tunnel_after_a_short_read_ends_the_lan_side() {
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let msg = pattern(4, 100);
    c.send(&msg);
    assert!(read_lan(&mut s, 100).await == msg, "the bytes differ");
    tokio::time::sleep(Duration::from_millis(30)).await;
    c.reset();
    // LAN の側は EOF か RST で終わる
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(WAIT, s.read(&mut buf))
        .await
        .expect("the LAN side was left open");
    assert!(matches!(r, Ok(0) | Err(_)), "unexpected data: {r:?}");
    wait_for("the flow to come back", || m.tcp_pool().in_use() == 0).await;
    m.close().await;
}

/// 大きいバッファを借りさせる。LAN から 24 KiB を流し、中継がその分を渡して借りるまで待つ。
async fn borrow_from_the_lan(c: &mut Client, s: &mut LanStream, base: usize) {
    let big = pattern(7, 24 << 10);
    s.write_all(&big).await.unwrap();
    assert!(read_tun(c, big.len()).await == big, "the bytes differ");
    wait_for("the bulk buffer to be lent", || lent() > base).await;
}

/// 大きいバッファを借りさせる。トンネルから 24 KiB を流す。
async fn borrow_from_the_tunnel(c: &mut Client, s: &mut LanStream, base: usize) {
    let big = pattern(11, 24 << 10);
    c.send(&big);
    assert!(read_lan(s, big.len()).await == big, "the bytes differ");
    wait_for("the bulk buffer to be lent", || lent() > base).await;
}

/// 最後のデータの前の時刻 `t0` から、貸出数が `base` に戻るまでを測る。戻るのが `BULK_WAIT` より早ければ
/// 落ちる。`t0` は最後のデータを書く前に取るので、中継が最後のデータを読んだ時刻以前であり、返却が
/// `t0 + BULK_WAIT` より前なら必ず早すぎる。
async fn released_after(t0: Instant, base: usize) {
    loop {
        if lent() <= base {
            let idle = t0.elapsed();
            assert!(
                idle >= BULK_WAIT,
                "the bulk buffer came back after {idle:?} without data, before {BULK_WAIT:?}"
            );
            return;
        }
        assert!(
            t0.elapsed() < 10 * BULK_WAIT,
            "the bulk buffer was not returned after {:?} without data",
            t0.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// LAN の側から借りた大きいバッファは、無通信が `BULK_WAIT` を超えるまで返らず、超えたら返る。
#[tokio::test]
async fn the_bulk_buffer_is_returned_after_the_idle_wait_and_not_before() {
    if !counted_alone() {
        eprintln!("skipped: the lent count is per process; run under cargo-nextest");
        return;
    }
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let base = lent();
    // 最後のデータ:短い 1 つ。大きいバッファを持ったまま受ける。借りた後、書く直前に貸出を確かめ、
    // 負荷で待ちが延びて正当に返却済みなら借り直してやり直す
    loop {
        borrow_from_the_lan(&mut c, &mut s, base).await;
        if lent() > base {
            break;
        }
    }
    let t0 = Instant::now();
    s.write_all(b"last").await.unwrap();
    assert_eq!(read_tun(&mut c, 4).await, b"last");
    released_after(t0, base).await;
    m.close().await;
}

/// トンネルの側から借りた大きいバッファも同じ。
#[tokio::test]
async fn the_bulk_buffer_of_the_tunnel_side_is_returned_after_the_idle_wait_and_not_before() {
    if !counted_alone() {
        eprintln!("skipped: the lent count is per process; run under cargo-nextest");
        return;
    }
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let base = lent();
    loop {
        borrow_from_the_tunnel(&mut c, &mut s, base).await;
        if lent() > base {
            break;
        }
    }
    let t0 = Instant::now();
    c.send(b"last");
    assert_eq!(read_lan(&mut s, 4).await, b"last");
    released_after(t0, base).await;
    m.close().await;
}

/// `BULK_WAIT` より短い間隔で送り続ける流れは、大きいバッファを持ち続ける。止まれば返す。
#[tokio::test]
async fn a_stream_with_gaps_shorter_than_the_wait_keeps_its_bulk_buffer() {
    if !counted_alone() {
        eprintln!("skipped: the lent count is per process; run under cargo-nextest");
        return;
    }
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let base = lent();
    borrow_from_the_lan(&mut c, &mut s, base).await;
    let gap = BULK_WAIT * 2 / 5;
    // 合計は BULK_WAIT の数倍。途中で返れば、貸出数が減っている
    let mut last = Instant::now();
    for i in 0..20u8 {
        tokio::time::sleep(gap).await;
        // 負荷で実際の間隔が延びたなら、正当に返却済みでありうるので、その回は確かめない
        if last.elapsed() < BULK_WAIT * 3 / 4 {
            assert!(
                lent() > base,
                "the bulk buffer was returned while data kept coming (round {i})"
            );
        }
        last = Instant::now();
        let msg = pattern(i, 100);
        s.write_all(&msg).await.unwrap();
        assert!(read_tun(&mut c, 100).await == msg, "the bytes differ");
    }
    let t0 = Instant::now();
    s.write_all(b"last").await.unwrap();
    assert_eq!(read_tun(&mut c, 4).await, b"last");
    released_after(t0, base).await;
    m.close().await;
}

/// 同じ流れを、トンネルの側から。
#[tokio::test]
async fn a_tunnel_side_stream_with_gaps_shorter_than_the_wait_keeps_its_bulk_buffer() {
    if !counted_alone() {
        eprintln!("skipped: the lent count is per process; run under cargo-nextest");
        return;
    }
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let base = lent();
    borrow_from_the_tunnel(&mut c, &mut s, base).await;
    let gap = BULK_WAIT * 2 / 5;
    let mut last = Instant::now();
    for i in 0..20u8 {
        tokio::time::sleep(gap).await;
        // 負荷で実際の間隔が延びたなら、正当に返却済みでありうるので、その回は確かめない
        if last.elapsed() < BULK_WAIT * 3 / 4 {
            assert!(
                lent() > base,
                "the bulk buffer was returned while data kept coming (round {i})"
            );
        }
        last = Instant::now();
        let msg = pattern(i, 100);
        c.send(&msg);
        assert!(read_lan(&mut s, 100).await == msg, "the bytes differ");
    }
    let t0 = Instant::now();
    c.send(b"last");
    assert_eq!(read_lan(&mut s, 4).await, b"last");
    released_after(t0, base).await;
    m.close().await;
}

/// 返却と借り直しを繰り返しても、両方の向きの byte は欠けず、順序も変わらない。返却の前後、返却の直前と
/// 直後に届く byte を含む。
#[tokio::test]
async fn data_is_not_lost_or_reordered_across_a_release_and_a_re_borrow() {
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let alone = counted_alone();
    let base = lent();
    let (mut up, mut down) = (Vec::new(), Vec::new());
    for round in 0u8..4 {
        // 大きい書き込み:大きいバッファを借りる
        let a = pattern(round, 24 << 10);
        let b = pattern(100 + round, 20 << 10);
        s.write_all(&a).await.unwrap();
        c.send(&b);
        down.extend(a);
        up.extend(b);
        // 持っている間の短い書き込み
        for k in 0..5usize {
            let a = pattern(50 + round, 30 + 41 * k);
            let b = pattern(150 + round, 20 + 17 * k);
            s.write_all(&a).await.unwrap();
            c.send(&b);
            down.extend(a);
            up.extend(b);
        }
        // 期限の付近で届く byte:返却の直前か直後か決まらない時刻に書く
        tokio::time::sleep(BULK_WAIT.saturating_sub(Duration::from_millis(10 * u64::from(round))))
            .await;
        s.write_all(&[round]).await.unwrap();
        c.send(&[round]);
        down.push(round);
        up.push(round);
        if round % 2 == 1 {
            // 返却を待ってから借り直す
            if alone {
                wait_for("the bulk buffers to come back", || lent() <= base).await;
            } else {
                tokio::time::sleep(3 * BULK_WAIT).await;
            }
        }
    }
    let got_down = read_tun(&mut c, down.len()).await;
    let got_up = read_lan(&mut s, up.len()).await;
    assert!(got_down == down, "LAN to tunnel differs");
    assert!(got_up == up, "tunnel to LAN differs");
    m.close().await;
}

/// このプロセスの CPU 時間 (user と system) を clock tick で返す。Linux だけ。
#[cfg(target_os = "linux")]
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    // コマンド名は括弧に囲まれ空白を含みうるので、最後の ')' の後から数える。utime は 14 番目、stime は 15 番目
    let rest = &stat[stat.rfind(')').unwrap() + 2..];
    let f: Vec<&str> = rest.split(' ').collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

/// 大きいバッファを返して黙った中継は、起き続けない。発火済みのタイマーで空回りすると CPU 時間が
/// 無通信の間じゅう使われる。製品に hook を足さず、プロセスの CPU 時間を無通信の 1 秒で見る。
/// 通常は 0 tick で、期限が過去のタイマーを毎回張り直す空回りは約 5 tick、タイマーを介さない空回りは約 100 tick
/// なので、上限は 3 tick とする。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_idle_relay_that_returned_its_bulk_buffer_does_not_keep_waking() {
    if !counted_alone() {
        eprintln!("skipped: the lent count is per process; run under cargo-nextest");
        return;
    }
    let peer = Peer::start().await;
    let (mut m, mut c, mut s) = setup(&peer).await;
    let base = lent();
    borrow_from_the_lan(&mut c, &mut s, base).await;
    borrow_from_the_tunnel(&mut c, &mut s, base + 1).await;
    wait_for("both bulk buffers to come back", || lent() <= base).await;
    // 落ち着くまで待ってから測る
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = cpu_ticks();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let used = cpu_ticks() - before;
    assert!(used < 3, "an idle relay used {used} ticks of CPU in 1 s");
    // 眠った後も、中継は動く
    s.write_all(b"awake").await.unwrap();
    assert_eq!(read_tun(&mut c, 5).await, b"awake");
    m.close().await;
}
