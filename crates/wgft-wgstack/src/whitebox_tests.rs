//! fuzz の被覆の地図で届かなかった危険な経路の決定的な白箱の試験:順序外のデータの取り消し、UDP の送信の予算の
//! 待ち、TIME_WAIT の表の追い出しと再送された FIN、cookie の行の RST です。
//!
//! 各試験は出力 (packet、知らせ、統計) と保持の会計を確かめ、`TestNet` が毎回の操作の後に不変条件を確かめます。
//! UDP の待ちと cookie の行は Go に無いか Go と意図して違う所なので、Go の試験の写しではありません。

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

use crate::boost_tests::{
    DEMAND_BYTES, Two, boost_two_with, boosted, inject_at, intervals, lent, read_n, send_bulk,
    wide_limits,
};
use crate::buf::chunk::CHUNK_SIZE;
use crate::buf::recv::splitmix64;
use crate::buf::{BOOST_INTERVALS, FLOOR_INTERVALS, RECV_FLOOR};
use crate::stack::{Error, Event, ListenerId};
use crate::testnet_tests::{DUT, PEER, PeerConn, TEST_MTU, TestNet, show, small_limits};
use crate::udp::{ENDPOINT_SHARE, TX_BYTES};
use crate::wire::{FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN};
use crate::{ConnId, Limits, UdpId};
use core::net::SocketAddrV4;
use core::time::Duration;

const PEER_UDP: SocketAddrV4 = SocketAddrV4::new(PEER, 5000);

// ---- UDP の送信の予算 ----

fn bind(n: &mut TestNet, port: u16) -> UdpId {
    n.s.bind_udp(n.now, SocketAddrV4::new(DUT, port)).unwrap()
}

fn send(n: &mut TestNet, id: UdpId, len: usize) -> Result<usize, Error> {
    let r = n.s.send_to(n.now, id, &vec![0xa5; len], PEER_UDP);
    n.check();
    r
}

/// 核の送信の byte の予算が尽きた時:`send_to` は待たずに `WouldBlock` を返し、断った datagram は何も数えず何も
/// 持たず、endpoint を待ちの list に入れます。予約が 1 つ返ると、待つ endpoint のすべてが 1 回ずつ `UdpWritable`
/// を受けます。datagram の最後の断片を出した時に返り、途中の断片では返りません。待つ endpoint を閉じると list
/// から外れ (先頭でも)、残る endpoint だけが起こされます。
#[test]
fn udp_send_waits_when_the_tunnel_budget_is_spent() {
    let mut n = TestNet::new(small_limits());
    let full: Vec<UdpId> = (0..ENDPOINT_SHARE as u16)
        .map(|p| bind(&mut n, 100 + p))
        .collect();
    let (a, b) = (bind(&mut n, 200), bind(&mut n, 201));
    // endpoint 1 つの上限 (chunk 64 個) まで送る 4 つの endpoint で、核の予算 (chunk 256 個) をちょうど使い切る
    let per_ep = TX_BYTES / ENDPOINT_SHARE / CHUNK_SIZE;
    for &u in &full {
        for _ in 0..per_ep {
            assert_eq!(send(&mut n, u, CHUNK_SIZE), Ok(CHUNK_SIZE));
        }
    }
    let h = n.s.held();
    assert_eq!(h.udp_tx_bytes, TX_BYTES);
    assert_eq!(h.udp_tx_datagrams, per_ep * ENDPOINT_SHARE);
    let before = n.s.stats();
    // 核の予算で断る。endpoint の上限には届いていない 2 つが待ちの list に入る
    assert_eq!(send(&mut n, a, 10), Err(Error::WouldBlock));
    assert_eq!(send(&mut n, b, 10), Err(Error::WouldBlock));
    assert_eq!(
        send(&mut n, a, 10),
        Err(Error::WouldBlock),
        "a second refusal"
    );
    let after = n.s.stats();
    assert_eq!(
        (
            after.udp_dropped,
            after.udp_endpoint_full,
            after.udp_tunnel_full
        ),
        (
            before.udp_dropped,
            before.udp_endpoint_full,
            before.udp_tunnel_full
        ),
        "a refused send is a wait, not a drop"
    );
    let h2 = n.s.held();
    assert_eq!(
        (h2.udp_tx_bytes, h2.udp_tx_datagrams),
        (h.udp_tx_bytes, h.udp_tx_datagrams),
        "a refused send holds nothing"
    );
    assert!(
        n.events()
            .iter()
            .all(|e| !matches!(e, Event::UdpWritable(_))),
        "no wake before a reservation returns"
    );
    // 最初の datagram は断片に分かれて出る。最後の断片を出すまで予約は返らない
    let frags = (CHUNK_SIZE + 8).div_ceil(TEST_MTU - 20);
    let mut buf = vec![0u8; TEST_MTU];
    for i in 0..frags {
        assert!(n.s.poll_transmit(n.now, &mut buf).is_some(), "fragment {i}");
        let ev: Vec<_> = n.events();
        if i + 1 < frags {
            assert!(ev.is_empty(), "woken after fragment {i}: {ev:?}");
        } else {
            assert_eq!(ev.len(), 2, "one wake per waiting endpoint: {ev:?}");
            assert!(ev.contains(&Event::UdpWritable(a)), "{ev:?}");
            assert!(ev.contains(&Event::UdpWritable(b)), "{ev:?}");
        }
    }
    n.check();
    assert_eq!(
        n.s.held().udp_tx_bytes,
        TX_BYTES - CHUNK_SIZE,
        "one chunk returned"
    );
    // 空きができたので、待っていた endpoint の送信は通る。その後は再び核の予算に届き、2 つとも待つ。list の先頭は
    // 最後に待った b で、先頭の endpoint を閉じても a の待ちは残り、a だけが起こされる
    assert_eq!(send(&mut n, a, CHUNK_SIZE), Ok(CHUNK_SIZE));
    assert_eq!(send(&mut n, a, 10), Err(Error::WouldBlock));
    assert_eq!(send(&mut n, b, 10), Err(Error::WouldBlock));
    n.s.close_udp(n.now, b);
    n.check();
    // 全部を送り終えると、保持は 0 に戻る
    while n.s.poll_transmit(n.now, &mut buf).is_some() {}
    n.check();
    let h = n.s.held();
    assert_eq!((h.udp_tx_bytes, h.udp_tx_datagrams), (0, 0), "{h:?}");
    let ev = n.events();
    assert!(ev.contains(&Event::UdpWritable(a)));
    assert!(
        !ev.contains(&Event::UdpWritable(b)),
        "a closed endpoint is not woken"
    );
    assert_eq!(send(&mut n, a, 10), Ok(10));
    let st = n.s.stats();
    assert_eq!(st.udp_dropped, before.udp_dropped, "nothing was dropped");
}

// ---- TIME_WAIT の表 ----

/// 80 番で待ち受ける核の、`sport` の相手との接続を核から閉じて TIME_WAIT の行にします。核の FIN の確認と相手の
/// FIN の後、行は TIME_WAIT で、相手の次の番号は FIN の次です。
fn into_time_wait(n: &mut TestNet, l: ListenerId, sport: u16) -> PeerConn {
    let mut p = n.handshake(sport, 80, true, true);
    let c = n.accept(l);
    n.drain();
    n.s.close_conn(n.now, c);
    let outs = n.drain();
    p.absorb(&outs);
    n.peer_ack(&mut p, &[]);
    n.peer_fin(&mut p);
    let outs = n.drain();
    assert!(
        outs.len() == 1 && outs[0].ack == p.snd && outs[0].flags == FLAG_ACK,
        "the FIN is acknowledged: {}",
        show(&outs)
    );
    p.absorb(&outs);
    p
}

/// 再送された FIN (相手の FIN の番号を繰り返す) を送り、核の出力を返します。
fn resend_fin(n: &mut TestNet, p: &mut PeerConn) -> Vec<crate::testnet_tests::Out> {
    let mut s = p.seg(FLAG_ACK | FLAG_FIN, &[]);
    s.seq = p.snd.wrapping_sub(1);
    n.inject(&s);
    n.drain()
}

fn tw_limits(rows: usize) -> Limits {
    Limits {
        tw_rows: rows,
        ..small_limits()
    }
}

/// TIME_WAIT の表が満ちると、最も古い行 (list の先頭) を外して数えます。再送された FIN
/// は行に ACK を返して期限を数え直し、行を list の末尾に移すので、追い出しの順が変わります。追い出された行の
/// 相手の FIN には RST を返し、期限を過ぎた行は外れ、その FIN は
/// どの接続にも当たらない segment として RST を受けます。
#[test]
fn time_wait_table_evicts_the_oldest_row_and_a_refreshed_row_survives() {
    let mut n = TestNet::new(tw_limits(3));
    let l = n.listen(80);
    let mut a = into_time_wait(&mut n, l, 40000);
    n.advance(Duration::from_secs(1));
    let mut b = into_time_wait(&mut n, l, 40001);
    n.advance(Duration::from_secs(1));
    let mut c = into_time_wait(&mut n, l, 40002);
    assert_eq!((n.s.held().tw_rows, n.s.stats().tw_evicted), (3, 0));
    // 再送された FIN は ACK を返す。行 A は list の末尾に移り、期限は今から数え直す (t = 10 s)
    n.advance(Duration::from_secs(8));
    let outs = resend_fin(&mut n, &mut a);
    assert!(
        outs.len() == 1 && outs[0].flags == FLAG_ACK && outs[0].ack == a.snd,
        "{}",
        show(&outs)
    );
    assert_eq!(n.s.held().tw_rows, 3, "a retransmitted FIN makes no row");
    // 4 本目の行は最も古い B を追い出す。A は新しい
    let mut d = into_time_wait(&mut n, l, 40003);
    let (h, st) = (n.s.held(), n.s.stats());
    assert_eq!((h.tw_rows, st.tw_evicted), (3, 1), "{h:?}");
    let outs = resend_fin(&mut n, &mut b);
    assert!(
        outs.len() == 1 && outs[0].has(FLAG_RST),
        "the evicted row's FIN meets no connection: {}",
        show(&outs)
    );
    for p in [&mut a, &mut c, &mut d] {
        let outs = resend_fin(&mut n, p);
        assert!(
            outs.len() == 1 && outs[0].flags == FLAG_ACK,
            "port {}: {}",
            p.sport,
            show(&outs)
        );
    }
    assert_eq!(n.s.stats().tw_evicted, 1);
    // t = 10 s で C と D と A の期限を数え直した。A の元の期限 60 s を過ぎても生きる
    n.advance(Duration::from_secs(55));
    assert_eq!(n.s.held().tw_rows, 3, "refreshed deadlines are 70 s");
    let outs = resend_fin(&mut n, &mut a);
    assert!(outs.len() == 1 && outs[0].flags == FLAG_ACK);
    // 最後の FIN から 60 s で行は外れる
    n.advance(Duration::from_secs(61));
    assert_eq!(n.s.held().tw_rows, 0);
    assert_eq!(n.s.stats().tw_evicted, 1, "expiry is not an eviction");
    let outs = resend_fin(&mut n, &mut a);
    assert!(outs.len() == 1 && outs[0].has(FLAG_RST), "{}", show(&outs));
}

// ---- cookie の行の RST ----

/// cookie の ACK が待ち受けの待ち行列の満杯で行になった相手 (握手を終えたと思っている) は、SYN-ACK の再送を使い
/// 切ると RST で切られます。再送は 1、2、4、8、16 秒の間隔で、使い切った行は次の 32 秒の後に RST を送ります。
/// RST の番号は相手の握手の番号で、送った時に行を外して数えます。相手が返す ACK は再送の回数を数え直しません。
/// 黙った相手と ACK を返す相手は同じ時刻に切られます。cookie でない偽の SYN の行は RST を出さずに外れます。
/// cookie は Go に無いので、Go との比較はありません。
#[test]
fn a_cookie_row_is_reset_exactly_when_its_retransmissions_run_out() {
    use crate::listen_tests::{cookies_then_full_queue, flooded};
    let (mut n, _l) = flooded();
    let [mut quiet, mut acking] = cookies_then_full_queue(&mut n, &[42000, 42001])[..] else {
        unreachable!()
    };
    n.peer_ack(&mut quiet, &[]);
    n.peer_ack(&mut acking, &[]);
    assert_eq!(n.s.stats().syn_cookies_deferred, 2);
    let rows = n.s.held().syn_rows;
    let t0 = n.now;
    let mut synacks: Vec<(u64, u16)> = Vec::new();
    let mut rsts: Vec<(u64, u16)> = Vec::new();
    for _ in 0..800 {
        n.advance(Duration::from_millis(100));
        let at = (n.now - t0).as_millis() as u64;
        for o in n.drain() {
            assert!(
                o.rport == 42000 || o.rport == 42001,
                "no packet goes to any other peer, spoofed sources included: {o}"
            );
            if o.has(FLAG_RST) {
                assert_eq!(o.flags, FLAG_RST | FLAG_ACK);
                let p = if o.rport == 42000 { &quiet } else { &acking };
                assert_eq!(
                    (o.seq, o.ack),
                    (p.dut_iss.wrapping_add(1), p.snd),
                    "the RST carries the numbers of the peer's handshake"
                );
                rsts.push((at, o.rport));
            } else {
                assert_eq!(o.flags, FLAG_SYN | FLAG_ACK);
                synacks.push((at, o.rport));
                if o.rport == 42001 {
                    n.peer_ack(&mut acking, &[]);
                    let outs = n.drain();
                    assert!(
                        outs.iter().all(|o| !o.has(FLAG_RST)),
                        "an ACK from the peer draws no RST: {}",
                        show(&outs)
                    );
                }
            }
        }
    }
    let at = |port| -> Vec<u64> {
        synacks
            .iter()
            .filter(|s| s.1 == port)
            .map(|s| s.0 / 1000)
            .collect()
    };
    assert_eq!(
        at(42000),
        [1, 3, 7, 15, 31],
        "retransmissions of the quiet peer"
    );
    assert_eq!(
        at(42001),
        [1, 3, 7, 15, 31],
        "the acking peer's ACKs do not restart them"
    );
    let mut want = vec![(63_000, 42000), (63_000, 42001)];
    rsts.sort_unstable();
    want.sort_unstable();
    assert_eq!(rsts, want, "one RST each, at the end of the 32 s wait");
    let st = n.s.stats();
    // 偽の SYN の行も同じ再送を使い切り、cookie の無い行は RST を出さずに外れる
    assert_eq!(
        rows,
        small_limits().syn_rows / 2 + 2,
        "setup: fake rows and the two cookie rows"
    );
    assert_eq!(n.s.held().syn_rows, 0, "every row is gone");
    assert_eq!(
        st.syn_cookies_reset, 2,
        "only the cookie rows reset their peers"
    );
    n.check();
}

// ---- 順序外のデータの取り消し ----

/// 取り消しに使う中身です。offset `i` の byte は `i` で決まります。
fn pattern(lo: usize, hi: usize) -> Vec<u8> {
    (lo..hi).map(|i| splitmix64(i as u64) as u8).collect()
}

/// 受信の offset `lo..hi` を、`seg` byte ごとの segment で送ります。
fn send_range(
    n: &mut TestNet,
    p: &mut PeerConn,
    c: ConnId,
    start: u64,
    lo: usize,
    hi: usize,
    seg: usize,
) {
    let mut o = lo;
    while o < hi {
        let e = (o + seg).min(hi);
        inject_at(n, p, c, start + o as u64, &pattern(o, e));
        o = e;
    }
}

/// 受信の窓が boost の段の保有者が floor の区間の数を超える順序外の区間を持つとき、取り消しは始まりの順で
/// floor の区間の数の個目までを残し、残りと floor の外の区間を捨てます。捨てた byte は数え、残した区間と広告した
/// 右端は変えず、受信の輪が持つ chunk は floor の分に減り、区間の表は floor の大きさになります。相手が累積の確認から
/// 送り直すと、捨てたデータも含めて壊れずに順に届きます。
#[test]
fn renege_keeps_the_first_floor_intervals_and_redelivery_is_intact() {
    let Two {
        mut n,
        c1,
        mut p1,
        c2,
        mut p2,
    } = boost_two_with(true);
    let start = n.s.conn(c1.slot).b.rcv.nxt_off;
    let edge = n.s.conn(c1.slot).b.rcv.read_off + RECV_FLOOR;
    // 100 byte の区間を 200 byte おきに置く。floor の区間の数より 10 個多く、floor の中に収まる
    let total = FLOOR_INTERVALS + 10;
    for k in 0..total {
        let o = 1000 + 200 * k;
        inject_at(&mut n, &mut p1, c1, start + o as u64, &pattern(o, o + 100));
    }
    // floor の外にもう 1 つ
    let far = (edge - start) as usize + 5000;
    inject_at(
        &mut n,
        &mut p1,
        c1,
        start + far as u64,
        &pattern(far, far + 100),
    );
    n.drain();
    let (len, ooo, chunks_before, cap_before, adv) = {
        let v = n.s.conn(c1.slot);
        (
            v.b.rcv.intervals_len(),
            v.b.rcv.ooo_bytes(),
            v.b.rcv.r.held_chunks(),
            v.b.rcv.intervals_capacity(),
            v.t.adv_right,
        )
    };
    assert_eq!((len, ooo), (total + 1, 100 * (total as u64 + 1)));
    assert_eq!(cap_before, BOOST_INTERVALS);
    // 1 秒を超えて黙った保有者から、枠の取り合いで取り戻す
    n.advance(Duration::from_secs(2));
    send_bulk(&mut n, &mut p2, DEMAND_BYTES);
    read_n(&mut n, c2, DEMAND_BYTES);
    assert!(!boosted(&mut n, c1) && boosted(&mut n, c2), "demoted");
    let want: Vec<(u64, u64)> = (0..FLOOR_INTERVALS)
        .map(|k| {
            let o = start + 1000 + 200 * k as u64;
            (o, o + 100)
        })
        .collect();
    assert_eq!(intervals(&mut n, c1), want, "the first intervals are kept");
    let v = n.s.conn(c1.slot);
    assert_eq!(v.b.rcv.ooo_bytes(), 100 * FLOOR_INTERVALS as u64);
    assert_eq!(v.b.rcv.intervals_capacity(), FLOOR_INTERVALS, "floor table");
    assert_eq!(v.t.adv_right, adv, "the advertised edge does not shrink");
    assert!(
        v.b.rcv.r.held_chunks() < chunks_before,
        "the chunk past the floor is returned: {} then {}",
        chunks_before,
        v.b.rcv.r.held_chunks()
    );
    assert!(v.b.rcv.r.held_chunks() <= RECV_FLOOR as usize / CHUNK_SIZE);
    assert_eq!(
        n.s.stats().boost_reneged_bytes,
        100 * (total as u64 + 1 - FLOOR_INTERVALS as u64),
        "dropped bytes are counted"
    );
    // 相手の送り直し:累積の確認から全部を送る。floor の外は窓の外なので、読んで窓が進むたびに送り直す
    let all = far + 100;
    let mut got: Vec<u8> = Vec::new();
    let mut rounds = 0;
    while got.len() < all {
        assert!(rounds < 100, "stalled at {} of {all}", got.len());
        rounds += 1;
        let from = (n.s.conn(c1.slot).b.rcv.nxt_off - start) as usize;
        send_range(&mut n, &mut p1, c1, start, from, all, 1380);
        n.drain();
        let k = n.s.conn(c1.slot).b.rcv.unread() as usize;
        if k > 0 {
            let mut buf = vec![0u8; k];
            let mut r = 0;
            while r < k {
                r += n.s.read(n.now, c1, &mut buf[r..]).unwrap();
            }
            got.extend_from_slice(&buf);
        }
    }
    assert_eq!(got, pattern(0, all));
    n.check();
}

/// 受信の窓が floor のままの (送信の需要だけで枠を得た) 保有者の取り消しは、受信の輪を写さずに、区間を floor の
/// 表の中で入れ直します。順序外のデータとその SACK の block は変わらず、会計 (不変条件) も保たれます。
#[test]
fn demoting_a_send_only_holder_moves_its_intervals_to_the_floor_table() {
    let mut n = TestNet::new(wide_limits());
    let l = n.listen(80);
    let mut p1 = n.handshake_sack(40000, 80, true, true, true);
    p1.wnd = 65535;
    let c1 = n.accept(l);
    n.drain();
    // 送信の需要で枠を得る。送り切って確認される
    assert_eq!(
        n.s.write(n.now, c1, &vec![7u8; DEMAND_BYTES]),
        Ok(DEMAND_BYTES)
    );
    let mut rounds = 0;
    loop {
        let outs = n.drain();
        p1.absorb(&outs);
        let v = n.s.conn(c1.slot);
        if v.t.tail_off == v.t.una_off && outs.is_empty() {
            break;
        }
        assert!(rounds < 200, "the write was not acknowledged");
        rounds += 1;
        n.peer_ack(&mut p1, &[]);
    }
    assert!(
        boosted(&mut n, c1) && !n.s.conn(c1.slot).k.rcv_boost,
        "send-only boost"
    );
    assert_eq!(n.s.conn(c1.slot).b.boost, Some(0));
    // 残りの枠をすべて受信の需要で埋める
    let mut _fill = Vec::new();
    for i in 0..15 {
        let mut p = n.handshake_sack(41000 + i, 80, true, true, true);
        let c = n.accept(l);
        send_bulk(&mut n, &mut p, DEMAND_BYTES);
        read_n(&mut n, c, DEMAND_BYTES);
        n.drain();
        assert!(boosted(&mut n, c), "filler {i}");
        _fill.push(c);
    }
    assert_eq!(lent(&mut n), 16);
    // floor の中に順序外の区間を 3 つ置く
    let start = n.s.conn(c1.slot).b.rcv.nxt_off;
    for o in [1000usize, 3000, 9000] {
        inject_at(&mut n, &mut p1, c1, start + o as u64, &pattern(o, o + 500));
    }
    let outs = n.drain();
    let sack_before = outs.last().map(|o| o.sack.clone()).unwrap();
    assert_eq!(sack_before.len(), 3, "{}", show(&outs));
    let want: Vec<(u64, u64)> = [1000u64, 3000, 9000]
        .iter()
        .map(|o| (start + o, start + o + 500))
        .collect();
    assert_eq!(intervals(&mut n, c1), want);
    assert_eq!(
        n.s.conn(c1.slot).b.rcv.intervals_capacity(),
        FLOOR_INTERVALS,
        "a receive window at the floor keeps its intervals in the floor table"
    );
    // 取り合い:16 本目の接続が需要を示す
    let mut p3 = n.handshake_sack(40100, 80, true, true, true);
    let c3 = n.accept(l);
    n.advance(Duration::from_secs(2));
    send_bulk(&mut n, &mut p3, DEMAND_BYTES);
    read_n(&mut n, c3, DEMAND_BYTES);
    assert!(!boosted(&mut n, c1) && boosted(&mut n, c3), "demoted");
    let v = n.s.conn(c1.slot);
    assert_eq!(v.b.rcv.intervals_capacity(), FLOOR_INTERVALS);
    assert_eq!(v.b.rcv.ooo_bytes(), 1500);
    assert_eq!(intervals(&mut n, c1), want, "no interval is lost");
    assert_eq!(n.s.stats().boost_reneged_bytes, 0, "nothing past the floor");
    // 次の ACK は取り消しの前と同じ block を知らせ、送り直したデータで穴を埋めると順に読める
    inject_at(&mut n, &mut p1, c1, start + 20000, &pattern(20000, 20010));
    let outs = n.drain();
    // 新しい block が先頭で、続く block は取り消しの前と同じ順で同じ番号です (block は 3 つまで)
    let last = outs.last().unwrap();
    assert_eq!(last.sack.len(), 3, "{}", show(&outs));
    assert_eq!(last.sack[1..], sack_before[..2], "{}", show(&outs));
    let base = n.s.conn(c1.slot).t.irs.wrapping_add(1);
    assert_eq!(last.sack[0].left, base.wrapping_add(20000));
    send_range(&mut n, &mut p1, c1, start, 0, 12000, 1380);
    n.drain();
    let mut buf = vec![0u8; 12000];
    let mut r = 0;
    while r < 12000 {
        r += n.s.read(n.now, c1, &mut buf[r..]).unwrap();
    }
    assert_eq!(buf, pattern(0, 12000));
}
