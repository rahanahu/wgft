//! 送りの手伝い (gated send) の試験。手で運ぶ 2 つの device ([`Bench`]) と本物の手伝いのスレッドを組み、
//! 手伝いの送り先と持ち主の送り先を 1 本の記録 ([`Wire`]) にして、送った順を確かめる。
//!
//! - counter:どの datagram も counter が一意で、手伝いが送る TCP は counter の順に出る。持ち主が直接送る
//!   UDP の追い越しは、手伝いが持てる数 (置き場 2 つの枠) 以下で、受け手の窓が受ける
//! - 切り替え:門が閉じても手伝いに束がある間は小さい束も手伝いに渡り、返った後に持ち主が送る。TCP の
//!   counter は記録の順に増える
//! - 軽い負荷:本物の 2 つのデータプレーンで少しずつ流す間、門は開かず、手伝いは一度も起きない
//! - 確保:定常で手伝いのスレッドと持ち主の手伝いの道は確保しない

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use wgft_alloc_count::thread_alloc_calls;
use wgft_wireguard::Transmit;

use super::super::batch::TxBatch;
use super::super::driver::{Sent, Sink, send_batch_helped};
use super::super::helper::{HANDOFF_MIN, Helper, HelperSink, JOBS};
use super::{A_ADDR, AGENT_IP, Bench, SERVER_IP, clock, packet, seq, tcp_packet};
use crate::batching::{Batching, MAX_SLOTS};

/// 手伝いと持ち主が送った datagram の記録。`hold` の間、手伝いの送りは止まる。
#[derive(Clone, Default)]
struct Wire {
    log: Arc<Mutex<Vec<Transmit>>>,
    hold: Arc<(Mutex<bool>, Condvar)>,
}

/// 落ちる時に手伝いの送りの止めを解く。
struct Release(Wire);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.hold(false);
    }
}

impl Wire {
    fn record(&self, tx: &TxBatch) -> usize {
        let mut log = self.log.lock().unwrap();
        for m in &tx.msgs[tx.next..tx.n_msgs] {
            for j in 0..usize::from(m.count) {
                let (to, payload) = tx.datagram(usize::from(m.first) + j);
                log.push(Transmit {
                    to,
                    payload: payload.to_vec(),
                });
            }
        }
        tx.n_msgs - tx.next
    }

    fn hold(&self, on: bool) {
        let (m, c) = &*self.hold;
        *m.lock().unwrap() = on;
        c.notify_all();
    }

    fn taken(&self) -> Vec<Transmit> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

impl HelperSink for Wire {
    fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        let (m, c) = &*self.hold;
        let _held = c.wait_while(m.lock().unwrap(), |h| *h).unwrap();
        Ok(self.record(tx))
    }

    fn wait_writable(&mut self) -> io::Result<bool> {
        Ok(true)
    }
}

impl Sink for Wire {
    fn send(&mut self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.log.lock().unwrap().push(Transmit {
            to,
            payload: payload.to_vec(),
        });
        Ok(())
    }

    fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
        Ok(self.record(tx))
    }

    fn gso(&self) -> bool {
        true
    }
}

fn helper_for(t: &Bench, wire: &Wire) -> Helper {
    Helper::spawn(
        Batching::default(),
        t.a.mtu(),
        t.a.max_transmit_len(),
        wire.clone(),
    )
    .unwrap()
}

fn udp(seq: u32) -> Vec<u8> {
    packet(AGENT_IP, SERVER_IP, seq)
}

fn counter(d: &Transmit) -> u64 {
    u64::from_le_bytes(d.payload[8..16].try_into().unwrap())
}

/// 1 回の helped のバッチ。置き場を待つ時は手伝いが返すまで待って繰り返す。
fn helped(t: &mut Bench, sink: &mut Wire, helper: &mut Helper, open: bool) -> (usize, Sent) {
    loop {
        let r = send_batch_helped(
            &mut t.a,
            &mut t.stub,
            &t.b_pub,
            clock::now(),
            &mut t.outbox,
            sink,
            helper,
            open,
        );
        if r.1 != Sent::Waiting {
            return r;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// B に渡し、受けた packet を返す。datagram はすべて受け付けられる。
fn deliver_all(t: &mut Bench, sent: &[Transmit]) -> Vec<Vec<u8>> {
    let now = clock::now();
    let mut plain = vec![0u8; usize::from(u16::MAX)];
    let mut got = Vec::new();
    for d in sent {
        let n =
            t.b.handle_datagram(now, A_ADDR.parse().unwrap(), &d.payload, &mut plain)
                .expect("the peer accepts every datagram");
        got.push(plain[..n].to_vec());
    }
    got
}

#[test]
fn the_helper_keeps_tcp_in_counter_order_and_udp_goes_out_first() {
    let mut t = Bench::new(0);
    t.connected();
    let mut wire = Wire::default();
    let mut helper = helper_for(&t, &wire);
    // TCP 300 個と、間に UDP を 7 個
    let mut tcp_seqs = Vec::new();
    for i in 0..300u32 {
        if i % 45 == 0 {
            t.stub.out.push_back(udp(10_000 + i));
        }
        t.stub.out.push_back(tcp_packet(i, 1200));
        tcp_seqs.push(i);
    }
    while !t.stub.out.is_empty() {
        helped(&mut t, &mut wire, &mut helper, true);
    }
    helper.finish();
    let c = helper.counters();
    assert!(c.jobs >= 4, "{c:?}");
    assert_eq!(c.packets, 300, "every TCP packet went to the helper: {c:?}");
    assert_eq!(c.owner_packets, 7, "the owner sent the UDP itself: {c:?}");
    assert!(c.jobs <= c.packets.div_ceil(HANDOFF_MIN as u64), "{c:?}");
    let sent = wire.taken();
    assert_eq!(sent.len(), 307);
    // counter は一意
    let mut counters: Vec<u64> = sent.iter().map(counter).collect();
    let in_wire_order = counters.clone();
    counters.sort_unstable();
    counters.dedup();
    assert_eq!(counters.len(), sent.len());
    // 追い越しは手伝いが持てる数以下
    let held = (JOBS * MAX_SLOTS) as u64;
    for (k, c) in in_wire_order.iter().enumerate() {
        let later_smaller = in_wire_order[k + 1..].iter().filter(|l| *l < c).count() as u64;
        assert!(
            later_smaller <= held,
            "datagram {k} overtook {later_smaller}"
        );
    }
    let got = deliver_all(&mut t, &sent);
    let (udp_got, tcp_got): (Vec<_>, Vec<_>) = got.iter().partition(|p| p[9] == 17);
    assert_eq!(udp_got.len(), 7);
    // TCP は記録の順に counter が増え、核が引いた順に届く
    let tcp_counters: Vec<u64> = sent
        .iter()
        .zip(&got)
        .filter(|(_, p)| p[9] == 6)
        .map(|(d, _)| counter(d))
        .collect();
    assert!(tcp_counters.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(tcp_got.iter().map(|p| seq(p)).collect::<Vec<_>>(), tcp_seqs);
    assert_eq!(t.b.drops().total(), 0, "{:?}", t.b.drops());
    assert_eq!(helper.send_errors(), 0);
}

#[test]
fn closing_hands_small_batches_to_the_helper_until_it_is_empty() {
    let mut t = Bench::new(0);
    t.connected();
    let mut wire = Wire::default();
    let mut helper = helper_for(&t, &wire);
    // 開いた門で 64 個を渡し、手伝いの送りを止めておく。試験が途中で落ちても、手伝いの join より先に
    // 止めを解く (後に宣言したものが先に落ちる)
    let _release = Release(wire.clone());
    wire.hold(true);
    for i in 0..64 {
        t.stub.out.push_back(tcp_packet(i, 1200));
    }
    assert_eq!(
        helped(&mut t, &mut wire, &mut helper, true),
        (64, Sent::Full)
    );
    assert_eq!(helper.outstanding(), 1);
    // 門が閉じた。手伝いに束があるので、小さい束も手伝いへ
    for i in 64..74 {
        t.stub.out.push_back(tcp_packet(i, 1200));
    }
    assert_eq!(
        helped(&mut t, &mut wire, &mut helper, false),
        (10, Sent::Idle)
    );
    assert_eq!(helper.outstanding(), 2);
    assert!(
        wire.log.lock().unwrap().is_empty(),
        "the owner sent nothing"
    );
    // 2 つの置き場がどちらも手伝いにある間は何も引かない
    t.stub.out.push_back(tcp_packet(74, 1200));
    let r = send_batch_helped(
        &mut t.a,
        &mut t.stub,
        &t.b_pub,
        clock::now(),
        &mut t.outbox,
        &mut wire,
        &mut helper,
        false,
    );
    assert_eq!(r, (0, Sent::Waiting));
    assert!(helper.is_waiting());
    wire.hold(false);
    // 手伝いが空になった後は、持ち主が自分で送る
    while helper.engaged() {
        let _ = helped(&mut t, &mut wire, &mut helper, false);
        std::thread::sleep(Duration::from_millis(1));
    }
    for i in 75..80 {
        t.stub.out.push_back(tcp_packet(i, 1200));
    }
    while !t.stub.out.is_empty() {
        let _ = super::super::driver::send_batch(
            &mut t.a,
            &mut t.stub,
            &t.b_pub,
            clock::now(),
            &mut t.outbox,
            &mut wire,
            64,
        );
    }
    // 74 番の packet は、手伝いが空になる前なら 1 つの束として渡る
    let c = helper.counters();
    assert!(matches!((c.jobs, c.packets), (2, 74) | (3, 75)), "{c:?}");
    let sent = wire.taken();
    assert_eq!(sent.len(), 80);
    assert!(sent.windows(2).all(|w| counter(&w[0]) < counter(&w[1])));
    let got = deliver_all(&mut t, &sent);
    assert_eq!(
        got.iter().map(|p| seq(p)).collect::<Vec<_>>(),
        (0..80).collect::<Vec<_>>()
    );
}

#[test]
fn a_small_batch_on_an_idle_helper_stays_on_the_owner() {
    let mut t = Bench::new(0);
    t.connected();
    let mut wire = Wire::default();
    let mut helper = helper_for(&t, &wire);
    // 設計の値 (起床の予算が決める) を数で書く。定数を変えたらこの試験と設計の記録を直す
    assert_eq!(HANDOFF_MIN, 32);
    for i in 0..31 {
        t.stub.out.push_back(tcp_packet(i, 1200));
    }
    let (pulled, _) = helped(&mut t, &mut wire, &mut helper, true);
    assert_eq!(pulled, 31);
    let c = helper.counters();
    assert_eq!((c.jobs, c.helper_wakes, helper.outstanding()), (0, 0, 0));
    assert_eq!(wire.taken().len(), 31);
}

/// 定常の束では、手伝いのスレッドも持ち主の手伝いの道も確保しない。
#[test]
fn the_helped_path_allocates_nothing_per_packet() {
    #[derive(Clone, Default)]
    struct Count(Arc<Mutex<Vec<usize>>>);
    impl HelperSink for Count {
        fn send_batch(&mut self, tx: &mut TxBatch) -> io::Result<usize> {
            self.0.lock().unwrap().push(thread_alloc_calls());
            Ok(tx.n_msgs - tx.next)
        }
        fn wait_writable(&mut self) -> io::Result<bool> {
            Ok(true)
        }
    }
    let mut t = Bench::new(0);
    t.connected();
    let count = Count::default();
    count.0.lock().unwrap().reserve(1000);
    let mut helper = Helper::spawn(
        Batching::default(),
        t.a.mtu(),
        t.a.max_transmit_len(),
        count.clone(),
    )
    .unwrap();
    let mut wire = Wire::default();
    let rounds = 40;
    for i in 0..rounds * 64 {
        t.stub.out.push_back(tcp_packet(i, 1200));
    }
    // 慣らしの後の定常で数える
    for _ in 0..4 {
        helped(&mut t, &mut wire, &mut helper, true);
    }
    let before = thread_alloc_calls();
    while !t.stub.out.is_empty() {
        helped(&mut t, &mut wire, &mut helper, true);
    }
    let owner = thread_alloc_calls() - before;
    helper.finish();
    let calls = count.0.lock().unwrap().clone();
    assert!(
        calls.len() >= usize::try_from(rounds).unwrap() - 1,
        "{}",
        calls.len()
    );
    assert_eq!(
        calls[calls.len() - 1] - calls[4],
        0,
        "the helper thread allocated"
    );
    assert_eq!(owner, 0, "the owner's helped path allocated");
}

/// 本物の 2 つのデータプレーンで、軽い負荷 (20 packet を 2 ms ごと) の間、門は開かず、手伝いは一度も
/// 起きず、束も渡らない。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn light_load_never_engages_the_helper() {
    use super::{Settings, Stub, loopback, pair_with, wait_for};
    let agent = Settings {
        batching: Batching::default().with_send_helper(true, 8),
        ..loopback()
    };
    assert!(agent.batching.send_helper());
    let (a, b) = pair_with(0, loopback(), agent).await;
    let n = 2000u32;
    for chunk in 0..n / 20 {
        a.call(move |l| {
            l.with(|s: &mut Stub| {
                s.out
                    .extend((chunk * 20..chunk * 20 + 20).map(|i| tcp_packet(i, 1200)));
            });
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let all: Vec<u32> = (0..n).collect();
    wait_for("the server to get every packet", async || {
        super::got(&b).await == all
    })
    .await;
    let st = a.status().await.unwrap();
    let c = st.helper.expect("the helper was made");
    assert_eq!(c, super::super::HelperCounters::default(), "{c:?}");
    a.stop().await;
    b.stop().await;
}
