//! wgstack の核の会計 (`Held`) が確保の数えとちょうど一致し、接続の枠をすべて満たした核が上界の floor の項に
//! 届いて超えないことを、確保の数えで確かめます。accept の待ち行列にいる接続が送信のデータを持たないことも
//! 測ります。数えはプロセスで 1 つなので、このファイルには試験を 1 つだけ置きます。

use wgft_alloc_count::{CountingAlloc, live_bytes};
use wgft_wgstack::{BoostPolicy, Held, Limits};
use wgft_wgstack_bench::{MSS, Rig};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// 受信の floor の容量です (核の `RECV_FLOOR`)。
const RECV_FLOOR: usize = 256 << 10;
/// 受信の floor を満たす segment の数です。窓の外の分は核が捨てます。
const FILL_SEGMENTS: usize = RECV_FLOOR / MSS + 8;

/// 会計から求めた、核を作った後に増えた heap の byte です (`Held` の文書の式)。
fn accounted(h: &Held) -> usize {
    h.chunk_bytes
        + h.record_bytes
        + h.interval_bytes
        + h.frag_bytes
        + h.udp_rx_bytes
        + h.udp_tx_bytes
        + h.pool_bytes
        - h.lent_array_bytes
}

/// 核と、会計を照らす起点の生きている byte です。
struct Probe {
    rig: Rig,
    base: usize,
}

impl Probe {
    fn new(limits: Limits, boost: BoostPolicy) -> Self {
        let rig = Rig::build(0, false, limits, boost);
        let base = live_bytes();
        let h = rig.held();
        assert_eq!(accounted(&h), 0, "a new stack accounts nothing: {h:?}");
        Self { rig, base }
    }

    /// 増えた byte が会計と一致することを確かめ、会計を返します。
    fn exact(&self, what: &str) -> Held {
        let h = self.rig.held();
        let grown = live_bytes() - self.base;
        assert_eq!(
            grown,
            accounted(&h),
            "{what}: the stack grew {grown} bytes: {h:?}"
        );
        h
    }

    /// 待ち受けの待ち行列 (待ち受け 1 つで Q の半分) に `n` 本を入れ、`segments` 個ずつ中身を届けます。
    fn queue(&mut self, first_port: u16, n: u16, segments: usize) {
        for p in first_port..first_port + n {
            assert!(self.rig.connect_unaccepted(p, segments), "port {p}");
        }
    }
}

#[test]
fn held_matches_the_allocations_and_the_floor_term_is_reached() {
    let limits = Limits {
        max_flows: 4,
        accept_queue: 8,
        syn_rows: 16,
        tw_rows: 32,
        ctl_slots: 16,
        ..Limits::default()
    };
    let slots = limits.conns();

    // accept の待ち行列の接続は、floor の記録の輪と区間の表と、受信の floor までの chunk だけを持ちます。
    let mut p = Probe::new(limits, BoostPolicy::Never);
    p.queue(20_000, 1, 0);
    let empty = p.exact("an empty queued connection");
    assert_eq!(empty.chunk_bytes, 0);
    let arrays = empty.record_bytes + empty.interval_bytes;
    p.queue(20_001, 3, FILL_SEGMENTS);
    let h = p.exact("filled queued connections");
    assert_eq!(h.accept_queued, 4);
    assert_eq!(h.record_bytes + h.interval_bytes, 4 * arrays);
    assert_eq!(
        h.chunk_bytes,
        3 * RECV_FLOOR,
        "a queued connection holds receive data only"
    );

    // 核は K を超えて accept します (K は中継が数えます)。枠をすべて accept して両方の輪を満たすと、会計は上界の
    // floor の項にちょうど届きます。
    p.rig.accept_queued();
    let mut port = 20_100;
    while p.rig.conns() < slots {
        p.queue(port, 4, 0);
        port += 4;
        p.rig.accept_queued();
    }
    assert_eq!(p.rig.conns(), slots);
    for k in 0..slots {
        p.rig.fill_send(k);
        p.rig.fill_recv(k, FILL_SEGMENTS);
    }
    let h = p.exact("every slot accepted and filled");
    let bound = p.rig.bound();
    assert_eq!(
        (h.chunk_bytes + h.record_bytes + h.interval_bytes) as u64,
        bound.floor_conn,
        "{h:?}"
    );
    assert!((live_bytes() - p.base) as u64 <= bound.total - bound.fix);
    // 確認を受けると送信の chunk は置き場に戻ります。
    for k in 0..slots {
        p.rig.ack(k);
    }
    let h = p.exact("after the acknowledgements");
    assert!(h.pool_chunks > 0, "{h:?}");
    drop(p);

    // boost の配列は Budget が先に確保し、借りている間は会計にだけ出ます。
    let mut p = Probe::new(limits, BoostPolicy::AtAccept);
    p.queue(21_000, 2, 0);
    p.rig.accept_queued();
    let h = p.exact("boosted at accept");
    assert!(h.boosted == 2 && h.lent_array_bytes > 0, "{h:?}");
    p.rig.fill_send(0);
    p.rig.fill_recv(1, FILL_SEGMENTS);
    p.exact("boosted and filled");
    p.rig.ack(0);
    let h = p.exact("boosted after the acknowledgement");
    assert!(h.pool_chunks > 0, "{h:?}");
}
