//! wgstack の核の既定の表の大きさ (`Limits::default()`) を測り、値を決めた根拠を試験として保ちます
//! (docs/design/v2/wgstack-rs.md の「既定の表の大きさ」)。
//!
//! 測るのは、作った時の確保 (試験のスレッドの確保の数え)、基本の TCP の通信の後の確保の最大値、上限に達した時の
//! 動作と確保です。結果は `--nocapture` で表に出します。RSS はプロセスの全体の値で、試験の道具の確保も含むので、
//! 比べのために出すだけで確かめません。試験はこの file に 1 つだけ置き、libtest がほかの試験を並べて RSS を
//! 揺らさないようにします。

use wgft_alloc_count::{CountingAlloc, ThreadWindow};
use wgft_wgstack::{BoostPolicy, Bound, Budget, Config, Limits, NoHook, Stack, Time};
use wgft_wgstack_bench::{MSS, Rig, agent_limits};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// 既定の核の上界の上限です。値を変えるときは、測った値と共にこの上限と設計文書を直します。
const DEFAULT_BOUND_MAX: u64 = 24 << 20;

fn mib(b: u64) -> String {
    #[expect(clippy::cast_precision_loss, reason = "a printed figure")]
    let m = b as f64 / f64::from(1 << 20);
    format!("{m:.1} MiB")
}

/// プロセスの RSS の KiB です。Linux の外では `None` です。
fn rss_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn rss_delta(before: Option<u64>) -> String {
    match (before, rss_kib()) {
        (Some(a), Some(b)) => format!(
            "{} KiB",
            i64::try_from(b).unwrap_or(0) - i64::try_from(a).unwrap_or(0)
        ),
        _ => "n/a".to_owned(),
    }
}

fn print_bound(name: &str, b: &Bound) {
    println!(
        "{name}: bound total {} = fix {} + floor_conn {} + boost {} + frag {} + udp_rx {} + udp_tx {} + ping {}",
        mib(b.total),
        mib(b.fix),
        mib(b.floor_conn),
        mib(b.boost),
        mib(b.frag),
        mib(b.udp_rx),
        mib(b.udp_tx),
        mib(b.ping)
    );
}

/// 作った時の確保と RSS を測ります。
fn creation(name: &str, limits: Limits) -> u64 {
    let config = Config {
        limits,
        ..Config::new(core::net::Ipv4Addr::new(10, 9, 0, 1), 1420)
    };
    let rss = rss_kib();
    let w = ThreadWindow::open();
    let budget = Budget::new(limits.boost_slots).expect("budget");
    let stack = Stack::new(config, budget, &[7; 64], NoHook).expect("stack");
    let used = w.grown() as u64;
    let bound = stack.bound();
    print_bound(name, &bound);
    println!(
        "{name}: allocated at creation {} ({used} bytes), RSS grew {}",
        mib(used),
        rss_delta(rss)
    );
    // 作った時の確保は、固定の項、boost の配列、UDP の管理の配列、ping の置き場の内です。
    assert!(used <= bound.fix + bound.boost + bound.udp_rx + bound.udp_tx + bound.ping);
    let closed = stack.close(Time::ZERO);
    assert!(closed.held.is_zero());
    drop(closed);
    bound.total
}

#[test]
fn default_limits_are_small_and_work() {
    let small = Limits::default();
    println!("default limits: {small:?}");
    let total = creation("default", small);
    assert!(
        total <= DEFAULT_BOUND_MAX,
        "the default bound {total} is over {DEFAULT_BOUND_MAX}"
    );
    creation("wgft agent", agent_limits(0));

    // 基本の TCP の通信:1 本の接続で 4 MiB を受け、4 MiB を送ります。確保の最大値は上界の内です。
    let rss = rss_kib();
    let w = ThreadWindow::open();
    let mut rig = Rig::build(1, true, small, BoostPolicy::OnDemand);
    let segments = (4 << 20) / MSS;
    for _ in 0..segments {
        rig.recv_one(0);
        rig.send_one(0);
    }
    rig.check();
    let bound = rig.bound();
    let peak = w.peak() as u64;
    println!(
        "default, one connection, {} KiB each way: peak allocation {} ({peak} bytes), held {:?}, RSS grew {}",
        (segments * MSS) >> 10,
        mib(peak),
        rig.held(),
        rss_delta(rss)
    );
    assert!(
        peak <= bound.total,
        "peak {peak} over the bound {}",
        bound.total
    );
    let st = rig.stats();
    println!(
        "default, one connection: boost granted {}, retransmits {:?}",
        st.boost_granted, st.retrans
    );
    assert_eq!(st.retrans, [0; 5], "the transfer needs no retransmission");
    assert_eq!(st.rtos, 0);

    // 上限:全部の接続の枠を使った後の握手は、accept の待ち行列の空きが無いので最後の ACK を捨てます。
    // どの接続も受信と送信の floor を満たしても、確保は上界の内です。
    let w = ThreadWindow::open();
    let mut rig = Rig::build(0, true, small, BoostPolicy::OnDemand);
    let mut port = 20_000;
    let mut established = 0;
    loop {
        if !rig.connect_unaccepted(port, 0) {
            break;
        }
        port += 1;
        established += 1;
        if established % (small.accept_queue / 2) == 0 {
            rig.accept_queued();
        }
        assert!(established <= small.conns(), "more connections than slots");
    }
    rig.accept_queued();
    let st = rig.stats();
    println!(
        "default, connection limit: {established} connections for {} slots, then accept_overflow {} syn_accept_full {}",
        small.conns(),
        st.accept_overflow,
        st.syn_accept_full
    );
    assert_eq!(established, small.conns(), "every slot takes a connection");
    assert!(
        st.accept_overflow >= 1,
        "the handshake after the last slot is dropped as accept_overflow"
    );
    for k in 0..rig.conns() {
        rig.fill_send(k);
        rig.fill_recv(k, (256 << 10) / MSS + 8);
    }
    rig.check();
    let peak = w.peak() as u64;
    let bound = rig.bound();
    println!(
        "default, every slot filled both ways: peak allocation {} of bound {}, held {:?}",
        mib(peak),
        mib(bound.total),
        rig.held()
    );
    assert!(peak <= bound.total);
}
