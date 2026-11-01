//! 上界の表の生成と、上界の項が確保した配列と一致することの試験です。

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "the test writes the table as a string"
)]
#![expect(
    clippy::cast_possible_truncation,
    reason = "buffer sizes of at most 4 MiB"
)]

use super::*;
use crate::config::Config;
use core::fmt::Write;
use core::net::Ipv4Addr;

/// 生成する上界の表の K の値です。
const TABLE_KS: [usize; 3] = [256, Limits::DEFAULT_MAX_FLOWS, 8192];
/// 生成する上界の表の MTU です。
const TABLE_MTU: usize = 1420;

fn mib(x: u64) -> String {
    let tenths = (x * 10 + (1 << 19)) >> 20;
    format!("{}.{}", tenths / 10, tenths % 10)
}

const BEGIN: &str = "<!-- BEGIN GENERATED TABLE -->\n";
const END: &str = "<!-- END GENERATED TABLE -->\n";

/// 生成する表です。行の名前は `FixParts` と `Bound` の欄の名前で、説明は文書の手で書いた部分が持ちます。
fn table() -> String {
    let limits = TABLE_KS.map(Limits::with_max_flows);
    let parts = limits.map(|l| fix_parts(&l, TABLE_MTU, size_of::<Stack<NoHook>>()));
    let bounds = limits.map(|l| Bound::for_limits(&l, TABLE_MTU));
    let mut w = String::new();
    w.push_str("| term |");
    for k in TABLE_KS {
        write!(w, " K = {k} |").unwrap();
    }
    w.push_str("\n| --- |");
    for _ in TABLE_KS {
        w.push_str(" ---: |");
    }
    w.push('\n');
    let rows: [(&str, &dyn Fn(usize) -> u64); 16] = [
        ("`stack`", &|i| parts[i].stack),
        ("`conn_slots`", &|i| parts[i].conn_slots),
        ("`conn_index`", &|i| parts[i].conn_index),
        ("`syn`", &|i| parts[i].syn),
        ("`tw`", &|i| parts[i].tw),
        ("`listeners`", &|i| parts[i].listeners),
        ("`wheel`", &|i| parts[i].wheel),
        ("`output`", &|i| parts[i].output),
        ("`events`", &|i| parts[i].events),
        ("`chunk_pool`", &|i| parts[i].chunk_pool),
        ("`fix`", &|i| bounds[i].fix),
        ("`floor_conn`", &|i| bounds[i].floor_conn),
        ("`boost`", &|i| bounds[i].boost),
        ("`frag`", &|i| bounds[i].frag),
        ("`total`", &|i| bounds[i].total),
        ("`transient`", &|i| bounds[i].transient),
    ];
    for (name, f) in rows {
        write!(w, "| {name} |").unwrap();
        for i in 0..TABLE_KS.len() {
            write!(w, " {} ({}) |", f(i), mib(f(i))).unwrap();
        }
        w.push('\n');
    }
    w
}

/// 上界の表は `Bound` の計算から生成し、生成し直しの差分で検査します。`WGFT_UPDATE_GOLDEN=1` を付けたときだけ
/// ファイルを書き直し、付けないときは差があれば失敗します。
#[test]
fn bound_table_is_up_to_date() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/design/v2/wgstack-bound.md");
    let doc = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\r\n", "\n");
    let (head, rest) = doc.split_once(BEGIN).expect("the begin marker");
    let (old, tail) = rest.split_once(END).expect("the end marker");
    let want = table();
    if std::env::var_os("WGFT_UPDATE_GOLDEN").is_some_and(|v| v == "1") {
        std::fs::write(&path, format!("{head}{BEGIN}{want}{END}{tail}")).unwrap();
        return;
    }
    assert!(
        old == want,
        "{} is out of date; run WGFT_UPDATE_GOLDEN=1 cargo nextest run -p wgft-wgstack bound_table",
        path.display()
    );
}

/// 上界の M_fix の項が、作った核の表が確保した配列の byte と一致することを確かめます。
#[test]
fn fix_matches_the_allocated_tables() {
    for limits in [
        Limits::default(),
        Limits {
            max_flows: 8,
            accept_queue: 4,
            syn_rows: 0,
            tw_rows: 3,
            ctl_slots: 2,
            frag_entries: 4,
            frag_pieces: 8,
        },
    ] {
        let config = Config {
            addr: Ipv4Addr::new(10, 9, 0, 1),
            mtu: 1420,
            limits,
            ..Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420)
        };
        let s = Stack::new(config, Budget::new().unwrap(), &[7; 64], NoHook).unwrap();
        let p = fix_parts(&limits, config.mtu, size_of::<Stack<NoHook>>());
        let sh = &s.s;
        assert_eq!(
            p.conn_slots,
            b(s.conns.heap_bytes() + sh.conn_free.heap_bytes() + sh.qlinks.heap_bytes())
        );
        assert_eq!(p.conn_index, b(sh.conn_idx.heap_bytes()));
        assert_eq!(p.syn, b(sh.syn.heap_bytes()));
        assert_eq!(p.tw, b(sh.tw.heap_bytes()));
        assert_eq!(p.listeners, b(sh.listeners.heap_bytes()));
        assert_eq!(p.wheel, b(sh.wheel.heap_bytes() + sh.fired.heap_bytes()));
        assert_eq!(
            p.output,
            b(sh.out.conns.heap_bytes() + sh.out.rows.heap_bytes() + sh.out.ctl.heap_bytes())
        );
        assert_eq!(p.events, b(sh.events.heap_bytes()));
        assert_eq!(
            p.chunk_pool,
            b(sh.chunks.heap_bytes() + POOL_KEEP * CHUNK_SIZE)
        );
        assert_eq!(p.stack, b(size_of::<Stack<NoHook>>()));
        let bound = s.bound();
        assert_eq!(bound, Bound::for_limits(&limits, 1420));
        // boost の項は Budget が確保した配列と管理を覆います。
        assert!(b(sh.budget.heap_bytes()) <= bound.boost);
        assert_eq!(
            bound.total,
            bound.fix + bound.floor_conn + bound.boost + bound.frag
        );
        s.check_invariants().unwrap();
        let closed = s.close(Time::ZERO);
        assert!(closed.held.is_zero());
    }
}

/// 上界は表の大きさだけで決まり、使い方で変わりません (Go の TestBoundDoesNotDependOnUse)。
#[test]
fn bound_does_not_depend_on_use() {
    let config = Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420);
    let mut s = Stack::new(config, Budget::new().unwrap(), &[1; 64], NoHook).unwrap();
    let before = s.bound();
    let slot = s.conns.alloc(&mut s.s.conn_free).unwrap().unwrap();
    s.conns
        .bufs_mut(slot)
        .snd
        .write(0, &[1; 1000], &mut s.s.chunks)
        .unwrap();
    assert_eq!(s.bound(), before);
    assert!(before.floor_conn > 0 && before.transient > 0);
    let _ = s.close(Time::ZERO);
}

use crate::time::Time;

/// すべての枠を使い、boost の枠をすべて貸し、どの輪も満たした核の保持を、上界の項ごとに比べます。
/// 再組み立ての表の余地のような別の項の余りが、足りない項を隠さないためです。
#[test]
fn a_full_stack_meets_each_term() {
    use crate::buf::{BOOST_INTERVALS, BOOST_RECORDS};
    let limits = Limits {
        max_flows: 16,
        accept_queue: 8,
        syn_rows: 4,
        tw_rows: 4,
        ctl_slots: 2,
        frag_entries: 4,
        frag_pieces: 8,
    };
    let config = Config {
        addr: Ipv4Addr::new(10, 9, 0, 1),
        mtu: 1420,
        limits,
        ..Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420)
    };
    let mut s = Stack::new(config, Budget::new().unwrap(), &[3; 64], NoHook).unwrap();
    let data = vec![7u8; BOOST_SIZE as usize];
    for _ in 0..limits.conns() {
        let i = s.conns.alloc(&mut s.s.conn_free).unwrap().unwrap();
        let id = s.conns.id(i);
        let boosted = s.s.budget.acquire(id);
        let (t, _, c) = s.conns.parts_mut(i);
        if let Some((b, recs, iv)) = boosted {
            c.boost = Some(b);
            c.snd = crate::buf::ring::Ring::new(BOOST_SIZE);
            c.spare_recs = c.recs.resize(recs);
            c.rcv.r = crate::buf::ring::Ring::new(BOOST_SIZE);
            c.spare_iv = c.rcv.set_intervals(iv).unwrap();
        }
        let (snd_cap, rcv_cap) = (c.snd.cap(), c.rcv.r.cap());
        (t.snd_cap, t.rcv_cap) = (snd_cap, rcv_cap);
        t.tail_off = snd_cap;
        c.snd
            .write(0, &data[..snd_cap as usize], &mut s.s.chunks)
            .unwrap();
        assert_eq!(
            c.rcv
                .insert(0, &data[..rcv_cap as usize], rcv_cap, &mut s.s.chunks)
                .accepted,
            rcv_cap as usize
        );
    }
    s.check_invariants().unwrap();
    let h = s.held();
    let bound = s.bound();
    let (n, slots) = (b(limits.conns()), b(BOOST_SLOTS));
    assert_eq!(h.boosted as u64, slots);
    let chunk_terms = n * (SEND_FLOOR + RECV_FLOOR)
        + slots * ((BOOST_SIZE - SEND_FLOOR) + (BOOST_SIZE - RECV_FLOOR));
    let record_terms =
        n * b(FLOOR_RECORDS * size_of::<Record>()) + slots * b(BOOST_RECORDS * size_of::<Record>());
    let interval_terms = n * b(FLOOR_INTERVALS * size_of::<Interval>())
        + slots * b(BOOST_INTERVALS * size_of::<Interval>());
    assert_eq!(b(h.chunk_bytes), chunk_terms, "chunk bytes");
    assert_eq!(b(h.record_bytes), record_terms, "record bytes");
    assert_eq!(b(h.interval_bytes), interval_terms, "interval bytes");
    assert_eq!(
        chunk_terms + record_terms + interval_terms,
        bound.floor_conn + bound.boost - b(Budget::slot_bytes()),
        "the filled stack reaches exactly the floor and boost terms"
    );
    assert!(
        h.reserved
            <= n * (SEND_FLOOR + RECV_FLOOR) + slots * (2 * BOOST_SIZE - SEND_FLOOR - RECV_FLOOR)
    );
    let closed = s.close(Time::ZERO);
    assert!(closed.held.is_zero());
}
