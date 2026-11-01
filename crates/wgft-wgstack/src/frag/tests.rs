//! Go の `internal/ipv4frag/table_test.go` の写しです。並行の試験は、表が錠を持たないので移しません。

#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "tests may hold growing collections"
)]

use super::*;
use crate::rng::ChaCha8;

const SEC: u64 = 1_000_000_000;
const MS: u64 = 1_000_000;

fn at(ns: u64) -> Time {
    Time::from_nanos(100 * SEC + ns)
}

fn pkt(
    proto: u8,
    id: u16,
    offset: usize,
    more: bool,
    tos: u8,
    options: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let hlen = 20 + options.len();
    let mut p = vec![0u8; hlen + data.len()];
    p[0] = 0x40 | u8::try_from(hlen / 4).unwrap();
    p[1] = tos;
    let total = u16::try_from(p.len()).unwrap();
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    let mut flags = u16::try_from(offset / 8).unwrap();
    if more {
        flags |= 0x2000;
    }
    p[6..8].copy_from_slice(&flags.to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&[10, 1, 1, 1]);
    p[16..20].copy_from_slice(&[10, 1, 1, 2]);
    p[20..hlen].copy_from_slice(options);
    p[hlen..].copy_from_slice(data);
    set_ipv4_checksum(&mut p[..hlen]);
    p
}

fn table(entries: usize, fragments: usize, bytes: usize) -> Table {
    Table::new(Limits {
        entries,
        fragments,
        bytes,
        lifetime: 2 * SEC,
    })
    .unwrap()
}

fn name(o: &Outcome) -> &'static str {
    match o {
        Outcome::Held => "held",
        Outcome::Complete(_) => "complete",
        Outcome::Duplicate => "duplicate",
        Outcome::Rejected(_) => "rejected",
        Outcome::Capacity => "capacity",
    }
}

fn rejected(o: Outcome) -> Notice {
    match o {
        Outcome::Rejected(n) => n,
        other => panic!("want a rejection, got {other:?}"),
    }
}

fn complete(o: Outcome) -> FixedVec<u8> {
    match o {
        Outcome::Complete(p) => p,
        other => panic!("want completion, got {other:?}"),
    }
}

fn hold(t: &mut Table, p: &[u8], now: Time) {
    let o = t.process(p, now);
    assert!(matches!(o, Outcome::Held), "hold: {o:?}");
}

fn ids(t: &Table) -> Vec<u16> {
    let mut v: Vec<u16> = t
        .entries
        .iter()
        .filter(|e| e.used)
        .map(|e| e.key.id)
        .collect();
    v.sort_unstable();
    v
}

fn want_ids(t: &Table, want: &[u16]) {
    let mut w = want.to_vec();
    w.sort_unstable();
    assert_eq!(ids(t), w);
}

#[test]
fn charged_sizes_bound_the_rust_types() {
    let t = Table::new(LIMITS).unwrap();
    assert_eq!(t.base_cost(), 120 + 128 * 264 + 512 * 56 + 128 * 72);
    assert!(t.entries.heap_bytes() <= 128 * ENTRY_CHARGE);
    assert!(t.pieces.heap_bytes() <= 512 * PIECE_CHARGE);
}

#[test]
fn rejects_invalid_limits() {
    let ok = Limits {
        entries: 1,
        fragments: 1,
        bytes: 4096,
        lifetime: SEC,
    };
    assert!(Table::new(ok).is_ok());
    for bad in [
        Limits { entries: 0, ..ok },
        Limits { fragments: 0, ..ok },
        Limits { bytes: 0, ..ok },
        Limits { lifetime: 0, ..ok },
        Limits {
            entries: 4097,
            bytes: 1 << 30,
            ..ok
        },
        Limits {
            fragments: 65537,
            bytes: 1 << 30,
            ..ok
        },
    ] {
        assert_eq!(
            Table::new(bad).err(),
            Some(NewError::InvalidLimits),
            "{bad:?}"
        );
    }
    for bytes in [100, 120 + 264, 120 + 264 + 56] {
        assert_eq!(
            Table::new(Limits { bytes, ..ok }).err(),
            Some(NewError::MetadataOverBudget),
            "{bytes}"
        );
    }
    assert!(
        Table::new(Limits {
            bytes: 120 + 264 + 56 + 72,
            ..ok
        })
        .is_ok()
    );
}

#[test]
fn rejects_dont_fragment_with_fragments() {
    let mut t = table(1, 2, 1024);
    let mut p = pkt(17, 7, 0, true, 0, &[], b"abcdefgh");
    p[6..8].copy_from_slice(&0x6000u16.to_be_bytes());
    set_ipv4_checksum(&mut p[..20]);
    assert_eq!(rejected(t.process(&p, at(0))).reason, Reason::Malformed);
}

#[test]
fn all_protocols_options_and_ecn() {
    for proto in [1, 6, 17, 99] {
        let mut t = table(2, 4, 2048);
        // 0x82 は写す option で、0x44 は写しません。後者は最初の header にだけ残ります。
        let first_opts = [0x82, 4, 7, 8, 0x44, 4, 1, 2];
        let later_opts = [0x82, 4, 7, 9]; // 写す option の値は途中で変わりえます
        let first = pkt(proto, 7, 0, true, 2, &first_opts, b"abcdefgh");
        let last = pkt(proto, 7, 8, false, 3, &later_opts, b"ijk");
        hold(&mut t, &last, at(0));
        assert!(matches!(t.process(&last, at(0)), Outcome::Duplicate));
        let out = complete(t.process(&first, at(0)));
        assert_eq!(out[20..28], first_opts);
        assert_eq!(&out[28..], b"abcdefghijk");
        assert_eq!(out[1] & 3, 3);
        assert!(ipv4_header_ok(&out[..28]));
        assert_eq!(be16(&out, 6), 0);
        assert_eq!(usize::from(be16(&out, 2)), out.len());
        assert_eq!(out[9], proto);
        assert_eq!(t.usage(), (t.base_cost(), 0, 0));
    }
}

#[test]
fn mixed_ect_keeps_first_or_ce() {
    for (first_tos, later_tos, want) in [(1, 2, 1), (2, 1, 2), (1, 3, 3), (2, 3, 3)] {
        let mut t = table(1, 2, 1024);
        hold(&mut t, &pkt(6, 1, 8, false, later_tos, &[], b"i"), at(0));
        let out = complete(t.process(&pkt(6, 1, 0, true, first_tos, &[], b"abcdefgh"), at(0)));
        assert_eq!(out[1] & 3, want, "ECN {first_tos}/{later_tos}");
    }
}

#[test]
fn overlap_conflict_and_duplicate() {
    let first = pkt(17, 1, 0, true, 2, &[0x82, 4, 7, 8], b"abcdefghabcdefgh");
    let partial = pkt(17, 1, 8, false, 2, &[0x82, 4, 7, 9], b"xxxxxxxx");
    let mut t = table(1, 3, 2048);
    hold(&mut t, &first, at(0));
    assert!(matches!(t.process(&first, at(0)), Outcome::Duplicate));
    let mut marked = first.clone();
    marked[1] = (marked[1] & !3) | 3;
    marked[23] = 9;
    set_ipv4_checksum(&mut marked[..24]);
    assert!(
        matches!(t.process(&marked, at(0)), Outcome::Duplicate),
        "CE-marked duplicate"
    );
    assert_eq!(rejected(t.process(&partial, at(0))).reason, Reason::Overlap);
    assert_eq!(t.usage().1..t.usage().2, 0..0);
    hold(&mut t, &pkt(17, 2, 0, true, 0, &[], b"abcdefgh"), at(0));
    complete(t.process(&pkt(17, 2, 8, false, 0, &[], b"ijk"), at(0)));
}

#[test]
fn late_first_length_and_last_conflict() {
    let mut t = table(1, 3, 2048);
    hold(
        &mut t,
        &pkt(6, 9, 65496, false, 0, &[0x82, 4, 7, 8], b"abcdefghijklmnop"),
        at(0),
    );
    let first = pkt(6, 9, 0, true, 0, &[0x82, 4, 7, 8, 0, 0, 0, 0], b"abcdefgh");
    assert_eq!(
        rejected(t.process(&first, at(0))).reason,
        Reason::Conflict,
        "late IHL"
    );
    assert_eq!(t.usage(), (t.base_cost(), 0, 0));
    hold(&mut t, &pkt(6, 10, 16, true, 0, &[], b"abcdefgh"), at(0));
    assert_eq!(
        rejected(t.process(&pkt(6, 10, 8, false, 0, &[], b"12345678"), at(0))).reason,
        Reason::Conflict
    );
}

#[test]
fn capacity_expiry_and_clear() {
    let mut t = table(1, 1, 1024);
    let first = pkt(6, 1, 0, true, 0, &[], b"abcdefgh");
    let other = pkt(1, 2, 0, true, 0, &[], b"abcdefgh");
    hold(&mut t, &first, at(0));
    // 1 つの鍵の表は満杯で、新しい鍵は断らずに古い鍵を追い出します。
    hold(&mut t, &other, at(0));
    assert_eq!(t.evicted(), 1);
    assert!(matches!(t.process(&other, at(0)), Outcome::Duplicate));
    assert!(t.sweep_next(at(SEC)).is_none(), "early expiry");
    let n = t.sweep_next(at(2 * SEC)).unwrap();
    assert!(n.has_first && n.reason == Reason::Expired && n.quote_len == 28);
    assert!(t.sweep_next(at(2 * SEC)).is_none());
    assert_eq!(t.usage(), (t.base_cost(), 0, 0));
    hold(&mut t, &first, at(3 * SEC));
    t.clear();
    assert_eq!(t.usage(), (t.base_cost(), 0, 0));
}

#[test]
fn expired_entry_is_rejected_with_its_notice() {
    let mut t = table(1, 2, 1024);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"abcdefgh"), at(0));
    let n = rejected(t.process(&pkt(17, 1, 8, false, 0, &[], b"i"), at(2 * SEC)));
    assert_eq!((n.reason, n.has_first), (Reason::Expired, true));
    // 呼び手は同じ断片を処理し直せます。
    hold(&mut t, &pkt(17, 1, 8, false, 0, &[], b"i"), at(2 * SEC));
}

#[test]
fn malformed_options_and_lengths() {
    let mut t = table(1, 3, 2048);
    let mut p = pkt(17, 1, 0, true, 0, &[], b"abcdefgh");
    p[10] ^= 1;
    assert_eq!(
        rejected(t.process(&p, at(0))).reason,
        Reason::Malformed,
        "checksum"
    );
    rejected(t.process(&pkt(17, 1, 0, true, 0, &[], b"abcdefg"), at(0))); // 8 byte の倍数でない
    assert_eq!(
        rejected(t.process(&pkt(17, 1, 8, false, 0, &[0x44, 4, 1, 2], b"x"), at(0))).reason,
        Reason::Options,
        "noncopied"
    );
    assert_eq!(
        rejected(t.process(&pkt(17, 1, 8, false, 0, &[0x82, 1, 0, 0], b"x"), at(0))).pointer,
        20,
        "bad option"
    );
    assert_eq!(
        rejected(t.process(&pkt(17, 1, 8, false, 0, &[0, 0, 1, 0], b"x"), at(0))).pointer,
        22,
        "nonzero padding"
    );
    hold(
        &mut t,
        &pkt(17, 2, 0, true, 0, &[0x82, 4, 7, 8], b"abcdefgh"),
        at(0),
    );
    assert_eq!(
        rejected(t.process(&pkt(17, 2, 8, false, 0, &[0x83, 4, 7, 8], b"x"), at(0))).reason,
        Reason::Options,
        "copied type mismatch"
    );
    // Total Length が packet の長さと違う、中身が無い、最初で最後の断片。
    let mut p = pkt(17, 3, 0, true, 0, &[], b"abcdefgh");
    p[3] -= 1;
    set_ipv4_checksum(&mut p[..20]);
    assert_eq!(rejected(t.process(&p, at(0))).reason, Reason::Malformed);
    assert_eq!(
        rejected(t.process(&pkt(17, 3, 8, false, 0, &[], b""), at(0))).reason,
        Reason::Malformed
    );
    assert_eq!(
        rejected(t.process(&pkt(17, 3, 0, false, 0, &[], b"x"), at(0))).reason,
        Reason::Malformed
    );
}

#[test]
fn completion_copy_budget() {
    let mut t = table(1, 2, 1024);
    // 2 つの断片の中身は入り、完成の写しは入らない上限にします。
    t.limits.bytes = t.base_cost() + 8 + 3 + 31 - 1;
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"abcdefgh"), at(0));
    assert!(matches!(
        t.process(&pkt(17, 1, 8, false, 0, &[], b"ijk"), at(0)),
        Outcome::Capacity
    ));
    let (_, e, p) = t.usage();
    assert_eq!((e, p), (1, 1), "capacity mutated retained state");
}

#[test]
fn evicts_oldest_for_new_key() {
    let mut t = table(2, 4, 4096);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"aaaaaaaa"), at(0));
    hold(&mut t, &pkt(17, 2, 0, true, 0, &[], b"bbbbbbbb"), at(MS));
    hold(
        &mut t,
        &pkt(17, 3, 0, true, 0, &[], b"cccccccc"),
        at(2 * MS),
    );
    want_ids(&t, &[2, 3]);
    assert_eq!(t.evicted(), 1);
    assert_eq!(t.usage(), (t.base_cost() + 16, 2, 2));
}

#[test]
fn evicts_oldest_for_fragment_slot() {
    let mut t = table(4, 3, 4096);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"aaaaaaaa"), at(0));
    hold(&mut t, &pkt(17, 1, 16, true, 0, &[], b"AAAAAAAA"), at(MS));
    hold(
        &mut t,
        &pkt(17, 2, 0, true, 0, &[], b"bbbbbbbb"),
        at(2 * MS),
    );
    // 鍵の枠は 2 つ空いていますが、断片の枠はすべて使われています。
    hold(
        &mut t,
        &pkt(17, 3, 0, true, 0, &[], b"cccccccc"),
        at(3 * MS),
    );
    want_ids(&t, &[2, 3]);
    assert_eq!(t.evicted(), 1);
    assert_eq!(t.usage(), (t.base_cost() + 16, 2, 2));
}

#[test]
fn evicts_oldest_for_bytes() {
    let mut t = table(4, 8, 4096);
    // 16 byte の中身が 2 つ入り、3 つ目は入らない上限です。
    t.limits.bytes = t.base_cost() + 32 + 15;
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], &[b'a'; 16]), at(0));
    hold(&mut t, &pkt(17, 2, 0, true, 0, &[], &[b'b'; 16]), at(MS));
    hold(
        &mut t,
        &pkt(17, 3, 0, true, 0, &[], &[b'c'; 16]),
        at(2 * MS),
    );
    want_ids(&t, &[2, 3]);
    assert_eq!(t.evicted(), 1);
    assert_eq!(t.usage(), (t.base_cost() + 32, 2, 2));
}

#[test]
fn evicts_oldest_for_completion_copy() {
    let mut t = table(2, 3, 1024);
    t.limits.lifetime = SEC;
    // 中身は両方入り、完成の写しは古い 8 byte の鍵が無いときだけ入ります。
    t.limits.bytes = t.base_cost() + 8 + 3 + 31 - 1 + 8;
    hold(&mut t, &pkt(17, 9, 0, true, 0, &[], b"oldoldol"), at(0));
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"abcdefgh"), at(MS));
    let out = complete(t.process(&pkt(17, 1, 8, false, 0, &[], b"ijk"), at(2 * MS)));
    assert_eq!(&out[20..], b"abcdefghijk");
    want_ids(&t, &[]);
    assert_eq!(t.evicted(), 1);
    assert_eq!(t.usage(), (t.base_cost(), 0, 0));
}

/// 中身がちょうど入るときは追い出しません。
#[test]
fn exact_byte_fit_does_not_evict() {
    let mut t = table(4, 8, 4096);
    t.limits.bytes = t.base_cost() + 48;
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], &[b'a'; 16]), at(0));
    hold(&mut t, &pkt(17, 2, 0, true, 0, &[], &[b'b'; 16]), at(MS));
    hold(
        &mut t,
        &pkt(17, 3, 0, true, 0, &[], &[b'c'; 16]),
        at(2 * MS),
    );
    want_ids(&t, &[1, 2, 3]);
    assert_eq!(t.evicted(), 0);
    assert_eq!(t.usage(), (t.limits.bytes, 3, 3));
}

/// 完成の写しがちょうど入るときは、古い鍵を追い出せても追い出しません。
#[test]
fn exact_completion_copy_fit_does_not_evict() {
    let first = pkt(17, 1, 0, true, 0, &[], b"abcdefgh");
    let last = pkt(17, 1, 8, false, 0, &[], b"ijk");
    let mut t = table(1, 2, 1024);
    t.limits.bytes = t.base_cost() + 8 + 3 + 31;
    hold(&mut t, &first, at(0));
    assert_eq!(&complete(t.process(&last, at(0)))[20..], b"abcdefghijk");
    assert_eq!(t.evicted(), 0);

    let mut t = table(2, 3, 1024);
    t.limits.bytes = t.base_cost() + 8 + 8 + 3 + 31;
    hold(&mut t, &pkt(17, 9, 0, true, 0, &[], b"oldoldol"), at(0));
    hold(&mut t, &first, at(MS));
    assert_eq!(
        &complete(t.process(&last, at(2 * MS)))[20..],
        b"abcdefghijk"
    );
    want_ids(&t, &[9]);
    assert_eq!(t.evicted(), 0);
}

/// 完成の写しの場所は、datagram を完成させる断片だけが求めます。
#[test]
fn non_completing_fragment_does_not_evict_for_copy() {
    let mut t = table(2, 4, 1024);
    t.limits.bytes = t.base_cost() + 60;
    hold(
        &mut t,
        &pkt(17, 9, 0, true, 0, &[], b"oldoldoloooooooo"),
        at(0),
    );
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"abcdefgh"), at(MS));
    hold(&mut t, &pkt(17, 1, 16, false, 0, &[], b"qrs"), at(2 * MS));
    want_ids(&t, &[1, 9]);
    assert_eq!(t.evicted(), 0);
    let out = complete(t.process(&pkt(17, 1, 8, true, 0, &[], b"ijklmnop"), at(3 * MS)));
    assert_eq!(&out[20..], b"abcdefghijklmnopqrs");
    want_ids(&t, &[]);
    assert_eq!(t.evicted(), 1);
}

#[test]
fn never_evicts_current_key() {
    let mut t = table(2, 4, 4096);
    t.limits.bytes = t.base_cost() + 8 + 4;
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"aaaaaaaa"), at(0));
    assert!(matches!(
        t.process(&pkt(17, 1, 16, true, 0, &[], b"AAAAAAAA"), at(0)),
        Outcome::Capacity
    ));
    want_ids(&t, &[1]);
    assert_eq!(t.evicted(), 0);
    assert_eq!(t.usage(), (t.base_cost() + 8, 1, 1));
    // datagram ごとの断片の上限が表の全体と同じなら、断るままです。
    let mut t = table(1, 1, 4096);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"aaaaaaaa"), at(0));
    assert!(matches!(
        t.process(&pkt(17, 1, 16, true, 0, &[], b"AAAAAAAA"), at(0)),
        Outcome::Capacity
    ));
    want_ids(&t, &[1]);
    assert_eq!(t.evicted(), 0);
}

#[test]
fn no_evictable_entry() {
    let mut t = table(2, 2, 4096);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"aaaaaaaa"), at(0));
    hold(&mut t, &pkt(17, 1, 16, true, 0, &[], b"AAAAAAAA"), at(0));
    assert!(matches!(
        t.process(&pkt(17, 1, 32, true, 0, &[], b"xxxxxxxx"), at(0)),
        Outcome::Capacity
    ));
    want_ids(&t, &[1]);
    assert_eq!(t.evicted(), 0);
    // 空の表にも入らない最初の断片は断り、保持しません。
    let mut t = table(2, 2, 4096);
    t.limits.bytes = t.base_cost() + 7;
    assert!(matches!(
        t.process(&pkt(17, 2, 0, true, 0, &[], b"bbbbbbbb"), at(0)),
        Outcome::Capacity
    ));
    want_ids(&t, &[]);
    assert_eq!(t.evicted(), 0);
}

#[test]
fn eviction_order() {
    let mut t = table(3, 8, 4096);
    for i in 1..=3u16 {
        hold(
            &mut t,
            &pkt(17, i, 0, true, 0, &[], b"pppppppp"),
            at(u64::from(i) * MS),
        );
    }
    // 鍵 4 は鍵 1 の位置を使うので、次に外すのは最も古い鍵 2 です。
    hold(
        &mut t,
        &pkt(17, 4, 0, true, 0, &[], b"pppppppp"),
        at(4 * MS),
    );
    want_ids(&t, &[2, 3, 4]);
    hold(
        &mut t,
        &pkt(17, 5, 0, true, 0, &[], b"pppppppp"),
        at(5 * MS),
    );
    want_ids(&t, &[3, 4, 5]);
    assert_eq!(t.evicted(), 2);
    // 同じ期限なら小さい位置を外します。
    let mut t = table(3, 8, 4096);
    for i in 1..=4u16 {
        hold(&mut t, &pkt(17, i, 0, true, 0, &[], b"pppppppp"), at(0));
    }
    want_ids(&t, &[2, 3, 4]);
    assert_eq!(t.evicted(), 1);
}

#[test]
fn evicted_expired_entry_is_silent() {
    let mut t = table(1, 2, 4096);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"aaaaaaaa"), at(0));
    // 鍵 1 は期限を過ぎていますが、まだ掃除していません。鍵 2 のために追い出すと、Time Exceeded は出ません。
    hold(
        &mut t,
        &pkt(17, 2, 0, true, 0, &[], b"bbbbbbbb"),
        at(3 * SEC),
    );
    assert_eq!(t.evicted(), 1);
    assert!(t.sweep_next(at(3 * SEC)).is_none());
    want_ids(&t, &[2]);
}

#[test]
fn rotation_breaks_distant_fragments() {
    let mut t = table(4, 4, 4096);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"abcdefgh"), at(0));
    for i in 10..14u16 {
        hold(
            &mut t,
            &pkt(17, i, 0, true, 0, &[], b"pppppppp"),
            at(u64::from(i) * MS),
        );
    }
    hold(&mut t, &pkt(17, 1, 8, false, 0, &[], b"ijk"), at(SEC));
    assert_eq!(t.evicted(), 2);
    want_ids(&t, &[1, 11, 12, 13]);
}

#[test]
fn adjacent_fragments_complete_in_full_table() {
    let mut t = table(4, 4, 4096);
    for i in 10..14u16 {
        hold(
            &mut t,
            &pkt(17, i, 0, true, 0, &[], b"pppppppp"),
            at(u64::from(i) * MS),
        );
    }
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], b"abcdefgh"), at(SEC));
    let out = complete(t.process(&pkt(17, 1, 8, false, 0, &[], b"ijk"), at(SEC)));
    assert_eq!(&out[20..], b"abcdefghijk");
    assert_eq!(t.evicted(), 2);
    want_ids(&t, &[12, 13]);
    assert_eq!(t.usage(), (t.base_cost() + 16, 2, 2));
}

/// 追い出しの経路が保つ構造の不変条件を確かめます。
fn check_ledger(t: &Table, step: usize) {
    let mut sum = 0;
    let mut owned = vec![0usize; t.entries.len()];
    let mut covered = vec![0usize; t.entries.len()];
    let mut pieces = 0;
    for (i, p) in t.pieces.iter().enumerate() {
        if !p.used {
            assert_eq!(
                p.data.capacity(),
                0,
                "step {step}: free piece {i} keeps data"
            );
            continue;
        }
        pieces += 1;
        sum += p.data.capacity();
        assert!(
            t.entries[p.owner].used,
            "step {step}: piece {i} owned by unused entry {}",
            p.owner
        );
        owned[p.owner] += 1;
        covered[p.owner] += p.data.len();
    }
    let mut entries = 0;
    for (i, e) in t.entries.iter().enumerate() {
        if e.used {
            entries += 1;
            assert_eq!(
                (e.parts, e.covered),
                (owned[i], covered[i]),
                "step {step}: entry {i}"
            );
        }
    }
    assert_eq!(t.used, t.base_cost + sum, "step {step}");
    assert!(
        t.used <= t.limits.bytes && pieces <= t.limits.fragments && entries <= t.limits.entries,
        "step {step}"
    );
    assert_eq!(t.usage(), (t.used, entries, pieces), "step {step}");
}

#[test]
fn eviction_ledger_invariant() {
    let mut rng = ChaCha8::new([0x26; 32]);
    let mut n = |k: u64| -> usize { usize::try_from(rng.below(k)).unwrap() };
    let mut t = table(8, 24, 1 << 16);
    t.limits.bytes = t.base_cost() + 900; // byte の追い出しを起こす程度に狭くします
    let mut now = at(0);
    let mut last_evicted = 0;
    let mut counts = std::collections::HashMap::<&str, usize>::new();
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let body = |n: &mut dyn FnMut(u64) -> usize, len: usize| -> Vec<u8> {
        (0..len).map(|_| u8::try_from(n(256)).unwrap()).collect()
    };
    for step in 0..20000 {
        now = now.saturating_add_nanos(n(200) as u64 * MS);
        let id = u16::try_from(n(24)).unwrap();
        match n(8) {
            0 | 1 => {
                // 断片が続けて届く正しい datagram。
                let id = u16::try_from(1000 + step % 60000).unwrap();
                let plen = 8 * (1 + n(8));
                let payload = body(&mut n, plen);
                let tlen = 1 + n(40);
                let tail = body(&mut n, tlen);
                let mut first = pkt(17, id, 0, true, 0, &[], &payload);
                let mut last = pkt(17, id, payload.len(), false, 0, &[], &tail);
                if n(2) == 0 {
                    core::mem::swap(&mut first, &mut last);
                }
                let o = t.process(&first, now);
                assert!(matches!(o, Outcome::Held), "step {step}: legit first {o:?}");
                let out = complete(t.process(&last, now));
                let mut want = payload.clone();
                want.extend_from_slice(&tail);
                assert_eq!(out[20..], want[..], "step {step}");
                *counts.entry("complete").or_default() += 1;
            }
            2 => {
                let len = 8 * (1 + n(6));
                let p = pkt(17, id, 0, true, 0, &[], &body(&mut n, len));
                *counts.entry(name(&t.process(&p, now))).or_default() += 1;
                sent.push(p);
            }
            3 => {
                let off = 8 * (1 + n(12));
                let len = 8 * (1 + n(3));
                let p = pkt(17, id, off, true, 0, &[], &body(&mut n, len));
                *counts.entry(name(&t.process(&p, now))).or_default() += 1;
                sent.push(p);
            }
            4 => {
                if !sent.is_empty() {
                    let i = n(sent.len() as u64);
                    *counts.entry(name(&t.process(&sent[i], now))).or_default() += 1;
                }
            }
            5 => {
                let off = 8 * n(14);
                let len = 1 + n(20);
                let p = pkt(17, id, off, false, 0, &[], &body(&mut n, len));
                *counts.entry(name(&t.process(&p, now))).or_default() += 1;
                sent.push(p);
            }
            6 => {
                now = now.saturating_add_nanos(n(3000) as u64 * MS);
                while t.sweep_next(now).is_some() {
                    *counts.entry("expired").or_default() += 1;
                }
            }
            _ => {
                let off = 8 * n(2) * (120 + n(10));
                let len = 8 * (20 + n(92));
                let p = pkt(17, id, off, true, 0, &[], &body(&mut n, len));
                *counts.entry(name(&t.process(&p, now))).or_default() += 1;
            }
        }
        check_ledger(&t, step);
        assert!(
            t.evicted() >= last_evicted,
            "step {step}: evicted went back"
        );
        last_evicted = t.evicted();
    }
    assert!(last_evicted > 0, "no eviction: {counts:?}");
    for k in ["complete", "expired", "rejected", "duplicate", "capacity"] {
        assert!(
            counts.get(k).copied().unwrap_or(0) > 0,
            "the mix did not reach {k}: {counts:?}"
        );
    }
}

#[test]
fn timeout_quote_conditions() {
    let local = [10, 1, 1, 2];
    let mut t = table(1, 2, 4096);
    hold(&mut t, &pkt(17, 1, 0, true, 0, &[], &[1; 16]), at(0));
    let n = t.sweep_next(at(2 * SEC)).unwrap();
    assert_eq!(n.timeout_quote(local).map(<[u8]>::len), Some(28));
    assert!(
        n.timeout_quote([10, 1, 1, 3]).is_none(),
        "the destination is not local"
    );
    // 最初の断片の無い項目は引用を持ちません。
    hold(&mut t, &pkt(17, 2, 8, false, 0, &[], &[1; 16]), at(0));
    let n = t.sweep_next(at(2 * SEC)).unwrap();
    assert!(!n.has_first && n.timeout_quote(local).is_none());
}

#[test]
fn param_problem_conditions() {
    let local = [10, 1, 1, 2];
    let mut t = table(1, 2, 4096);
    // 後続の断片の写さない option:その断片そのものを引用します。
    let bad = pkt(17, 1, 8, false, 0, &[0x44, 4, 1, 2], b"abcdefgh");
    let n = rejected(t.process(&bad, at(0)));
    assert_eq!(n.param_problem_ok(&bad, local), Some(24));
    assert!(
        n.param_problem_ok(&bad, [10, 1, 1, 9]).is_none(),
        "the destination is not local"
    );
    // 最初の断片の崩れた option:引用は最初の断片で、同じ断片だけを対象にします。
    let bad_first = pkt(17, 2, 0, true, 0, &[0x82, 1, 0, 0], b"abcdefgh");
    let n = rejected(t.process(&bad_first, at(0)));
    assert_eq!(n.param_problem_ok(&bad_first, local), Some(24));
    // ICMP の誤りへの誤りには返しません。echo の要求には返します。
    let mut icmp_err = pkt(
        1,
        3,
        0,
        true,
        0,
        &[0x82, 1, 0, 0],
        &[3, 0, 0, 0, 0, 0, 0, 0],
    );
    let n = rejected(t.process(&icmp_err, at(0)));
    assert!(n.param_problem_ok(&icmp_err, local).is_none());
    icmp_err[24] = 8;
    set_ipv4_checksum(&mut icmp_err[..24]);
    let n = rejected(t.process(&icmp_err, at(0)));
    assert_eq!(n.param_problem_ok(&icmp_err, local), Some(24));
    // 送信元が 0 なら返しません。
    let mut zero_src = bad_first.clone();
    zero_src[12..16].fill(0);
    set_ipv4_checksum(&mut zero_src[..24]);
    let n = rejected(t.process(&zero_src, at(0)));
    assert!(n.param_problem_ok(&zero_src, local).is_none());
}

#[test]
fn fuzz_table_runs_on_records() {
    // 印の bit 0 で checksum を直す 2 つの断片の記録。
    let first = pkt(17, 1, 0, true, 0, &[], b"abcdefgh");
    let last = pkt(17, 1, 8, false, 0, &[], b"ijk");
    let mut input = Vec::new();
    for p in [&first, &last] {
        input.push(1);
        input.extend_from_slice(&u16::try_from(p.len()).unwrap().to_be_bytes());
        input.extend_from_slice(p);
    }
    input.extend_from_slice(&[0xff, 0, 0]);
    fuzz_table(&input);
}
