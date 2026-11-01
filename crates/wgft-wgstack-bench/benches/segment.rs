//! wgstack の核の segment ごとの受信と送信の経路の criterion のベンチです。
//!
//! 接続の数を 1 本と多数で測ります。多数の接続を順に回すと、同じ接続の欄を触る間隔が長くなります。
//! 値は相手の packet の組み立てと checksum を含むので、その費用を `rig_overhead` で別に測ります。
//! `_sack` の付く組は SACK を交渉した接続で、ACK ごとの RACK の状態の更新と TLP の期限の張り直しを含みます。
//! `check_invariants` は試験と fuzz が各段の後に呼ぶ検査の手間を、`stack_new` は核の作成と閉じる手間を測ります。
//! どちらも製品の segment ごとの経路ではありません。

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use wgft_wgstack::{BoostPolicy, Limits};
use wgft_wgstack_bench::{MSS, Rig, new_and_close};

const CONNS: [usize; 3] = [1, 64, 1024];

fn recv(c: &mut Criterion) {
    recv_group(c, "recv_segment", false);
    recv_group(c, "recv_segment_sack", true);
}

fn recv_group(c: &mut Criterion, name: &str, sack: bool) {
    let mut g = c.benchmark_group(name);
    g.throughput(Throughput::Bytes(MSS as u64));
    for n in CONNS {
        let mut rig = Rig::with_sack(n, sack);
        let mut k = 0;
        g.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                rig.recv_one(black_box(k));
                k = (k + 1) % n;
            });
        });
        rig.check();
    }
    g.finish();
}

fn send(c: &mut Criterion) {
    send_group(c, "send_segment", false);
    send_group(c, "send_segment_sack", true);
}

fn send_group(c: &mut Criterion, name: &str, sack: bool) {
    let mut g = c.benchmark_group(name);
    g.throughput(Throughput::Bytes(MSS as u64));
    for n in CONNS {
        let mut rig = Rig::with_sack(n, sack);
        let mut k = 0;
        g.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                rig.send_one(black_box(k));
                k = (k + 1) % n;
            });
        });
        rig.check();
    }
    g.finish();
}

fn rig(c: &mut Criterion) {
    let mut g = c.benchmark_group("rig_overhead");
    g.throughput(Throughput::Bytes(MSS as u64));
    let mut rig = Rig::new(1);
    g.bench_function("build_and_parse", |b| b.iter(|| rig.rig_only(black_box(0))));
    g.finish();
}

/// 試験の小さな表の大きさです (試験の `small_limits` と同じ)。
fn small_limits() -> Limits {
    Limits {
        max_flows: 16,
        accept_queue: 8,
        syn_rows: 16,
        tw_rows: 32,
        ctl_slots: 16,
        ..Limits::default()
    }
}

fn check(c: &mut Criterion) {
    let mut g = c.benchmark_group("check_invariants");
    for (name, limits, n) in [
        ("small", small_limits(), 1),
        ("small", small_limits(), 16),
        ("default", Limits::default(), 1),
        ("default", Limits::default(), 1024),
    ] {
        let mut rig = Rig::build(n, true, limits, BoostPolicy::OnDemand);
        for i in 0..4 * n {
            rig.send_one(i % n);
        }
        g.bench_function(BenchmarkId::new(name, n), |b| {
            b.iter(|| assert!(black_box(&rig).check_ok()));
        });
    }
    g.finish();
}

fn create(c: &mut Criterion) {
    let mut g = c.benchmark_group("stack_new");
    g.bench_function("default_limits", |b| b.iter(new_and_close));
    g.finish();
}

criterion_group!(benches, recv, send, rig, check, create);
criterion_main!(benches);
