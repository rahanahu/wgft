//! wgstack の核の segment ごとの受信と送信の経路の criterion のベンチです。
//!
//! 接続の数を 1 本と多数で測ります。多数の接続を順に回すと、同じ接続の欄を触る間隔が長くなります。
//! 値は相手の packet の組み立てと checksum を含むので、その費用を `rig_overhead` で別に測ります。

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use wgft_wgstack_bench::{MSS, Rig};

const CONNS: [usize; 3] = [1, 64, 1024];

fn recv(c: &mut Criterion) {
    let mut g = c.benchmark_group("recv_segment");
    g.throughput(Throughput::Bytes(MSS as u64));
    for n in CONNS {
        let mut rig = Rig::new(n);
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
    let mut g = c.benchmark_group("send_segment");
    g.throughput(Throughput::Bytes(MSS as u64));
    for n in CONNS {
        let mut rig = Rig::new(n);
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

criterion_group!(benches, recv, send, rig);
criterion_main!(benches);
