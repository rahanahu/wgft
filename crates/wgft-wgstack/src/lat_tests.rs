//! 遅れの目標の窓 (rcv_window.rs、agent-throughput.md の「受信の窓の段」) の白箱の試験。
//!
//! 相手から核へ大きな転送を流し、核の手前に一定の速さで流す待ち行列 (詰まり) と、片道の遅れを置きます。相手は
//! 輻輳の窓を持たず、核が広告した窓を使い切るまで送ります。核は届いたデータをすぐに読みます。窓が詰まりの
//! 待ち行列の長さを決める場面です。
#![expect(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "tests collect segments"
)]
#![expect(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::many_single_char_names,
    reason = "test sequence numbers kept as the low 32 bits, ratios printed as floats and short test names"
)]

use std::collections::VecDeque;

use crate::ConnId;
use crate::boost_tests::DEMAND_BYTES;
use crate::buf::RECV_FLOOR;
use crate::seq;
use crate::stack::ns;
use crate::tcp::rcv_window::lat_target;
use crate::testnet_tests::{
    PeerConn, TEST_MTU, TSeg, TestNet, build_peer, parse_out, small_limits,
};
use crate::wire::FLAG_ACK;
use core::time::Duration;

const MS: u64 = 1_000_000;

/// 1 回の模擬の経路と相手です。
struct Path {
    /// 詰まりの速さ (byte / ms) です。
    rate: u64,
    /// 片道の遅れ (ns) です。時刻 (ns) ごとに返します。
    one_way: fn(u64) -> u64,
    /// 流れごとに、相手が timestamp を使うかです。流れは相手のポート 40000 から順に開きます。
    ts: &'static [bool],
    /// 流れごとに、相手が送り始める時刻 (ms) です。接続は初めにすべて開きます。
    start: &'static [u64],
}

/// 模擬の結果です。区間は 100 ms ごとです。
#[derive(Debug, Default)]
struct Run {
    /// 区間ごとの、詰まりの待ち行列で待った時間の平均 (ns) です。
    queue_ns: Vec<u64>,
    /// 流れと区間ごとに核が読んだ byte です。
    read: Vec<Vec<u64>>,
}

impl Run {
    /// `from` から `to` の区間 (100 ms 単位) の平均の待ち (ms) と、流れの全体の速さ (詰まりの速さに対する比) です。
    fn summary(&self, path: &Path, from: usize, to: usize) -> (f64, f64) {
        let q = self.queue_ns[from..to].iter().sum::<u64>() as f64 / (to - from) as f64 / MS as f64;
        let total: u64 = self
            .read
            .iter()
            .map(|r| r[from..to].iter().sum::<u64>())
            .sum();
        (
            q,
            total as f64 / ((to - from) as u64 * 100 * path.rate) as f64,
        )
    }

    /// `from` から `to` の区間で、流れ `f` が読んだ byte の全体に対する比です。
    fn share(&self, f: usize, from: usize, to: usize) -> f64 {
        let total: u64 = self
            .read
            .iter()
            .map(|r| r[from..to].iter().sum::<u64>())
            .sum();
        self.read[f][from..to].iter().sum::<u64>() as f64 / total as f64
    }
}

/// 核の手前の待ち行列に入った segment です。
struct Queued {
    flow: usize,
    seg: TSeg,
    enter: u64,
    leave: u64,
}

/// 相手の側の 1 つの流れです。
struct Flow {
    p: PeerConn,
    c: ConnId,
    mss: usize,
    ws: u8,
    /// 相手が知る右端 (相手の番号) です。
    edge: u32,
    /// 核が広告した右端 (受信の offset) です。
    seen: u64,
}

/// 核の側の 80 番に相手の 40000 番から順に流れを開き、`dur_ms` の間、どの相手も窓を使い切るまで送り続けます。
/// 右端が後ろへ戻らないこと (RFC 9293 3.8.6) を segment を送るごとに確かめます。
fn simulate(path: &Path, dur_ms: u64) -> (TestNet, Vec<ConnId>, Run) {
    let mut n = TestNet::new(small_limits());
    let l = n.listen(80);
    let mut flows = Vec::new();
    for (i, &ts) in path.ts.iter().enumerate() {
        let p: PeerConn = n.handshake_sack(40000 + i as u16, 80, ts, true, true);
        let c = n.accept(l);
        n.drain();
        let v = n.s.conn(c.slot);
        let edge = p.iss.wrapping_add(1).wrapping_add(v.t.adv_right as u32);
        let (ws, seen) = (v.t.rcv_wscale, v.t.adv_right);
        flows.push(Flow {
            p,
            c,
            mss: if ts { TEST_MTU - 52 } else { TEST_MTU - 40 },
            ws,
            edge,
            seen,
        });
    }
    let payload = vec![0u8; TEST_MTU];
    let mut buf = vec![0u8; 65536];
    let mut rbuf = vec![0u8; 1 << 20];
    let t0 = ns(n.now).cast_unsigned();
    let end = t0 + dur_ms * MS;
    let mut queue: VecDeque<Queued> = VecDeque::new();
    let mut acks: VecDeque<(u64, crate::testnet_tests::Out)> = VecDeque::new();
    let mut busy_until = t0;
    let buckets = usize::try_from(dur_ms / 100).unwrap();
    let mut run = Run {
        queue_ns: vec![0; buckets],
        read: vec![vec![0; buckets]; flows.len()],
    };
    let mut counts = vec![0u64; buckets];
    let mut steps = 0u64;
    let mut now = t0;
    loop {
        // 相手は窓の内側で送れるだけ送ります
        for (i, f) in flows.iter_mut().enumerate() {
            if now < t0 + path.start[i] * MS {
                continue;
            }
            while seq::le(f.p.snd.wrapping_add(f.mss as u32), f.edge) {
                let seg = f.p.seg(FLAG_ACK, &payload[..f.mss]);
                f.p.snd = f.p.snd.wrapping_add(f.mss as u32);
                let enter = now + (path.one_way)(now);
                let leave = busy_until.max(enter) + f.mss as u64 * MS / path.rate;
                busy_until = leave;
                queue.push_back(Queued {
                    flow: i,
                    seg,
                    enter,
                    leave,
                });
            }
        }
        let next_seg = queue.front().map_or(u64::MAX, |q| q.leave);
        let next_ack = acks.front().map_or(u64::MAX, |a| a.0);
        let next = path
            .start
            .iter()
            .map(|st| t0 + st * MS)
            .filter(|&st| st > now)
            .fold(next_seg.min(next_ack), u64::min);
        if next >= end {
            break;
        }
        if next > now {
            now = next;
            n.now = n.now + Duration::from_nanos(next - ns(n.now).cast_unsigned());
            n.s.handle_timeout(n.now);
        }
        if next_seg <= now {
            let q = queue.pop_front().unwrap();
            let f = &flows[q.flow];
            n.s.handle_packet(n.now, &build_peer(&q.seg));
            let mut got = 0;
            while let Ok(k) = n.s.read(n.now, f.c, &mut rbuf) {
                if k == 0 {
                    break;
                }
                got += k as u64;
            }
            let b = usize::try_from((now - t0) / (100 * MS))
                .unwrap()
                .min(buckets - 1);
            run.queue_ns[b] += q.leave - q.enter - f.mss as u64 * MS / path.rate;
            counts[b] += 1;
            run.read[q.flow][b] += got;
        }
        while let Some(k) = n.s.poll_transmit(n.now, &mut buf) {
            let o = parse_out(&buf[..k]);
            for f in &mut flows {
                let v = n.s.conn(f.c.slot);
                assert!(
                    v.t.adv_right >= f.seen,
                    "the advertised edge went back from {} to {}",
                    f.seen,
                    v.t.adv_right
                );
                f.seen = v.t.adv_right;
            }
            acks.push_back((now + (path.one_way)(now), o));
        }
        while acks.front().is_some_and(|a| a.0 <= now) {
            let (_, o) = acks.pop_front().unwrap();
            let Some(f) = flows.iter_mut().find(|f| f.p.sport == o.rport) else {
                continue;
            };
            f.p.absorb(std::slice::from_ref(&o));
            let e = o.ack.wrapping_add(u32::from(o.wnd) << f.ws);
            if seq::lt(f.edge, e) {
                f.edge = e;
            }
        }
        steps += 1;
        if steps.is_multiple_of(4096) {
            n.check();
        }
    }
    n.check();
    for (q, k) in run.queue_ns.iter_mut().zip(&counts) {
        *q /= (*k).max(1);
    }
    (n, flows.iter().map(|f| f.c).collect(), run)
}

/// 経路の往復の時間 (ns) です。模擬の終わりの片道の遅れの 2 倍です。
fn rtt_ns(path: &Path) -> i64 {
    i64::try_from(2 * (path.one_way)(u64::MAX)).unwrap()
}

fn short_path(_: u64) -> u64 {
    5 * MS
}

/// 窓が詰まりの待ち行列を遅れの目標の近くに保ち、速さを落とさないことを確かめます。経路は片道 5 ms、
/// 800 Mbit/s で、帯域と往復の時間の積は約 1 MB です。10 秒の後の最小の測り直し (右端を止めて待ち行列を空に
/// します) を含めて、速さを確かめます。
#[test]
fn latency_cap_keeps_the_queue_near_the_target() {
    let path = Path {
        rate: 100_000,
        one_way: short_path,
        ts: &[true],
        start: &[0],
    };
    let (mut n, c, run) = simulate(&path, 13000);
    let (q, r) = run.summary(&path, 10, 130);
    println!("queue {q:.3} ms, rate {r:.3} of the bottleneck, runs {run:?}");
    let v = n.s.conn(c[0].slot);
    assert!(v.k.rcv_boost, "no receive boost");
    let target = lat_target(rtt_ns(&path)) as f64 / MS as f64;
    assert!(
        q <= 2.0 * target,
        "queue {q:.3} ms above twice the target {target} ms"
    );
    assert!(r >= 0.97, "rate {r:.3} of the bottleneck");
    assert!(v.t.lat_cap > 0, "no latency cap");
}

/// timestamp の無い相手は往復の時間を測れず、窓を遅れの目標で頭打ちにしません。前の試験の検出力の確かめでも
/// あります。同じ経路で、待ち行列は受信の窓の自動調整が決めた窓の分だけ溜まり、目標の 3 倍を超えます。
#[test]
fn latency_cap_needs_timestamps() {
    let path = Path {
        rate: 100_000,
        one_way: short_path,
        ts: &[false],
        start: &[0],
    };
    let (mut n, c, run) = simulate(&path, 3000);
    let (q, r) = run.summary(&path, 10, 30);
    println!("queue {q:.3} ms, rate {r:.3} of the bottleneck");
    assert_eq!(n.s.conn(c[0].slot).t.lat_cap, 0);
    let target = lat_target(rtt_ns(&path)) as f64 / MS as f64;
    assert!(q > 3.0 * target, "queue {q:.3} ms without the cap");
    assert!(r >= 0.97, "rate {r:.3} of the bottleneck");
}

fn longer_after_2s(t: u64) -> u64 {
    if t < 2000 * MS { 5 * MS } else { 8 * MS }
}

/// 経路の往復の時間が目標より大きく延びると、古い最小の下では窓が帯域と往復の時間の積を下回り、速さが落ちます。
/// 10 秒の境目の測り直しの後に、速さが戻ることを確かめます。
#[test]
fn latency_cap_recovers_after_the_path_gets_longer() {
    let path = Path {
        rate: 100_000,
        one_way: longer_after_2s,
        ts: &[true],
        start: &[0],
    };
    let (_, _, run) = simulate(&path, 14000);
    let last = run.queue_ns.len();
    let (q, r) = run.summary(&path, last - 30, last);
    // 延びた後 (3 秒から 10 秒の境目まで) は、floor の窓の分 (floor / 速さ / 往復の時間) に落ちます。この落ち込みを
    // 縮める変更は、ここの上の側の確かめを直します (agent-throughput.md の「短すぎる最小と譲る量」)
    let (_, collapse) = run.summary(&path, 30, 100);
    let floor_share = RECV_FLOOR as f64 / (path.rate as f64 * rtt_ns(&path) as f64 / MS as f64);
    println!(
        "collapse {collapse:.3} (floor share {floor_share:.3}); after the refresh: queue {q:.3} ms, rate {r:.3}; per 100 ms {:?}",
        run.read
    );
    assert!(
        collapse >= 0.9 * floor_share && collapse <= floor_share + 0.05,
        "rate {collapse:.3} between the change and the boundary, the floor's share {floor_share:.3}"
    );
    for s in 11..14 {
        let (_, rs) = run.summary(&path, 10 * s, 10 * s + 10);
        assert!(
            rs >= 0.97,
            "rate {rs:.3} in second {s}, after the boundary at 10 s"
        );
    }
    let target = lat_target(rtt_ns(&path)) as f64 / MS as f64;
    assert!(
        q <= 2.0 * target,
        "queue {q:.3} ms above twice the target {target} ms"
    );
    assert!(r >= 0.97, "rate {r:.3} of the bottleneck after the refresh");
}

fn long_path(_: u64) -> u64 {
    25 * MS
}

/// timestamp を使う流れが、timestamp の無い流れ (遅れの上限が働かず、受信の窓の自動調整の窓で送る流れ) と
/// 詰まりを分け合う場合に、相手の流れが保つ待ち行列のために floor の窓まで縮み続けないことを確かめます。経路は
/// 片道 25 ms、240 Mbit/s で、帯域と往復の時間の積は約 1.5 MB です。floor の窓だけでは全体の約 17% しか
/// 送れません。10 秒の境目の測り直しは、相手の流れの待ちを含む最小を測ります。その後を確かめます。
#[test]
fn latency_cap_does_not_starve_beside_a_flow_without_it() {
    let path = Path {
        rate: 30_000,
        one_way: long_path,
        ts: &[true, false],
        start: &[0, 0],
    };
    let (mut n, c, run) = simulate(&path, 14000);
    let last = run.queue_ns.len();
    let (q, r) = run.summary(&path, last - 30, last);
    let share = run.share(0, last - 30, last);
    println!(
        "queue {q:.3} ms, rate {r:.3}, share of the capped flow {share:.3}, cap {}; per 100 ms {:?}",
        n.s.conn(c[0].slot).t.lat_cap,
        run.read
    );
    // floor の窓だけの取り分:floor を、速さと待ちを含む往復の時間の積で割った値
    let floor_share =
        RECV_FLOOR as f64 / (path.rate as f64 * (rtt_ns(&path) as f64 / MS as f64 + q));
    assert!(r >= 0.97, "rate {r:.3} of the bottleneck");
    assert!(
        share >= floor_share + 0.05,
        "the capped flow got {share:.3} of the bottleneck, the floor alone {floor_share:.3}"
    );
}

/// 帯域と往復の時間の積が floor より小さい経路 (片道 25 ms、20 Mbit/s) では、floor の窓が待ち行列を作ります。この
/// 待ちを自分の窓のものでないとみなして最小を置き直すと、置き直すたびに窓が広がり、待ち行列が延び続けます。
/// 模擬の相手は初めに floor の窓をまとめて送るので、最初の標本は約 80 ms の待ちを含みます。最小を測り直した後
/// (10 秒の後) に、待ち行列が floor の窓の作る長さ (floor を速さで割った時間から往復の時間を引いた約 55 ms) に
/// 留まることを確かめます。
#[test]
fn latency_cap_leaves_the_floor_queue_alone() {
    let path = Path {
        rate: 2_500,
        one_way: long_path,
        ts: &[true],
        start: &[0],
    };
    let (_, _, run) = simulate(&path, 14000);
    let last = run.queue_ns.len();
    let (q, r) = run.summary(&path, last - 30, last);
    let floor_q = (RECV_FLOOR * MS / path.rate) as f64 / MS as f64 - 50.0;
    println!(
        "queue {q:.3} ms, floor queue {floor_q:.1} ms, rate {r:.3}; per 100 ms {:?}",
        run.queue_ns
    );
    assert!(r >= 0.97, "rate {r:.3} of the bottleneck");
    assert!(
        q <= floor_q + 10.0,
        "queue {q:.3} ms beyond the floor's {floor_q:.1} ms"
    );
}

/// 時刻の跳び (核は 25 日までの跳びを受けます) の後の標本と、最大の読んだ量でも、遅れの上限の計算が溢れないことを
/// 確かめます。敵対的な送り手の fuzz の種が、64 bit の掛け算の溢れを見つけました。
#[test]
fn latency_cap_survives_huge_samples() {
    let mut n = TestNet::new(small_limits());
    let (c, _) = n.accepted(true);
    let mut v = n.s.conn(c.slot);
    for (min, rtt) in [
        (i64::MAX / 2, i64::MAX),
        (1, i64::MAX),
        (i64::MAX, i64::MAX),
    ] {
        (v.k.lat_min, v.k.lat_rtt) = (min, rtt);
        v.lat_adjust(u64::MAX, 1);
        assert_eq!(v.t.lat_cap, u64::MAX);
        v.lat_adjust(0, i64::MAX);
        assert_eq!(v.t.lat_cap, 1);
    }
}

/// 時刻ごとの片道の遅れ 0.25 ms です。ラボの経路の往復の時間に近い値です。
fn lab_path(_: u64) -> u64 {
    MS / 4
}

/// 遅れの上限を持つ流れを時刻をずらして重ねた時の、最後の `tail` 区間 (100 ms) の待ち行列の平均 (ms) を、同じ
/// 経路と開始の時刻で timestamp の無い流れ (遅れの上限の無い流れ) の値と並べて返します。
/// N 本の流れの floor の窓が作る待ち (ms) の 1.5 倍と、目標の 2 倍の和です。遅れの上限が floor より小さい流れは
/// 測り直しで右端を止めないので、floor の待ちは空にならず、その間に測った最小が待ちを含み、伸びの余地がその分
/// だけ窓を広げます。1.5 倍はこの分の余裕です。
fn stagger_bound(n: usize, rate: u64, rtt: i64) -> f64 {
    1.5 * n as f64 * RECV_FLOOR as f64 / rate as f64 + 2.0 * lat_target(rtt) as f64 / MS as f64
}

fn staggered(
    rate: u64,
    one_way: fn(u64) -> u64,
    start: &'static [u64],
    dur: u64,
    tail: usize,
) -> (f64, f64, f64) {
    const CAPPED: [bool; 3] = [true; 3];
    const PLAIN: [bool; 3] = [false; 3];
    let k = start.len();
    let capped = Path {
        rate,
        one_way,
        ts: &CAPPED[..k],
        start,
    };
    let plain = Path {
        rate,
        one_way,
        ts: &PLAIN[..k],
        start,
    };
    let (_, _, a) = simulate(&capped, dur);
    let (_, _, b) = simulate(&plain, dur);
    let last = a.queue_ns.len();
    let (qa, ra) = a.summary(&capped, last - tail, last);
    let (qb, _) = b.summary(&plain, last - tail, last);
    println!(
        "capped: queue {qa:.3} ms rate {ra:.3}; without the cap: queue {qb:.3} ms; capped per 100 ms {:?}",
        a.queue_ns
    );
    (qa, ra, qb)
}

/// 遅れの上限を持つ流れを 2 つと 3 つ、時刻をずらして重ねても、待ち行列が遅れの上限の無い流れより延びないこと
/// を確かめます。後から来た流れは前の流れが保つ待ちを含む最小を測りますが、10 秒の境目ですべての流れが同時に
/// 右端を止めて測り直すので、最小は空の待ち行列の値に戻ります。経路は片道 5 ms、800 Mbit/s です。
#[test]
fn latency_cap_staggered_flows_keep_the_queue_short() {
    for start in [&[0, 3500][..], &[0, 3300, 6600][..]] {
        let (qa, ra, qb) = staggered(100_000, short_path, start, 25000, 100);
        let bound = stagger_bound(start.len(), 100_000, (10 * MS).cast_signed());
        assert!(ra >= 0.97, "rate {ra:.3} of the bottleneck");
        assert!(
            qa <= qb,
            "queue {qa:.3} ms with the cap, {qb:.3} ms without"
        );
        assert!(
            qa <= bound,
            "queue {qa:.3} ms above the bound {bound:.3} ms"
        );
    }
}

/// ラボに近い経路 (片道 0.25 ms、1 Gbit/s) で、3 つの流れをずらして重ねても、待ち行列が遅れの上限の無い流れより
/// 延びないことを確かめます。
#[test]
fn latency_cap_staggered_flows_on_a_short_path() {
    let (qa, ra, qb) = staggered(125_000, lab_path, &[0, 3300, 6600], 25000, 100);
    let bound = stagger_bound(3, 125_000, (MS / 2).cast_signed());
    assert!(ra >= 0.97, "rate {ra:.3} of the bottleneck");
    assert!(
        qa <= qb,
        "queue {qa:.3} ms with the cap, {qb:.3} ms without"
    );
    assert!(
        qa <= bound,
        "queue {qa:.3} ms above the bound {bound:.3} ms"
    );
}

/// 中継が詰まりより遅く読む接続 (受信のバッファが埋まり、窓が 0 か小さい接続) で、10 秒の境目が来ても右端を
/// 止めたままにならないことを確かめます。窓が 0 の時に止め始めると、data が届かないので止めるのをやめる時が
/// 来ません。相手は 200 ms ごとに窓の probe を送ります。
#[test]
fn latency_cap_drain_never_sticks_with_a_slow_reader() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(true);
    let ws = n.s.conn(c.slot).t.rcv_wscale;
    let mss = TEST_MTU - 52;
    let payload = vec![0u8; TEST_MTU];
    let mut rbuf = vec![0u8; 1 << 20];
    let mut edge = p
        .iss
        .wrapping_add(1)
        .wrapping_add(n.s.conn(c.slot).t.adv_right as u32);
    let mut stuck = 0u64;
    let mut read = 0u64;
    // 相手は窓を使い切るまで 1 ms ごとに送り、中継は 1 ms ごとに 2 KB だけ読みます。40 秒の間に 4 回の境目が来ます
    for ms in 0..40_000u64 {
        n.advance(Duration::from_millis(1));
        while seq::le(p.snd.wrapping_add(mss as u32), edge) {
            let seg = p.seg(FLAG_ACK, &payload[..mss]);
            p.snd = p.snd.wrapping_add(mss as u32);
            n.inject(&seg);
        }
        if ms % 200 == 0 && seq::le(edge, p.snd) {
            // 窓の probe:1 つ前の番号の中身の無い segment
            p.snd = p.snd.wrapping_sub(1);
            let seg = p.seg(FLAG_ACK, &[]);
            p.snd = p.snd.wrapping_add(1);
            n.inject(&seg);
        }
        if let Ok(k) = n.s.read(n.now, c, &mut rbuf[..2000]) {
            read += k as u64;
        }
        for o in n.drain() {
            p.absorb(std::slice::from_ref(&o));
            let e = o.ack.wrapping_add(u32::from(o.wnd) << ws);
            if seq::lt(edge, e) {
                edge = e;
            }
        }
        let v = n.s.conn(c.slot);
        stuck = if v.t.lat_drain { stuck + 1 } else { 0 };
        assert!(
            stuck <= 250,
            "the right edge held for {stuck} ms at {ms} ms, window {}",
            v.rcv_window()
        );
    }
    assert!(read > 70_000_000, "the reader got {read} bytes in 40 s");
}

/// 窓が 0 の時に 10 秒の境目が来ても、右端を止めずに最小だけを捨てることを確かめます。止めた後に窓が 0 に
/// なった場合も、窓の欄を作る時に止めるのをやめます。
#[test]
fn latency_cap_drain_does_not_start_at_a_zero_window() {
    let mut n = TestNet::new(small_limits());
    let (c, mut p) = n.accepted(true);
    let ws = n.s.conn(c.slot).t.rcv_wscale;
    let mss = TEST_MTU - 52;
    let payload = vec![0u8; TEST_MTU];
    let mut edge = p
        .iss
        .wrapping_add(1)
        .wrapping_add(n.s.conn(c.slot).t.adv_right as u32);
    // 読まずに窓が 0 になるまで送ります
    for _ in 0..10_000 {
        let left = edge.wrapping_sub(p.snd) as usize;
        if left == 0 {
            break;
        }
        let seg = p.seg(FLAG_ACK, &payload[..left.min(mss)]);
        p.snd = p.snd.wrapping_add(left.min(mss) as u32);
        n.inject(&seg);
        for o in n.drain() {
            p.absorb(std::slice::from_ref(&o));
            let e = o.ack.wrapping_add(u32::from(o.wnd) << ws);
            if seq::lt(edge, e) {
                edge = e;
            }
        }
    }
    let now = ns(n.now);
    {
        let v = n.s.conn(c.slot);
        assert_eq!(v.rcv_window(), 0, "the window did not close");
        // 測り直しの時刻が来た接続にします
        (v.k.lat_min, v.k.lat_rtt, v.k.lat_next) = (1_000_000, 1_000_000, now + 1);
        v.t.lat_cap = 4 * RECV_FLOOR;
    }
    n.advance(Duration::from_millis(2));
    let mut rbuf = vec![0u8; 1000];
    n.s.read(n.now, c, &mut rbuf).unwrap();
    n.drain();
    {
        let v = n.s.conn(c.slot);
        assert!(!v.t.lat_drain, "a drain started at a zero window");
        assert_eq!(v.k.lat_min, 0, "the minimum was not dropped");
        // 止めている途中に窓が 0 になった場合:窓の欄を作る時に止めるのをやめます
        (v.t.lat_drain, v.k.lat_drain_at) = (true, now);
    }
    p.snd = p.snd.wrapping_sub(1);
    let seg = p.seg(FLAG_ACK, &[]);
    n.inject(&seg);
    n.drain();
    assert!(
        !n.s.conn(c.slot).t.lat_drain,
        "the drain outlived the window"
    );
}

fn path_100ms(_: u64) -> u64 {
    50 * MS
}

/// 往復の時間の長い経路 (片道 50 ms、100 Mbit/s) で、遅れの上限の速さの費用を、遅れの上限の無い流れと比べます。
/// 費用は始めの立ち上がりと、10 秒ごとの測り直しで右端を止める間です。
#[test]
fn latency_cap_cost_on_a_long_path() {
    let capped = Path {
        rate: 12_500,
        one_way: path_100ms,
        ts: &[true],
        start: &[0],
    };
    let plain = Path {
        ts: &[false],
        ..capped
    };
    let (_, _, a) = simulate(&capped, 25000);
    let (_, _, b) = simulate(&plain, 25000);
    let sec = |r: &Run, p: &Path, i: usize| r.summary(p, 10 * i, 10 * i + 10);
    let per_s: Vec<(f64, f64)> = (0..25).map(|i| sec(&a, &capped, i)).collect();
    let (_, first_plain) = sec(&b, &plain, 0);
    let (q_all, r_all) = a.summary(&capped, 10, 250);
    let (q_plain, r_plain) = b.summary(&plain, 10, 250);
    println!(
        "first second {:.3} (without the cap {first_plain:.3}); after it: rate {r_all:.3} queue {q_all:.2} ms (without the cap {r_plain:.3}, {q_plain:.2} ms); per second {per_s:.3?}",
        per_s[0].1
    );
    assert!(
        r_all >= 0.97,
        "rate {r_all:.3} of the bottleneck after the first second"
    );
}

/// 需要の量の確かめです。この試験の転送は boost を得る量より大きいことを前提にします。
const _: () = assert!(DEMAND_BYTES < 1 << 20);
