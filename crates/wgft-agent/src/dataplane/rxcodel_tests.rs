//! 受信の取り出しの CoDel の試験。状態機械 (RFC 8289 の入る・出る・interval・数と次の落としの間隔)、
//! 落とせる packet の見分け、待ちの標本、模型の待ち行列での UDP の待ちの上界を確かめる。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::*;

const MS: Duration = Duration::from_millis(1);
const TARGET: Duration = Duration::from_millis(5);

/// IPv4 の TCP の segment。`flags` は TCP の flag の byte、`data` は中身の長さ、`opts` は TCP の option の
/// 長さ (4 の倍数)。
fn tcp(flags: u8, data: usize, opts: usize) -> Vec<u8> {
    let doff = 20 + opts;
    let total = 20 + doff + data;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[6] = 0x40; // DF
    p[8] = 64;
    p[9] = 6;
    p[20 + 12] = u8::try_from(doff / 4).unwrap() << 4;
    p[20 + 13] = flags;
    p
}

const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;

fn udp(data: usize) -> Vec<u8> {
    let total = 28 + data;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    p[9] = 17;
    p
}

/// 設計:落とせるのは中身のある TCP の segment だけ。中身の無い ACK、SYN、FIN、RST、UDP、ほかの protocol、
/// 断片、読めない packet は落とさない。
#[test]
fn only_tcp_segments_with_data_are_droppable() {
    assert!(droppable(&tcp(ACK, 1, 0)));
    assert!(droppable(&tcp(PSH_ACK, 1368, 12)));
    // 中身の無い ACK (timestamp の option つきも)
    assert!(!droppable(&tcp(ACK, 0, 0)));
    assert!(!droppable(&tcp(ACK, 0, 12)));
    // 中身があっても SYN、FIN、RST は落とさない
    for f in [0x02, 0x12, 0x01 | ACK, 0x04, 0x04 | ACK] {
        assert!(!droppable(&tcp(f, 100, 0)), "flags {f:#x}");
    }
    // UDP とほかの protocol
    assert!(!droppable(&udp(1000)));
    let mut icmp = udp(100);
    icmp[9] = 1;
    assert!(!droppable(&icmp));
    // 断片:MF か offset のある packet
    let mut mf = tcp(ACK, 100, 0);
    mf[6] = 0x20;
    assert!(!droppable(&mf));
    let mut off = tcp(ACK, 100, 0);
    off[7] = 1;
    off[6] = 0;
    assert!(!droppable(&off));
    // IPv4 でない、header の長さが足りない、全長が buffer を超える、TCP の header が切れた
    let mut v6 = tcp(ACK, 100, 0);
    v6[0] = 0x65;
    assert!(!droppable(&v6));
    let mut short_ihl = tcp(ACK, 100, 0);
    short_ihl[0] = 0x44;
    assert!(!droppable(&short_ihl));
    let mut long_total = tcp(ACK, 100, 0);
    long_total[2..4].copy_from_slice(&2000u16.to_be_bytes());
    assert!(!droppable(&long_total));
    assert!(!droppable(&tcp(ACK, 100, 0)[..30]));
    assert!(!droppable(&[]));
    // data offset が 20 未満か全長を超える
    let mut bad_doff = tcp(ACK, 100, 0);
    bad_doff[32] = 4 << 4;
    assert!(!droppable(&bad_doff));
    let mut big_doff = tcp(ACK, 10, 0);
    big_doff[32] = 15 << 4;
    assert!(!droppable(&big_doff));
    // IP の option つき (IHL 6) の中身のある segment は落とせる
    let mut with_ip_opt = vec![0u8; 24 + 20 + 10];
    with_ip_opt[0] = 0x46;
    with_ip_opt[2..4].copy_from_slice(&54u16.to_be_bytes());
    with_ip_opt[9] = 6;
    with_ip_opt[24 + 12] = 5 << 4;
    with_ip_opt[24 + 13] = ACK;
    assert!(droppable(&with_ip_opt));
    // buffer が全長より長くても、全長で中身を数える
    let mut padded = tcp(ACK, 0, 0);
    padded.extend_from_slice(&[0; 10]);
    assert!(!droppable(&padded));
}

/// 時刻 `t0 + ms` のバッチを 1 つ進める。
fn batch(c: &mut Codel, t0: Instant, at: Duration, sojourn: Duration) {
    c.on_batch(t0 + at, sojourn, false);
}

/// 設計 (RFC 8289):待ちが目標を interval の間ずっと超えた後の最初のバッチで、落とす状態に入る。目標の下や
/// 空の読みが挟まると、数え直す。
#[test]
fn the_drop_state_starts_after_a_whole_interval_above_target() {
    let t0 = Instant::now();
    let mut c = Codel::new(TARGET);
    let data = tcp(ACK, 100, 0);
    // 目標ちょうどは「超えた」に入る (RFC は sojourn < target を下とする)
    batch(&mut c, t0, Duration::ZERO, TARGET);
    batch(&mut c, t0, 99 * MS, 9 * MS);
    assert!(!c.pending() && !c.dropping());
    assert!(!c.take(&data));
    // 目標の下が 1 つ挟まると、そこから数え直す
    batch(&mut c, t0, 99 * MS + MS / 2, 4 * MS);
    batch(&mut c, t0, 100 * MS, 9 * MS);
    batch(&mut c, t0, 199 * MS, 9 * MS);
    assert!(!c.pending());
    // 空の読みも数え直す
    c.on_batch(t0 + 199 * MS + MS / 2, 9 * MS, true);
    batch(&mut c, t0, 200 * MS, 9 * MS);
    batch(&mut c, t0, 299 * MS, 9 * MS);
    assert!(!c.pending());
    batch(&mut c, t0, 300 * MS, 9 * MS);
    assert!(c.pending() && c.dropping());
    assert_eq!(c.drops(), 0);
}

/// 設計 (RFC 8289 の制御の則):落とす状態の i 回目の落としの後、次の落としは interval / sqrt(i) 後。1 つの
/// バッチで落とすのは高々 1 つ。
#[test]
fn drops_follow_the_control_law_one_per_batch() {
    let t0 = Instant::now();
    let mut c = Codel::new(TARGET);
    let data = tcp(PSH_ACK, 1368, 12);
    batch(&mut c, t0, Duration::ZERO, 9 * MS);
    batch(&mut c, t0, 100 * MS, 9 * MS);
    assert!(c.pending());
    assert!(c.take(&data));
    // 同じバッチの 2 つ目は落とさない
    assert!(!c.take(&data));
    assert_eq!((c.drops(), c.count()), (1, 1));
    assert_eq!(c.drop_next(), Some(t0 + 200 * MS));
    let mut expect = t0 + 200 * MS;
    for i in 2..=6u32 {
        // 次の落としの直前のバッチでは決めない
        c.on_batch(
            expect.checked_sub(Duration::from_micros(1)).unwrap(),
            9 * MS,
            false,
        );
        assert!(!c.pending(), "drop {i}");
        c.on_batch(expect, 9 * MS, false);
        assert!(c.pending(), "drop {i}");
        assert!(c.take(&data));
        assert_eq!(c.count(), i);
        expect += INTERVAL.div_f64(f64::from(i).sqrt());
        assert_eq!(c.drop_next(), Some(expect), "drop {i}");
    }
    assert_eq!(c.drops(), 6);
}

/// 設計:待ちが目標の下に戻るか、読みがソケットを空にしたら、落とす状態を出て、決めていた落としも取り消す。
#[test]
fn the_drop_state_ends_below_target_or_on_an_empty_read() {
    let t0 = Instant::now();
    let data = tcp(ACK, 100, 0);
    for empty in [false, true] {
        let mut c = Codel::new(TARGET);
        batch(&mut c, t0, Duration::ZERO, 9 * MS);
        batch(&mut c, t0, 100 * MS, 9 * MS);
        assert!(c.take(&data));
        c.on_batch(t0 + 200 * MS, 9 * MS, false);
        assert!(c.pending());
        if empty {
            c.on_batch(t0 + 201 * MS, 9 * MS, true);
        } else {
            c.on_batch(t0 + 201 * MS, 4 * MS, false);
        }
        assert!(!c.dropping() && !c.pending());
        assert!(!c.take(&data));
        assert_eq!(c.drops(), 1);
    }
}

/// 設計 (RFC 8289):落とす状態を出て 16 interval 以内に入り直したら、前の状態の数の差から続ける。長く空いたら
/// 1 から。
#[test]
fn a_quick_return_resumes_the_count() {
    let t0 = Instant::now();
    let data = tcp(ACK, 100, 0);
    let run = |gap: Duration| {
        let mut c = Codel::new(TARGET);
        let mut at = Duration::ZERO;
        batch(&mut c, t0, at, 9 * MS);
        at += INTERVAL;
        // 4 回落とす
        loop {
            batch(&mut c, t0, at, 9 * MS);
            if c.take(&data) && c.drops() == 4 {
                break;
            }
            at += MS;
        }
        assert_eq!(c.count(), 4);
        // 目標の下で出て、gap の後に入り直す
        at += MS;
        batch(&mut c, t0, at, Duration::ZERO);
        at += gap;
        batch(&mut c, t0, at, 9 * MS);
        at += INTERVAL;
        batch(&mut c, t0, at, 9 * MS);
        assert!(c.take(&data));
        c.count()
    };
    // 前の last_count は 1 で、count は 4 なので差は 3
    assert_eq!(run(10 * MS), 3);
    assert_eq!(run(INTERVAL * 17), 1);
}

/// 設計:落とすと決めても、落とせる packet (中身のある TCP の segment) が来るまで落とさず、待つ間に次を
/// 重ねない。UDP、ACK、SYN は通す。
#[test]
fn a_decided_drop_waits_for_a_droppable_packet_without_piling_up() {
    let t0 = Instant::now();
    let mut c = Codel::new(TARGET);
    batch(&mut c, t0, Duration::ZERO, 9 * MS);
    batch(&mut c, t0, 100 * MS, 9 * MS);
    assert!(c.pending());
    for p in [udp(1000), tcp(ACK, 0, 12), tcp(0x02, 0, 0)] {
        assert!(!c.take(&p));
    }
    // 落とせる packet の無いバッチが続いても、数は進まない
    for k in 1..=500u32 {
        batch(&mut c, t0, 100 * MS + k * MS, 9 * MS);
        assert!(!c.take(&udp(100)));
    }
    assert_eq!((c.drops(), c.count()), (0, 0));
    batch(&mut c, t0, 700 * MS, 9 * MS);
    assert!(c.take(&tcp(ACK, 10, 0)));
    assert!(!c.pending());
    assert_eq!((c.drops(), c.count()), (1, 1));
}

/// 設計:標本は、前の標本から 1 ms 以上経ち、読みがソケットを空にしなかった時だけ受信の時刻を読む。空の読みは
/// 待ち 0。受信の時刻が無いか、差が負か 2 秒を超えると 0 (壁時計の飛び)。
#[test]
fn the_sampler_reads_at_most_once_a_millisecond_and_guards_the_clock() {
    let t0 = Instant::now();
    let wall = 1_000_000 * 1_000_000_000u64;
    let mut s = Sampler::default();
    let mut reads = 0;
    let mut at = |s: &mut Sampler, t: Duration, emptied: bool, stamp: Option<u64>| {
        s.sojourn(
            t0 + t,
            emptied,
            || {
                reads += 1;
                stamp
            },
            || wall,
        )
    };
    let ms = |n: u64| n * 1_000_000;
    assert_eq!(
        at(&mut s, Duration::ZERO, false, Some(wall - ms(7))),
        7 * MS
    );
    // 1 ms 未満は前の値を使い、時刻を読まない
    assert_eq!(at(&mut s, MS / 2, false, Some(wall - ms(1))), 7 * MS);
    // 空の読みは 0 で、時刻を読まない
    assert_eq!(at(&mut s, MS / 2, true, Some(wall - ms(1))), Duration::ZERO);
    assert_eq!(
        at(&mut s, MS / 2, false, Some(wall - ms(1))),
        Duration::ZERO
    );
    assert_eq!(at(&mut s, MS, false, Some(wall - ms(3))), 3 * MS);
    // 時計の飛び:未来の時刻と 2 秒を超える差は 0。2 秒ちょうどは待ち
    assert_eq!(at(&mut s, 2 * MS, false, Some(wall + 1)), Duration::ZERO);
    assert_eq!(
        at(&mut s, 3 * MS, false, Some(wall - ms(2001))),
        Duration::ZERO
    );
    assert_eq!(
        at(&mut s, 4 * MS, false, Some(wall - ms(2000))),
        MAX_SOJOURN
    );
    assert_eq!(at(&mut s, 5 * MS, false, None), Duration::ZERO);
    drop(at);
    assert_eq!(reads, 6);
}

/// 設計:落とした数のログの行は、増えた時だけ、10 秒に 1 回まで。止める時は間隔を待たない。
#[test]
fn the_drop_log_line_is_rate_limited() {
    let t0 = Instant::now();
    let mut r = RxCodel::new(TARGET);
    assert_eq!(r.log_line(t0, false), None);
    r.codel.drops = 3;
    let line = r.log_line(t0, false).unwrap();
    assert_eq!(
        line,
        "tunnel: the experimental receive queue control dropped 3 TCP segments so far"
    );
    assert!(!line.contains('('));
    r.codel.drops = 4;
    assert_eq!(r.log_line(t0 + 9 * 1000 * MS, false), None);
    assert!(r.log_line(t0 + 9 * 1000 * MS, true).is_some());
    assert_eq!(r.log_line(t0 + 30 * 1000 * MS, false), None);
}

/// 模型:agent が詰まりの受ける向き。`flows` 本の TCP の送り手は、それぞれ窓 (4 MiB) まで Q1 に詰め込み、
/// agent は一定の速さでバッチずつ取り出す。Q1 は `cap` 個で溢れ、溢れた datagram は末尾で捨てる。10 ms ごとの
/// UDP の datagram の Q1 の待ちの p99 を、CoDel が有る時と無い時で比べる。待ちの標本は製品と同じ
/// [`RxCodel`] の道 (1 ms に 1 回、バッチの最も新しい datagram の受信の時刻) を通す。
///
/// 送り手は CUBIC の TCP-friendly の領域 (短い RTT) の AIMD:落とされた segment に 1 RTT 後に気付いて cwnd を
/// 0.7 倍 (1 RTT に 1 回まで)、それ以外は RTT ごとに 0.53 segment 増やす。経路の RTT は 0.3 ms で、Q1 の外を
/// 飛ぶ量はその分だけ。値はラボの fast の経路の 1 vCPU の agent (約 4 Gbit/s、バッチ約 12 datagram) に合わせた。
/// 模型であって、CUBIC の立方の増え方、slow start、SACK の回復、Q1 の skb の大きさの会計は持たない。
struct Model {
    /// Q1 の中身:(入った時刻、流れの番号、UDP なら `None`)。
    q1: VecDeque<(Duration, Option<usize>)>,
    cap: usize,
    flows: Vec<Flow>,
    rwnd: f64,
    udp_waits: Vec<Duration>,
    udp_lost: usize,
    codel_drops: u64,
    tail_drops: u64,
}

struct Flow {
    cwnd: f64,
    queued: usize,
    /// 落とされた segment に送り手が気付く時刻。
    loss_seen_at: Option<Duration>,
    /// 最後に cwnd を下げた時刻。1 RTT に 1 回だけ下げる。
    last_cut: Option<Duration>,
}

const SEG: f64 = 1368.0;
const RATE_SEG_PER_S: f64 = 4.0e9 / 8.0 / 1420.0;
const BASE_RTT: Duration = Duration::from_micros(300);
const BATCH: usize = 12;

#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the model counts segments in floating point, with small positive values"
)]
impl Model {
    fn new(flows: usize, cap: usize) -> Self {
        let rwnd = f64::from(4u32 << 20) / SEG;
        Self {
            q1: VecDeque::new(),
            cap,
            flows: (0..flows)
                .map(|_| Flow {
                    cwnd: rwnd,
                    queued: 0,
                    loss_seen_at: None,
                    last_cut: None,
                })
                .collect(),
            rwnd,
            udp_waits: Vec::new(),
            udp_lost: 0,
            codel_drops: 0,
            tail_drops: 0,
        }
    }

    /// Q1 の末尾に入れる。満ちていれば捨てて `false`。
    fn enqueue(&mut self, now: Duration, flow: Option<usize>) -> bool {
        if self.q1.len() >= self.cap {
            return false;
        }
        self.q1.push_back((now, flow));
        true
    }

    /// `secs` 秒を回し、`warm` より後の UDP の待ちの p99 を返す。
    fn run(&mut self, mut codel: Option<RxCodel>, secs: u64, warm: Duration) -> Duration {
        let t0 = Instant::now();
        let wall0 = 1_000_000 * 1_000_000_000u64;
        let nanos = |d: Duration| u64::try_from(d.as_nanos()).unwrap();
        let step = Duration::from_secs_f64(BATCH as f64 / RATE_SEG_PER_S);
        let in_path =
            (RATE_SEG_PER_S * BASE_RTT.as_secs_f64() / self.flows.len() as f64).ceil() as usize;
        let segment = tcp(PSH_ACK, 1368, 12);
        let mut now = Duration::ZERO;
        let mut next_udp = Duration::ZERO;
        while now < Duration::from_secs(secs) {
            let front = self.q1.front().map(|(t, _)| *t);
            for f in &mut self.flows {
                if f.loss_seen_at.is_some_and(|t| now >= t) {
                    f.loss_seen_at = None;
                    let rtt = front.map_or(BASE_RTT, |t| now.saturating_sub(t) + BASE_RTT);
                    if f.last_cut.is_none_or(|t| now >= t + rtt) {
                        f.cwnd = (f.cwnd * 0.7).max(2.0);
                        f.last_cut = Some(now);
                    }
                }
            }
            if now >= next_udp {
                next_udp += Duration::from_millis(10);
                if !self.enqueue(now, None) && now > warm {
                    self.udp_lost += 1;
                }
            }
            // 送り手:窓の分まで、流れを順に 1 つずつ Q1 に詰める。溢れた segment は 1 RTT 後に気付く
            let mut sending = true;
            while sending {
                sending = false;
                for k in 0..self.flows.len() {
                    let f = &self.flows[k];
                    // 溢れで落とされた流れは、気付くまで送らない (ACK が来ないので窓が進まない近似)
                    if f.loss_seen_at.is_some()
                        || f.queued + in_path >= f.cwnd.min(self.rwnd) as usize
                    {
                        continue;
                    }
                    sending = true;
                    if self.enqueue(now, Some(k)) {
                        self.flows[k].queued += 1;
                    } else {
                        self.tail_drops += 1;
                        let at = now
                            + front.map_or(Duration::ZERO, |t| now.saturating_sub(t))
                            + BASE_RTT;
                        self.flows[k].loss_seen_at = Some(at);
                    }
                }
                if self.q1.len() >= self.cap {
                    break;
                }
            }
            // agent:1 バッチを取り出す
            let n = BATCH.min(self.q1.len());
            let newest = self.q1.get(n.saturating_sub(1)).map(|(t, _)| *t);
            if let Some(c) = codel.as_mut() {
                c.after_read_at(
                    t0 + now,
                    n,
                    BATCH,
                    || newest.map(|t| wall0 + nanos(t)),
                    || wall0 + nanos(now),
                );
            }
            let sojourn = newest.map_or(Duration::ZERO, |t| now.saturating_sub(t));
            let mut acked = vec![0.0; self.flows.len()];
            for (t, flow) in self.q1.drain(..n) {
                let Some(k) = flow else {
                    if now > warm {
                        self.udp_waits.push(now.saturating_sub(t));
                    }
                    continue;
                };
                self.flows[k].queued -= 1;
                if codel.as_mut().is_some_and(|c| c.codel.take(&segment)) {
                    self.codel_drops += 1;
                    self.flows[k]
                        .loss_seen_at
                        .get_or_insert(now + sojourn + BASE_RTT);
                } else {
                    acked[k] += 1.0;
                }
            }
            // RTT ごとに 0.53 segment (CUBIC の TCP-friendly の増え方)
            for (f, a) in self.flows.iter_mut().zip(acked) {
                f.cwnd += 0.53 * a / f.cwnd.max(1.0);
            }
            now += step;
        }
        self.udp_waits.sort();
        self.udp_waits[self.udp_waits.len() * 99 / 100]
    }
}

/// 模型の結果:CoDel が無いと UDP は窓の和の分を待つ (1 本は 4 MiB で約 8.4 ms、4 本は Q1 が溢れるまで)。
/// 目標 5 ms と 2 ms の CoDel は、落としを始めた後の UDP の待ちの p99 を目標の 1.5 倍以下に抑え、UDP を 1 つも
/// 落とさない。4 本では、溢れの末尾の破棄 (UDP も落ちうる) が CoDel の少ない破棄に替わる。
#[test]
fn the_model_bounds_the_udp_wait_near_the_target() {
    let warm = Duration::from_secs(2);
    // Q1 に入る datagram の数の上限。14 MiB を datagram あたり約 2 KiB の会計で割った程度の値 (模型の仮定)
    let cap = 7000;
    for flows in [1, 4] {
        let mut off = Model::new(flows, cap);
        let p99_off = off.run(None, 10, warm);
        assert!(p99_off >= 8 * MS, "{flows} flows: {p99_off:?}");
        let sent = off.udp_waits.len() + off.udp_lost;
        for target in [5 * MS, 2 * MS] {
            let mut m = Model::new(flows, cap);
            let p99 = m.run(Some(RxCodel::new(target)), 10, warm);
            eprintln!(
                "{flows} flows, target {target:?}: UDP wait p99 {p99:?} (off {p99_off:?}, off lost {} UDP and {} TCP to the full queue), {} TCP drops, {} lost to the full queue",
                off.udp_lost, off.tail_drops, m.codel_drops, m.tail_drops
            );
            assert!(
                p99 <= target + target / 2,
                "{flows} flows, target {target:?}: {p99:?}"
            );
            assert!(m.codel_drops >= 1, "{flows} flows, target {target:?}");
            // UDP は 1 つも落ちない
            assert_eq!(m.udp_lost, 0, "{flows} flows, target {target:?}");
            assert_eq!(m.udp_waits.len(), sent, "{flows} flows, target {target:?}");
        }
    }
}
