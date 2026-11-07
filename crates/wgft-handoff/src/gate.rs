//! 飽和の門。持ち主 (データプレーンのスレッド) が飽和し続けた時だけ開き、Inline に換算した負荷が下がり
//! 続けたら閉じる。値は試作の評価の前に決めた内部の定数で、設定にせず、測定の結果に合わせて動かさない。
//!
//! 入力は起床の始めと終わりの時刻 (駆動の task が既に読んでいる値) と、その起床の送信の相が時間の予算で
//! 切れたか、だけである。時計を読まず、timer も張らない。窓の判定は起床の終わりに窓が過ぎていた時だけ行う。
//!
//! - 閉じている時の負荷:窓の中の、送信の相が予算で切れた起床の時間の和 / 窓の長さ
//! - 開いている時の負荷:窓の中のすべての起床の時間の和と、手伝いが封じて送った時間の和 / 窓の長さ。
//!   Inline ならこれだけ持ち主が使う、という換算である
//! - 開く:負荷が [`OPEN_PERMILLE`] 以上の窓が [`OPEN_WINDOWS`] 続く。閉じる:[`CLOSE_PERMILLE`] 未満の窓が
//!   [`CLOSE_WINDOWS`] 続く。1 回の判定が窓の k 倍の長さなら k 窓ぶんを数える (長い休みで閉じるため)

use std::time::{Duration, Instant};

/// 判定の窓の長さ。
pub const WINDOW: Duration = Duration::from_millis(5);
/// 開く負荷 (千分率)。
pub const OPEN_PERMILLE: u64 = 750;
/// 開くのに要る続いた窓の数。
pub const OPEN_WINDOWS: u32 = 4;
/// 閉じる負荷 (千分率)。この値未満で閉じる。
pub const CLOSE_PERMILLE: u64 = 450;
/// 閉じるのに要る続いた窓の数。
pub const CLOSE_WINDOWS: u32 = 10;

/// 門の状態。
#[derive(Debug, Default)]
pub struct Gate {
    open: bool,
    /// 今の窓の始まり。最初の起床で決まる。
    since: Option<Instant>,
    /// 今の窓で足した起床の時間 (ns)。
    busy_ns: u64,
    /// 開いた時と窓の終わりに読んだ、手伝いの仕事の累計 (ns)。
    helper_mark: u64,
    /// 開く (閉じている時) か閉じる (開いている時) 条件を満たして続いた窓の数。
    streak: u32,
    /// 切り替わった数。
    transitions: u64,
    /// 開いていた時間の和 (ns、今開いている分を除く) と、今開いているならその時刻。
    open_ns: u64,
    opened_at: Option<Instant>,
}

impl Gate {
    /// 閉じた門。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// `now` までに開いていた時間の和。
    #[must_use]
    pub fn open_time(&self, now: Instant) -> Duration {
        let current = self
            .opened_at
            .map_or(Duration::ZERO, |at| now.saturating_duration_since(at));
        Duration::from_nanos(self.open_ns) + current
    }

    /// これまでに切り替わった数。
    #[must_use]
    pub fn transitions(&self) -> u64 {
        self.transitions
    }

    /// 1 回の起床の終わりに呼ぶ。`start` と `end` はその起床の始めと最後に読んだ時刻、`cut` は送信の相が
    /// 時間の予算で切れて送るものが残ったか。`helper_busy` は手伝いの仕事の累計 (ns) を読み、開いている
    /// 時の窓の終わりと、開く時だけ呼ぶ。切り替わった時だけ新しい状態を返す。
    pub fn end_wake(
        &mut self,
        start: Instant,
        end: Instant,
        cut: bool,
        helper_busy: impl Fn() -> u64,
    ) -> Option<bool> {
        let since = *self.since.get_or_insert(start);
        if self.open || cut {
            self.busy_ns = self
                .busy_ns
                .saturating_add(nanos(end.saturating_duration_since(start)));
        }
        let elapsed = nanos(end.saturating_duration_since(since));
        let window = nanos(WINDOW);
        if elapsed < window {
            return None;
        }
        let helper = if self.open {
            let h = helper_busy();
            let d = h.saturating_sub(self.helper_mark);
            self.helper_mark = h;
            d
        } else {
            0
        };
        let load = self.busy_ns.saturating_add(helper).saturating_mul(1000) / elapsed;
        let windows = u32::try_from(elapsed / window).unwrap_or(u32::MAX);
        self.since = Some(end);
        self.busy_ns = 0;
        let (met, need) = if self.open {
            (load < CLOSE_PERMILLE, CLOSE_WINDOWS)
        } else {
            (load >= OPEN_PERMILLE, OPEN_WINDOWS)
        };
        if !met {
            self.streak = 0;
            return None;
        }
        self.streak = self.streak.saturating_add(windows);
        if self.streak < need {
            return None;
        }
        self.streak = 0;
        self.open = !self.open;
        self.transitions += 1;
        if self.open {
            self.opened_at = Some(end);
        } else if let Some(at) = self.opened_at.take() {
            self.open_ns = self
                .open_ns
                .saturating_add(nanos(end.saturating_duration_since(at)));
        }
        if self.open {
            self.helper_mark = helper_busy();
        }
        Some(self.open)
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a load model in floating point"
)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const US: Duration = Duration::from_micros(1);

    /// 持ち主の模型。負荷 `load` (0 から 1) で Inline の持ち主が使う割合を決め、その仕事を `wake` の長さの起床に
    /// 分ける。閉じている時は起床が予算で切れるのは飽和に近い時だけで、その割合を `cut(load)` が決める。
    /// 開いている時は、持ち主と手伝いの仕事の和が Inline の `(1 - eps)` 倍と見る (3.3 節の ε)。
    struct Sim {
        gate: Gate,
        t: Instant,
        helper: Cell<u64>,
        seed: u64,
    }

    impl Sim {
        fn new() -> Self {
            Self {
                gate: Gate::new(),
                t: Instant::now(),
                helper: Cell::new(0),
                seed: 0x9e37_79b9_7f4a_7c15,
            }
        }

        fn rand(&mut self) -> f64 {
            // xorshift。試験の再現のための決まった列
            self.seed ^= self.seed << 13;
            self.seed ^= self.seed >> 7;
            self.seed ^= self.seed << 17;
            (self.seed >> 11) as f64 / (1u64 << 53) as f64
        }

        /// `dur` の間、負荷 `load` を流す。切り替わった数を返す。
        fn run(&mut self, dur: Duration, load: impl Fn(f64) -> f64, eps: f64) -> u32 {
            let end = self.t + dur;
            let begin = self.t;
            let mut flips = 0;
            while self.t < end {
                let at = (self.t - begin).as_secs_f64();
                let l = load(at).max(0.0);
                // 1 回の起床は 20 から 70 µs の仕事。間の休みは負荷から決める
                let work = Duration::from_secs_f64((20.0 + 50.0 * self.rand()) * 1e-6);
                let (owner_work, cut) = if self.gate.is_open() {
                    // 開いた持ち主は Inline の約 4 割の仕事、残りは手伝い
                    let total = work.as_secs_f64() * (1.0 - eps);
                    self.helper
                        .set(self.helper.get() + (total * 0.6 * 1e9) as u64);
                    (Duration::from_secs_f64(total * 0.4), false)
                } else {
                    // 予算で切れる起床の割合は飽和に近づくと急に増える (模型の仮定、c(λ) ≤ w(λ))
                    let p_cut = ((l - 0.6) / 0.3).clamp(0.0, 1.0);
                    (work, self.rand() < p_cut)
                };
                let start = self.t;
                self.t += owner_work;
                let helper = &self.helper;
                if self
                    .gate
                    .end_wake(start, self.t, cut, || helper.get())
                    .is_some()
                {
                    flips += 1;
                }
                // 負荷 l の持ち主:仕事 / (仕事 + 休み) = l。飽和 (l ≥ 1) では休みが無い
                let busy_share = if self.gate.is_open() {
                    (l * 0.4 * (1.0 - eps)).min(1.0)
                } else {
                    l.min(1.0)
                };
                let idle = if busy_share >= 1.0 {
                    Duration::ZERO
                } else {
                    owner_work.mul_f64((1.0 - busy_share) / busy_share.max(1e-4))
                };
                self.t += idle.min(Duration::from_secs(1));
            }
            flips
        }
    }

    #[test]
    fn light_and_medium_load_never_open() {
        for load in [0.001, 0.01, 0.1, 0.25, 0.5, 0.6, 0.7] {
            let mut s = Sim::new();
            assert_eq!(
                s.run(Duration::from_secs(10), |_| load, 0.0),
                0,
                "load {load}"
            );
            assert!(!s.gate.is_open());
        }
        // 軽い負荷の中の 5 ms の山 (飽和) は開かない
        let mut s = Sim::new();
        let bursty = |t: f64| if t.fract() < 0.005 { 1.2 } else { 0.05 };
        assert_eq!(s.run(Duration::from_secs(10), bursty, 0.0), 0);
    }

    #[test]
    fn sustained_saturation_opens_and_the_end_of_it_closes() {
        let mut s = Sim::new();
        assert_eq!(s.run(Duration::from_millis(100), |_| 1.5, 0.0), 1);
        assert!(s.gate.is_open());
        // 負荷が消えると閉じる
        assert_eq!(s.run(Duration::from_millis(200), |_| 0.1, 0.0), 1);
        assert!(!s.gate.is_open());
        // 開いたまま通信が止まり (起床が無い)、また軽い負荷で始まった時も閉じる
        assert_eq!(s.run(Duration::from_millis(100), |_| 1.5, 0.0), 1);
        let start = s.t + Duration::from_millis(500);
        s.t = start;
        assert_eq!(
            s.gate
                .end_wake(start, start + 30 * US, false, || s.helper.get()),
            Some(false)
        );
    }

    /// 3.3 節:決まった負荷では、ε < 0.30 なら高々 1 回しか切り替わらない。負荷の格子と ε の格子で
    /// 10 秒ずつ流す。
    #[test]
    fn a_fixed_load_switches_at_most_once() {
        for i in 0..=30 {
            let load = f64::from(i) * 0.05;
            for eps in [0.0, 0.1, 0.2, 0.29] {
                let mut s = Sim::new();
                let flips = s.run(Duration::from_secs(10), |_| load, eps);
                assert!(flips <= 1, "load {load} eps {eps}: {flips} switches");
            }
        }
    }

    /// 負荷が境を揺れても、切り替わりは 70 ms に 1 往復を超えない。
    #[test]
    fn a_swinging_load_switches_at_most_once_per_70_ms_each_way() {
        for period_ms in [1.0, 10.0, 30.0, 100.0, 500.0] {
            let mut s = Sim::new();
            let swing = move |t: f64| {
                if (t * 1000.0 / period_ms).fract() < 0.5 {
                    1.4
                } else {
                    0.0
                }
            };
            let secs = 10.0;
            let flips = s.run(Duration::from_secs_f64(secs), swing, 0.0);
            let max = (secs / 0.070 * 2.0).ceil() as u32;
            assert!(
                flips <= max,
                "period {period_ms} ms: {flips} switches > {max}"
            );
        }
    }

    #[test]
    fn the_window_counts_only_cut_wakes_while_closed() {
        let mut g = Gate::new();
        let t0 = Instant::now();
        // 窓の 100% が起床だが、予算で切れていなければ数えない
        let mut t = t0;
        for _ in 0..1000 {
            assert_eq!(g.end_wake(t, t + 50 * US, false, || 0), None);
            t += 50 * US;
        }
        assert!(!g.is_open());
        // 切れた起床だけで 20 ms 埋めると開く
        let mut opened = false;
        for _ in 0..400 {
            if g.end_wake(t, t + 50 * US, true, || 0) == Some(true) {
                opened = true;
            }
            t += 50 * US;
        }
        assert!(opened);
        assert_eq!(g.transitions(), 1);
        assert!(g.open_time(t) < WINDOW, "{:?}", g.open_time(t));
        assert_eq!(
            g.open_time(t + WINDOW).checked_sub(g.open_time(t)),
            Some(WINDOW)
        );
    }
}
