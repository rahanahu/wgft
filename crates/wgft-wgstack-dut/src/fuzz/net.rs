//! 手で進める時計の核と、トンネルの側の出入り口です。Go の試験の補助 `testNet` に当たります。

use std::cell::{Cell, RefCell};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::Ipv4Addr;
use std::time::Duration;

use wgft_tcpharness::ip::{self, PROTO_TCP};
use wgft_tcpharness::packet::{self, Segment};
use wgft_wgstack::{Bound, Budget, Config, Held, Hook, Limits, Spare, Stack, Time, TouchedCheck};

/// DUT のアドレスです。Go の試験の `dutAddr` と同じです。
pub const DUT: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
/// 相手のアドレスです。Go の試験の `peerAddr` と同じです。
pub const PEER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
/// トンネルの MTU です。Go の試験の `testMTU` と同じです。
pub const MTU: usize = 1420;

/// 1 回の `drain` が引き取る packet の上限です。Go の `testNet.drain` と同じく、超えたら送り続けたとみなします。
const DRAIN_MAX: usize = 100_000;

/// Go の `smallLimits` です。上界の試験が表の満ちる所を見るための小さな表です。
pub fn small_limits() -> Limits {
    Limits {
        max_flows: 16,
        accept_queue: 8,
        syn_rows: 16,
        tw_rows: 32,
        ctl_slots: 16,
        ..Limits::default()
    }
}

/// Go の `fuzzLimits` です。`small_limits` から、FuzzCore が触れない UDP の枠と再組み立ての表も小さくした
/// 値です。
pub fn fuzz_limits() -> Limits {
    Limits {
        max_flows: 8,
        accept_queue: 4,
        frag_entries: 4,
        frag_pieces: 8,
        udp_rx_datagrams: 8,
        udp_tx_datagrams: 8,
        ..small_limits()
    }
}

/// 各段の確かめの形です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// 前の段から書き換えた接続の枠だけを確かめます ([`Stack::check_invariants_touched`])。fuzz の既定です。
    Touched,
    /// すべての枠を確かめ、数をすべて数え直します ([`Stack::check_invariants`])。
    Full,
    /// 両方を確かめ、答え (誤りの文を含みます) が違えば panic します。2 つが同じ答えを返すことの試験が使います。
    Both,
}

/// 核の作り方と確かめの形です。スレッドごとに持ち、[`set_options`] で変えます。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub check: Check,
    /// 前の入力の核のポートの数の行を持つ表を、作成の時の値に戻して使い回します ([`Stack::close_keeping`])。
    pub reuse: bool,
    /// 外から見える出力 (送った packet、各段の保持と事象の数と次の起床の時刻、最後の会計) を hash に畳み込み、
    /// [`last_digest`] で返します。使い回した核と新しい核が同じ入力に同じ出力を返すことの試験が使います。
    pub digest: bool,
}

impl Options {
    /// `Net` の既定です。書き換えた枠だけを確かめ、核を毎回新しく作り、hash を取りません。保持の試験のように
    /// 核を作った後の確保を数える試験が、前の核の表を数えに入れないためです。
    pub const DEFAULT: Self = Self {
        check: Check::Touched,
        reuse: false,
        digest: false,
    };

    /// cargo-fuzz の target が使う形です。書き換えた枠だけを確かめ、表を使い回し、hash を取りません。target の
    /// 初期化が [`set_options`] で選びます。
    pub const FUZZ: Self = Self {
        check: Check::Touched,
        reuse: true,
        digest: false,
    };
}

thread_local! {
    /// 入力から入力へ渡す boost の枠の集まりです。
    static BUDGET: RefCell<Option<Budget>> = const { RefCell::new(None) };
    /// 入力から入力へ渡す、作成の時の値に戻したポートの数の行を持つ表です。
    static SPARE: RefCell<Option<Spare>> = const { RefCell::new(None) };
    static OPTIONS: Cell<Options> = const { Cell::new(Options::DEFAULT) };
    static DIGEST: Cell<u64> = const { Cell::new(0) };
}

/// このスレッドの核の作り方と確かめの形を変え、前の値を返します。
pub fn set_options(o: Options) -> Options {
    OPTIONS.replace(o)
}

/// このスレッドで最後に閉じた核の出力の hash です。[`Options::digest`] が偽なら 0 です。
pub fn last_digest() -> u64 {
    DIGEST.get()
}

/// このスレッドが次の核に渡す表を取り出します。試験が、閉じた核の表が作成の時の値に戻ったかを確かめます。
pub fn take_spare() -> Option<Spare> {
    SPARE.with_borrow_mut(Option::take)
}

/// 表を、このスレッドの次の核に渡します。[`take_spare`] で取り出して確かめた表を戻すのに使います。
pub fn put_spare(s: Spare) {
    SPARE.with_borrow_mut(|slot| *slot = Some(s));
}

pub(crate) fn take_budget() -> Budget {
    BUDGET
        .with_borrow_mut(Option::take)
        .unwrap_or_else(|| Budget::new().expect("allocate the boost budget"))
}

pub(crate) fn put_budget(b: Budget) {
    assert_eq!(
        b.lent(),
        0,
        "a closed stack hands back a budget with slots lent"
    );
    BUDGET.with_borrow_mut(|slot| *slot = Some(b));
}

/// 手で進める時計の核です。時刻は核を作ってからの ns で、Go の `ManualClock` と同じ値です。
///
/// 各段の確かめは [`Options::check`] の形で行います。
#[derive(Debug)]
pub struct Net<H: Hook> {
    stack: Option<Stack<H>>,
    now: u64,
    buf: Vec<u8>,
    limits: Limits,
    bound: Bound,
    slots: usize,
    options: Options,
    touched: TouchedCheck,
    digest: DefaultHasher,
}

impl<H: Hook> Net<H> {
    /// 表の大きさ `limits` の核を、Go の試験と同じ固定の種 (64 byte の 7) で作ります。[`Options::reuse`] が真なら、
    /// 前の入力の核の表を使い回します。
    pub fn new(config: Config, hook: H) -> Self {
        let options = OPTIONS.get();
        let budget = take_budget();
        let slots = budget.slots();
        let limits = config.limits;
        let spare = if options.reuse {
            take_spare().unwrap_or_default()
        } else {
            Spare::new()
        };
        let mut stack = match Stack::new_reusing(config, budget, spare, &[7; 64], hook) {
            Ok(s) => s,
            Err(e) => {
                let kind = e.kind();
                put_budget(e.into_budget());
                panic!("make the stack: {kind:?}");
            }
        };
        let bound = stack.bound();
        // 数えの控えは作成の時に作ります。保持の試験は核を作った後の確保をすべて核の保持と比べるためです。
        let mut touched = TouchedCheck::new();
        if options.check != Check::Full
            && let Err(e) = stack.check_invariants_touched(&mut touched)
        {
            panic!("invariant of a new stack: {e}");
        }
        Self {
            stack: Some(stack),
            now: 0,
            buf: vec![0; 65536],
            limits,
            bound,
            slots,
            options,
            touched,
            digest: DefaultHasher::new(),
        }
    }

    /// 既定の設定に表の大きさ `limits` を入れた設定です。
    pub fn config(limits: Limits) -> Config {
        Config {
            limits,
            ..Config::new(DUT, MTU)
        }
    }

    /// 核です。
    pub fn stack(&mut self) -> &mut Stack<H> {
        self.stack.as_mut().expect("the stack is open")
    }

    /// 今の時刻です。
    pub fn now(&self) -> Time {
        Time::from_nanos(self.now)
    }

    /// 核の上界です。
    pub fn bound(&self) -> Bound {
        self.bound
    }

    /// boost の枠の数 (B) です。
    pub fn slots(&self) -> usize {
        self.slots
    }

    /// 核の今の保持です。
    pub fn held(&self) -> Held {
        self.stack.as_ref().expect("the stack is open").held()
    }

    /// トンネルから packet を 1 つ入れます。
    pub fn write(&mut self, pkt: &[u8]) {
        let now = self.now();
        self.stack().handle_packet(now, pkt);
    }

    /// 相手の segment を入れます。
    pub fn inject(&mut self, s: &Segment) {
        self.write(&s.marshal());
    }

    /// 時計を `d` 進め、期限の来たタイマーを動かします。Go の `testNet.advance` と同じく時間 0 でも動かします。
    pub fn advance(&mut self, d: Duration) {
        self.now = self
            .now
            .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let now = self.now();
        self.stack().handle_timeout(now);
    }

    /// 核が今送るものをすべて引き取り、TCP の segment にして返します。壊れた packet、MTU を超える packet、
    /// 終わらない出力は panic です。TCP でない packet は `others` に入れます。
    pub fn drain_into(&mut self, segs: &mut Vec<Segment>, others: &mut Vec<Vec<u8>>) {
        let now = self.now();
        for _ in 0..DRAIN_MAX {
            let stack = self.stack.as_mut().expect("the stack is open");
            let Some(n) = stack.poll_transmit(now, &mut self.buf) else {
                return;
            };
            let pkt = &self.buf[..n];
            assert!(n <= MTU, "a packet of {n} bytes exceeds the MTU {MTU}");
            if self.options.digest {
                pkt.hash(&mut self.digest);
            }
            let ip = ip::parse_ipv4(pkt)
                .unwrap_or_else(|e| panic!("the stack sent a bad IPv4 packet: {e}"));
            if ip.proto != PROTO_TCP {
                others.push(pkt.to_vec());
                continue;
            }
            let seg = packet::parse(pkt)
                .unwrap_or_else(|e| panic!("the stack sent a bad TCP segment: {e}"));
            segs.push(seg);
        }
        panic!("the stack kept sending past {DRAIN_MAX} packets in one drain");
    }

    /// 核が今送る packet を `max` まで引き取り、TCP の segment を返します。TCP でない packet は数に入れて捨てます。
    pub fn poll_some(&mut self, max: usize) -> Vec<Segment> {
        let now = self.now();
        let mut segs = Vec::new();
        for _ in 0..max {
            let stack = self.stack.as_mut().expect("the stack is open");
            let Some(n) = stack.poll_transmit(now, &mut self.buf) else {
                break;
            };
            let pkt = &self.buf[..n];
            assert!(n <= MTU, "a packet of {n} bytes exceeds the MTU {MTU}");
            if self.options.digest {
                pkt.hash(&mut self.digest);
            }
            if let Ok(seg) = packet::parse(pkt) {
                segs.push(seg);
            }
        }
        segs
    }

    /// 核が今送る TCP の segment をすべて返します。
    pub fn drain(&mut self) -> Vec<Segment> {
        let mut segs = Vec::new();
        let mut others = Vec::new();
        self.drain_into(&mut segs, &mut others);
        segs
    }

    /// 核の不変条件と、保持が表の大きさと上界の内にあることを確かめます。Go の `checkHeld` のうち、公開の
    /// API で見える部分です。不変条件は [`Options::check`] の形で確かめます。
    pub fn check(&mut self) {
        let stack = self.stack.as_mut().expect("the stack is open");
        let result = match self.options.check {
            Check::Touched => stack.check_invariants_touched(&mut self.touched),
            Check::Full => stack.check_invariants(),
            Check::Both => {
                let full = stack.check_invariants();
                let touched = stack.check_invariants_touched(&mut self.touched);
                assert_eq!(
                    touched, full,
                    "the touched-slot check and the full check disagree"
                );
                full
            }
        };
        if let Err(e) = result {
            panic!("invariant: {e}");
        }
        if self.options.digest {
            let h = stack.held();
            format!("{h:?}").hash(&mut self.digest);
            format!("{:?}", stack.stats()).hash(&mut self.digest);
            format!("{:?}", stack.poll_timeout()).hash(&mut self.digest);
        }
        let h = stack.held();
        let l = &self.limits;
        assert!(
            h.syn_rows <= l.syn_rows
                && h.tw_rows <= l.tw_rows
                && h.accept_queued <= l.accept_queue
                && h.ctl_queued <= l.ctl_slots
                && h.conns <= l.conns(),
            "a table exceeds its size: {h:?} limits {l:?}"
        );
        let buffers = (h.chunk_bytes + h.record_bytes + h.interval_bytes) as u64;
        let b = &self.bound;
        assert!(
            buffers <= b.floor_conn + b.boost,
            "held buffers {buffers} exceed the bound {} {h:?}",
            b.floor_conn + b.boost
        );
        assert!(
            h.frag_bytes as u64 <= b.frag,
            "reassembly holds {} bytes over its bound {}",
            h.frag_bytes,
            b.frag
        );
        assert!(
            h.udp_rx_bytes as u64 <= b.udp_rx
                && h.udp_tx_bytes as u64 <= b.udp_tx
                && h.udp_rx_datagrams <= l.udp_rx_datagrams
                && h.udp_tx_datagrams <= l.udp_tx_datagrams,
            "UDP beyond its budget: {h:?} bound {b:?} limits {l:?}"
        );
        assert!(
            h.boosted <= self.slots,
            "{} boosted connections with {} boost slots",
            h.boosted,
            self.slots
        );
    }

    /// 核を閉じ、最後の会計がすべて 0 であることを確かめ、`Budget` を次の入力のために取り戻します。
    /// [`Options::reuse`] が真なら、ポートの数の行を持つ表も作成の時の値に戻して取り戻します。
    pub fn finish(mut self) -> Held {
        let now = self.now();
        let stack = self.stack.take().expect("the stack is open");
        if self.options.digest {
            format!("{:?}", stack.stats()).hash(&mut self.digest);
            format!("{:?}", self.bound).hash(&mut self.digest);
        }
        let (closed, spare) = stack.close_keeping(now);
        let held = closed.held;
        put_budget(closed.budget);
        if self.options.reuse {
            put_spare(spare);
        }
        DIGEST.set(if self.options.digest {
            self.digest.finish()
        } else {
            0
        });
        assert!(held.is_zero(), "after close {held:?}");
        held
    }
}
