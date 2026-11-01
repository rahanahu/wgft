//! `replay` の target:3 節の要求の列を `wgstack-dut` の adapter に流します (`docs/design/v2/test-tooling.md`
//! の 6 節)。種は Go の wgstack の記録の要求の列です。
//!
//! 入力の形:
//!
//! 1. 1 byte の印。`INJECT` の n 番目の packet (要求をまたいで数えます) は、印の bit `n % 8` が立っていれば
//!    IPv4 の header の checksum と、断片でない TCP、UDP、ICMP の checksum を直してから渡します。変異で checksum
//!    が壊れただけの入力が入口で落ちるのを避けるためで、bit の立たない packet は壊れたまま渡します
//! 2. 要求の frame (長さ、種類、本体) の列。壊れた frame とその後は捨てます
//!
//! 最初の要求が `HELLO` なら、その輻輳の制御、boost の方針、アドレス、MTU、種で核を作ります。上限の組は使わず、
//! 速さのために小さな表 ([`super::fuzz_limits`]) にします。核がまだ持たない選択と範囲の外の値は、持つ選択と
//! 既定の値に替えます。最初が `HELLO` でなければ既定の `HELLO` で作ります。
//!
//! 各要求の後に不変条件を確かめ、最後に核を閉じて会計が 0 に戻ることを確かめます。adapter が口の誤りとする
//! 要求 (知らない handle など) は飛ばします。

use std::time::Duration;

use wgft_tcpharness::dut::{DutError, answer};
use wgft_tcpharness::frame::{self, Clock, Hello, Msg, VERSION};
use wgft_wgstack::{BoostPolicy, Config, Congestion, MAX_MTU, MIN_MTU};

use super::net::{DUT, MTU, fuzz_limits, put_budget, take_budget};
use crate::dut::WgstackDut;
use crate::rec::Recording;

/// 1 つの入力で流す要求の上限です。
const MAX_REQUESTS: usize = 2000;
/// 1 つの `ADVANCE` で進める時間の上限です。記録の待ちは長くても数分です。
const MAX_ADVANCE: Duration = Duration::from_secs(3600);
/// 1 つの `POLL` で引き取る packet の上限です。
const MAX_POLL: u32 = 4096;

/// 入力の要求の frame を読みます。
struct Frames<'a>(&'a [u8]);

impl Iterator for Frames<'_> {
    type Item = Msg;

    fn next(&mut self) -> Option<Msg> {
        let (hdr, rest) = self.0.split_first_chunk::<4>()?;
        let n = u32::from_le_bytes(*hdr) as usize;
        if n == 0 || n > rest.len() {
            self.0 = &[];
            return None;
        }
        let (f, rest) = rest.split_at(n);
        self.0 = rest;
        let m = Msg::decode(f[0], &f[1..]).ok();
        if m.is_none() {
            self.0 = &[];
        }
        m
    }
}

fn default_hello() -> Hello {
    Hello {
        version: VERSION,
        clock: Clock::Fake,
        addr: DUT,
        mtu: u32::try_from(MTU).expect("the MTU fits"),
        seed: [7; frame::SEED_LEN],
        limits: Vec::new(),
        boost: frame::Boost::Never,
        congestion: frame::Congestion::NewReno,
    }
}

/// 核がこの選択を持たないかです。既定の設定から 1 つだけ変えた設定で見るので、誤りは選択によります。
fn unsupported(c: &Config) -> bool {
    c.validate().is_err()
}

/// 核が作れる `HELLO` に直します。
fn sanitize(mut h: Hello) -> Hello {
    h.version = VERSION;
    h.clock = Clock::Fake;
    h.limits.clear();
    if !(MIN_MTU..=MAX_MTU).contains(&usize::try_from(h.mtu).unwrap_or(usize::MAX)) {
        h.mtu = u32::try_from(MTU).expect("the MTU fits");
    }
    let base = Config::new(DUT, MTU);
    if matches!(h.congestion, frame::Congestion::Cubic)
        && unsupported(&Config {
            congestion: Congestion::Cubic,
            ..base
        })
    {
        h.congestion = frame::Congestion::NewReno;
    }
    let boost = match h.boost {
        frame::Boost::OnDemand => BoostPolicy::OnDemand,
        frame::Boost::AtAccept => BoostPolicy::AtAccept,
        frame::Boost::Never => BoostPolicy::Never,
    };
    if unsupported(&Config { boost, ..base }) {
        h.boost = frame::Boost::Never;
    }
    h
}

/// 1 つの packet の checksum を直します。短すぎる packet と IPv4 でない packet はそのままです。
fn fix_checksums(p: &mut [u8]) {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    if ihl < 20 || ihl > p.len() {
        return;
    }
    p[10] = 0;
    p[11] = 0;
    let sum = !fold(sum16(0, &p[..ihl]));
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    let total = usize::from(u16::from_be_bytes([p[2], p[3]])).min(p.len());
    let frag = u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0;
    if frag || total < ihl {
        return;
    }
    let proto = p[9];
    let (src, dst) = ([p[12], p[13], p[14], p[15]], [p[16], p[17], p[18], p[19]]);
    let t = &mut p[ihl..total];
    let at = match proto {
        6 if t.len() >= 20 => 16,
        17 if t.len() >= 8 => 6,
        1 if t.len() >= 4 => 2,
        _ => return,
    };
    t[at] = 0;
    t[at + 1] = 0;
    let mut acc = 0;
    if proto != 1 {
        acc = sum16(acc, &src);
        acc = sum16(acc, &dst);
        acc += u32::from(proto);
        acc += u32::try_from(t.len()).expect("below 64 KiB");
    }
    let mut sum = !fold(sum16(acc, t));
    if proto == 17 && sum == 0 {
        sum = 0xffff;
    }
    t[at..at + 2].copy_from_slice(&sum.to_be_bytes());
}

fn sum16(mut acc: u32, b: &[u8]) -> u32 {
    let (pairs, odd) = b.as_chunks::<2>();
    for w in pairs {
        acc += u32::from(u16::from_be_bytes(*w));
    }
    if let [x] = odd {
        acc += u32::from(*x) << 8;
    }
    // 長い packet でも溢れないよう、途中で畳む
    (acc & 0xffff) + (acc >> 16)
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    u16::try_from(acc).expect("folded")
}

/// 記録 `rec` の要求の列から `replay` の種を作ります。印はすべての packet の checksum を直す 0xff で、要求は
/// 合わせて `max` byte を超えない所までの frame です。
pub fn replay_seed(rec: &Recording, max: usize) -> Result<Vec<u8>, String> {
    let mut out = vec![0xff];
    for (q, _) in rec.pairs()? {
        if out.len() + q.bytes.len() > max {
            break;
        }
        out.extend_from_slice(q.bytes);
    }
    Ok(out)
}

/// `replay` の target の 1 回分です。
pub fn replay(data: &[u8]) {
    let Some((&mask, rest)) = data.split_first() else {
        return;
    };
    let mut frames = Frames(rest).peekable();
    let hello = match frames.next_if(|m| matches!(m, Msg::Hello(_))) {
        Some(Msg::Hello(h)) => sanitize(h),
        _ => default_hello(),
    };
    let mut budget = take_budget();
    let mut dut = match WgstackDut::for_fuzz(&hello, fuzz_limits(), budget) {
        Ok(d) => d,
        Err((_, b)) => {
            // アドレスが核の受け付けない値なら、既定のアドレスで作り直す
            budget = b;
            let h = Hello { addr: DUT, ..hello };
            match WgstackDut::for_fuzz(&h, fuzz_limits(), budget) {
                Ok(d) => d,
                Err((e, b)) => {
                    put_budget(b);
                    panic!("make the stack from {h:?}: {e}");
                }
            }
        }
    };
    let mut packets = 0usize;
    for mut msg in frames.take(MAX_REQUESTS) {
        match &mut msg {
            Msg::Hello(_) | Msg::RtoAt { .. } | Msg::ConnSocket { .. } => continue,
            Msg::Inject(ps) => {
                for p in ps.iter_mut() {
                    if mask >> (packets % 8) & 1 != 0 {
                        fix_checksums(p);
                    }
                    packets += 1;
                }
            }
            Msg::Advance(d) => *d = (*d).min(MAX_ADVANCE),
            Msg::Poll { max } => *max = (*max).min(MAX_POLL),
            _ => {}
        }
        // engine の誤りは応答の 1 つで、口の誤り (知らない handle など) は飛ばす
        let _: Result<Msg, DutError> = answer(&mut dut, &msg);
        if let Err(e) = dut.check_invariants() {
            panic!("invariant after {}: {e}", msg.kind());
        }
    }
    let closed = dut.close_stack();
    let held = closed.held;
    put_budget(closed.budget);
    assert!(held.is_zero(), "after close {held:?}");
}
