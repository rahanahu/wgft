//! SYN cookie (RFC 4987 3.6、wgstack-rs.md の「SYN cookie」)。
//!
//! 待ち受けが握手の途中の表の自分の分 (N_syn の半分) を使い切ったか、表の全体が満杯の時だけ、行を作らずに
//! SYN-ACK を返します。握手の途中の状態は SYN-ACK の ISN と TSval に入れ、最後の ACK の確認番号と TSecr から
//! 取り戻します。凍結した Go の wgstack は SYN cookie を持たないので、Go と意図して違う所です。
//!
//! ISN (32 bit) の並びは上位から MAC 27 bit、時刻の数の下位 2 bit、MSS の表の番号 3 bit です。MAC は鍵付きの
//! SipHash-2-4 で、4 つ組、相手の ISN、時刻の数、相手の option (MSS の番号、timestamp、窓の scale、SACK) を
//! 覆います。timestamp を示した相手には、窓の scale と SACK の許可を TSval の下位 5 bit に入れます。timestamp を
//! 示さない相手には窓の scale と SACK を返しません。
//!
//! cookie の SYN-ACK は制御の輪から送り、核は SYN ごとに何も確保せず、行も持ちません。

use super::listen::Listener;
use super::syn::SynRow;
use super::{SEC, TW_TIMEOUT, ts_clock};
use crate::siphash::SipKey;
use crate::stack::Shared;
use crate::stack::shared::LogKind;
use crate::wire::{FLAG_ACK, FLAG_SYN, OptWriter, Segment, TcpHeader, Tuple};

/// 時刻の数が 1 進む間隔です。cookie は作った数と次の数の間だけ通るので、寿命は 30 秒から 60 秒の手前です。
pub(crate) const COOKIE_PERIOD: i64 = 30 * SEC;

// 寿命の上限 (2 周期) は TIME_WAIT の長さ以下です。自分が TIME_WAIT を経て閉じた接続の最後の ACK の写しは、
// cookie が通る間ずっと TIME_WAIT の行に当たり、新しい接続を作りません。
const _: () = assert!(2 * COOKIE_PERIOD <= TW_TIMEOUT);

/// MSS の表です。相手の MSS 以下で最も大きい値を選びます。相手が示した値との差は送る segment が小さくなる
/// だけです。
pub(crate) const MSS_TABLE: [u16; 8] = [536, 1200, 1280, 1340, 1380, 1400, 1440, 1460];

/// ISN の MAC の bit の数です。
const MAC_BITS: u32 = 27;
/// TSval に入れる option の bit です。下位 4 bit は窓の scale (無ければ 15)、bit 4 は SACK の許可です。
const TS_OPT_MASK: u32 = 0x1f;
const TS_NO_WSCALE: u32 = 0xf;
const TS_SACK: u32 = 0x10;

/// cookie に入れる相手の option です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CookieOpts {
    pub(crate) mss_idx: u8,
    pub(crate) ts_ok: bool,
    /// 相手の窓の scale です。timestamp の無い相手は常に `None` です。
    pub(crate) wscale: Option<u8>,
    /// timestamp の無い相手は常に偽です。
    pub(crate) sack_ok: bool,
}

impl CookieOpts {
    /// SYN の option から入れる値を決めます。
    pub(crate) fn from_syn(seg: &Segment<'_>) -> Self {
        let mss = seg.opt.mss.filter(|&m| m != 0).unwrap_or(536);
        let mss_idx = MSS_TABLE.iter().rposition(|&m| m <= mss).unwrap_or(0);
        let ts_ok = seg.opt.ts.is_some();
        Self {
            mss_idx: u8::try_from(mss_idx).unwrap_or(0),
            ts_ok,
            wscale: seg.opt.wscale.filter(|_| ts_ok),
            sack_ok: ts_ok && seg.opt.sack_ok,
        }
    }

    /// TSval の下位 5 bit に入れる値です。
    fn ts_bits(self) -> u32 {
        self.wscale.map_or(TS_NO_WSCALE, u32::from) | if self.sack_ok { TS_SACK } else { 0 }
    }

    /// TSecr の下位 5 bit から取り戻します。15 は窓の scale が無いことで、ほかの 14 を超える値は MAC が断ります。
    fn from_ts_bits(mss_idx: u8, bits: u32) -> Self {
        let ws = bits & TS_NO_WSCALE;
        Self {
            mss_idx,
            ts_ok: true,
            wscale: (ws != TS_NO_WSCALE).then(|| u8::try_from(ws).unwrap_or(0)),
            sack_ok: bits & TS_SACK != 0,
        }
    }

    /// MAC が覆う 1 語です。
    fn word(self) -> u32 {
        u32::from(self.mss_idx)
            | u32::from(self.ts_ok) << 3
            | u32::from(self.wscale.is_some()) << 4
            | u32::from(self.wscale.unwrap_or(0)) << 5
            | u32::from(self.sack_ok) << 9
    }
}

/// 時刻 `now` (ns) の時刻の数です。
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the counter wraps; only its difference within two periods matters"
)]
pub(crate) fn counter(now: i64) -> u32 {
    (now / COOKIE_PERIOD) as u32
}

/// MAC の上位 27 bit を返します。
#[expect(
    clippy::cast_possible_truncation,
    reason = "the cookie keeps the low bits of the hash"
)]
fn mac(key: SipKey, tup: Tuple, irs: u32, count: u32, o: CookieOpts) -> u32 {
    let h = key.sum3(
        u64::from(tup.laddr) | u64::from(tup.raddr) << 32,
        u64::from(tup.lport) | u64::from(tup.rport) << 16 | u64::from(irs) << 32,
        u64::from(count) | u64::from(o.word()) << 32,
    );
    (h as u32) & ((1 << MAC_BITS) - 1)
}

/// cookie の ISN を作ります。
pub(crate) fn make(key: SipKey, tup: Tuple, irs: u32, count: u32, o: CookieOpts) -> u32 {
    mac(key, tup, irs, count, o) << (32 - MAC_BITS) | (count & 3) << 3 | u32::from(o.mss_idx)
}

/// 最後の ACK の確認番号 `iss` + 1 の cookie を確かめ、通れば相手の option を返します。`ts` は ACK の
/// timestamp の option です。時刻の数は作った数か次の数だけを受け入れます。
pub(crate) fn check(
    key: SipKey,
    tup: Tuple,
    irs: u32,
    iss: u32,
    ts: Option<(u32, u32)>,
    now_count: u32,
) -> Option<CookieOpts> {
    let age = now_count.wrapping_sub(iss >> 3) & 3;
    if age > 1 {
        return None;
    }
    let count = now_count.wrapping_sub(age);
    let mss_idx = u8::try_from(iss & 7).unwrap_or(0);
    let o = match ts {
        Some((_, ecr)) => CookieOpts::from_ts_bits(mss_idx, ecr & TS_OPT_MASK),
        None => CookieOpts {
            mss_idx,
            ..CookieOpts::default()
        },
    };
    (iss >> (32 - MAC_BITS) == mac(key, tup, irs, count, o)).then_some(o)
}

impl Shared {
    /// 待ち受け `l` への SYN に cookie で応えるかです。行を作れない時だけ応えます。
    pub(crate) fn use_cookie(&self, l: &Listener) -> bool {
        !self.syn_room(l)
    }

    /// cookie の SYN-ACK を制御の輪に積みます。行も接続の枠も使いません。
    pub(crate) fn send_cookie(&mut self, seg: &Segment<'_>, now: i64) {
        let o = CookieOpts::from_syn(seg);
        let count = counter(now);
        let iss = make(self.cookie_key, seg.tup, seg.seq, count, o);
        let mut w = OptWriter::default();
        w.mss(u16::try_from(self.our_mss()).unwrap_or(u16::MAX));
        if let Some((ts_val, _)) = seg.opt.ts {
            // TSval の下位 5 bit を option に替えます。値は時計より最大 31 ms 小さくなるだけです。
            let ours = ts_clock(now).wrapping_add(self.ts_offset(seg.tup));
            let v = (ours & !TS_OPT_MASK) | o.ts_bits();
            if o.sack_ok {
                w.sack_perm_with_ts(v, ts_val);
            } else {
                w.ts(v, ts_val);
            }
            if o.wscale.is_some() {
                w.wscale(super::RCV_WINDOW_SHIFT);
            }
        }
        let h = TcpHeader {
            tup: seg.tup,
            seq: iss,
            ack: seg.seq.wrapping_add(1),
            flags: FLAG_SYN | FLAG_ACK,
            wnd: u16::try_from(self.initial_window(o.ts_ok)).unwrap_or(u16::MAX),
        };
        if !self.send_ctl_with(h, Some(&mut w)) {
            return;
        }
        self.cookie_sent = Some(now);
        self.stats.syn_cookies_sent += 1;
        self.gates
            .allow(LogKind::SynCookies, now, self.stats.syn_cookies_sent);
    }

    /// cookie を送ってから 2 周期の内かを返します。外なら ACK を cookie として確かめず、どの行にも当たらない
    /// segment として扱います。洪水の無い時に偽の ACK で MAC を総当たりする機会を作らないためです。
    pub(crate) fn cookie_window(&self, now: i64) -> bool {
        self.cookie_sent
            .is_some_and(|t| counter(now).wrapping_sub(counter(t)) <= 1)
    }

    /// 待ち受けへの、どの行にも当たらない ACK を cookie として確かめ、通れば握手の途中の行の値を返します。
    /// 通らなければ数えて `None` を返します。
    pub(crate) fn check_cookie(&mut self, seg: &Segment<'_>, now: i64) -> Option<SynRow> {
        let irs = seg.seq.wrapping_sub(1);
        let iss = seg.ack.wrapping_sub(1);
        let Some(o) = check(self.cookie_key, seg.tup, irs, iss, seg.opt.ts, counter(now)) else {
            self.stats.syn_cookies_rejected += 1;
            return None;
        };
        let ts_recent = seg.opt.ts.map_or(0, |(v, _)| v);
        Some(SynRow {
            tup: seg.tup,
            listener: seg.tup.lport,
            iss,
            irs,
            peer_mss: MSS_TABLE[usize::from(o.mss_idx)],
            ws_ok: o.wscale.is_some(),
            snd_wscale: o.wscale.unwrap_or(0),
            sack_ok: o.sack_ok,
            ts_ok: o.ts_ok,
            ts_recent,
            ts_offset: if o.ts_ok { self.ts_offset(seg.tup) } else { 0 },
            rcv_wnd: u16::try_from(self.initial_window(o.ts_ok)).unwrap_or(u16::MAX),
            cookie: true,
            ..SynRow::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: SipKey = SipKey { k0: 11, k1: 22 };
    const TUP: Tuple = Tuple {
        laddr: 0x0a09_0001,
        raddr: 0x0a09_0002,
        lport: 80,
        rport: 40000,
    };

    fn ts_opts(o: CookieOpts) -> Option<(u32, u32)> {
        o.ts_ok.then(|| (5, 0x1234_5600 | o.ts_bits()))
    }

    #[test]
    fn round_trips_every_option_combination() {
        for mss_idx in 0..8u8 {
            for ws in [None, Some(0), Some(7), Some(14)] {
                for sack in [false, true] {
                    for ts in [false, true] {
                        let o = CookieOpts {
                            mss_idx,
                            ts_ok: ts,
                            wscale: ws.filter(|_| ts),
                            sack_ok: sack && ts,
                        };
                        for (made, now) in [(7, 7), (7, 8), (u32::MAX, 0)] {
                            let iss = make(KEY, TUP, 99, made, o);
                            assert_eq!(
                                check(KEY, TUP, 99, iss, ts_opts(o), now),
                                Some(o),
                                "{o:?} made {made} checked {now}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_forged_expired_and_altered_cookies() {
        let o = CookieOpts {
            mss_idx: 4,
            ts_ok: true,
            wscale: Some(7),
            sack_ok: true,
        };
        let iss = make(KEY, TUP, 99, 10, o);
        let ts = ts_opts(o);
        assert!(check(KEY, TUP, 99, iss, ts, 10).is_some());
        // 2 周期の後と、作る前の時刻
        for now in [12, 13, 14, 9] {
            assert_eq!(check(KEY, TUP, 99, iss, ts, now), None, "now {now}");
        }
        // 違う相手の ISN、4 つ組、鍵
        assert_eq!(check(KEY, TUP, 100, iss, ts, 10), None);
        let other = Tuple {
            rport: 40001,
            ..TUP
        };
        assert_eq!(check(KEY, other, 99, iss, ts, 10), None);
        assert_eq!(check(SipKey { k0: 1, k1: 2 }, TUP, 99, iss, ts, 10), None);
        // option を書き換えた TSecr と、timestamp を落とした ACK
        let bad_ts = ts.map(|(v, e)| (v, e ^ TS_SACK));
        assert_eq!(check(KEY, TUP, 99, iss, bad_ts, 10), None);
        assert_eq!(check(KEY, TUP, 99, iss, None, 10), None);
        // MSS の番号の書き換えと、MAC の 1 bit の書き換え
        assert_eq!(check(KEY, TUP, 99, iss ^ 1, ts, 10), None);
        assert_eq!(check(KEY, TUP, 99, iss ^ (1 << 31), ts, 10), None);
    }

    #[test]
    fn mss_index_picks_the_largest_entry_not_above_the_peer() {
        assert_eq!(MSS_TABLE.iter().rposition(|&m| m <= 1460), Some(7));
        assert_eq!(MSS_TABLE.iter().rposition(|&m| m <= 1459), Some(6));
        assert_eq!(MSS_TABLE.iter().rposition(|&m| m <= 536), Some(0));
        assert!(MSS_TABLE.is_sorted());
    }
}
