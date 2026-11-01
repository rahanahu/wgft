//! IPv4 の断片の入口 (Go の wgstack の `frag.go`)。
//!
//! 断片はすべて再組み立ての表に渡し、完成した datagram だけを核の入口に戻します。Time Exceeded と Parameter
//! Problem は核が自分で作り、送る条件は表の [`Notice`] が決めます (packet-validation.md の断片に対する ICMP)。

use super::{Notice, Outcome, Reason};
use crate::icmp::{PARAM_PROBLEM, TIME_EXCEEDED};
use crate::stack::shared::Shared;
use crate::stack::{Hook, Stack, time};
use crate::tcp::SEC;
use crate::wire::{Ipv4, be16};

/// 再組み立ての表を掃除する間隔です。
const SWEEP: i64 = SEC;

impl Shared {
    /// 表の知らせに ICMP の誤りを返します。期限には Time Exceeded を、option の誤りには Parameter Problem を
    /// 返します。`offending` は誤りを起こした断片で、期限の知らせには空を渡します。
    pub(crate) fn frag_notice(&mut self, n: &Notice, offending: &[u8], now: i64) {
        // Go と同じ条件です。期限の知らせは最初の断片の引用を持つときだけ、option の誤りはいつも対象にします。
        let expired = n.reason == Reason::Expired;
        if !(expired && n.has_first || n.reason == Reason::Options) {
            return;
        }
        // 保存した最初の引用は、後から届いた不正な断片を対象にしません。
        if n.reason == Reason::Options
            && n.has_first
            && offending.len() >= 8
            && be16(offending, 6) & 0x1fff != 0
        {
            return;
        }
        let local = self.addr.to_be_bytes();
        if n.reason == Reason::Expired {
            if let Some(quote) = n.timeout_quote(local) {
                self.send_icmp_error_raw(quote, TIME_EXCEEDED, 1, 0, now, false);
            }
            return;
        }
        if n.param_problem_ok(offending, local).is_none() {
            return;
        }
        self.send_icmp_error_raw(
            offending,
            PARAM_PROBLEM,
            0,
            u32::from(n.pointer) << 24,
            now,
            true,
        );
    }

    /// 断片を保持した後に、次の掃除の期限を決めます。期限が過ぎていれば今から 1 秒後にします。
    fn note_frag_sweep(&mut self, now: i64) {
        if self.frag_next_sweep <= now {
            self.frag_next_sweep = now + SWEEP;
        }
    }

    /// 1 秒ごとに期限を過ぎた項目を外し、Time Exceeded を返します。`handle_timeout` から呼びます。
    pub(crate) fn sweep_frag(&mut self, now: i64) {
        if now < self.frag_next_sweep {
            return;
        }
        self.frag_next_sweep = now + SWEEP;
        while let Some(n) = self.frag.sweep_next(time(now)) {
            self.frag_notice(&n, &[], now);
        }
    }

    /// 再組み立ての表が項目を持つ間の、次の掃除の時刻です。
    pub(crate) fn frag_deadline(&self) -> Option<i64> {
        self.frag.has_entries().then_some(self.frag_next_sweep)
    }
}

impl<H: Hook> Stack<H> {
    /// 1 つの断片を表に渡します (Go の `inputFragment`)。
    pub(crate) fn input_fragment(&mut self, ip: &Ipv4<'_>, now: i64) {
        let pkt = ip.packet;
        let s = &mut self.s;
        let mut res = s.frag.process(pkt, time(now));
        if let Outcome::Rejected(n) = &res
            && n.reason == Reason::Expired
        {
            // 前の項目の期限を知らせた後、この断片を空いた項目で処理し直します。
            let n = *n;
            s.frag_notice(&n, &[], now);
            res = s.frag.process(pkt, time(now));
        }
        match res {
            Outcome::Held => {
                s.stats.fragments_dropped += 1;
                s.note_frag_sweep(now);
            }
            Outcome::Complete(p) => self.input(&p, now),
            // 1 つの datagram だけで表が満ちる Capacity は、ICMP を返さずに捨てます。
            Outcome::Duplicate | Outcome::Capacity => s.stats.fragments_dropped += 1,
            Outcome::Rejected(n) => {
                s.stats.fragments_dropped += 1;
                s.frag_notice(&n, pkt, now);
            }
        }
    }
}
