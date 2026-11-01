//! IPv4 の断片の有限な再組み立ての表 (Go の `internal/ipv4frag` の写し)。
//!
//! 表は項目、断片の枠、保持 byte の 3 つの上限を持つ固定の配列です。
//! 満杯のときは今の鍵以外で最も古い未完成の項目を追い出します。
//! 呼び手は、packet が来ないときも時計に合わせて [`Table::sweep_next`] を呼び、返った知らせを ICMP の経路へ
//! 渡します。
//!
//! 保持 byte の上限は、固定の管理領域と保持する断片の写しと完成した datagram の写し 1 つを数えます。
//! 管理領域の大きさは、Go の linux/amd64 の型の大きさ (`*_CHARGE`) で数えます。
//! 追い出しの時機が管理領域の大きさで変わり、移行の間は Go と同じ出力を求めるためです。
//! Rust の型はそれ以下の大きさであることを試験で確かめるので、数えた値は実際の保持の上界です。
//!
//! Go の表との違いは 2 つです。Go の `Close` の後の `Closed` の状態はありません。核の `close` が表ごと消費する
//! ので、閉じた表に断片が届くことが無いためです。表を空にするのは [`Table::clear`] です。また、上限で断る
//! [`Outcome::Capacity`] は知らせを持ちません。Go の wgstack はその知らせを使わずに捨てるためです。

use crate::fixed_vec::{AllocError, FixedVec};
use crate::time::Time;
use crate::wire::{IP_HEADER_LEN, be16, ipv4_header_ok, set_ipv4_checksum};
use core::mem::size_of;

/// Go の `ipv4frag.Table` の linux/amd64 での大きさです。
const TABLE_CHARGE: usize = 120;
/// Go の項目 (`ipv4Assembly`) の大きさです。
const ENTRY_CHARGE: usize = 264;
/// Go の断片の枠 (`ipv4Piece`) の大きさです。
const PIECE_CHARGE: usize = 56;
/// Go の知らせ (`Notice`) の大きさです。Go の `Sweep` が返す写しの分で、Rust は写しを作りませんが同じく数えます。
const NOTICE_CHARGE: usize = 72;

const MAX_DATAGRAM: usize = 65535;
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// 表の上限です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) entries: usize,
    pub(crate) fragments: usize,
    /// 保持 byte の上限です。固定の管理領域、保持する断片の写しの容量、完成の写し 1 つを数えます。
    pub(crate) bytes: usize,
    /// 項目の寿命の nanosecond です。
    pub(crate) lifetime: u64,
}

/// 本番の上限です。Go の wgstack と `internal/nettun` と同じ値で、設定の項目にしません。
pub(crate) const LIMITS: Limits = Limits {
    entries: 128,
    fragments: 512,
    bytes: 4 << 20,
    lifetime: 30 * NANOS_PER_SEC,
};

/// 表を作れなかった理由です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NewError {
    /// 上限の値が範囲の外です。
    InvalidLimits,
    /// 固定の管理領域が保持 byte の上限を超えます。
    MetadataOverBudget,
    /// 確保に失敗しました。
    Alloc,
}

impl From<AllocError> for NewError {
    fn from(_: AllocError) -> Self {
        Self::Alloc
    }
}

/// 断片を捨てた理由と、項目を外した理由です。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Reason {
    #[default]
    None,
    Malformed,
    Options,
    Overlap,
    Conflict,
    Expired,
}

/// ICMP の誤りを作るための材料です。元の最初の header と中身の 8 byte までを持ちます。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Notice {
    pub(crate) reason: Reason,
    /// option の誤りで分かるときの、誤りの位置です。
    pub(crate) pointer: u8,
    pub(crate) quote: [u8; 68],
    pub(crate) quote_len: u8,
    pub(crate) has_first: bool,
}

impl Default for Notice {
    fn default() -> Self {
        Self {
            reason: Reason::None,
            pointer: 0,
            quote: [0; 68],
            quote_len: 0,
            has_first: false,
        }
    }
}

/// 1 つの断片を処理した結果です。
#[derive(Debug)]
pub(crate) enum Outcome {
    /// 断片を保持しました。
    Held,
    /// datagram が完成しました。呼び手が完成した写しを持ちます。表はこの写しを保持しません。
    Complete(FixedVec<u8>),
    /// 保持している断片と同じ断片です。
    Duplicate,
    /// 断片を捨てました。項目を外した場合は、その項目の知らせを持ちます。
    Rejected(Notice),
    /// 上限のために断片を保持できません。
    Capacity,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Key {
    src: [u8; 4],
    dst: [u8; 4],
    id: u16,
    protocol: u8,
}

#[derive(Clone, Copy)]
struct Assembly {
    used: bool,
    key: Key,
    deadline: Time,
    /// 最後の断片を見るまでは `None` です。
    total: Option<usize>,
    covered: usize,
    parts: usize,
    first_len: usize,
    first: [u8; 60],
    quote: [u8; 68],
    quote_len: u8,
    copied: [u8; 40],
    copied_len: usize,
    copied_set: bool,
    ecn_mask: u8,
}

impl Default for Assembly {
    fn default() -> Self {
        Self {
            used: false,
            key: Key::default(),
            deadline: Time::ZERO,
            total: None,
            covered: 0,
            parts: 0,
            first_len: 0,
            first: [0; 60],
            quote: [0; 68],
            quote_len: 0,
            copied: [0; 40],
            copied_len: 0,
            copied_set: false,
            ecn_mask: 0,
        }
    }
}

#[derive(Debug, Default)]
struct Piece {
    used: bool,
    owner: usize,
    start: usize,
    more: bool,
    data: FixedVec<u8>,
}

/// IPv4 の断片の再組み立ての表です。
pub(crate) struct Table {
    limits: Limits,
    entries: FixedVec<Assembly>,
    pieces: FixedVec<Piece>,
    base_cost: usize,
    /// `base_cost` と保持する断片の写しの容量の和です。
    used: usize,
    /// 使っている項目の数です。核が掃除の期限を毎回の待ちで調べるので、数えて持ちます。
    live: usize,
    evicted: u64,
}

impl core::fmt::Debug for Table {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (used, entries, fragments) = self.usage();
        f.debug_struct("Table")
            .field("limits", &self.limits)
            .field("used", &used)
            .field("entries", &entries)
            .field("fragments", &fragments)
            .field("evicted", &self.evicted)
            .finish_non_exhaustive()
    }
}

/// 写す option (copied の bit が立った option) を、詰め物を除いて返します。最初でない断片は写す option
/// だけを持てます。知らない写す option は捨てずに残します。誤りでは誤りの位置を返します。
fn copied_options(h: &[u8], first: bool) -> Result<([u8; 40], usize), u8> {
    let mut copied = [0u8; 40];
    let mut n = 0;
    let mut p = IP_HEADER_LEN;
    // header は 60 byte 以下なので、位置は u8 に収まります。
    let at = |p: usize| u8::try_from(p).unwrap_or(u8::MAX);
    while p < h.len() {
        let kind = h[p];
        if kind == 0 {
            // EOL:残りは詰め物でなければなりません。
            if let Some(q) = (p + 1..h.len()).find(|&q| h[q] != 0) {
                return Err(at(q));
            }
            break;
        }
        if kind == 1 {
            p += 1;
            continue;
        }
        let Some(&length) = h.get(p + 1) else {
            return Err(at(p));
        };
        let length = usize::from(length);
        if length < 2 || p + length > h.len() {
            return Err(at(p));
        }
        if kind & 0x80 == 0 && !first {
            return Err(at(p));
        }
        if kind & 0x80 != 0 {
            copied[n..n + length].copy_from_slice(&h[p..p + length]);
            n += length;
        }
        p += length;
    }
    Ok((copied, n))
}

impl Notice {
    fn from_packet(reason: Reason, pointer: u8, packet: &[u8], first: bool) -> Self {
        let mut n = Self {
            reason,
            pointer,
            has_first: first,
            ..Self::default()
        };
        if first {
            let mut length = packet.len();
            if let Some(&b0) = packet.first() {
                let h = usize::from(b0 & 15) * 4;
                if (20..=60).contains(&h) && length > h + 8 {
                    length = h + 8;
                }
            }
            length = length.min(n.quote.len());
            n.quote[..length].copy_from_slice(&packet[..length]);
            n.quote_len = u8::try_from(length).unwrap_or(u8::MAX);
        }
        n
    }

    /// 期限を過ぎた項目への Time Exceeded が引用する、最初の断片の header と 8 byte を返します。最初の断片を
    /// 持ち、header が正しく、宛先が `local` のときだけ返します。
    pub(crate) fn timeout_quote(&self, local: [u8; 4]) -> Option<&[u8]> {
        if !self.has_first || self.quote_len < 28 {
            return None;
        }
        let quote = &self.quote[..usize::from(self.quote_len)];
        let hlen = usize::from(quote[0] & 15) * 4;
        if !(20..=60).contains(&hlen)
            || quote.len() < hlen + 8
            || !ipv4_header_ok(&quote[..hlen])
            || quote[6] & 0x1f != 0
            || quote[7] != 0
            || quote[16..20] != local
        {
            return None;
        }
        Some(quote)
    }

    /// option の不正な断片 `offending` に Parameter Problem を返すかと、引用する datagram の header の長さを
    /// 返します。引用するのは `offending` です。最初の断片の引用を持つときは、`offending` がその最初の断片と
    /// 同じであることを求めます。宛先が `local` でない誤り、送信元が 0 の誤り、broadcast と multicast の宛先、
    /// ICMP の誤りへの誤りには返しません。
    pub(crate) fn param_problem_ok(&self, offending: &[u8], local: [u8; 4]) -> Option<usize> {
        if self.pointer < 20 || offending.len() < 20 {
            return None;
        }
        let saved: &[u8] = if self.has_first {
            if self.quote_len < 20 {
                return None;
            }
            &self.quote[..usize::from(self.quote_len)]
        } else {
            // 後続の断片の option の誤りには最初の断片の引用が無いので、その断片そのものを使います。
            offending
        };
        let hlen = usize::from(saved[0] & 15) * 4;
        if !(20..=60).contains(&hlen)
            || saved.len() < hlen
            || offending.len() < hlen
            || usize::from(self.pointer) >= hlen
        {
            return None;
        }
        // 中身の無い断片は option を確かめる前に捨てます。
        if saved.len() == hlen || offending.len() == hlen {
            return None;
        }
        let prefix = (hlen + 8).min(saved.len());
        if offending.len() < prefix {
            return None;
        }
        // option の形の矛盾は後続の入力にも保存した最初の引用を付けうるので、元の最初の断片だけを対象にします。
        if (self.has_first
            && (offending[..prefix] != saved[..prefix]
                || offending[6] & 0x1f != 0
                || offending[7] != 0))
            || !ipv4_header_ok(&saved[..hlen])
            || usize::from(be16(offending, 2)) != offending.len()
        {
            return None;
        }
        if saved[12..16] == [0; 4]
            || saved[16] & 0xf0 == 0xe0
            || saved[16..20] == [255; 4]
            || saved[16..20] != local
        {
            return None;
        }
        if saved[9] == 1 {
            // ICMP:echo、timestamp、information の要求と応答だけに返します。
            match saved[hlen] {
                0 | 8 | 13 | 14 | 15 | 16 => {}
                _ => return None,
            }
        }
        Some(hlen)
    }
}

/// 重複した最初の断片の header が、保存した header と同じ形かを返します。ECN、DSCP、TTL、checksum、
/// 変わりうる option の値は違ってよく、固定の構造と option の種類と長さの一致を求めます。
fn same_first_header(saved: &[u8], incoming: &[u8]) -> bool {
    if saved.len() != incoming.len() {
        return false;
    }
    let mut normalized = [0u8; 20];
    normalized.copy_from_slice(&incoming[..20]);
    normalized[1] = saved[1];
    normalized[8] = saved[8];
    normalized[10] = saved[10];
    normalized[11] = saved[11];
    if saved[..20] != normalized {
        return false;
    }
    let mut p = 20;
    while p < saved.len() {
        if saved[p] != incoming[p] {
            return false;
        }
        match saved[p] {
            0 => return true,
            1 => p += 1,
            _ => {
                let (Some(&a), Some(&b)) = (saved.get(p + 1), incoming.get(p + 1)) else {
                    return false;
                };
                if a != b || a < 2 {
                    return false;
                }
                p += usize::from(a);
            }
        }
    }
    true
}

/// 2 つの写す option の列が、同じ種類と長さの並びかを返します。
fn same_copied_shape(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut p = 0;
    while p < a.len() {
        let (Some(&la), Some(&lb)) = (a.get(p + 1), b.get(p + 1)) else {
            return false;
        };
        if a[p] != b[p] || la != lb || la < 2 {
            return false;
        }
        p += usize::from(la);
    }
    true
}

impl Limits {
    /// 上限を確かめ、固定の管理領域と通知の写しの数えた byte を返します。
    pub(crate) fn base_cost(&self) -> Result<usize, NewError> {
        let l = self;
        if l.entries == 0
            || l.fragments == 0
            || l.bytes == 0
            || l.lifetime == 0
            || l.entries > 4096
            || l.fragments > 65536
        {
            return Err(NewError::InvalidLimits);
        }
        let room = |used: usize, each: usize| l.bytes.checked_sub(used).map_or(0, |r| r / each);
        if l.bytes < TABLE_CHARGE || l.entries > room(TABLE_CHARGE, ENTRY_CHARGE) {
            return Err(NewError::MetadataOverBudget);
        }
        let mut base = TABLE_CHARGE + l.entries * ENTRY_CHARGE;
        if l.fragments > room(base, PIECE_CHARGE) {
            return Err(NewError::MetadataOverBudget);
        }
        base += l.fragments * PIECE_CHARGE;
        if l.entries > room(base, NOTICE_CHARGE) {
            return Err(NewError::MetadataOverBudget);
        }
        Ok(base + l.entries * NOTICE_CHARGE)
    }
}

impl Table {
    /// 表を作り、固定の配列をすべて確保します。
    pub(crate) fn new(l: Limits) -> Result<Self, NewError> {
        let base = l.base_cost()?;
        Ok(Self {
            limits: l,
            entries: FixedVec::try_filled(l.entries, |_| Assembly::default())?,
            pieces: FixedVec::try_filled(l.fragments, |_| Piece::default())?,
            base_cost: base,
            used: base,
            live: 0,
            evicted: 0,
        })
    }

    fn clear_entry(&mut self, i: usize) {
        for p in self.pieces.iter_mut() {
            if p.used && p.owner == i {
                self.used -= p.data.capacity();
                *p = Piece::default();
            }
        }
        if self.entries[i].used {
            self.live -= 1;
        }
        self.entries[i] = Assembly::default();
    }

    /// `keep` 以外で最も早い期限の項目を外し、その位置を返します。ほかに項目が無ければ `None` です。
    /// 期限はどれも受け入れの時刻と同じ寿命の和なので、最も早い期限が最も古い項目です。同じ期限なら小さい
    /// 位置を外します。追い出しは知らせも ICMP も出しません。Time Exceeded を送るのはタイマーだけです。
    fn evict_oldest(&mut self, keep: Option<usize>) -> Option<usize> {
        let mut victim: Option<usize> = None;
        for (i, e) in self.entries.iter().enumerate() {
            if !e.used || Some(i) == keep {
                continue;
            }
            if victim.is_none_or(|v| e.deadline < self.entries[v].deadline) {
                victim = Some(i);
            }
        }
        let v = victim?;
        self.clear_entry(v);
        self.evicted += 1;
        Some(v)
    }

    fn notice_entry(&self, i: usize, reason: Reason) -> Notice {
        let e = &self.entries[i];
        Notice {
            reason,
            pointer: 0,
            quote: e.quote,
            quote_len: e.quote_len,
            has_first: e.first_len != 0,
        }
    }

    /// 期限を過ぎた項目を 1 つ外し、その知らせを返します。無ければ `None` です。
    /// 呼び手は `None` まで繰り返し呼びます。知らせは項目の位置の順に出ます。
    pub(crate) fn sweep_next(&mut self, now: Time) -> Option<Notice> {
        let i = self
            .entries
            .iter()
            .position(|e| e.used && now >= e.deadline)?;
        let n = self.notice_entry(i, Reason::Expired);
        self.clear_entry(i);
        Some(n)
    }

    /// 保持している項目と断片をすべて外します。
    pub(crate) fn clear(&mut self) {
        for i in 0..self.entries.len() {
            if self.entries[i].used {
                self.clear_entry(i);
            }
        }
    }

    /// 使っている項目があるかを返します。
    pub(crate) fn has_entries(&self) -> bool {
        self.live > 0
    }

    /// 保持 byte (`base_cost` を含む)、項目の数、断片の数を返します。
    pub(crate) fn usage(&self) -> (usize, usize, usize) {
        let entries = self.entries.iter().filter(|e| e.used).count();
        let fragments = self.pieces.iter().filter(|p| p.used).count();
        (self.used, entries, fragments)
    }

    /// 固定の管理領域と通知の写しの数えた byte です。
    pub(crate) fn base_cost(&self) -> usize {
        self.base_cost
    }

    /// これまでに追い出した項目の数です。
    #[cfg(test)]
    pub(crate) fn evicted(&self) -> u64 {
        self.evicted
    }

    /// 1 つの断片を処理します。`packet` は Total Length の長さの IPv4 の packet です。
    pub(crate) fn process(&mut self, packet: &[u8], now: Time) -> Outcome {
        let reject =
            |reason, ptr, first| Outcome::Rejected(Notice::from_packet(reason, ptr, packet, first));
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return reject(Reason::Malformed, 0, false);
        }
        let hlen = usize::from(packet[0] & 15) * 4;
        if !(20..=60).contains(&hlen)
            || hlen > packet.len()
            || usize::from(be16(packet, 2)) != packet.len()
        {
            return reject(Reason::Malformed, 0, false);
        }
        let flags = be16(packet, 6);
        let start = usize::from(flags & 0x1fff) * 8;
        let more = flags & 0x2000 != 0;
        let first = start == 0;
        // 断片でない packet と、DF の立った断片は断片の誤りです。
        let is_fragment = more || start != 0;
        if !ipv4_header_ok(&packet[..hlen])
            || flags & 0x8000 != 0
            || flags & 0x4000 != 0
            || !is_fragment
        {
            return reject(Reason::Malformed, 6, first);
        }
        let (copied, copied_len) = match copied_options(&packet[..hlen], first) {
            Ok(c) => c,
            Err(pointer) => return reject(Reason::Options, pointer, first),
        };
        let payload = &packet[hlen..];
        if payload.is_empty()
            || (more && !payload.len().is_multiple_of(8))
            || start + payload.len() > MAX_DATAGRAM - 20
        {
            return reject(Reason::Malformed, 6, first);
        }
        let key = Key {
            src: [packet[12], packet[13], packet[14], packet[15]],
            dst: [packet[16], packet[17], packet[18], packet[19]],
            id: be16(packet, 4),
            protocol: packet[9],
        };
        let mut index = None;
        let mut free = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.used && e.key == key {
                index = Some(i);
                break;
            }
            if !e.used && free.is_none() {
                free = Some(i);
            }
        }
        if let Some(i) = index
            && now >= self.entries[i].deadline
        {
            // 同じ鍵の新しい断片を受け入れる間に、期限の知らせを黙って消しません。呼び手はこの断片を処理し直せます。
            let n = self.notice_entry(i, Reason::Expired);
            self.clear_entry(i);
            return Outcome::Rejected(n);
        }
        let index = if let Some(i) = index {
            i
        } else {
            // 満杯の鍵の表には、追い出せるほかの項目が必ずあります。
            let Some(i) = free.or_else(|| self.evict_oldest(None)) else {
                return Outcome::Capacity;
            };
            self.live += 1;
            self.entries[i] = Assembly {
                used: true,
                key,
                deadline: now.saturating_add_nanos(self.limits.lifetime),
                ..Assembly::default()
            };
            i
        };
        let conflict = |t: &mut Self, reason| {
            let n = t.notice_entry(index, reason);
            t.clear_entry(index);
            Outcome::Rejected(n)
        };
        let e = &self.entries[index];
        let end = start + payload.len();
        if first {
            if e.first_len != 0 && !same_first_header(&e.first[..e.first_len], &packet[..hlen]) {
                return conflict(self, Reason::Conflict);
            }
            if e.total.is_some_and(|t| t > MAX_DATAGRAM - hlen) {
                return conflict(self, Reason::Conflict);
            }
        }
        if e.first_len != 0 && end > MAX_DATAGRAM - e.first_len {
            return conflict(self, Reason::Conflict);
        }
        if e.total.is_some_and(|t| end > t || (!more && end != t)) {
            return conflict(self, Reason::Conflict);
        }
        if e.copied_set && !same_copied_shape(&copied[..copied_len], &e.copied[..e.copied_len]) {
            return conflict(self, Reason::Options);
        }
        let mask = e.ecn_mask | (1 << (packet[1] & 3));
        if mask & 1 != 0 && mask & 8 != 0 {
            // CE と Not-ECT。
            return conflict(self, Reason::Conflict);
        }
        let mut duplicate = false;
        for part in self.pieces.iter() {
            if !part.used || part.owner != index {
                continue;
            }
            let part_end = part.start + part.data.len();
            if start == part.start && end == part_end && payload == &part.data[..] {
                if more != part.more {
                    return conflict(self, Reason::Conflict);
                }
                duplicate = true;
                break;
            }
            if start < part_end && part.start < end {
                return conflict(self, Reason::Overlap);
            }
            if (!more && part_end > end) || (first && part_end > MAX_DATAGRAM - hlen) {
                return conflict(self, Reason::Conflict);
            }
        }
        if duplicate {
            self.entries[index].ecn_mask = mask;
            return Outcome::Duplicate;
        }
        let e = &self.entries[index];
        if !more && e.total.is_some_and(|t| t != end) {
            return conflict(self, Reason::Conflict);
        }
        if e.parts >= self.limits.fragments {
            return Outcome::Capacity;
        }
        let capacity = |t: &mut Self| {
            if t.entries[index].parts == 0 {
                t.clear_entry(index);
            }
            Outcome::Capacity
        };
        let free_part = loop {
            let free_part = self.pieces.iter().position(|p| !p.used);
            if let Some(p) = free_part
                && self.used + payload.len() <= self.limits.bytes
            {
                break p;
            }
            if self.evict_oldest(Some(index)).is_none() {
                return capacity(self);
            }
        };
        // 完成した写しは、保持するすべての断片と並んで持てる必要があります。
        let e = &self.entries[index];
        let new_first_len = if first { hlen } else { e.first_len };
        let new_total = if more { e.total } else { Some(end) };
        let new_covered = e.covered + payload.len();
        let completes = new_first_len != 0 && new_total == Some(new_covered);
        while completes
            && new_first_len + new_covered + self.used + payload.len() > self.limits.bytes
        {
            if self.evict_oldest(Some(index)).is_none() {
                return capacity(self);
            }
        }
        // 確保は状態を変える前に済ませ、失敗を上限と同じ動作にします。
        let Ok(data) = FixedVec::try_from_slice(payload) else {
            return capacity(self);
        };
        let out = if completes {
            let Ok(o) = FixedVec::try_filled(new_first_len + new_covered, |_| 0u8) else {
                return capacity(self);
            };
            Some(o)
        } else {
            None
        };
        self.used += data.capacity();
        self.pieces[free_part] = Piece {
            used: true,
            owner: index,
            start,
            more,
            data,
        };
        let e = &mut self.entries[index];
        e.parts += 1;
        e.covered = new_covered;
        e.ecn_mask = mask;
        if !e.copied_set {
            e.copied[..copied_len].copy_from_slice(&copied[..copied_len]);
            e.copied_len = copied_len;
            e.copied_set = true;
        }
        if first {
            e.first[..hlen].copy_from_slice(&packet[..hlen]);
            e.first_len = hlen;
            let n = (hlen + 8).min(packet.len());
            e.quote[..n].copy_from_slice(&packet[..n]);
            e.quote_len = u8::try_from(n).unwrap_or(u8::MAX);
        }
        if !more {
            e.total = Some(end);
        }
        let Some(mut out) = out else {
            return Outcome::Held;
        };
        let first_len = e.first_len;
        let ce = e.ecn_mask & 8 != 0;
        out[..first_len].copy_from_slice(&e.first[..first_len]);
        for p in self.pieces.iter() {
            if p.used && p.owner == index {
                out[first_len + p.start..first_len + p.start + p.data.len()]
                    .copy_from_slice(&p.data);
            }
        }
        let total = u16::try_from(out.len()).unwrap_or(u16::MAX);
        out[2..4].copy_from_slice(&total.to_be_bytes());
        out[6] = 0;
        out[7] = 0;
        // RFC 3168 は ECT(0) と ECT(1) の混ざった断片の結果を決めていません。CE の断片があれば輻輳を残し、
        // 無ければ最初の header の値を保ちます。
        if ce {
            out[1] |= 3;
        }
        set_ipv4_checksum(&mut out[..first_len]);
        self.clear_entry(index);
        Outcome::Complete(out)
    }
}

/// `parse` の fuzz の target の再組み立ての部分です。入力の全体を 1 つの断片として渡した後、入力を
/// 「印の byte、長さの 2 byte、packet」の列として読み、表に順に渡します。印の bit 0 が立った packet は
/// IPv4 の header の checksum を直してから渡し、残りの bit は時刻を 100 ms の単位で進めます。
/// 各段の後に会計が上限の内にあり、表の数と一致することを確かめます。
#[cfg(any(test, fuzzing))]
pub(crate) fn fuzz_table(input: &[u8]) {
    let Ok(mut t) = Table::new(Limits {
        entries: 4,
        fragments: 8,
        bytes: TABLE_CHARGE + 4 * (ENTRY_CHARGE + NOTICE_CHARGE) + 8 * PIECE_CHARGE + 600,
        lifetime: 1_000_000_000,
    }) else {
        unreachable!("the fuzz limits are valid");
    };
    let mut now = Time::ZERO;
    let check = |t: &Table| {
        let mut sum = 0;
        let mut owned = [0usize; 4];
        let mut covered = [0usize; 4];
        for p in t.pieces.iter() {
            if !p.used {
                assert_eq!(p.data.capacity(), 0, "a free piece keeps data");
                continue;
            }
            sum += p.data.capacity();
            assert!(
                t.entries[p.owner].used,
                "a piece is owned by an unused entry"
            );
            owned[p.owner] += 1;
            covered[p.owner] += p.data.len();
        }
        for (i, e) in t.entries.iter().enumerate() {
            if e.used {
                assert_eq!((e.parts, e.covered), (owned[i], covered[i]));
            }
        }
        assert_eq!(t.used, t.base_cost + sum);
        assert!(t.used <= t.limits.bytes);
    };
    let _ = t.process(input, now);
    check(&t);
    let mut buf = [0u8; 2048];
    let mut rest = input;
    while let [mark, hi, lo, tail @ ..] = rest {
        let n = (usize::from(*hi) << 8 | usize::from(*lo)) % buf.len();
        let n = n.min(tail.len());
        let pkt = &mut buf[..n];
        pkt.copy_from_slice(&tail[..n]);
        rest = &tail[n..];
        if mark & 1 != 0 && n >= 20 {
            let hlen = usize::from(pkt[0] & 15) * 4;
            if (20..=n).contains(&hlen) {
                set_ipv4_checksum(&mut pkt[..hlen]);
            }
        }
        now = now.saturating_add_nanos(u64::from(mark >> 1) * 100_000_000);
        while let Some(notice) = t.sweep_next(now) {
            let _ = notice.timeout_quote([10, 1, 1, 2]);
        }
        match t.process(pkt, now) {
            Outcome::Complete(out) => {
                assert!(ipv4_header_ok(&out[..usize::from(out[0] & 15) * 4]));
                assert_eq!(usize::from(be16(&out, 2)), out.len());
            }
            Outcome::Rejected(notice) => {
                let _ = notice.timeout_quote([10, 1, 1, 2]);
                let _ = notice.param_problem_ok(pkt, [10, 1, 1, 2]);
            }
            Outcome::Held | Outcome::Duplicate | Outcome::Capacity => {}
        }
        check(&t);
    }
    t.clear();
    assert_eq!(t.usage(), (t.base_cost, 0, 0));
}

/// Rust の型の大きさが、数える Go の大きさ以下であることを確かめます。
const _: () = {
    assert!(size_of::<Assembly>() <= ENTRY_CHARGE);
    assert!(size_of::<Piece>() <= PIECE_CHARGE);
    assert!(size_of::<Notice>() <= NOTICE_CHARGE);
    assert!(size_of::<Table>() <= TABLE_CHARGE);
};

mod entry;
#[cfg(test)]
mod tests;
