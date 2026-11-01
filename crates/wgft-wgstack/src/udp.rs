//! UDP の endpoint と予算 (Go の `udp.go`、udp-accounting.md、wgstack-rs.md の「アプリケーションの操作」)。
//!
//! 受信と送信はそれぞれ核の予算と endpoint 1 つの上限 (予算の 4 分の 1) を持ちます。datagram の中身は、大きさの
//! 区分ごとの枠に分けた 16 KiB の chunk に置き、16 KiB を超える datagram は chunk の列に置きます。chunk は
//! 1 つの endpoint だけが持ち、chunk の中に生きている枠が 1 つでもある間は、その chunk 全体を endpoint と核の
//! 予算に数えます。会計は保持そのものなので、受け入れの判定に別の帳簿は要りません。管理の情報は作成の時に
//! 確保する固定の数の配列に置きます。
//!
//! endpoint の表はポートごとの固定の行です ([`PortTable`])。行は予算と区分ごとの今の chunk と受信の FIFO を
//! 持ち、datagram の番号は 16 bit です。閉じた endpoint の送り残しの datagram は送り終えるまで残り、その時に
//! 核の予算だけを返します。Go でも閉じた endpoint の値は送り残しが持ち続け、同じポートを開き直した endpoint の
//! 予算には数えないためです。
//!
//! 送信の予算を予約できない `send_to` は `WouldBlock` を返し、endpoint を待ちの list に入れます。送信の予約が
//! 返ったら、待ちの list の endpoint にすべて `UdpWritable` を出します。Go の `WriteTo` が、どの予約が返っても
//! 待つ書き手をすべて起こすのと同じです。

use crate::buf::chunk::{CHUNK_SIZE, Chunk, ChunkPool};
use crate::config::Limits;
use crate::fixed_vec::{AllocError, FixedVec};
use crate::stack::shared::{EV_UDP_READ, EV_UDP_WRITE, Shared};
use crate::stack::{Error, Hook, LogKind, Stack};
use crate::tcp::listen::PortTable;
use crate::time::Time;
use crate::wire::{self, IP_HEADER_LEN, Ipv4, PROTO_UDP, PayloadDrop, UDP_HEADER_LEN};
use core::fmt;
use core::net::{Ipv4Addr, SocketAddrV4};

/// 受信の byte の予算です。値はどれも設定の項目にしません (udp-accounting.md の UDP の受信の予算)。
pub(crate) const RX_BYTES: usize = 4 << 20;
/// 受信の datagram の数の予算の本番の値です。
pub(crate) const RX_DATAGRAMS: usize = 4096;
/// 送信の byte の予算です。
pub(crate) const TX_BYTES: usize = 4 << 20;
/// 送信の datagram の数の予算の本番の値です。
pub(crate) const TX_DATAGRAMS: usize = 1024;
/// endpoint 1 つの上限は予算のこの数分の 1 です。
pub(crate) const ENDPOINT_SHARE: usize = 4;
/// 1 つの datagram の中身の上限です。
pub(crate) const MAX_PAYLOAD: usize = 65535 - IP_HEADER_LEN - UDP_HEADER_LEN;
/// 2 つの向きの予算を合わせた chunk の数です。chunk の管理の配列はこの数で持ちます。
pub(crate) const CHUNKS: usize = (RX_BYTES + TX_BYTES) / CHUNK_SIZE;
/// 枠の大きさの区分です。最後の区分を超える datagram は chunk の列に置きます。
const CLASSES: [usize; 3] = [256, 2048, CHUNK_SIZE];
/// chunk の列を表す区分の番号です。
const LARGE: u8 = 3;
/// 1 つの datagram が使う chunk の数の上限です。
const MAX_DGRAM_CHUNKS: usize = MAX_PAYLOAD.div_ceil(CHUNK_SIZE);
/// 16 bit の番号の「無し」です。
pub(crate) const NIL16: u16 = u16::MAX;
/// 受信の向きです。
pub(crate) const RX: usize = 0;
/// 送信の向きです。
pub(crate) const TX: usize = 1;

const CHUNK_BYTES: i64 = 1 << crate::buf::chunk::CHUNK_SHIFT;

fn class_of(n: usize) -> u8 {
    match n {
        0..=256 => 0,
        257..=2048 => 1,
        2049..=CHUNK_SIZE => 2,
        _ => LARGE,
    }
}

fn u16_of(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(NIL16)
}

/// UDP の socket の handle です。ポートと 32 bit の世代の組で、閉じた後の handle は誤りになります。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UdpId {
    pub(crate) port: u16,
    pub(crate) generation: u32,
}

impl UdpId {
    /// socket のポートです。
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// UDP の会計が見つけた不変条件の違反です。最初の違反で核の UDP をすべて止めます
/// (udp-accounting.md の会計の不整合)。`agent doctor` の `tunnel.udp_accounting` に使います。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UdpFault {
    /// datagram の枠を 2 回返しました。
    SlotReleasedTwice,
    /// 予算の数が負になりました。値は違反を見つけた時の核の予算の byte と件数です。
    BudgetNegative { bytes: i64, datagrams: i64 },
}

impl fmt::Display for UdpFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotReleasedTwice => f.write_str("UDP slot released twice"),
            Self::BudgetNegative { bytes, datagrams } => write!(
                f,
                "UDP budget went negative: {bytes} bytes {datagrams} datagrams"
            ),
        }
    }
}

impl core::error::Error for UdpFault {}

/// 核の 1 つの向きの byte と件数の予算です。
#[derive(Clone, Copy, Debug, Default)]
struct DevBudget {
    bytes: i64,
    count: i64,
    max_bytes: i64,
    max_count: i64,
}

impl DevBudget {
    fn fits(&self, bytes: i64, count: i64) -> bool {
        self.bytes + bytes <= self.max_bytes && self.count + count <= self.max_count
    }
}

/// endpoint の 1 つの向きの予算です。byte はいつも chunk の倍数なので chunk の数で持ちます。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EpBudget {
    chunks: u16,
    count: u16,
}

/// endpoint の行です。受信の datagram は行の FIFO に並び、送信の datagram は核の 1 つの FIFO に並びます。
#[derive(Clone, Copy, Debug)]
#[cfg_attr(any(test, feature = "harness"), derive(PartialEq, Eq))]
pub(crate) struct UdpEp {
    budget: [EpBudget; 2],
    /// 向きと区分ごとの今の chunk です。
    cur: [[u16; 3]; 2],
    rx_head: u16,
    rx_tail: u16,
    /// 送信の予算の空きを待つ list の次のポートです。
    wait_next: u16,
    waiting: bool,
}

impl Default for UdpEp {
    fn default() -> Self {
        Self {
            budget: [EpBudget::default(); 2],
            cur: [[NIL16; 3]; 2],
            rx_head: NIL16,
            rx_tail: NIL16,
            wait_next: 0,
            waiting: false,
        }
    }
}

/// 1 つの datagram の管理の情報です。
#[derive(Clone, Copy, Debug)]
struct Dgram {
    used: bool,
    class: u8,
    /// 持ち主の endpoint のポートと、開いた時の世代です。
    ep_port: u16,
    ep_gen: u32,
    /// 受信では送信元、送信では宛先です。
    peer_addr: u32,
    peer_port: u16,
    /// 区分の枠の chunk の中の位置です。
    off: u16,
    /// 中身の長さです。
    n: u32,
    /// 区分の枠では `ck[0]` だけ、chunk の列では使う chunk の数だけを使います。
    ck: [u16; MAX_DGRAM_CHUNKS],
    /// 受信の FIFO か送信の FIFO の次です。
    next: u16,
    ip_id: u16,
    csum: u16,
    /// 送信で、断片に分けて送った UDP の byte (header を含む) です。
    sent: u32,
}

impl Default for Dgram {
    fn default() -> Self {
        Self {
            used: false,
            class: 0,
            ep_port: 0,
            ep_gen: 0,
            peer_addr: 0,
            peer_port: 0,
            off: 0,
            n: 0,
            ck: [NIL16; MAX_DGRAM_CHUNKS],
            next: NIL16,
            ip_id: 0,
            csum: 0,
            sent: 0,
        }
    }
}

/// endpoint が持つ 1 つの chunk です。`live` は使っている枠の数、`next` は次に使う枠の番号です。
#[derive(Debug, Default)]
struct ChunkRec {
    buf: Option<Chunk>,
    live: u16,
    next: u16,
}

/// 予約を断った予算です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// endpoint 1 つの上限です。
    Endpoint,
    /// 核の全体の予算です。
    Tunnel,
    /// chunk を確保できませんでした。予算の空きを待っても解けないので、送信は待ちの list に入れません。
    NoMemory,
}

/// 核の UDP の状態です。
#[derive(Debug)]
pub(crate) struct Udp {
    pub(crate) eps: PortTable<UdpEp>,
    dg: [FixedVec<Dgram>; 2],
    dg_free: [FixedVec<u16>; 2],
    ck: FixedVec<ChunkRec>,
    ck_free: FixedVec<u16>,
    dev: [DevBudget; 2],
    /// endpoint 1 つの上限の chunk の数と件数です。
    ep_max: [EpBudget; 2],
    tx_head: u16,
    tx_tail: u16,
    /// 送信の予算の空きを待つ endpoint の list の先頭のポートです。
    wait_head: Option<u16>,
    fault: Option<UdpFault>,
    /// 会計の不整合をまだログに出していません。
    fault_unlogged: bool,
}

impl Udp {
    /// endpoint の表 `eps` を使い、ほかの表を確保します。`eps` は新しく作った表か、核を使い回す試験が作成の時の
    /// 値に戻した表です。
    pub(crate) fn with_eps(l: &Limits, eps: PortTable<UdpEp>) -> Result<Self, AllocError> {
        let sizes = [l.udp_rx_datagrams, l.udp_tx_datagrams];
        let free = |n: usize| FixedVec::try_filled(n, |i| u16_of(n - 1 - i));
        let dev = |bytes: usize, count: usize| DevBudget {
            bytes: 0,
            count: 0,
            max_bytes: i64::try_from(bytes).unwrap_or(i64::MAX),
            max_count: i64::try_from(count).unwrap_or(i64::MAX),
        };
        let ep = |bytes: usize, count: usize| EpBudget {
            chunks: u16_of(bytes / ENDPOINT_SHARE / CHUNK_SIZE),
            count: u16_of(count / ENDPOINT_SHARE),
        };
        Ok(Self {
            eps,
            dg: [
                FixedVec::try_filled(sizes[RX], |_| Dgram::default())?,
                FixedVec::try_filled(sizes[TX], |_| Dgram::default())?,
            ],
            dg_free: [free(sizes[RX])?, free(sizes[TX])?],
            ck: FixedVec::try_filled(CHUNKS, |_| ChunkRec::default())?,
            ck_free: free(CHUNKS)?,
            dev: [dev(RX_BYTES, sizes[RX]), dev(TX_BYTES, sizes[TX])],
            ep_max: [ep(RX_BYTES, sizes[RX]), ep(TX_BYTES, sizes[TX])],
            tx_head: NIL16,
            tx_tail: NIL16,
            wait_head: None,
            fault: None,
            fault_unlogged: false,
        })
    }

    /// 管理の配列の byte です。endpoint の表は含みません。
    #[cfg(test)]
    pub(crate) fn heap_bytes(&self, dir: usize) -> usize {
        self.dg[dir].heap_bytes() + self.dg_free[dir].heap_bytes()
    }

    /// chunk の管理の配列の byte です。
    #[cfg(test)]
    pub(crate) fn chunk_heap_bytes(&self) -> usize {
        self.ck.heap_bytes() + self.ck_free.heap_bytes()
    }

    /// 管理の情報の 1 件の大きさです。上界が使います。
    pub(crate) fn dgram_size() -> usize {
        size_of::<Dgram>() + size_of::<u16>()
    }

    /// chunk の管理の 1 件の大きさです。上界が使います。
    pub(crate) fn chunk_rec_size() -> usize {
        size_of::<ChunkRec>() + size_of::<u16>()
    }

    /// 最初の会計の不整合です。
    pub(crate) fn fault(&self) -> Option<UdpFault> {
        self.fault
    }

    /// 会計の不整合を記録し、核の UDP を止めます。最初の違反を保ちます。
    fn fail(&mut self, f: UdpFault) {
        if self.fault.is_none() {
            self.fault = Some(f);
            self.fault_unlogged = true;
        }
    }

    /// まだログに出していない会計の不整合を 1 回だけ返します。
    pub(crate) fn take_fault_log(&mut self) -> bool {
        core::mem::take(&mut self.fault_unlogged)
    }

    /// 向き `dir` が持つ chunk の byte と datagram の数です。
    pub(crate) fn held(&self, dir: usize) -> (usize, usize) {
        let b = &self.dev[dir];
        (
            usize::try_from(b.bytes).unwrap_or(0),
            usize::try_from(b.count).unwrap_or(0),
        )
    }

    /// endpoint `port` の向き `dir` に `n` byte の datagram の置き場を予約し、datagram の番号を返します。
    /// endpoint は開いていることを呼び手が確かめます。予約できなければ、断った予算を返します。
    fn reserve(
        &mut self,
        chunks: &mut ChunkPool,
        port: u16,
        dir: usize,
        n: usize,
    ) -> Result<u16, Refused> {
        let generation = self.eps.generation(port);
        let Some(ep) = self.eps.by_port_mut(port) else {
            return Err(Refused::Endpoint);
        };
        let dev = &self.dev[dir];
        let own = ep.budget[dir];
        let max = self.ep_max[dir];
        if self.dg_free[dir].is_empty() || !dev.fits(0, 1) {
            return Err(Refused::Tunnel);
        }
        if own.count >= max.count {
            return Err(Refused::Endpoint);
        }
        let c = class_of(n);
        let need = if c == LARGE {
            n.div_ceil(CHUNK_SIZE)
        } else {
            let cur = ep.cur[dir][usize::from(c)];
            let per = CHUNK_SIZE / CLASSES[usize::from(c)];
            usize::from(cur == NIL16 || usize::from(self.ck[usize::from(cur)].next) >= per)
        };
        if need > 0 {
            let bytes = i64::try_from(need).unwrap_or(i64::MAX) * CHUNK_BYTES;
            if !dev.fits(bytes, 0) {
                return Err(Refused::Tunnel);
            }
            if usize::from(own.chunks) + need > usize::from(max.chunks) {
                return Err(Refused::Endpoint);
            }
            if self.ck_free.len() < need {
                return Err(Refused::Tunnel);
            }
        }
        let Some(id) = self.dg_free[dir].pop() else {
            return Err(Refused::Tunnel);
        };
        // chunk を先に揃えます。揃わなければ何も変えずに断ります。
        let mut got: [Option<Chunk>; MAX_DGRAM_CHUNKS] = Default::default();
        for slot in &mut got[..need] {
            let Ok(b) = chunks.get() else {
                for b in got.iter_mut().filter_map(Option::take) {
                    chunks.put(b);
                }
                let _ = self.dg_free[dir].try_push(id);
                return Err(Refused::NoMemory);
            };
            *slot = Some(b);
        }
        let mut new_ck = [NIL16; MAX_DGRAM_CHUNKS];
        for (slot, b) in new_ck.iter_mut().zip(got.iter_mut()) {
            if let Some(b) = b.take() {
                let Some(i) = self.ck_free.pop() else {
                    chunks.put(b);
                    continue;
                };
                self.ck[usize::from(i)] = ChunkRec {
                    buf: Some(b),
                    live: 0,
                    next: 0,
                };
                *slot = i;
            }
        }
        let bytes = i64::try_from(need).unwrap_or(0) * CHUNK_BYTES;
        let need16 = u16_of(need);
        self.dev[dir].count += 1;
        self.dev[dir].bytes += bytes;
        let Some(ep) = self.eps.by_port_mut(port) else {
            return Err(Refused::Endpoint);
        };
        ep.budget[dir].count += 1;
        ep.budget[dir].chunks += need16;
        let mut g = Dgram {
            used: true,
            class: c,
            ep_port: port,
            ep_gen: generation,
            n: u32::try_from(n).unwrap_or(u32::MAX),
            ..Dgram::default()
        };
        if c == LARGE {
            g.ck = new_ck;
        } else {
            let ci = usize::from(c);
            if need > 0 {
                ep.cur[dir][ci] = new_ck[0];
            }
            let cur = ep.cur[dir][ci];
            let rec = &mut self.ck[usize::from(cur)];
            g.ck[0] = cur;
            g.off = u16_of(usize::from(rec.next) * CLASSES[ci]);
            rec.next += 1;
            rec.live += 1;
        }
        self.dg[dir][usize::from(id)] = g;
        Ok(id)
    }

    fn free_chunk(&mut self, chunks: &mut ChunkPool, i: u16) {
        let rec = core::mem::take(&mut self.ck[usize::from(i)]);
        if let Some(b) = rec.buf {
            chunks.put(b);
        }
        let _ = self.ck_free.try_push(i);
    }

    /// datagram の予約を返します。送信の向きなら、空きを待つ endpoint に知らせるポートを `woken` に渡します。
    fn release(
        &mut self,
        chunks: &mut ChunkPool,
        dir: usize,
        id: u16,
        woken: &mut impl FnMut(u16),
    ) {
        let g = self.dg[dir][usize::from(id)];
        let mut freed: u16 = 0;
        if g.class == LARGE {
            let n = usize::try_from(g.n).unwrap_or(0).div_ceil(CHUNK_SIZE);
            for &c in &g.ck[..n] {
                self.free_chunk(chunks, c);
                freed += 1;
            }
        } else {
            let c = g.ck[0];
            let rec = &mut self.ck[usize::from(c)];
            if rec.live == 0 {
                self.fail(UdpFault::SlotReleasedTwice);
            } else {
                rec.live -= 1;
                if rec.live == 0 {
                    if self.eps.generation(g.ep_port) == g.ep_gen
                        && let Some(ep) = self.eps.by_port_mut(g.ep_port)
                        && ep.cur[dir][usize::from(g.class)] == c
                    {
                        ep.cur[dir][usize::from(g.class)] = NIL16;
                    }
                    self.free_chunk(chunks, c);
                    freed = 1;
                }
            }
        }
        let dev = &mut self.dev[dir];
        dev.count -= 1;
        dev.bytes -= i64::from(freed) * CHUNK_BYTES;
        let mut negative = dev.count < 0 || dev.bytes < 0;
        let (bytes, count) = (dev.bytes, dev.count);
        // 閉じた endpoint の送り残しは、核の予算だけを返します。
        if self.eps.generation(g.ep_port) == g.ep_gen
            && let Some(ep) = self.eps.by_port_mut(g.ep_port)
        {
            let own = &mut ep.budget[dir];
            match (own.count.checked_sub(1), own.chunks.checked_sub(freed)) {
                (Some(count), Some(chunks)) => *own = EpBudget { chunks, count },
                _ => negative = true,
            }
        }
        if negative {
            self.fail(UdpFault::BudgetNegative {
                bytes,
                datagrams: count,
            });
        }
        self.dg[dir][usize::from(id)] = Dgram::default();
        let _ = self.dg_free[dir].try_push(id);
        if dir == TX {
            while let Some(port) = self.wait_head {
                let ep = self.eps.by_port_mut(port);
                self.wait_head = match ep {
                    Some(ep) => {
                        ep.waiting = false;
                        (ep.wait_next != port).then_some(ep.wait_next)
                    }
                    None => None,
                };
                woken(port);
            }
        }
    }

    /// endpoint `port` を送信の予算の空きを待つ list に入れます。
    fn wait(&mut self, port: u16) {
        let head = self.wait_head;
        let Some(ep) = self.eps.by_port_mut(port) else {
            return;
        };
        if ep.waiting {
            return;
        }
        ep.waiting = true;
        // list の末尾は自分を指します。
        ep.wait_next = head.unwrap_or(port);
        self.wait_head = Some(port);
    }

    /// endpoint `port` を待ちの list から外します。閉じる時に呼びます。
    fn unwait(&mut self, port: u16) {
        if !self.eps.by_port(port).is_some_and(|e| e.waiting) {
            return;
        }
        let mut prev: Option<u16> = None;
        let mut cur = self.wait_head;
        while let Some(p) = cur {
            let Some(ep) = self.eps.by_port(p) else {
                return;
            };
            let next = (ep.wait_next != p).then_some(ep.wait_next);
            if p == port {
                match prev {
                    None => self.wait_head = next,
                    Some(q) => {
                        if let Some(e) = self.eps.by_port_mut(q) {
                            e.wait_next = next.unwrap_or(q);
                        }
                    }
                }
                if let Some(e) = self.eps.by_port_mut(port) {
                    e.waiting = false;
                }
                return;
            }
            prev = Some(p);
            cur = next;
        }
    }

    /// datagram の中身を `data` にします。
    fn put(&mut self, dir: usize, id: u16, data: &[u8]) {
        let g = self.dg[dir][usize::from(id)];
        if g.class == LARGE {
            for (&c, part) in g.ck.iter().zip(data.chunks(CHUNK_SIZE)) {
                if let Some(b) = self.ck[usize::from(c)].buf.as_deref_mut() {
                    b[..part.len()].copy_from_slice(part);
                }
            }
            return;
        }
        let off = usize::from(g.off);
        if let Some(b) = self.ck[usize::from(g.ck[0])].buf.as_deref_mut() {
            b[off..off + data.len()].copy_from_slice(data);
        }
    }

    /// datagram の中身の `off` から `dst` に写し、写した長さを返します。
    fn get(&self, dir: usize, id: u16, off: usize, dst: &mut [u8]) -> usize {
        let dg = &self.dg[dir][usize::from(id)];
        let len = usize::try_from(dg.n).unwrap_or(0);
        if off >= len {
            return 0;
        }
        let want = dst.len().min(len - off);
        if dg.class != LARGE {
            let start = usize::from(dg.off) + off;
            if let Some(buf) = self.ck[usize::from(dg.ck[0])].buf.as_deref() {
                dst[..want].copy_from_slice(&buf[start..start + want]);
            }
            return want;
        }
        let mut done = 0;
        while done < want {
            let pos = off + done;
            let Some(buf) = self.ck[usize::from(dg.ck[pos / CHUNK_SIZE])].buf.as_deref() else {
                break;
            };
            let from = pos % CHUNK_SIZE;
            let k = (want - done).min(CHUNK_SIZE - from);
            dst[done..done + k].copy_from_slice(&buf[from..from + k]);
            done += k;
        }
        done
    }

    /// 送信の datagram `id` の UDP の checksum を求めます。chunk の境目は偶数の位置にあるので、chunk ごとに
    /// 足しても 16 bit の語の並びは 1 回で足したときと同じです。
    fn checksum(&self, id: u16, src: u32, dst: u32) -> u16 {
        let g = &self.dg[TX][usize::from(id)];
        let len = usize::try_from(g.n).unwrap_or(0);
        let ulen = UDP_HEADER_LEN + len;
        let mut sum = wire::pseudo_sum(src, dst, PROTO_UDP, ulen);
        let mut h = [0u8; UDP_HEADER_LEN];
        h[0..2].copy_from_slice(&g.ep_port.to_be_bytes());
        h[2..4].copy_from_slice(&g.peer_port.to_be_bytes());
        h[4..6].copy_from_slice(&u16_of(ulen).to_be_bytes());
        sum = u32::from(wire::checksum(sum, &h));
        if g.class == LARGE {
            let mut left = len;
            for &c in &g.ck[..len.div_ceil(CHUNK_SIZE)] {
                let k = left.min(CHUNK_SIZE);
                if let Some(b) = self.ck[usize::from(c)].buf.as_deref() {
                    sum = u32::from(wire::checksum(sum, &b[..k]));
                }
                left -= k;
            }
        } else if let Some(b) = self.ck[usize::from(g.ck[0])].buf.as_deref() {
            let off = usize::from(g.off);
            sum = u32::from(wire::checksum(sum, &b[off..off + len]));
        }
        #[expect(clippy::cast_possible_truncation, reason = "the folded sum is 16 bits")]
        let cs = !(sum as u16);
        if cs == 0 { 0xffff } else { cs }
    }

    /// 受信の datagram `id` を endpoint `port` の FIFO の末尾に入れます。
    fn push_rx(&mut self, port: u16, id: u16) {
        let Some(ep) = self.eps.by_port_mut(port) else {
            return;
        };
        if ep.rx_tail == NIL16 {
            ep.rx_head = id;
        } else {
            self.dg[RX][usize::from(ep.rx_tail)].next = id;
        }
        ep.rx_tail = id;
    }

    /// 送信の datagram `id` を送信の FIFO の末尾に入れます。
    fn push_tx(&mut self, id: u16) {
        if self.tx_tail == NIL16 {
            self.tx_head = id;
        } else {
            self.dg[TX][usize::from(self.tx_tail)].next = id;
        }
        self.tx_tail = id;
    }

    /// 予約をすべて返し、chunk を置き場に返します。核を閉じる時に呼びます。
    pub(crate) fn clear(&mut self, chunks: &mut ChunkPool) {
        for i in 0..self.ck.len() {
            if let Some(b) = self.ck[i].buf.take() {
                chunks.put(b);
            }
        }
        for d in [RX, TX] {
            self.dev[d].bytes = 0;
            self.dev[d].count = 0;
            for g in self.dg[d].iter_mut() {
                *g = Dgram::default();
            }
        }
        self.tx_head = NIL16;
        self.tx_tail = NIL16;
        self.wait_head = None;
    }

    /// 会計の不変条件を確かめます。
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        self.eps.check()?;
        let mut held_chunks = 0usize;
        let mut live = 0u64;
        for r in self.ck.iter() {
            if r.buf.is_some() {
                held_chunks += 1;
                live += u64::from(r.live);
            } else if r.live != 0 {
                return Err("a free UDP chunk has live slots");
            }
        }
        if held_chunks + self.ck_free.len() != self.ck.len() {
            return Err("the UDP chunk free list disagrees with the held chunks");
        }
        for &i in self.ck_free.iter() {
            if self.ck.get(usize::from(i)).is_none_or(|r| r.buf.is_some()) {
                return Err("the UDP chunk free list holds a used chunk");
            }
        }
        let bytes = self.dev[RX].bytes + self.dev[TX].bytes;
        if i64::try_from(held_chunks).unwrap_or(i64::MAX) * CHUNK_BYTES != bytes {
            return Err("the UDP budgets disagree with the held chunks");
        }
        let mut small = 0u64;
        for d in [RX, TX] {
            let b = &self.dev[d];
            let mut used = 0usize;
            for g in self.dg[d].iter().filter(|g| g.used) {
                used += 1;
                let n = if g.class == LARGE {
                    usize::try_from(g.n).unwrap_or(0).div_ceil(CHUNK_SIZE)
                } else {
                    small += 1;
                    1
                };
                for &c in &g.ck[..n] {
                    if self.ck.get(usize::from(c)).is_none_or(|r| r.buf.is_none()) {
                        return Err("a UDP datagram points to a free chunk");
                    }
                }
            }
            if b.count != i64::try_from(used).unwrap_or(-1) || b.count > b.max_count {
                return Err("a UDP datagram count disagrees with the budget");
            }
            if b.bytes > b.max_bytes || b.bytes < 0 {
                return Err("a UDP byte budget is out of range");
            }
            if used + self.dg_free[d].len() != self.dg[d].len() {
                return Err("the UDP datagram free list disagrees with the used datagrams");
            }
        }
        if small != live {
            return Err("the UDP chunk slot counts disagree with the datagrams");
        }
        // 送信の FIFO は送信の datagram をすべて持ちます。
        let mut n = 0;
        let mut id = self.tx_head;
        while id != NIL16 {
            let g = self.dg[TX]
                .get(usize::from(id))
                .ok_or("the UDP send FIFO is broken")?;
            if !g.used || n > self.dg[TX].len() {
                return Err("the UDP send FIFO is broken");
            }
            n += 1;
            if g.next == NIL16 && id != self.tx_tail {
                return Err("the UDP send FIFO tail is wrong");
            }
            id = g.next;
        }
        if i64::try_from(n).unwrap_or(-1) != self.dev[TX].count {
            return Err("the UDP send FIFO disagrees with the send budget");
        }
        // 受信の datagram はどれも開いている endpoint の FIFO にあります。
        let mut rx = 0usize;
        let mut waiting = 0usize;
        let mut bad = None;
        self.eps.for_each_open(|port, ep| {
            let mut k = 0usize;
            let mut id = ep.rx_head;
            while id != NIL16 {
                let Some(g) = self.dg[RX].get(usize::from(id)) else {
                    bad = Some("an endpoint receive FIFO is broken");
                    return;
                };
                if !g.used || g.ep_port != port || k > self.dg[RX].len() {
                    bad = Some("an endpoint receive FIFO is broken");
                    return;
                }
                k += 1;
                id = g.next;
            }
            if k != usize::from(ep.budget[RX].count) {
                bad = Some("an endpoint receive FIFO disagrees with its budget");
            }
            for d in [RX, TX] {
                let (b, m) = (ep.budget[d], self.ep_max[d]);
                if b.count > m.count || b.chunks > m.chunks {
                    bad = Some("an endpoint is over its share of the UDP budget");
                }
            }
            rx += k;
            waiting += usize::from(ep.waiting);
        });
        if let Some(e) = bad {
            return Err(e);
        }
        if i64::try_from(rx).unwrap_or(-1) != self.dev[RX].count {
            return Err("the receive FIFOs disagree with the receive budget");
        }
        let mut listed = 0usize;
        let mut cur = self.wait_head;
        while let Some(p) = cur {
            let Some(ep) = self.eps.by_port(p) else {
                return Err("a closed endpoint waits for send space");
            };
            if !ep.waiting || listed > waiting {
                return Err("the send space wait list is broken");
            }
            listed += 1;
            cur = (ep.wait_next != p).then_some(ep.wait_next);
        }
        if listed != waiting {
            return Err("the send space wait list disagrees with the endpoints");
        }
        Ok(())
    }
}

impl Shared {
    /// UDP の endpoint `port` の知らせの対象です。待ち受けのポートの対象を分け合い、印で分けます。
    pub(crate) fn port_target(&self, port: u16) -> u32 {
        u32::try_from(self.qlinks.len()).unwrap_or(0) + u32::from(port)
    }

    /// datagram の予約を返し、送信の予算の空きを待つ endpoint に知らせます。
    fn release_udp(&mut self, dir: usize, id: u16) {
        let base = u32::try_from(self.qlinks.len()).unwrap_or(0);
        let events = &mut self.events;
        self.udp.release(&mut self.chunks, dir, id, &mut |port| {
            events.raise(base + u32::from(port), EV_UDP_WRITE);
        });
    }

    /// この核の宛先の完成した UDP の datagram を受けます (Go の `inputUDP`)。
    pub(crate) fn input_udp(&mut self, ip: &Ipv4<'_>, now: i64) {
        let u = match wire::parse_udp(ip) {
            Ok(u) => u,
            Err(PayloadDrop::Malformed) => {
                self.stats.udp_dropped += 1;
                return;
            }
            Err(PayloadDrop::BadChecksum) => {
                self.stats.bad_checksum += 1;
                return;
            }
        };
        if self.udp.fault.is_some() {
            self.stats.udp_dropped += 1;
            return;
        }
        if self.udp.eps.by_port(u.dport).is_none() {
            self.send_icmp_error(ip, 3, 3, 0, now); // Port Unreachable
            return;
        }
        let id = match self
            .udp
            .reserve(&mut self.chunks, u.dport, RX, u.payload.len())
        {
            Ok(id) => id,
            Err(r) => {
                match r {
                    Refused::Endpoint => self.stats.udp_endpoint_full += 1,
                    // 受信では chunk の確保の失敗も核の予算で断ったことにします。
                    Refused::Tunnel | Refused::NoMemory => self.stats.udp_tunnel_full += 1,
                }
                self.stats.udp_dropped += 1;
                let n = self.stats.udp_endpoint_full + self.stats.udp_tunnel_full;
                self.gates.allow(LogKind::UdpDropped, now, n);
                return;
            }
        };
        let g = &mut self.udp.dg[RX][usize::from(id)];
        g.peer_addr = ip.src;
        g.peer_port = u.sport;
        self.udp.put(RX, id, u.payload);
        self.udp.push_rx(u.dport, id);
        let t = self.port_target(u.dport);
        self.events.raise(t, EV_UDP_READ);
    }

    /// 送信の FIFO の先頭の datagram の次の断片を `b` に作り、長さを返します。datagram を送り終えたら予約を
    /// 返します (Go の `pollUDP`)。DF は立てません。
    pub(crate) fn poll_udp(&mut self, b: &mut [u8]) -> usize {
        let id = self.udp.tx_head;
        if id == NIL16 {
            return 0;
        }
        let g = self.udp.dg[TX][usize::from(id)];
        let len = usize::try_from(g.n).unwrap_or(0);
        let total = UDP_HEADER_LEN + len;
        let space = b.len().min(self.config.mtu).saturating_sub(IP_HEADER_LEN);
        if space < 8 {
            return 0;
        }
        let sent = usize::try_from(g.sent).unwrap_or(0);
        let mut frag = total - sent;
        let mut more = false;
        if frag > space {
            frag = space & !7;
            more = true;
        }
        let p = &mut b[..IP_HEADER_LEN + frag];
        let plen = p.len();
        wire::write_ipv4_header(p, plen, g.ip_id, PROTO_UDP, self.addr, g.peer_addr);
        let mut flags = u16_of(sent / 8);
        if more {
            flags |= 0x2000;
        }
        wire::set_frag_field(p, flags);
        let body = &mut p[IP_HEADER_LEN..];
        if sent == 0 {
            wire::write_udp_header(body, g.ep_port, g.peer_port, total, g.csum);
            self.udp.get(TX, id, 0, &mut body[UDP_HEADER_LEN..]);
        } else {
            self.udp.get(TX, id, sent - UDP_HEADER_LEN, body);
        }
        let sent = sent + frag;
        self.udp.dg[TX][usize::from(id)].sent = u32::try_from(sent).unwrap_or(u32::MAX);
        if sent >= total {
            self.udp.tx_head = g.next;
            if g.next == NIL16 {
                self.udp.tx_tail = NIL16;
            }
            self.release_udp(TX, id);
            self.out.udp_queued -= 1;
        }
        IP_HEADER_LEN + frag
    }
}

impl<H: Hook> Stack<H> {
    /// `addr` で UDP を待ち受ける、接続しない endpoint を開きます。アドレスはトンネルのアドレスです。
    pub fn bind_udp(&mut self, now: Time, addr: SocketAddrV4) -> Result<UdpId, Error> {
        self.clock(now);
        if addr.ip().to_bits() != self.s.addr {
            return Err(Error::AddrNotLocal);
        }
        let port = addr.port();
        if port == 0 {
            return Err(Error::PortZero);
        }
        if self.s.udp.fault.is_some() {
            return Err(Error::UdpStopped);
        }
        let generation = self
            .s
            .udp
            .eps
            .open(port)
            .map_err(|crate::tcp::listen::OpenError::InUse| Error::AddrInUse)?;
        let t = self.s.port_target(port);
        self.s.events.clear_bits(t, EV_UDP_READ | EV_UDP_WRITE);
        Ok(UdpId { port, generation })
    }

    /// 届いた順に datagram を 1 つ `dst` に写し、写した長さと送信元を返します。`dst` より長い datagram は
    /// `dst` の長さで切り、残りを捨てます。写した時点で予約を返します。読む物が無ければ `WouldBlock` です。
    pub fn recv_from(
        &mut self,
        now: Time,
        id: UdpId,
        dst: &mut [u8],
    ) -> Result<(usize, SocketAddrV4), Error> {
        self.clock(now);
        let u = &mut self.s.udp;
        let Some(ep) = u.eps.get(id.port, id.generation) else {
            return Err(Error::Closed);
        };
        let head = ep.rx_head;
        if head == NIL16 {
            return Err(Error::WouldBlock);
        }
        let g = u.dg[RX][usize::from(head)];
        ep.rx_head = g.next;
        if g.next == NIL16 {
            ep.rx_tail = NIL16;
        }
        let n = u.get(RX, head, 0, dst);
        self.s.release_udp(RX, head);
        Ok((
            n,
            SocketAddrV4::new(Ipv4Addr::from_bits(g.peer_addr), g.peer_port),
        ))
    }

    /// `data` を 1 つの datagram として `to` に送り、受け取った byte 数を返します。送信の予算 (核の全体と
    /// endpoint 1 つの上限) を予約できなければ `WouldBlock` を返し、予約が返ったら `UdpWritable` を出します。
    /// chunk を確保できなければ、待たずに [`Error::NoMemory`] を返します。
    /// MTU を超える datagram は、送る時に DF を立てない断片に分けます。
    pub fn send_to(
        &mut self,
        now: Time,
        id: UdpId,
        data: &[u8],
        to: SocketAddrV4,
    ) -> Result<usize, Error> {
        self.clock(now);
        if to.port() == 0 {
            return Err(Error::InvalidAddress);
        }
        if data.len() > MAX_PAYLOAD {
            return Err(Error::MessageTooLong);
        }
        let s = &mut self.s;
        if s.udp.eps.get(id.port, id.generation).is_none() {
            return Err(Error::Closed);
        }
        if s.udp.fault.is_some() {
            return Err(Error::UdpStopped);
        }
        let gid = match s.udp.reserve(&mut s.chunks, id.port, TX, data.len()) {
            Ok(gid) => gid,
            // TCP の `write` と同じく、確保の失敗は待たずに誤りで返します。送信の予約が返る当てが無いためです。
            Err(Refused::NoMemory) => return Err(Error::NoMemory),
            Err(Refused::Endpoint | Refused::Tunnel) => {
                s.udp.wait(id.port);
                return Err(Error::WouldBlock);
            }
        };
        let g = &mut s.udp.dg[TX][usize::from(gid)];
        g.peer_addr = to.ip().to_bits();
        g.peer_port = to.port();
        s.udp.put(TX, gid, data);
        let mut ip_id = s.next_id();
        if ip_id == 0 {
            ip_id = s.next_id();
        }
        let csum = s.udp.checksum(gid, s.addr, to.ip().to_bits());
        let g = &mut s.udp.dg[TX][usize::from(gid)];
        g.ip_id = ip_id;
        g.csum = csum;
        s.udp.push_tx(gid);
        s.out.udp_queued += 1;
        Ok(data.len())
    }

    /// endpoint を閉じます。受けて読まれていない datagram の予約を返します。送り残しの datagram は送り終えた
    /// 時に返します。古い handle では何もしません。
    pub fn close_udp(&mut self, now: Time, id: UdpId) {
        self.clock(now);
        let s = &mut self.s;
        let Some(ep) = s.udp.eps.get(id.port, id.generation) else {
            return;
        };
        let mut head = ep.rx_head;
        while head != NIL16 {
            let next = s.udp.dg[RX][usize::from(head)].next;
            s.release_udp(RX, head);
            head = next;
        }
        s.udp.unwait(id.port);
        s.udp.eps.close(id.port, id.generation);
        let t = s.port_target(id.port);
        s.events.clear_bits(t, EV_UDP_READ | EV_UDP_WRITE);
    }

    /// UDP の会計が不変条件の違反を見つけて核の UDP を止めていれば、最初の違反を返します。健全な間は `None`
    /// です。`agent doctor` の `tunnel.udp_accounting` に使います。
    pub fn udp_receive_fault(&self) -> Option<UdpFault> {
        self.s.udp.fault()
    }
}

#[cfg(test)]
mod tests;
