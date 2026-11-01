//! The agent's tunnel batch store and, on Linux, the batch system calls (`recvmmsg`, `sendmmsg`, UDP
//! GRO and GSO). `wgft-agent`'s data plane uses it, and so does the host-side measurement tool
//! (`wgft-agent-perf`), so that the tool drives the same code.
//!
//! 規則の正本は `docs/design/v2/agent-throughput.md` の「バッチの作りの規則」と「バッチの作り」である。
//!
//! - 置き場:受信と送信の向きごとに、枠の数だけの buffer と見出しを、起動の時に 1 回だけ連続して確保する。
//!   datagram ごとには確保しない。大きさは [`store_bytes`] と一致し、試験がそれを確かめる
//! - 受信:1 つの枠は最大の datagram の長さで、UDP の GRO がまとめた datagram の列も入る。復号した
//!   packet は、枠と同じ大きさの平文の領域に詰めて並べる。packet は IPv4 の全長を持つので、並べた列は
//!   先頭から読み直せる
//! - 送信:核が書く packet の枠と、device の層が暗号化して書く datagram の枠を持つ。送る順に暗号化し、
//!   同じ長さの datagram の並びを UDP の GSO の 1 つの message にまとめる
//! - unsafe は Linux の system call の包み ([`sys`]) だけに置く

#[cfg(target_os = "linux")]
pub mod sys;

use std::net::SocketAddr;

/// The most slots per direction: datagrams one `recvmmsg` or `sendmmsg` call may carry. It is also
/// the most segments one UDP GSO send carries on every kernel that has GSO.
pub const MAX_SLOTS: usize = 64;

/// One receive slot: the largest UDP datagram, which also holds what UDP GRO joins.
pub const RX_SLOT: usize = u16::MAX as usize;

/// The most datagrams in one UDP GSO message.
pub const GSO_MAX_SEGMENTS: usize = MAX_SLOTS;

/// The most bytes in one UDP GSO message: the largest UDP payload over IPv4.
pub const GSO_MAX_BYTES: usize = 65_507;

/// The protocol number of UDP in the IPv4 header.
const IPPROTO_UDP: u8 = 17;

/// What one receive slot read.
#[derive(Clone, Copy, Debug)]
pub struct RxMeta {
    /// The sender, or `None` for an address family the data plane does not use.
    pub from: Option<SocketAddr>,
    /// The bytes read.
    pub len: u32,
    /// The segment size when UDP GRO joined several datagrams, else 0.
    pub seg: u32,
}

const EMPTY_META: RxMeta = RxMeta {
    from: None,
    len: 0,
    seg: 0,
};

/// One datagram the device sealed into a send slot.
#[derive(Clone, Copy, Debug)]
pub struct Sealed {
    pub to: SocketAddr,
    pub len: u32,
}

const EMPTY_SEALED: Sealed = Sealed {
    to: SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::UNSPECIFIED,
        0,
    )),
    len: 0,
};

/// One message of a send batch: the sealed datagrams `first..first + count`, sent as one UDP
/// GSO send of segments of `seg` bytes when there are more than one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msg {
    pub first: u16,
    pub count: u16,
    pub seg: u32,
}

const EMPTY_MSG: Msg = Msg {
    first: 0,
    count: 0,
    seg: 0,
};

/// The bytes of a batch store of `slots` slots per direction, with the system call headers when
/// `on`, for packets of up to `mtu` bytes sealed into datagrams of up to `max_datagram` bytes:
/// what [`RxBatch::new`] and [`TxBatch::new`] allocate.
#[must_use]
pub const fn store_bytes(slots: usize, on: bool, mtu: usize, max_datagram: usize) -> usize {
    let headers = if on { header_bytes() } else { 0 };
    let rx = 2 * RX_SLOT + size_of::<RxMeta>() + headers;
    let tx =
        mtu + max_datagram + size_of::<u16>() + size_of::<Sealed>() + size_of::<Msg>() + headers;
    let scratch = if slots > 1 { RX_SLOT } else { 0 };
    slots * (rx + tx) + scratch
}

#[cfg(target_os = "linux")]
const fn header_bytes() -> usize {
    sys::HEADER_BYTES
}

#[cfg(not(target_os = "linux"))]
const fn header_bytes() -> usize {
    0
}

/// The receive side of the batch store.
///
/// Each slot holds [`RX_SLOT`] bytes in two parts. Its first `dense` bytes lie in the dense part,
/// where slot `i` starts at `i × dense`, so that the datagrams of a batch without GRO sit one
/// after the other; the rest of a longer read (a GRO buffer, or a datagram longer than `dense`)
/// goes to the slot's spill part after the dense parts. Slots `RX_SLOT` bytes apart would put every
/// datagram at the same offset of its own 64 KiB, on its own page and in the same cache sets; on the
/// host that made a batch of 64 slots read no faster than one `recvfrom` per datagram. With one
/// slot the two parts follow each other and form one buffer.
pub struct RxBatch {
    /// The datagrams read.
    pub data: Box<[u8]>,
    /// The packets decrypted from them, one after the other.
    pub plain: Box<[u8]>,
    pub meta: Box<[RxMeta]>,
    /// The bytes of a slot in the dense part.
    dense: usize,
    /// A datagram that crosses from the dense part to the spill part is copied here to be
    /// decrypted; [`RX_SLOT`] bytes with more than one slot, else empty.
    scratch: Box<[u8]>,
    #[cfg(target_os = "linux")]
    headers: Option<sys::Headers>,
}

impl std::fmt::Debug for RxBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RxBatch")
            .field("slots", &self.meta.len())
            .finish_non_exhaustive()
    }
}

impl RxBatch {
    /// The store of `slots` slots whose dense parts hold `dense` bytes each (the longest datagram
    /// the peer sends), with the system call headers when `on` (Linux only).
    #[must_use]
    pub fn new(slots: usize, on: bool, dense: usize) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = on;
        Self {
            data: vec![0; slots * RX_SLOT].into_boxed_slice(),
            plain: vec![0; slots * RX_SLOT].into_boxed_slice(),
            meta: vec![EMPTY_META; slots].into_boxed_slice(),
            dense: dense.clamp(1, RX_SLOT),
            scratch: vec![0; if slots > 1 { RX_SLOT } else { 0 }].into_boxed_slice(),
            #[cfg(target_os = "linux")]
            headers: on.then(|| sys::Headers::new(slots)),
        }
    }

    #[must_use]
    pub fn slots(&self) -> usize {
        self.meta.len()
    }

    /// Whether the store has the system call headers, so that [`RxBatch::recv`] reads in batches.
    #[must_use]
    pub fn batched(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.headers.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// The bytes allocated, for the test that checks the memory bound's term.
    #[cfg(test)]
    pub fn allocated(&self) -> usize {
        #[cfg(target_os = "linux")]
        let headers = self.headers.as_ref().map_or(0, sys::Headers::allocated);
        #[cfg(not(target_os = "linux"))]
        let headers = 0;
        self.data.len() + self.plain.len() + size_of_val(&*self.meta) + self.scratch.len() + headers
    }

    /// The bytes of a slot in the dense part.
    #[must_use]
    pub fn dense(&self) -> usize {
        self.dense
    }

    /// Where slot `i`'s spill part begins in `data`.
    fn spill_at(&self, i: usize) -> usize {
        self.slots() * self.dense + i * (RX_SLOT - self.dense)
    }

    /// Calls `f` with each datagram of the first `n` filled slots in order, GRO buffers split into
    /// their segments, its sender, and the plaintext area after what earlier calls wrote; `f`
    /// returns how many bytes it wrote there. Returns the plaintext area's used length.
    pub fn decrypt_each(
        &mut self,
        n: usize,
        mut f: impl FnMut(SocketAddr, &[u8], &mut [u8]) -> usize,
    ) -> usize {
        let slots = self.slots();
        let (dense, spills) = (self.dense, self.spill_at(0));
        let Self {
            data,
            plain,
            meta,
            scratch,
            ..
        } = self;
        let mut end = 0;
        for (i, m) in meta.iter().enumerate().take(n) {
            let Some(from) = m.from else {
                continue;
            };
            let len = (m.len as usize).min(RX_SLOT);
            let (head, tail): (&[u8], &[u8]) = if slots == 1 {
                (&data[..len], &[])
            } else {
                let at = spills + i * (RX_SLOT - dense);
                (
                    &data[i * dense..i * dense + len.min(dense)],
                    &data[at..at + len.saturating_sub(dense)],
                )
            };
            let seg = match m.seg as usize {
                0 => len.max(1),
                s => s,
            };
            let mut start = 0;
            while start < len {
                let stop = (start + seg).min(len);
                let cut = head.len();
                let datagram: &[u8] = if stop <= cut {
                    &head[start..stop]
                } else if start >= cut {
                    &tail[start - cut..stop - cut]
                } else {
                    // 2 つの部分にまたがる datagram だけを写す
                    scratch[..cut - start].copy_from_slice(&head[start..]);
                    scratch[cut - start..stop - start].copy_from_slice(&tail[..stop - cut]);
                    &scratch[..stop - start]
                };
                end += f(from, datagram, &mut plain[end..]);
                start = stop;
            }
        }
        end
    }
}

/// Walks the packets laid one after the other in `plain` and calls `f` on those whose being UDP
/// is `udp`. Returns how many it passed to `f` and how many of the other kind it passed over.
pub fn each_packet(plain: &[u8], udp: bool, mut f: impl FnMut(&[u8])) -> (usize, usize) {
    let mut off = 0;
    let (mut taken, mut others) = (0, 0);
    while let Some(head) = plain.get(off..off + 20) {
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let Some(p) = plain.get(off..off + len).filter(|_| len >= 20) else {
            break;
        };
        if is_udp(p) == udp {
            f(p);
            taken += 1;
        } else {
            others += 1;
        }
        off += len;
    }
    (taken, others)
}

/// Whether an IPv4 packet carries UDP.
pub fn is_udp(packet: &[u8]) -> bool {
    packet.get(9) == Some(&IPPROTO_UDP)
}

/// The send side of the batch store.
pub struct TxBatch {
    /// The packets the layer above wrote, `mtu` bytes per slot.
    packets: Box<[u8]>,
    /// Their lengths.
    lens: Box<[u16]>,
    /// The datagrams the device sealed, in send order, `stride` bytes per slot.
    pub sealed: Box<[u8]>,
    pub out: Box<[Sealed]>,
    pub msgs: Box<[Msg]>,
    #[cfg(target_os = "linux")]
    headers: Option<sys::Headers>,
    mtu: usize,
    pub stride: usize,
    /// Sealed datagrams in the batch.
    pub n_sealed: usize,
    /// Messages laid out, and the first one not sent yet.
    pub n_msgs: usize,
    pub next: usize,
}

impl std::fmt::Debug for TxBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxBatch")
            .field("slots", &self.lens.len())
            .field("n_sealed", &self.n_sealed)
            .field("n_msgs", &self.n_msgs)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl TxBatch {
    /// The store of `slots` slots, with the system call headers when `on` (Linux only), with packets
    /// of up to `mtu` bytes sealed into datagrams of up to `max_datagram` bytes.
    #[must_use]
    pub fn new(slots: usize, on: bool, mtu: usize, max_datagram: usize) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = on;
        Self {
            packets: vec![0; slots * mtu].into_boxed_slice(),
            lens: vec![0; slots].into_boxed_slice(),
            sealed: vec![0; slots * max_datagram].into_boxed_slice(),
            out: vec![EMPTY_SEALED; slots].into_boxed_slice(),
            msgs: vec![EMPTY_MSG; slots].into_boxed_slice(),
            #[cfg(target_os = "linux")]
            headers: on.then(|| sys::Headers::new(slots)),
            mtu,
            stride: max_datagram,
            n_sealed: 0,
            n_msgs: 0,
            next: 0,
        }
    }

    #[must_use]
    pub fn slots(&self) -> usize {
        self.lens.len()
    }

    /// Whether the store has the system call headers, so that [`TxBatch::send`] sends in batches.
    #[must_use]
    pub fn batched(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.headers.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Whether messages of the batch wait to be sent.
    pub fn is_pending(&self) -> bool {
        self.next < self.n_msgs
    }

    /// The packet slot `i`, for the layer above to write into.
    pub fn packet_slot(&mut self, i: usize) -> &mut [u8] {
        &mut self.packets[i * self.mtu..(i + 1) * self.mtu]
    }

    pub fn set_len(&mut self, i: usize, len: usize) {
        self.lens[i] = u16::try_from(len).unwrap_or(0);
    }

    /// Whether the packet in slot `i` carries UDP.
    pub fn is_udp_slot(&self, i: usize) -> bool {
        is_udp(&self.packets[i * self.mtu..(i + 1) * self.mtu])
    }

    /// The packet in slot `i` and the next free sealed slot, borrowed together.
    pub fn seal_slot(&mut self, i: usize) -> (&[u8], &mut [u8]) {
        let len = usize::from(self.lens[i]).min(self.mtu);
        let j = self.n_sealed;
        (
            &self.packets[i * self.mtu..i * self.mtu + len],
            &mut self.sealed[j * self.stride..(j + 1) * self.stride],
        )
    }

    /// Records the datagram just sealed into the next free sealed slot.
    pub fn push_sealed(&mut self, to: SocketAddr, len: usize) {
        self.out[self.n_sealed] = Sealed {
            to,
            len: u32::try_from(len).unwrap_or(0),
        };
        self.n_sealed += 1;
    }

    /// The datagram of sealed slot `j`.
    pub fn datagram(&self, j: usize) -> (SocketAddr, &[u8]) {
        let s = self.out[j];
        let at = j * self.stride;
        (s.to, &self.sealed[at..at + s.len as usize])
    }

    /// Groups the sealed datagrams from slot `from` into messages from message `self.next` on.
    /// With `gso`, a run of datagrams of one length to one address becomes one message, which may
    /// end with one shorter datagram, as UDP GSO allows; without it every datagram is a message.
    pub fn lay_out(&mut self, from: usize, gso: bool) {
        let mut k = self.next;
        let mut s = from;
        while s < self.n_sealed {
            let head = self.out[s];
            let seg = head.len as usize;
            let mut count = 1;
            let mut total = seg;
            if gso {
                while s + count < self.n_sealed && count < GSO_MAX_SEGMENTS {
                    let next = self.out[s + count];
                    let len = next.len as usize;
                    if next.to != head.to || len > seg || total + len > GSO_MAX_BYTES {
                        break;
                    }
                    count += 1;
                    total += len;
                    if len < seg {
                        break;
                    }
                }
            }
            self.msgs[k] = Msg {
                first: u16::try_from(s).unwrap_or(u16::MAX),
                count: u16::try_from(count).unwrap_or(1),
                seg: head.len,
            };
            k += 1;
            s += count;
        }
        self.n_msgs = k;
    }

    /// Lays out again, one datagram per message, from the first message not sent: after the
    /// kernel refused a GSO send.
    pub fn lay_out_without_gso(&mut self) {
        let from = usize::from(self.msgs[self.next].first);
        self.lay_out(from, false);
    }

    /// Empties the batch once every message went out.
    pub fn clear(&mut self) {
        self.n_sealed = 0;
        self.n_msgs = 0;
        self.next = 0;
    }

    /// The bytes allocated, for the test that checks the memory bound's term.
    #[cfg(test)]
    pub fn allocated(&self) -> usize {
        #[cfg(target_os = "linux")]
        let headers = self.headers.as_ref().map_or(0, sys::Headers::allocated);
        #[cfg(not(target_os = "linux"))]
        let headers = 0;
        self.packets.len()
            + size_of_val(&*self.lens)
            + self.sealed.len()
            + size_of_val(&*self.out)
            + size_of_val(&*self.msgs)
            + headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(proto: u8, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        p[9] = proto;
        p
    }

    #[test]
    fn the_store_is_what_store_bytes_counts() {
        let mtu = 9216;
        for (slots, on) in [(1, false), (1, true), (7, true), (MAX_SLOTS, true)] {
            let rx = RxBatch::new(slots, on, mtu + 32);
            let tx = TxBatch::new(slots, on, mtu, mtu + 32);
            assert_eq!(
                rx.allocated() + tx.allocated(),
                store_bytes(slots, on, mtu, mtu + 32),
                "{slots} {on}"
            );
        }
    }

    #[test]
    fn the_packet_walk_splits_udp_from_the_rest_in_order() {
        let mut plain = Vec::new();
        for (proto, len) in [(6, 40), (17, 28), (6, 52), (1, 84), (17, 30)] {
            plain.extend(packet(proto, len));
        }
        let mut udp = Vec::new();
        let counts = each_packet(&plain, true, |p| udp.push(p.len()));
        assert_eq!((udp, counts), (vec![28, 30], (2, 3)));
        let mut rest = Vec::new();
        assert_eq!(each_packet(&plain, false, |p| rest.push(p.len())), (3, 2));
        assert_eq!(rest, vec![40, 52, 84]);
        // 壊れた長さで止まる
        plain.extend([0x45, 0, 0, 10]);
        assert_eq!(each_packet(&plain, false, |_| {}), (3, 2));
    }

    #[test]
    fn runs_of_one_length_become_one_message() {
        let mut t = TxBatch::new(MAX_SLOTS, false, 1408, 1440);
        let a: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let c: SocketAddr = "192.0.2.2:51820".parse().unwrap();
        for (to, len) in [
            (a, 80),
            (a, 1440),
            (a, 1440),
            (a, 1440),
            (a, 600),
            (a, 1440),
            (c, 1440),
            (c, 1440),
        ] {
            t.push_sealed(to, len);
        }
        t.lay_out(0, true);
        let got: Vec<(u16, u16)> = t.msgs[..t.n_msgs]
            .iter()
            .map(|m| (m.first, m.count))
            .collect();
        assert_eq!(got, vec![(0, 1), (1, 4), (5, 1), (6, 2)]);
        t.lay_out(0, false);
        assert_eq!(t.n_msgs, 8);
        // GSO の message の上限の長さで分ける
        t.clear();
        for _ in 0..50 {
            t.push_sealed(a, 1440);
        }
        t.lay_out(0, true);
        let counts: Vec<u16> = t.msgs[..t.n_msgs].iter().map(|m| m.count).collect();
        assert_eq!(counts, vec![45, 5]);
        // 送れなかった message から 1 つずつに並べ直す
        t.next = 1;
        t.lay_out_without_gso();
        assert_eq!((t.next, t.n_msgs), (1, 6));
        assert_eq!(t.msgs[1].first, 45);
    }

    #[test]
    fn datagrams_split_across_the_dense_and_spill_parts_read_back_whole() {
        let mut rx = RxBatch::new(4, false, 100);
        let from: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        // 枠 1 に 250 byte を、密な部分の 100 byte と溢れの部分の 150 byte に分けて置く
        let bytes: Vec<u8> = (0..250u32)
            .map(|b| u8::try_from(b % 251).unwrap())
            .collect();
        rx.data[100..200].copy_from_slice(&bytes[..100]);
        let at = rx.spill_at(1);
        rx.data[at..at + 150].copy_from_slice(&bytes[100..]);
        // 枠 0 は密な部分に収まる 40 byte
        rx.data[..40].copy_from_slice(&bytes[..40]);
        for (seg, want) in [
            (0u32, vec![bytes[..40].to_vec(), bytes.clone()]),
            (
                100,
                vec![
                    bytes[..40].to_vec(),
                    bytes[..100].to_vec(),
                    bytes[100..200].to_vec(),
                    bytes[200..].to_vec(),
                ],
            ),
            (
                80,
                vec![
                    bytes[..40].to_vec(),
                    bytes[..80].to_vec(),
                    bytes[80..160].to_vec(),
                    bytes[160..240].to_vec(),
                    bytes[240..].to_vec(),
                ],
            ),
        ] {
            rx.meta[0] = RxMeta {
                from: Some(from),
                len: 40,
                seg: 0,
            };
            rx.meta[1] = RxMeta {
                from: Some(from),
                len: 250,
                seg,
            };
            let mut got = Vec::new();
            let end = rx.decrypt_each(2, |f, d, out| {
                assert_eq!(f, from);
                got.push(d.to_vec());
                out[..1].copy_from_slice(&d[..1]);
                1
            });
            assert_eq!(got, want, "segment size {seg}");
            assert_eq!(end, want.len());
        }
    }
}
