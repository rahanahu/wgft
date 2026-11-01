//! Linux の `recvmmsg` と `sendmmsg`、UDP の GRO (`UDP_GRO`) と GSO (`UDP_SEGMENT`)。agent のデータプレーンの
//! unsafe はこの module の system call の包みだけに置く。
//!
//! 見出し (`mmsghdr`)、`iovec`、宛先の名前、制御の領域の配列は、バッチの置き場が起動の時に 1 回だけ連続して
//! 確保し ([`Headers`])、呼び出しのたびに使う枠の分だけ書き直す。書き直すのは、カーネルが
//! `msg_namelen` と `msg_controllen` を書き換えるためと、指す先の buffer への raw pointer を呼び出しを
//! またいで持たないためである。
//!
//! 使える crate を見て採らなかった理由は `docs/design/v2/agent-throughput.md` の「バッチの作り」にある。

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;

use crate::{Msg, RxBatch, RxMeta, Sealed, TxBatch};

/// The size of `struct cmsghdr`, and the alignment of a control message.
const CMSG_HDR: usize = size_of::<libc::cmsghdr>();
const CMSG_ALIGN: usize = size_of::<usize>();

const fn cmsg_align(n: usize) -> usize {
    n.next_multiple_of(CMSG_ALIGN)
}

/// `CMSG_SPACE(n)` and `CMSG_LEN(n)`, from the kernel's layout: the header, aligned, then the data.
const fn cmsg_space(n: usize) -> usize {
    cmsg_align(CMSG_HDR) + cmsg_align(n)
}
const fn cmsg_len(n: usize) -> usize {
    cmsg_align(CMSG_HDR) + n
}

/// One message's control area: room for the one control message the data plane sends or reads,
/// `UDP_SEGMENT` (a `u16`) or `UDP_GRO` (an `int`).
const CTRL_LEN: usize = cmsg_space(size_of::<libc::c_int>());

#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Ctrl([u8; CTRL_LEN]);

/// The headers of one batch direction, one of each per slot, allocated once.
pub(crate) struct Headers {
    hdrs: Box<[libc::mmsghdr]>,
    iov: Box<[libc::iovec]>,
    names: Box<[libc::sockaddr_in6]>,
    ctrl: Box<[Ctrl]>,
}

impl std::fmt::Debug for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Headers")
            .field("slots", &self.hdrs.len())
            .finish_non_exhaustive()
    }
}

/// The bytes [`Headers`] holds per slot: two `iovec`, since a receive slot reads into its dense
/// part and its spill part.
pub(crate) const HEADER_BYTES: usize = size_of::<libc::mmsghdr>()
    + 2 * size_of::<libc::iovec>()
    + size_of::<libc::sockaddr_in6>()
    + size_of::<Ctrl>();

const EMPTY_NAME: libc::sockaddr_in6 = libc::sockaddr_in6 {
    sin6_family: 0,
    sin6_port: 0,
    sin6_flowinfo: 0,
    sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
    sin6_scope_id: 0,
};

impl Headers {
    pub(crate) fn new(slots: usize) -> Self {
        // SAFETY: mmsghdr は整数と raw pointer だけの C の構造体で、すべて 0 の値は空の見出し (null の
        // pointer と長さ 0) である。musl の版は名前の無い詰め物の欄を持つので、欄ごとには書けない
        let empty: libc::mmsghdr = unsafe { std::mem::zeroed() };
        Self {
            hdrs: vec![empty; slots].into_boxed_slice(),
            iov: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                2 * slots
            ]
            .into_boxed_slice(),
            names: vec![EMPTY_NAME; slots].into_boxed_slice(),
            ctrl: vec![Ctrl([0; CTRL_LEN]); slots].into_boxed_slice(),
        }
    }

    /// The bytes allocated, for the test that checks the memory bound's term.
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.hdrs.len() * HEADER_BYTES
    }
}

impl RxBatch {
    /// Reads up to `vlen` datagrams from the non-blocking socket `fd` with one `recvmmsg` into the
    /// first slots, and returns how many slots were filled. A store made without headers reads
    /// nothing.
    ///
    /// # Errors
    ///
    /// The system call's error, `WouldBlock` when nothing waits.
    pub fn recv(&mut self, fd: RawFd, vlen: usize) -> io::Result<usize> {
        let parts = Parts {
            slots: self.meta.len(),
            dense: self.dense(),
        };
        let Some(headers) = self.headers.as_mut() else {
            return Ok(0);
        };
        recv(fd, headers, &mut self.data, parts, vlen, &mut self.meta)
    }
}

impl TxBatch {
    /// Sends the messages from `self.next` on to the socket `fd` with one `sendmmsg` and returns
    /// how many the kernel took; it does not move `self.next`. A store made without headers sends
    /// nothing.
    ///
    /// # Errors
    ///
    /// The system call's error when the kernel took none, `WouldBlock` when the socket is full.
    pub fn send(&mut self, fd: RawFd) -> io::Result<usize> {
        let Some(headers) = self.headers.as_mut() else {
            return Ok(0);
        };
        let msgs = &self.msgs[self.next..self.n_msgs];
        send(fd, headers, &self.sealed, self.stride, &self.out, msgs)
    }
}

/// Turns on UDP GRO: the kernel may hand several datagrams of one flow as one buffer with their
/// segment size. Returns whether the kernel took it.
pub fn enable_gro(fd: RawFd) -> bool {
    let on: libc::c_int = 1;
    // SAFETY: 値は呼び出しの間生きている c_int で、長さはその大きさである
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_UDP,
            libc::UDP_GRO,
            (&raw const on).cast(),
            socklen(size_of::<libc::c_int>()),
        )
    };
    rc == 0
}

/// Whether the kernel has UDP GSO (`UDP_SEGMENT`, Linux 4.18 and later) for this socket.
pub fn has_gso(fd: RawFd) -> bool {
    let mut v: libc::c_int = 0;
    let mut len = socklen(size_of::<libc::c_int>());
    // SAFETY: 書き先は呼び出しの間生きている c_int とその長さである
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            (&raw mut v).cast(),
            &raw mut len,
        )
    };
    rc == 0
}

/// A length for a header field whose type differs between the C libraries: `size_t` in glibc,
/// `int` or `socklen_t` in musl.
fn field<T: TryFrom<usize> + Default>(n: usize) -> T {
    T::try_from(n).unwrap_or_default()
}

/// A header field's length as `usize`, whatever its type in this C library.
fn to_usize<T: TryInto<usize>>(n: T) -> usize {
    n.try_into().unwrap_or(0)
}

fn socklen(n: usize) -> libc::socklen_t {
    libc::socklen_t::try_from(n).unwrap_or(libc::socklen_t::MAX)
}

/// The layout of the receive slots in `RxBatch::data`.
#[derive(Clone, Copy)]
struct Parts {
    slots: usize,
    dense: usize,
}

/// Reads up to `vlen` datagrams with one `recvmmsg` into the slots of `data` (laid out as
/// `RxBatch` describes: a dense part and a spill part per slot, or one buffer with one slot), and
/// describes them in `meta`. Returns how many slots were filled.
fn recv(
    fd: RawFd,
    h: &mut Headers,
    data: &mut [u8],
    p: Parts,
    vlen: usize,
    meta: &mut [RxMeta],
) -> io::Result<usize> {
    let slot = crate::RX_SLOT;
    let vlen = vlen
        .min(h.hdrs.len())
        .min(p.slots)
        .min(data.len() / slot)
        .min(meta.len());
    let base = data.as_mut_ptr();
    let spill = slot - p.dense;
    for i in 0..vlen {
        let parts = if p.slots == 1 {
            h.iov[0] = libc::iovec {
                iov_base: base.cast(),
                iov_len: slot,
            };
            1
        } else {
            h.iov[2 * i] = libc::iovec {
                iov_base: base.wrapping_add(i * p.dense).cast(),
                iov_len: p.dense,
            };
            h.iov[2 * i + 1] = libc::iovec {
                iov_base: base.wrapping_add(p.slots * p.dense + i * spill).cast(),
                iov_len: spill,
            };
            2
        };
        let m = &mut h.hdrs[i].msg_hdr;
        m.msg_name = (&raw mut h.names[i]).cast();
        m.msg_namelen = socklen(size_of::<libc::sockaddr_in6>());
        m.msg_iov = &raw mut h.iov[2 * i];
        m.msg_iovlen = field(parts);
        m.msg_control = (&raw mut h.ctrl[i]).cast();
        m.msg_controllen = field(CTRL_LEN);
        m.msg_flags = 0;
        h.hdrs[i].msg_len = 0;
    }
    let count = libc::c_uint::try_from(vlen).unwrap_or(0);
    // SAFETY: 見出しの先頭の vlen 個は、この呼び出しの間生きている名前、iovec、制御の領域を指し、iovec は
    // data の重ならない部分を指す (枠ごとの密な部分と溢れの部分の長さの和は RX_SLOT で、data は枠の数の
    // RX_SLOT 倍である)。どれも長さは確保した大きさ以下である。時間切れは使わない
    let n = unsafe { libc::recvmmsg(fd, h.hdrs.as_mut_ptr(), count, 0, std::ptr::null_mut()) };
    let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
    for (((slot, m), name), ctrl) in meta
        .iter_mut()
        .zip(&h.hdrs[..n])
        .zip(&h.names[..n])
        .zip(&h.ctrl[..n])
    {
        *slot = RxMeta {
            from: name_to_addr(name),
            len: m.msg_len,
            seg: gro_segment(ctrl, to_usize(m.msg_hdr.msg_controllen)),
        };
    }
    Ok(n)
}

/// Sends `msgs` with one `sendmmsg`: each message is the datagrams `first..first + count` of
/// `sealed` (`stride` bytes apart, lengths in `out`) to the address of its first datagram, as one
/// UDP GSO send with the segment size `seg` when it has more than one. Returns how many messages
/// the kernel took; an error means it took none.
fn send(
    fd: RawFd,
    h: &mut Headers,
    sealed: &[u8],
    stride: usize,
    out: &[Sealed],
    msgs: &[Msg],
) -> io::Result<usize> {
    let n = msgs.len().min(h.hdrs.len());
    let base = sealed.as_ptr();
    for (k, msg) in msgs[..n].iter().enumerate() {
        let first = usize::from(msg.first);
        let count = usize::from(msg.count);
        for (s, (iov, sealed)) in h.iov[first..first + count]
            .iter_mut()
            .zip(&out[first..first + count])
            .enumerate()
        {
            *iov = libc::iovec {
                iov_base: base.wrapping_add((first + s) * stride).cast_mut().cast(),
                iov_len: sealed.len as usize,
            };
        }
        h.names[k] = addr_to_name(out[first].to);
        let namelen = match out[first].to {
            SocketAddr::V4(_) => size_of::<libc::sockaddr_in>(),
            SocketAddr::V6(_) => size_of::<libc::sockaddr_in6>(),
        };
        let m = &mut h.hdrs[k].msg_hdr;
        m.msg_name = (&raw mut h.names[k]).cast();
        m.msg_namelen = socklen(namelen);
        m.msg_iov = &raw mut h.iov[first];
        m.msg_iovlen = field(count);
        m.msg_flags = 0;
        if count > 1 {
            write_segment(&mut h.ctrl[k], msg.seg);
            m.msg_control = (&raw mut h.ctrl[k]).cast();
            m.msg_controllen = field(cmsg_space(size_of::<u16>()));
        } else {
            m.msg_control = std::ptr::null_mut();
            m.msg_controllen = 0;
        }
        h.hdrs[k].msg_len = 0;
    }
    let count = libc::c_uint::try_from(n).unwrap_or(0);
    // SAFETY: 見出しの先頭の n 個は、この呼び出しの間生きている名前、制御の領域、iovec を指し、iovec は
    // sealed の中の暗号文を指す。カーネルはそれらを読むだけで、見出しの msg_len だけを書く
    let sent = unsafe { libc::sendmmsg(fd, h.hdrs.as_mut_ptr(), count, 0) };
    usize::try_from(sent).map_err(|_| io::Error::last_os_error())
}

/// `UDP_SEGMENT` with the segment size `seg`, in the kernel's control message layout.
fn write_segment(ctrl: &mut Ctrl, seg: u32) {
    let b = &mut ctrl.0;
    b.fill(0);
    b[..CMSG_ALIGN].copy_from_slice(&cmsg_len(size_of::<u16>()).to_ne_bytes());
    b[CMSG_ALIGN..CMSG_ALIGN + 4].copy_from_slice(&libc::SOL_UDP.to_ne_bytes());
    b[CMSG_ALIGN + 4..CMSG_ALIGN + 8].copy_from_slice(&libc::UDP_SEGMENT.to_ne_bytes());
    let data = cmsg_align(CMSG_HDR);
    let seg = u16::try_from(seg).unwrap_or(u16::MAX);
    b[data..data + 2].copy_from_slice(&seg.to_ne_bytes());
}

/// The segment size of a `UDP_GRO` control message among the first `len` bytes of `ctrl`, or 0
/// when the datagram came alone.
fn gro_segment(ctrl: &Ctrl, len: usize) -> u32 {
    let b = &ctrl.0[..len.min(CTRL_LEN)];
    let mut off = 0;
    while off + CMSG_HDR <= b.len() {
        let word = |at: usize| -> [u8; 4] { [b[at], b[at + 1], b[at + 2], b[at + 3]] };
        let mut size = [0u8; CMSG_ALIGN];
        size.copy_from_slice(&b[off..off + CMSG_ALIGN]);
        let size = usize::from_ne_bytes(size);
        let level = i32::from_ne_bytes(word(off + CMSG_ALIGN));
        let kind = i32::from_ne_bytes(word(off + CMSG_ALIGN + 4));
        if size < CMSG_HDR {
            break;
        }
        let data = off + cmsg_align(CMSG_HDR);
        if level == libc::SOL_UDP && kind == libc::UDP_GRO && data + 4 <= b.len() {
            return u32::try_from(i32::from_ne_bytes(word(data))).unwrap_or(0);
        }
        off += cmsg_align(size);
    }
    0
}

/// The address the kernel wrote into a name buffer. An IPv4 socket writes a `sockaddr_in`, whose
/// address lies where `sockaddr_in6` has its flow label.
fn name_to_addr(n: &libc::sockaddr_in6) -> Option<SocketAddr> {
    let port = u16::from_be(n.sin6_port);
    match i32::from(n.sin6_family) {
        libc::AF_INET => Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(n.sin6_flowinfo.to_ne_bytes()),
            port,
        ))),
        libc::AF_INET6 => Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(n.sin6_addr.s6_addr),
            port,
            u32::from_be(n.sin6_flowinfo),
            n.sin6_scope_id,
        ))),
        _ => None,
    }
}

/// `to` as a name buffer: a `sockaddr_in` in the first bytes for IPv4, a `sockaddr_in6` for IPv6.
fn addr_to_name(to: SocketAddr) -> libc::sockaddr_in6 {
    match to {
        SocketAddr::V4(a) => libc::sockaddr_in6 {
            sin6_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap_or(0),
            sin6_port: a.port().to_be(),
            sin6_flowinfo: u32::from_ne_bytes(a.ip().octets()),
            ..EMPTY_NAME
        },
        SocketAddr::V6(a) => libc::sockaddr_in6 {
            sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).unwrap_or(0),
            sin6_port: a.port().to_be(),
            sin6_flowinfo: a.flowinfo().to_be(),
            sin6_addr: libc::in6_addr {
                s6_addr: a.ip().octets(),
            },
            sin6_scope_id: a.scope_id(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_control_layout_matches_libc() {
        // SAFETY: 引数の長さから値を計算するだけである
        let (space_int, space_u16, len_u16) = unsafe {
            (
                libc::CMSG_SPACE(4) as usize,
                libc::CMSG_SPACE(2) as usize,
                libc::CMSG_LEN(2) as usize,
            )
        };
        assert_eq!(CTRL_LEN, space_int);
        assert_eq!(cmsg_space(2), space_u16);
        assert_eq!(cmsg_len(2), len_u16);
    }

    #[test]
    fn names_round_trip() {
        for a in [
            "192.0.2.7:51820".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ] {
            assert_eq!(name_to_addr(&addr_to_name(a)), Some(a));
        }
        assert_eq!(name_to_addr(&EMPTY_NAME), None);
    }

    #[test]
    fn a_segment_control_message_reads_back_as_gro() {
        let mut c = Ctrl([0; CTRL_LEN]);
        write_segment(&mut c, 1452);
        // 同じ形で種類だけ GRO にして、読む側を確かめる。値は int なので 4 byte で読む
        c.0[CMSG_ALIGN + 4..CMSG_ALIGN + 8].copy_from_slice(&libc::UDP_GRO.to_ne_bytes());
        let data = cmsg_align(CMSG_HDR);
        c.0[data..data + 4].copy_from_slice(&1452i32.to_ne_bytes());
        assert_eq!(gro_segment(&c, CTRL_LEN), 1452);
        assert_eq!(gro_segment(&c, 0), 0);
    }
}
