//! Unix の 1 つずつの受信 (`recvmsg`) と、受けた datagram の IP の TOS を制御の message で受ける設定
//! (`IP_RECVTOS`)。バッチを使わない道 (macOS と、Linux の `WGFT_AGENT_BATCH_MIB=0`) が使う。Linux の
//! バッチの道では、[`crate::sys`] の `recvmmsg` が同じ制御の message を読む。
//!
//! 制御の message の並びは libc の `CMSG_*` で辿る。見出しの形と揃え方が Linux と macOS で違うためである。
//! TOS の message の種類は、Linux の `IP_TOS` (ip(7)) と、BSD の系統の `IP_RECVTOS` の両方を受ける。
//! macOS の実機では確かめていない。

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;

use crate::{EMPTY_META, RX_SLOT, RxBatch, RxMeta};

/// The control area of one `recvmsg`: room for the `IP_TOS` message and one more.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Ctrl([u8; 64]);

/// A length for a header field whose type differs between the C libraries: `size_t` in glibc,
/// `int` or `socklen_t` in musl and macOS.
pub(crate) fn field<T: TryFrom<usize> + Default>(n: usize) -> T {
    T::try_from(n).unwrap_or_default()
}

/// A header field's length as `usize`, whatever its type in this C library.
pub(crate) fn to_usize<T: TryInto<usize>>(n: T) -> usize {
    n.try_into().unwrap_or(0)
}

pub(crate) fn socklen(n: usize) -> libc::socklen_t {
    libc::socklen_t::try_from(n).unwrap_or(libc::socklen_t::MAX)
}

/// Asks the IPv4 socket `fd` to hand the TOS byte of each datagram's IP header with it, as a
/// control message that [`RxBatch::recv_one`] and the batch receive read.
///
/// # Errors
///
/// The system call's error; datagrams then read as Not-ECT.
pub fn enable_recv_tos(fd: RawFd) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: 値は呼び出しの間生きている c_int で、長さはその大きさである
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTOS,
            (&raw const on).cast(),
            socklen(size_of::<libc::c_int>()),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl RxBatch {
    /// Reads one datagram with `recvmsg` from the non-blocking socket `fd` into slot 0, laid out as
    /// [`RxBatch::decrypt_each`] reads it, with the ECN field of its IP header when the socket has
    /// [`enable_recv_tos`] on, and returns 1. A datagram or control area the kernel cut short is
    /// counted in `truncated` and leaves the slot empty, as the batch receive does.
    ///
    /// # Errors
    ///
    /// The system call's error, `WouldBlock` when nothing waits.
    pub fn recv_one(&mut self, fd: RawFd) -> io::Result<usize> {
        let (slots, dense, spill) = (self.slots(), self.dense(), self.spill_at(0));
        if slots == 0 {
            return Ok(0);
        }
        let base = self.data.as_mut_ptr();
        // 枠 0 の密な部分と溢れの部分。枠が 1 つなら、2 つの部分は続いて 1 つの buffer になる
        let (mut iov, parts) = if slots == 1 {
            let whole = libc::iovec {
                iov_base: base.cast(),
                iov_len: RX_SLOT,
            };
            ([whole, whole], 1)
        } else {
            (
                [
                    libc::iovec {
                        iov_base: base.cast(),
                        iov_len: dense,
                    },
                    libc::iovec {
                        iov_base: base.wrapping_add(spill).cast(),
                        iov_len: RX_SLOT - dense,
                    },
                ],
                2,
            )
        };
        // SAFETY: sockaddr_storage と msghdr は整数と raw pointer だけの C の構造体で、すべて 0 の値は空の名前と
        // 空の見出し (null の pointer と長さ 0) である。musl と macOS の msghdr は名前の無い詰め物の欄を持つ
        // ので、欄ごとには書けない
        let (mut name, mut msg): (libc::sockaddr_storage, libc::msghdr) =
            unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
        let mut ctrl = Ctrl([0; 64]);
        msg.msg_name = (&raw mut name).cast();
        msg.msg_namelen = socklen(size_of::<libc::sockaddr_storage>());
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = field(parts);
        msg.msg_control = (&raw mut ctrl).cast();
        msg.msg_controllen = field(size_of::<Ctrl>());
        // SAFETY: 見出しは、この呼び出しの間生きている名前、iovec、制御の領域を指し、iovec は data の重ならない
        // 部分を指す (枠 1 つなら先頭の RX_SLOT byte、そうでなければ枠 0 の密な部分と溢れの部分で、どちらも
        // data の中にある)。どれも長さは確保した大きさ以下である
        let n = unsafe { libc::recvmsg(fd, &raw mut msg, 0) };
        let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            self.truncated += 1;
            self.meta[0] = EMPTY_META;
            return Ok(1);
        }
        self.meta[0] = RxMeta {
            from: name_to_addr(&name),
            len: u32::try_from(n).unwrap_or(0),
            seg: 0,
            ecn: read_ecn(&msg),
        };
        Ok(1)
    }
}

/// The ECN field (the low two bits) of the TOS control message that `recvmsg` wrote into `msg`'s
/// control area, or 0 (Not-ECT) when there is none.
fn read_ecn(msg: &libc::msghdr) -> u8 {
    // SAFETY: 引数の長さから値を計算するだけである
    let min_len = to_usize(unsafe { libc::CMSG_LEN(1) });
    // SAFETY: msg の制御の領域は呼び手が持つ Ctrl を指し、msg_controllen は recvmsg が書いた長さである。
    // CMSG_FIRSTHDR はその長さに収まる最初の見出しか null を返す
    let mut c = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !c.is_null() {
        // SAFETY: c は制御の領域の中の、揃った見出しを指す
        let h = unsafe { &*c };
        let tos = h.cmsg_type == libc::IP_TOS || h.cmsg_type == libc::IP_RECVTOS;
        if h.cmsg_level == libc::IPPROTO_IP && tos && to_usize(h.cmsg_len) >= min_len {
            // SAFETY: 見出しの長さは 1 byte の値を含み、CMSG_DATA はその値の先頭を指す
            return unsafe { *libc::CMSG_DATA(c) } & 0b11;
        }
        // SAFETY: c は msg の制御の領域の中の見出しで、CMSG_NXTHDR は同じ領域の中の次の見出しか null を返す
        c = unsafe { libc::CMSG_NXTHDR(msg, c) };
    }
    0
}

/// The sender the kernel wrote into a name buffer.
fn name_to_addr(s: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match i32::from(s.ss_family) {
        libc::AF_INET => {
            // SAFETY: 種類が AF_INET なら、カーネルは先頭に sockaddr_in を書いた。sockaddr_storage はそれより
            // 大きく、揃え方も足りる
            let a = unsafe { &*(&raw const *s).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: 種類が AF_INET6 なら、カーネルは先頭に sockaddr_in6 を書いた。大きさと揃え方は上と同じ
            let a = unsafe { &*(&raw const *s).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                u32::from_be(a.sin6_flowinfo),
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    fn set_tos(socket: &UdpSocket, tos: u8) {
        let v = libc::c_int::from(tos);
        // SAFETY: 値は呼び出しの間生きている c_int で、長さはその大きさである
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                (&raw const v).cast(),
                socklen(size_of::<libc::c_int>()),
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    }

    /// 待っている datagram を 1 つ読む。5 秒で諦める。
    fn read(rx: &mut RxBatch, socket: &UdpSocket) -> usize {
        let start = Instant::now();
        loop {
            match rx.recv_one(socket.as_raw_fd()) {
                Ok(n) => return n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(5), "nothing arrived");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("recvmsg: {e}"),
            }
        }
    }

    #[test]
    fn each_datagram_reads_back_whole_with_its_own_ecn_field() {
        let rx_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_socket.set_nonblocking(true).unwrap();
        enable_recv_tos(rx_socket.as_raw_fd()).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx_socket.local_addr().unwrap();
        // 枠 1 つの置き場と、密な部分 (100 byte) を越える datagram が溢れの部分に続く置き場
        for (slots, len) in [(1, 300), (4, 250)] {
            let mut rx = RxBatch::new(slots, false, 100);
            for tos in [0u8, 0b10, 0b01, 0b11, 0b1011_1011] {
                let payload: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
                set_tos(&tx, tos);
                tx.send_to(&payload, to).unwrap();
                assert_eq!(read(&mut rx, &rx_socket), 1);
                assert_eq!(rx.meta[0].from, Some(tx.local_addr().unwrap()));
                assert_eq!(rx.meta[0].ecn, tos & 0b11, "TOS {tos:#04x}");
                let mut got = Vec::new();
                rx.decrypt_each(1, |_, ecn, d, _| {
                    assert_eq!(ecn, tos & 0b11);
                    got.extend_from_slice(d);
                    0
                });
                assert_eq!(got, payload, "{slots} slots");
            }
        }
    }

    #[test]
    fn without_recv_tos_every_datagram_reads_as_not_ect() {
        let rx_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx_socket.set_nonblocking(true).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_tos(&tx, 0b11);
        tx.send_to(b"ce", rx_socket.local_addr().unwrap()).unwrap();
        let mut rx = RxBatch::new(1, false, 100);
        assert_eq!(read(&mut rx, &rx_socket), 1);
        assert_eq!((rx.meta[0].len, rx.meta[0].ecn), (2, 0));
    }
}
