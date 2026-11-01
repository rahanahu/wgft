//! 中継の LAN の側のカーネルの TCP ソケット。Go の `internal/netpipe` の Linux の部分を写す。
//!
//! - 受信のバッファ:トンネルの側の接続が boost の枠を持つ間は大きく、持たない間は floor に固定し、窓の
//!   上限を置く (Go の `FollowBoost`)。floor を超える受信のデータを持つ間は floor に戻さず、核に枠を返させ
//!   ない ([`LanConn`] が核の hook に答える)
//! - 中継の終わり:受信のメモリを持てば RST で終え、持たなければ読み書きだけを止めて送信のキューの後ろの
//!   FIN を残す ([`stop`]、Go の `stopKernel`)。届け終えたかは送信のキューの量と状態で読む
//!   ([`delivered`]、Go の `kernelDelivered`)
//!
//! Linux 以外は何もせず、中継の終わりに通常の close で閉じる。Go と同じである。

use std::rc::Rc;

use tokio::net::TcpStream;
use wgft_netstack::LanSocket;

/// The receive buffer the LAN socket asks for while the tunnel side has no boost slot. Linux
/// doubles it.
#[cfg(target_os = "linux")]
pub(crate) const RECV_FLOOR: usize = 128 << 10;

/// The receive buffer the LAN socket asks for while the tunnel side holds a boost slot.
#[cfg(target_os = "linux")]
pub(crate) const RECV_BOOST: usize = 4 << 20;

/// The window clamp of the LAN socket, the size of the wgstack's boost receive buffer.
#[cfg(target_os = "linux")]
pub(crate) const BOOST_WINDOW: usize = 4 << 20;

/// The LAN socket of a relayed connection, as the core's boost hook sees it.
#[derive(Debug)]
pub struct LanConn {
    sock: Rc<TcpStream>,
    /// 受信のバッファを boost の大きさに固定しているか。
    boosted: bool,
}

impl LanConn {
    /// Pairs the hook with `sock` and fixes its receive buffer at the floor with the window clamp,
    /// as Go's `OnBoost` does by calling its function with the current state at once. Without it,
    /// the kernel autotunes the buffer up to `net.ipv4.tcp_rmem`'s maximum while the tunnel side
    /// stalls, on every relayed connection. The relay makes it before the first read.
    #[must_use]
    pub fn new(sock: Rc<TcpStream>) -> Self {
        sys::fix(&sock, false);
        Self {
            sock,
            boosted: false,
        }
    }
}

impl LanSocket for LanConn {
    fn boost_granted(&mut self) {
        sys::fix(&self.sock, true);
        self.boosted = true;
    }

    fn may_return(&mut self) -> bool {
        if !self.boosted {
            return true;
        }
        let ok = sys::refix_floor(&self.sock);
        if ok {
            self.boosted = false;
        }
        ok
    }

    fn boost_returned(&mut self) {
        if self.boosted {
            sys::fix(&self.sock, false);
            self.boosted = false;
        }
    }
}

/// How [`stop`] left the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stopped {
    /// Reading and writing stopped; the socket still delivers its send queue and FIN, and closes
    /// when dropped.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "only Linux holds a stopped socket")
    )]
    Held,
    /// The socket ends when dropped: with a RST when it held received data, or with a plain close
    /// on systems that cannot hold it. There is nothing to wait for.
    Closing,
}

/// Stops the LAN socket at the end of a relay, as Go's `stopKernel` does on Linux.
pub(super) fn stop(sock: &TcpStream) -> Stopped {
    sys::stop(sock)
}

/// Whether the LAN socket that [`stop`] held has delivered its send queue and FIN, or is closed.
pub(super) fn delivered(sock: &TcpStream) -> bool {
    sys::delivered(sock)
}

#[cfg(target_os = "linux")]
mod sys {
    use std::os::fd::{AsRawFd, RawFd};
    use std::time::Duration;

    use socket2::SockRef;
    use tokio::net::TcpStream;

    use super::{BOOST_WINDOW, RECV_BOOST, RECV_FLOOR, Stopped};

    /// floor の実効の値。Linux は SO_RCVBUF の要求の 2 倍を置く。
    const FLOOR_BYTES: usize = 2 * RECV_FLOOR;

    /// Linux の `include/net/tcp_states.h` の TCP_CLOSE。
    const TCP_CLOSE: u8 = 7;

    fn set_int(fd: RawFd, level: libc::c_int, option: libc::c_int, value: usize) -> bool {
        let value = libc::c_int::try_from(value).unwrap_or(libc::c_int::MAX);
        // SAFETY: 値は呼び出しの間生きている c_int で、長さはその大きさである。記述子は呼び手が持つ
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                (&raw const value).cast(),
                libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4),
            )
        };
        rc == 0
    }

    /// 受信のバッファを floor か boost に固定し、窓の上限を置く。SO_RCVBUFFORCE を先に試し、権限が無ければ
    /// SO_RCVBUF にする (Go の `fix`)。
    pub(super) fn fix(sock: &TcpStream, boost: bool) {
        let fd = sock.as_raw_fd();
        let n = if boost { RECV_BOOST } else { RECV_FLOOR };
        if !set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, n) {
            set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, n);
        }
        set_int(fd, libc::IPPROTO_TCP, libc::TCP_WINDOW_CLAMP, BOOST_WINDOW);
    }

    /// 受信のメモリ (受信のキューと順序外のキューの segment の truesize の和) と受信のバッファ。
    fn mem_info(sock: &TcpStream) -> Option<(usize, usize)> {
        let mut m = [0u32; 9];
        let mut len = libc::socklen_t::try_from(size_of_val(&m)).ok()?;
        // SAFETY: 書き先は呼び出しの間生きている配列で、長さはその大きさである。記述子は sock が持つ
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MEMINFO,
                m.as_mut_ptr().cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let rmem = m[usize::try_from(libc::SK_MEMINFO_RMEM_ALLOC).ok()?];
        let rcvbuf = m[usize::try_from(libc::SK_MEMINFO_RCVBUF).ok()?];
        Some((usize::try_from(rmem).ok()?, usize::try_from(rcvbuf).ok()?))
    }

    /// boost から floor に戻す。受信のメモリが floor を超えていれば触らずに偽を返す。下げた後にもう一度
    /// 確かめ、収まらなければ boost に戻して偽を返す (Go の `refix`)。
    pub(super) fn refix_floor(sock: &TcpStream) -> bool {
        if mem_info(sock).is_none_or(|(rmem, _)| rmem > FLOOR_BYTES) {
            return false;
        }
        fix(sock, false);
        if mem_info(sock).is_some_and(|(rmem, rcvbuf)| rcvbuf <= FLOOR_BYTES && rmem <= FLOOR_BYTES)
        {
            return true;
        }
        fix(sock, true);
        false
    }

    /// 受信のメモリを持つか読めない接続は RST で終える。持たなければ読み書きを止め、その後に届いたデータが
    /// あれば RST で終える。
    pub(super) fn stop(sock: &TcpStream) -> Stopped {
        let reset = || {
            let _ = SockRef::from(sock).set_linger(Some(Duration::ZERO));
            Stopped::Closing
        };
        if mem_info(sock).is_none_or(|(rmem, _)| rmem != 0) {
            return reset();
        }
        if SockRef::from(sock)
            .shutdown(std::net::Shutdown::Both)
            .is_err()
        {
            return reset();
        }
        if mem_info(sock).is_none_or(|(rmem, _)| rmem != 0) {
            return reset();
        }
        Stopped::Held
    }

    /// 送信のキューの量 (自分の FIN を含む) が 0 か、状態が CLOSE なら真。読めなければ真。
    pub(super) fn delivered(sock: &TcpStream) -> bool {
        let fd = sock.as_raw_fd();
        // SAFETY: tcp_info は整数だけの C の構造体で、0 の値が有効である
        let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = libc::socklen_t::try_from(size_of::<libc::tcp_info>()).unwrap_or(0);
        // SAFETY: 書き先は呼び出しの間生きている tcp_info で、長さはその大きさである。記述子は sock が持つ
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                (&raw mut info).cast(),
                &raw mut len,
            )
        };
        if rc == 0 && info.tcpi_state == TCP_CLOSE {
            return true;
        }
        let mut queued: libc::c_int = 0;
        // SAFETY: 書き先は呼び出しの間生きている c_int である。記述子は sock が持つ
        let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &raw mut queued) };
        rc == 0 && queued == 0
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    use tokio::net::TcpStream;

    use super::Stopped;

    pub(super) fn fix(_sock: &TcpStream, _boost: bool) {}

    pub(super) fn refix_floor(_sock: &TcpStream) -> bool {
        true
    }

    pub(super) fn stop(_sock: &TcpStream) -> Stopped {
        Stopped::Closing
    }

    pub(super) fn delivered(_sock: &TcpStream) -> bool {
        true
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;
    use std::rc::Rc;

    use super::*;

    fn get_int(sock: &TcpStream, level: libc::c_int, option: libc::c_int) -> usize {
        let mut v: libc::c_int = 0;
        let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap();
        // SAFETY: 書き先は呼び出しの間生きている c_int で、長さはその大きさである
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                level,
                option,
                (&raw mut v).cast(),
                &raw mut len,
            )
        };
        assert_eq!(rc, 0);
        usize::try_from(v).unwrap()
    }

    /// 組にした時点で受信のバッファを floor に固定し、窓の上限を置く。boost で広げ、floor に戻す。
    #[tokio::test]
    async fn the_lan_socket_is_fixed_at_the_floor_when_paired() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sock = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let _peer = l.accept().await.unwrap();
        let sock = Rc::new(sock);
        let mut conn = LanConn::new(Rc::clone(&sock));
        assert_eq!(
            get_int(&sock, libc::SOL_SOCKET, libc::SO_RCVBUF),
            2 * RECV_FLOOR
        );
        assert_eq!(
            get_int(&sock, libc::IPPROTO_TCP, libc::TCP_WINDOW_CLAMP),
            BOOST_WINDOW
        );
        conn.boost_granted();
        // 権限が無ければ SO_RCVBUF は net.core.rmem_max で切り詰められる
        assert!(get_int(&sock, libc::SOL_SOCKET, libc::SO_RCVBUF) > 2 * RECV_FLOOR);
        assert!(conn.may_return());
        assert_eq!(
            get_int(&sock, libc::SOL_SOCKET, libc::SO_RCVBUF),
            2 * RECV_FLOOR
        );
    }
}
