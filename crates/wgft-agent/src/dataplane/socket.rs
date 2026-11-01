//! WireGuard の UDP のソケット。開き方、バッファの要求と測定と警告、Windows の `SIO_UDP_CONNRESET`。
//!
//! バッファの規則の正本は `docs/design/userspace/socket-buffers.md` で、Go の
//! `internal/dataplane/userspace/sockbuf` と同じ値と文面を使う。Go の agent は wireguard-go の
//! ソケットを自分の記述子から探して測るが、Rust の agent はソケットを自分で開くので、開いた
//! ソケットをそのまま測る。

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

/// The receive and send buffer the data plane asks for, as wireguard-go does: 7 MiB.
pub const REQUESTED: usize = 7 << 20;

/// The effective buffer a socket that got [`REQUESTED`] reports on Linux, which doubles the
/// request: the requirement of userspace mode.
pub const REQUIRED: usize = 2 * REQUESTED;

/// One measurement of the WireGuard UDP socket's buffers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketBuffers {
    /// Whether this system has a way to measure them. Only Linux does; the other fields mean
    /// nothing otherwise.
    pub supported: bool,
    /// The socket's local port.
    pub port: u16,
    /// The effective receive buffer in bytes.
    pub recv: usize,
    /// The effective send buffer in bytes.
    pub send: usize,
    /// Why the buffers could not be read. `recv` and `send` mean nothing when it is set.
    pub error: Option<String>,
}

impl SocketBuffers {
    /// Whether the buffers were read.
    #[must_use]
    pub fn measured(&self) -> bool {
        self.supported && self.error.is_none()
    }

    /// Whether both buffers reach [`REQUIRED`].
    #[must_use]
    pub fn met(&self) -> bool {
        self.measured() && self.recv >= REQUIRED && self.send >= REQUIRED
    }

    /// The warning line for a socket below the requirement or one that could not be measured, in
    /// the Go agent's words; `None` when the requirement is met or cannot be checked here.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        if !self.supported || self.met() {
            return None;
        }
        if let Some(e) = &self.error {
            return Some(format!(
                "warning: cannot measure the WireGuard UDP socket buffers: {e}; userspace mode requires {REQUIRED} bytes each for receive and send"
            ));
        }
        Some(format!(
            "warning: the WireGuard UDP sockets on port {} got a receive buffer of {} bytes and a send buffer of {} bytes; \
             userspace mode requires {REQUIRED} bytes each. Set net.core.rmem_max and net.core.wmem_max to {REQUESTED} or more on this host, \
             or on the container host for a container, then restart; wgft never changes these sysctls",
            self.port, self.recv, self.send
        ))
    }
}

/// Logs [`SocketBuffers::warning`] at most once a minute in the process, so that a tunnel rebuilt
/// again and again does not repeat the line.
pub(crate) fn warn(buffers: &SocketBuffers) {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let Some(line) = buffers.warning() else {
        return;
    };
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    if last.is_some_and(|at| now.duration_since(at) < Duration::from_mins(1)) {
        return;
    }
    *last = Some(now);
    crate::logf!("{line}");
}

/// Opens the non-blocking UDP socket bound to `listen`, after asking for [`REQUESTED`] bytes of
/// receive and send buffer, and on Linux also with the FORCE options that pass only with
/// `CAP_NET_ADMIN` in the initial user namespace. Errors of these requests are ignored, as
/// wireguard-go ignores them; the measurement shows the outcome.
pub(crate) fn open(listen: SocketAddr) -> io::Result<(std::net::UdpSocket, SocketBuffers)> {
    let socket = Socket::new(
        Domain::for_address(listen),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_recv_buffer_size(REQUESTED);
    let _ = socket.set_send_buffer_size(REQUESTED);
    #[cfg(target_os = "linux")]
    force_buffers(&socket);
    #[cfg(windows)]
    if let Err(e) = disable_connection_reset(&socket) {
        // トンネルを作り直すたびに並ばないよう、プロセスで 1 回だけ出す
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            crate::logf!(
                "warning: cannot turn off connection reset reports on the WireGuard UDP socket: {e}; receive errors are counted and skipped"
            );
        });
    }
    socket.bind(&listen.into())?;
    let port = socket.local_addr()?.as_socket().map_or(0, |a| a.port());
    let buffers = measure(&socket, port);
    Ok((socket.into(), buffers))
}

#[cfg(target_os = "linux")]
fn measure(socket: &Socket, port: u16) -> SocketBuffers {
    let read = || -> io::Result<(usize, usize)> {
        Ok((socket.recv_buffer_size()?, socket.send_buffer_size()?))
    };
    match read() {
        Ok((recv, send)) => SocketBuffers {
            supported: true,
            port,
            recv,
            send,
            error: None,
        },
        Err(e) => SocketBuffers {
            supported: true,
            port,
            recv: 0,
            send: 0,
            error: Some(e.to_string()),
        },
    }
}

/// Linux 以外では測らない (socket-buffers.md の Linux 以外でのバッファの条件)。
#[cfg(not(target_os = "linux"))]
fn measure(_socket: &Socket, port: u16) -> SocketBuffers {
    SocketBuffers {
        supported: false,
        port,
        recv: 0,
        send: 0,
        error: None,
    }
}

#[cfg(target_os = "linux")]
fn force_buffers(socket: &Socket) {
    use std::os::fd::AsRawFd;
    let value = libc::c_int::try_from(REQUESTED).unwrap_or(libc::c_int::MAX);
    for option in [libc::SO_RCVBUFFORCE, libc::SO_SNDBUFFORCE] {
        // SAFETY: 値は呼び出しの間生きている c_int で、長さはその大きさである。記述子は socket が持つ
        let _ = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const value).cast(),
                libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4),
            )
        };
    }
}

/// Windows は、送った datagram への ICMP の Port Unreachable を、次の受信の `WSAECONNRESET` として
/// 返す。v1 は受信がこれで止まる故障を避けた (仕様 tunnel.md の受信の goroutine の停止)。その報告を
/// 切る。切れなくても受信の誤りは数えて読み続ける。
#[cfg(windows)]
fn disable_connection_reset(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAIoctl,
    };
    let raw = SOCKET::try_from(socket.as_raw_socket()).map_err(io::Error::other)?;
    // BOOL の FALSE
    let off: i32 = 0;
    let mut returned = 0u32;
    // SAFETY: 入力は呼び出しの間生きている 4 byte の BOOL で、出力の領域は無く、重ねた I/O も使わない。
    // 記述子は socket が持つ
    let rc = unsafe {
        WSAIoctl(
            raw,
            SIO_UDP_CONNRESET,
            (&raw const off).cast(),
            4,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        // SAFETY: 引数を取らず、この thread の最後の誤りを読むだけである
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(recv: usize, send: usize) -> SocketBuffers {
        SocketBuffers {
            supported: true,
            port: 40000,
            recv,
            send,
            error: None,
        }
    }

    #[test]
    fn the_warning_matches_the_go_agent() {
        assert_eq!(
            reading(425_984, 425_984).warning().unwrap(),
            "warning: the WireGuard UDP sockets on port 40000 got a receive buffer of 425984 bytes and a send buffer of 425984 bytes; \
             userspace mode requires 14680064 bytes each. Set net.core.rmem_max and net.core.wmem_max to 7340032 or more on this host, \
             or on the container host for a container, then restart; wgft never changes these sysctls"
        );
        assert_eq!(reading(REQUIRED, REQUIRED).warning(), None);
        assert!(reading(REQUIRED, REQUIRED - 1).warning().is_some());
        let mut failed = reading(0, 0);
        failed.error = Some("bad descriptor".into());
        assert_eq!(
            failed.warning().unwrap(),
            "warning: cannot measure the WireGuard UDP socket buffers: bad descriptor; userspace mode requires 14680064 bytes each for receive and send"
        );
        let mut unsupported = reading(0, 0);
        unsupported.supported = false;
        assert_eq!(unsupported.warning(), None);
        assert!(!unsupported.met());
    }

    #[test]
    fn open_binds_and_measures_on_linux_only() {
        let (socket, buffers) = open("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        assert_eq!(buffers.port, port);
        assert_eq!(buffers.supported, cfg!(target_os = "linux"));
        if buffers.supported {
            assert!(buffers.measured());
            assert!(buffers.recv > 0 && buffers.send > 0, "{buffers:?}");
        }
    }

    /// 同じプロセスの中で Windows の受信が止まらないことは、閉じたポートへ送った後も読めることで見る。
    /// Windows 以外では ICMP の誤りを未接続のソケットに返さないので、同じ試験がそのまま通る。
    #[test]
    fn a_send_to_a_closed_port_does_not_stop_receiving() {
        let (socket, _) = open("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let closed = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);
        socket.send_to(b"nobody", closed_addr).unwrap();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"hello", socket.local_addr().unwrap())
            .unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = socket.recv_from(&mut buf).unwrap();
        assert_eq!(
            (&buf[..n], from),
            (&b"hello"[..], peer.local_addr().unwrap())
        );
    }
}
