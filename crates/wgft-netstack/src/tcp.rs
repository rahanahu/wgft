//! TCP の handle。待ち受けと接続の操作を核の待たない操作に写し、`WouldBlock` を waker の表での待ちにします。
//!
//! どの future も、核の操作を 1 回の poll の中で終えます。核の操作は進んだか (`Ready`)、何も変えずに
//! `WouldBlock` を返して waker を登録したか (`Pending`) のどちらかなので、future をどの時点で落としても核の
//! 状態は一貫しています。落とした future の waker は表に残り、次の知らせで一度だけ起こされるか、handle を
//! 閉じる時に捨てられます。

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddrV4;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wgft_wgstack::{ConnId, Error, ListenerId};

use crate::Access;
use crate::error::{io_error, poisoned};

/// A TCP listener on the tunnel address. Dropping it closes the listener, which resets the
/// connections it has not accepted yet.
pub struct TcpListener<A: Access> {
    access: A,
    id: ListenerId,
    addr: SocketAddrV4,
}

impl<A: Access> fmt::Debug for TcpListener<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpListener")
            .field("id", &self.id)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl<A: Access> TcpListener<A> {
    /// Listens on `addr`, which must be the tunnel address.
    ///
    /// # Errors
    ///
    /// Fails when the address is not the tunnel's, the port is 0 or in use, or the generation
    /// has ended.
    pub fn bind(access: &A, addr: SocketAddrV4) -> io::Result<Self> {
        if access.is_poisoned() {
            return Err(poisoned());
        }
        let id = access.with(|ns| {
            ns.wakers
                .open_port(addr.port())
                .map_err(|_| Error::NoMemory)?;
            let now = ns.now();
            ns.core_mut().listen_tcp(now, addr)
        });
        Ok(Self {
            access: access.clone(),
            id: id.map_err(io_error)?,
            addr,
        })
    }

    /// The core's handle of this listener.
    pub fn id(&self) -> ListenerId {
        self.id
    }

    /// The address it listens on.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// Takes the next connection from the accept queue, or registers `cx` to be woken when one
    /// arrives.
    pub fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(TcpStream<A>, SocketAddrV4)>> {
        if self.access.is_poisoned() {
            return Poll::Ready(Err(poisoned()));
        }
        let id = self.id;
        let r = self.access.with(|ns| {
            let now = ns.now();
            let r = ns.core_mut().accept(now, id);
            if r == Err(Error::WouldBlock) {
                ns.wakers.accept(id.port(), cx.waker());
            }
            r
        });
        match r {
            Ok((conn, peer)) => {
                // accept は出力を生みません。boost を accept の時に与える方針で受信のバッファが広がっても、
                // 窓の更新は最初の読み取りが送ります。
                Poll::Ready(Ok((TcpStream::new(self.access.clone(), conn), peer)))
            }
            Err(Error::WouldBlock) => Poll::Pending,
            Err(e) => Poll::Ready(Err(io_error(e))),
        }
    }

    /// Waits for the next connection. Cancel-safe: a connection is taken from the queue only
    /// when the future completes.
    pub async fn accept(&mut self) -> io::Result<(TcpStream<A>, SocketAddrV4)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
}

impl<A: Access> Drop for TcpListener<A> {
    fn drop(&mut self) {
        if self.access.is_poisoned() {
            return;
        }
        let id = self.id;
        self.access.with(|ns| {
            let now = ns.now();
            ns.core_mut().close_listener(now, id);
            ns.wakers.clear_accept(id.port());
        });
        self.access.wake_driver();
    }
}

/// A TCP connection accepted from the tunnel.
///
/// Reads and writes copy between the caller's buffer and the core's rings.
///
/// Dropping the stream without [`TcpStream::close`] or [`TcpStream::abort`]:
///
/// - after the sending direction was closed ([`TcpStream::close_write`] or tokio's `shutdown`),
///   and not while a panic unwinds: closes the connection as [`TcpStream::close`] does, so the
///   data already written is still delivered. As on Linux, unread received data turns the close
///   into a RST
/// - otherwise: aborts the connection with a RST, which is how the relay ends a connection when
///   its rule goes away or its task is cancelled or panics
pub struct TcpStream<A: Access> {
    access: A,
    id: ConnId,
    /// `close` か `abort` で閉じた後は偽です。`Drop` はそれから何もしません。
    open: bool,
    /// 送信の向きを閉じたかです。閉じた後に落とした stream は RST でなく `close` で閉じます。
    write_shut: bool,
}

impl<A: Access> fmt::Debug for TcpStream<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<A: Access> TcpStream<A> {
    fn new(access: A, id: ConnId) -> Self {
        Self {
            access,
            id,
            open: true,
            write_shut: false,
        }
    }

    /// The core's handle of this connection. [`ConnId::index`] is a stable position for tables
    /// kept beside the core, such as the [`LanSockets`](crate::LanSockets).
    pub fn id(&self) -> ConnId {
        self.id
    }

    /// The tunnel side's address, or `None` once the core has freed the connection.
    pub fn local_addr(&self) -> Option<SocketAddrV4> {
        let id = self.id;
        if self.access.is_poisoned() {
            return None;
        }
        self.access.with(|ns| ns.core().local_addr(id))
    }

    /// The peer's address, or `None` once the core has freed the connection.
    pub fn peer_addr(&self) -> Option<SocketAddrV4> {
        let id = self.id;
        if self.access.is_poisoned() {
            return None;
        }
        self.access.with(|ns| ns.core().peer_addr(id))
    }

    /// Copies unread data into `dst`, or registers `cx` to be woken when there is some. Returns 0
    /// at the end of the stream, or when `dst` is empty.
    pub fn poll_read_bytes(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.access.is_poisoned() {
            return Poll::Ready(Err(poisoned()));
        }
        let id = self.id;
        let r = self.access.with(|ns| {
            let now = ns.now();
            let r = ns.core_mut().read(now, id, dst);
            if r == Err(Error::WouldBlock) {
                ns.wakers.conn_read(id, cx.waker());
            }
            r
        });
        match r {
            Ok(n) => {
                if n > 0 {
                    // 読んだ分だけ窓が開くので、窓の更新を送らせます。
                    self.access.wake_driver();
                }
                Poll::Ready(Ok(n))
            }
            Err(Error::WouldBlock) => Poll::Pending,
            Err(e) => Poll::Ready(Err(io_error(e))),
        }
    }

    /// Copies as much of `src` as fits into the send buffer and returns how much, or registers
    /// `cx` to be woken when there is room.
    pub fn poll_write_bytes(
        &mut self,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.access.is_poisoned() {
            return Poll::Ready(Err(poisoned()));
        }
        let id = self.id;
        let r = self.access.with(|ns| {
            let now = ns.now();
            let r = ns.core_mut().write(now, id, src);
            if r == Err(Error::WouldBlock) {
                ns.wakers.conn_write(id, cx.waker());
            }
            r
        });
        match r {
            Ok(n) => {
                if n > 0 {
                    self.access.wake_driver();
                }
                Poll::Ready(Ok(n))
            }
            Err(Error::WouldBlock) => Poll::Pending,
            Err(e) => Poll::Ready(Err(io_error(e))),
        }
    }

    /// Reads into `dst`; see [`TcpStream::poll_read_bytes`]. Cancel-safe: data is taken from the
    /// core only when the future completes.
    pub async fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_read_bytes(cx, dst)).await
    }

    /// Writes from `src`; see [`TcpStream::poll_write_bytes`]. Cancel-safe: data enters the core
    /// only when the future completes.
    pub async fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_write_bytes(cx, src)).await
    }

    /// Closes the sending direction: a FIN follows the data already written. Reading goes on.
    ///
    /// # Errors
    ///
    /// Fails when the connection is closed or the generation has ended.
    pub fn close_write(&mut self) -> io::Result<()> {
        if self.access.is_poisoned() {
            return Err(poisoned());
        }
        let id = self.id;
        let r = self.access.with(|ns| {
            let now = ns.now();
            ns.core_mut().close_write(now, id)
        });
        self.access.wake_driver();
        if r.is_ok() {
            self.write_shut = true;
        }
        r.map_err(io_error)
    }

    /// Closes the connection: a FIN follows the data already written, or a RST when unread data
    /// is left, as Linux does. The connection keeps its slot until it has delivered what it
    /// sent; [`Closing::delivered`] tells when.
    pub fn close(mut self) -> Closing<A> {
        self.open = false;
        close(&self.access, self.id);
        Closing {
            access: self.access.clone(),
            id: self.id,
        }
    }

    /// Resets the connection and frees its slot at once.
    pub fn abort(mut self) {
        self.open = false;
        abort(&self.access, self.id, true);
    }
}

/// 接続 `id` を閉じます。送り残しの後ろに FIN を置き、未読のデータがあれば RST で終えます。handle はまだ枠を
/// 持つので、枠の waker を捨てます。
fn close<A: Access>(access: &A, id: ConnId) {
    if access.is_poisoned() {
        return;
    }
    access.with(|ns| {
        let now = ns.now();
        ns.core_mut().close_conn(now, id);
        ns.wakers.clear_conn(id);
    });
    access.wake_driver();
}

/// 接続 `id` を RST で終えます。`owned` は handle がまだ枠を持つ (閉じていない) ことで、そのときだけ枠の waker を
/// 捨てます。閉じた後の枠は別の接続に使われているかもしれず、その接続の waker を捨てると知らせを失うためです。
fn abort<A: Access>(access: &A, id: ConnId, owned: bool) {
    if access.is_poisoned() {
        return;
    }
    access.with(|ns| {
        let now = ns.now();
        ns.core_mut().abort(now, id);
        if owned {
            ns.wakers.clear_conn(id);
        }
    });
    access.wake_driver();
}

impl<A: Access> Drop for TcpStream<A> {
    fn drop(&mut self) {
        if !self.open {
            return;
        }
        if self.write_shut && !std::thread::panicking() {
            close(&self.access, self.id);
        } else {
            abort(&self.access, self.id, true);
        }
    }
}

impl<A: Access> AsyncRead for TcpStream<A> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let dst = buf.initialize_unfilled();
        match this.poll_read_bytes(cx, dst) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<A: Access> AsyncWrite for TcpStream<A> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_bytes(cx, buf)
    }

    /// The core sends what is written without being asked, so there is nothing to flush.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Closes the sending direction, as [`TcpStream::close_write`] does. Dropping the stream after
    /// this closes it gracefully instead of aborting it.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().close_write())
    }
}

/// A connection closed with [`TcpStream::close`] that may still be delivering what it sent.
/// Dropping it leaves the connection to finish on its own.
pub struct Closing<A: Access> {
    access: A,
    id: ConnId,
}

impl<A: Access> fmt::Debug for Closing<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Closing")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<A: Access> Closing<A> {
    /// The core's handle of the closed connection.
    pub fn id(&self) -> ConnId {
        self.id
    }

    /// Whether the connection has delivered its data and FIN, or holds nothing any more. The
    /// core does not announce this, so the relay asks again with a backoff, as the Go agent does.
    pub fn delivered(&self) -> bool {
        let id = self.id;
        self.access.is_poisoned() || self.access.with(|ns| ns.core().delivered(id))
    }

    /// Resets the connection, also after it has moved to the TIME_WAIT table.
    pub fn abort(self) {
        abort(&self.access, self.id, false);
    }
}
