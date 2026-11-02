//! UDP の handle (agent-parity.md の「wgstack の UDP の口」)。
//!
//! 受け取りは endpoint を持つ 1 つの task が行い、送りは [`UdpSender`] を持つ複数の task が行えます。
//! UDP の中継では、待ち受けの task が受け取り、セッションの task が応答を送るためです。
//! 送りの待ちは核の全 endpoint で 1 つの [`Notify`](tokio::sync::Notify) を分け合います。核は送信の予約が
//! 1 つ返ると待つ endpoint すべてに `UdpWritable` を出すので、全体で 1 つにしても起こす相手は変わりません。

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddrV4;
#[cfg(feature = "harness")]
use std::pin::pin;
#[cfg(feature = "harness")]
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use wgft_wgstack::{Error, UdpId};

use crate::Access;
use crate::error::{io_error, poisoned};
#[cfg(feature = "harness")]
use crate::wakers::UdpWrite;

/// An unconnected UDP endpoint on the tunnel address. Dropping it closes the endpoint, returns
/// the reservations of the datagrams nobody read, and fails the sends that wait on it.
pub struct UdpSocket<A: Access> {
    access: A,
    id: UdpId,
    addr: SocketAddrV4,
}

impl<A: Access> fmt::Debug for UdpSocket<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSocket")
            .field("id", &self.id)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl<A: Access> UdpSocket<A> {
    /// Opens an endpoint on `addr`, which must be the tunnel address.
    ///
    /// # Errors
    ///
    /// Fails when the address is not the tunnel's, the port is 0 or in use, UDP has stopped after
    /// an accounting fault, or the generation has ended.
    pub fn bind(access: &A, addr: SocketAddrV4) -> io::Result<Self> {
        if access.is_poisoned() {
            return Err(poisoned());
        }
        let id = access.with(|ns| {
            ns.wakers
                .open_port(addr.port())
                .map_err(|_| Error::NoMemory)?;
            let now = ns.now();
            ns.core_mut().bind_udp(now, addr)
        });
        Ok(Self {
            access: access.clone(),
            id: id.map_err(io_error)?,
            addr,
        })
    }

    /// The core's handle of this endpoint.
    pub fn id(&self) -> UdpId {
        self.id
    }

    /// The address it is bound to.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// A handle for sending from this endpoint, for other tasks. It fails once the endpoint is
    /// closed.
    pub fn sender(&self) -> UdpSender<A> {
        UdpSender {
            access: self.access.clone(),
            id: self.id,
        }
    }

    /// Copies the next datagram into `dst` and returns its length and sender, or registers `cx`
    /// to be woken when one arrives. A datagram longer than `dst` is cut to fit.
    pub fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddrV4)>> {
        if self.access.is_poisoned() {
            return Poll::Ready(Err(poisoned()));
        }
        let id = self.id;
        let r = self.access.with(|ns| {
            let now = ns.now();
            let r = ns.core_mut().recv_from(now, id, dst);
            if r == Err(Error::WouldBlock) {
                ns.wakers.udp_read(id.port(), cx.waker());
            }
            r
        });
        match r {
            Ok(v) => Poll::Ready(Ok(v)),
            Err(Error::WouldBlock) => Poll::Pending,
            Err(e) => Poll::Ready(Err(io_error(e))),
        }
    }

    /// Waits for the next datagram; see [`UdpSocket::poll_recv_from`]. Cancel-safe: a datagram
    /// leaves the core only when the future completes.
    pub async fn recv_from(&mut self, dst: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        poll_fn(|cx| self.poll_recv_from(cx, dst)).await
    }

    /// Sends `data` as one datagram to `to`; see [`UdpSender::send_to`].
    #[cfg(feature = "harness")]
    pub async fn send_to(&self, data: &[u8], to: SocketAddrV4) -> io::Result<usize> {
        send_to(&self.access, self.id, data, to).await
    }

    /// Sends `data` as one datagram to `to` without waiting; see [`UdpSender::send_to_latest`].
    pub fn send_to_latest(
        &self,
        data: &[u8],
        to: SocketAddrV4,
        max_age: Duration,
    ) -> io::Result<usize> {
        send_to_latest(&self.access, self.id, data, to, max_age)
    }
}

impl<A: Access> Drop for UdpSocket<A> {
    fn drop(&mut self) {
        if self.access.is_poisoned() {
            return;
        }
        let id = self.id;
        let close = |ns: &mut crate::Netstack<A::Hook>| {
            let now = ns.now();
            ns.core_mut().close_udp(now, id);
            ns.wakers.clear_udp_read(id.port());
        };
        // 待っている送り手は試し直して、閉じた誤りを受けます。借用を返した後に起こします。製品の build には
        // 待つ送り手がいない
        #[cfg(feature = "harness")]
        {
            let waiters = self.access.with(|ns| {
                close(ns);
                ns.wakers.udp_write()
            });
            waiters.0.notify_waiters();
        }
        #[cfg(not(feature = "harness"))]
        self.access.with(close);
    }
}

/// A handle for sending from a [`UdpSocket`] in other tasks.
#[derive(Clone)]
pub struct UdpSender<A: Access> {
    access: A,
    id: UdpId,
}

impl<A: Access> fmt::Debug for UdpSender<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSender")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<A: Access> UdpSender<A> {
    /// The core's handle of the endpoint.
    pub fn id(&self) -> UdpId {
        self.id
    }

    /// Sends `data` as one datagram to `to`, waiting while the send budget is used up. Only tests and
    /// the replay of the Go recordings have it; the product sends with [`UdpSender::send_to_latest`]. A
    /// datagram longer than the MTU leaves in fragments. Cancel-safe: the datagram is queued
    /// whole when the future completes, and not at all before.
    ///
    /// # Errors
    ///
    /// Fails when the endpoint is closed, `to` or the length is invalid, UDP has stopped after an
    /// accounting fault, or the generation has ended.
    #[cfg(feature = "harness")]
    pub async fn send_to(&self, data: &[u8], to: SocketAddrV4) -> io::Result<usize> {
        send_to(&self.access, self.id, data, to).await
    }

    /// Sends `data` as one datagram to `to` and never waits. When the send budget is used up, the
    /// oldest queued datagram is dropped to make room: the endpoint's own oldest when its share
    /// is full, the tunnel's oldest when the tunnel's budget is. A datagram that has waited longer
    /// than `max_age` without starting to leave is dropped instead of sent. A zero `max_age`
    /// means no limit; any other value counts in whole milliseconds, rounded up to at least 1 ms, and
    /// is capped at 65535 ms. Drops are counted in the core's statistics and logged at most once a
    /// minute.
    ///
    /// # Errors
    ///
    /// Fails when the endpoint is closed, `to` or the length is invalid, UDP has stopped after an
    /// accounting fault, or the generation has ended.
    pub fn send_to_latest(
        &self,
        data: &[u8],
        to: SocketAddrV4,
        max_age: Duration,
    ) -> io::Result<usize> {
        send_to_latest(&self.access, self.id, data, to, max_age)
    }
}

fn send_to_latest<A: Access>(
    access: &A,
    id: UdpId,
    data: &[u8],
    to: SocketAddrV4,
    max_age: Duration,
) -> io::Result<usize> {
    if access.is_poisoned() {
        return Err(poisoned());
    }
    let ms = if max_age.is_zero() {
        0
    } else {
        u16::try_from(max_age.as_millis().max(1)).unwrap_or(u16::MAX)
    };
    let r = access.with(|ns| {
        let now = ns.now();
        ns.core_mut().send_to_latest(now, id, data, to, ms)
    });
    match r {
        Ok(n) => {
            access.wake_driver();
            Ok(n)
        }
        Err(e) => Err(io_error(e)),
    }
}

/// 1 回の試しの結果です。
#[cfg(feature = "harness")]
enum Sent {
    Done(usize),
    Wait(Arc<UdpWrite>),
    Failed(Error),
}

#[cfg(feature = "harness")]
async fn send_to<A: Access>(
    access: &A,
    id: UdpId,
    data: &[u8],
    to: SocketAddrV4,
) -> io::Result<usize> {
    loop {
        if access.is_poisoned() {
            return Err(poisoned());
        }
        let r = access.with(|ns| {
            let now = ns.now();
            match ns.core_mut().send_to(now, id, data, to) {
                Ok(n) => Sent::Done(n),
                Err(Error::WouldBlock) => Sent::Wait(ns.wakers.udp_write()),
                Err(e) => Sent::Failed(e),
            }
        });
        match r {
            Sent::Done(n) => {
                access.wake_driver();
                return Ok(n);
            }
            Sent::Wait(waiters) => {
                // 核は今 WouldBlock を返し、この endpoint を待ちの list に入れました。知らせは駆動の task が
                // 次に動くまで処理されないので、ここで待ち手を登録すれば知らせを失いません。
                let mut notified = pin!(waiters.0.notified());
                notified.as_mut().enable();
                notified.await;
            }
            Sent::Failed(e) => return Err(io_error(e)),
        }
    }
}
