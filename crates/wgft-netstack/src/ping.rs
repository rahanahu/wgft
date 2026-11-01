//! ping の handle。agent の keepalive の ping が使います (tunnel.md の keepalive の ping)。

use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::Ipv4Addr;
use std::task::{Context, Poll};

use wgft_wgstack::{Error, PingId};

use crate::Access;
use crate::error::{io_error, poisoned};

/// An ICMP echo endpoint from the tunnel address to one peer address. Dropping it closes the
/// endpoint and frees its identifier.
pub struct Ping<A: Access> {
    access: A,
    id: PingId,
}

impl<A: Access> fmt::Debug for Ping<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ping")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<A: Access> Ping<A> {
    /// Opens an endpoint towards `peer`.
    ///
    /// # Errors
    ///
    /// Fails when every endpoint of the core's fixed table is in use, or the generation has
    /// ended.
    pub fn open(access: &A, peer: Ipv4Addr) -> io::Result<Self> {
        if access.is_poisoned() {
            return Err(poisoned());
        }
        let id = access.with(|ns| {
            let now = ns.now();
            ns.core_mut().open_ping(now, peer)
        });
        Ok(Self {
            access: access.clone(),
            id: id.map_err(io_error)?,
        })
    }

    /// The core's handle of this endpoint.
    pub fn id(&self) -> PingId {
        self.id
    }

    /// Sends the ICMP echo request message `msg`; the core writes this endpoint's identifier into
    /// it. It does not wait: a full control ring is an error, as in the Go agent.
    ///
    /// # Errors
    ///
    /// Fails when `msg` is not an echo request that fits the MTU, the control ring is full, the
    /// endpoint is closed, or the generation has ended.
    pub fn send(&mut self, msg: &[u8]) -> io::Result<usize> {
        if self.access.is_poisoned() {
            return Err(poisoned());
        }
        let id = self.id;
        let r = self.access.with(|ns| {
            let now = ns.now();
            ns.core_mut().send_ping(now, id, msg)
        });
        if r.is_ok() {
            self.access.wake_driver();
        }
        r.map_err(io_error)
    }

    /// Copies the next reply message into `dst`, or registers `cx` to be woken when one arrives.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>, dst: &mut [u8]) -> Poll<io::Result<usize>> {
        if self.access.is_poisoned() {
            return Poll::Ready(Err(poisoned()));
        }
        let id = self.id;
        let r = self.access.with(|ns| {
            let now = ns.now();
            let r = ns.core_mut().recv_ping(now, id, dst);
            if r == Err(Error::WouldBlock) {
                ns.wakers.ping(id.index(), cx.waker());
            }
            r
        });
        match r {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(Error::WouldBlock) => Poll::Pending,
            Err(e) => Poll::Ready(Err(io_error(e))),
        }
    }

    /// Waits for the next reply; see [`Ping::poll_recv`]. Cancel-safe: a reply leaves the core
    /// only when the future completes. The caller bounds the wait with a timeout.
    pub async fn recv(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_recv(cx, dst)).await
    }
}

impl<A: Access> Drop for Ping<A> {
    fn drop(&mut self) {
        if self.access.is_poisoned() {
            return;
        }
        let id = self.id;
        self.access.with(|ns| {
            let now = ns.now();
            ns.core_mut().close_ping(now, id);
            ns.wakers.clear_ping(id.index());
        });
    }
}
