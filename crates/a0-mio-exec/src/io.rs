//! 準備の置き場と、mio の source を async にする `Async<S>`。
//!
//! mio は edge-triggered なので、準備の印は `WouldBlock` を見るまで持ち続ける。印を消すのは
//! `WouldBlock` を見た時だけで、event が印を立てる。1 つのスレッドの loop なので、event は task の poll の
//! 間には届かない (tokio の `try_io` の印の世代は要らない)。

use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use mio::event::{Event, Source};
use mio::{Interest, Token};

use crate::exec::{try_with_core, with_core};

pub const READABLE: u8 = 1;
pub const WRITABLE: u8 = 2;
pub const ERROR: u8 = 4;

#[derive(Default)]
struct Slot {
    generation: u32,
    live: bool,
    ready: u8,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

#[derive(Default)]
pub(crate) struct IoTable {
    slots: Vec<Slot>,
    free: Vec<u32>,
}

fn token(slot: u32, generation: u32) -> Token {
    Token((usize::try_from(generation).unwrap_or(0) << 32) | slot as usize)
}

impl IoTable {
    fn add(&mut self) -> (u32, u32) {
        let slot = self.free.pop().unwrap_or_else(|| {
            self.slots.push(Slot::default());
            u32::try_from(self.slots.len() - 1).expect("fewer than 2^32 sources")
        });
        let s = &mut self.slots[slot as usize];
        s.live = true;
        s.ready = 0;
        (slot, s.generation)
    }

    fn remove(&mut self, slot: u32) {
        let s = &mut self.slots[slot as usize];
        s.live = false;
        s.generation = s.generation.wrapping_add(1) & 0x7fff_ffff;
        s.reader = None;
        s.writer = None;
        self.free.push(slot);
    }

    pub(crate) fn dispatch(&mut self, ev: &Event) {
        let t = ev.token().0;
        let slot = (t & 0xffff_ffff) as u32;
        let generation = (t >> 32) as u32;
        let Some(s) = self.slots.get_mut(slot as usize) else {
            return;
        };
        if !s.live || s.generation != generation {
            return;
        }
        if ev.is_error() {
            s.ready |= ERROR | READABLE | WRITABLE;
        }
        if ev.is_readable() || ev.is_read_closed() {
            s.ready |= READABLE;
        }
        if ev.is_writable() || ev.is_write_closed() {
            s.ready |= WRITABLE;
        }
        if s.ready & (READABLE | ERROR) != 0
            && let Some(w) = s.reader.take()
        {
            w.wake();
        }
        if s.ready & (WRITABLE | ERROR) != 0
            && let Some(w) = s.writer.take()
        {
            w.wake();
        }
    }
}

/// 実行器に登録した mio の source。
#[derive(Debug)]
pub struct Async<S: Source> {
    io: S,
    slot: u32,
}

impl<S: Source> Async<S> {
    /// 読み書きの両方で登録する。
    ///
    /// # Errors
    ///
    /// 登録できなければ誤りを返す。
    pub fn new(mut io: S) -> io::Result<Self> {
        with_core(|c| {
            let (slot, generation) = c.io.borrow_mut().add();
            match c.registry.register(
                &mut io,
                token(slot, generation),
                Interest::READABLE | Interest::WRITABLE,
            ) {
                Ok(()) => Ok(Self { io, slot }),
                Err(e) => {
                    c.io.borrow_mut().remove(slot);
                    Err(e)
                }
            }
        })
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// `dir` の準備の印が立つまで待つ。
    pub fn poll_ready(&self, cx: &mut Context<'_>, dir: u8) -> Poll<u8> {
        with_core(|c| {
            let mut t = c.io.borrow_mut();
            let s = &mut t.slots[self.slot as usize];
            if s.ready & (dir | ERROR) != 0 {
                return Poll::Ready(s.ready);
            }
            let w = if dir == READABLE {
                &mut s.reader
            } else {
                &mut s.writer
            };
            if !w.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                *w = Some(cx.waker().clone());
            }
            Poll::Pending
        })
    }

    pub async fn ready(&self, dir: u8) -> u8 {
        poll_fn(|cx| self.poll_ready(cx, dir)).await
    }

    fn clear(&self, bits: u8) {
        with_core(|c| c.io.borrow_mut().slots[self.slot as usize].ready &= !bits);
    }

    /// `f` を呼び、`WouldBlock` なら `dir` の印 (と誤りの印) を消す。
    ///
    /// # Errors
    ///
    /// `f` の誤りを返す。
    pub fn try_io<R>(&self, dir: u8, f: impl FnOnce(&S) -> io::Result<R>) -> io::Result<R> {
        let r = f(&self.io);
        if let Err(e) = &r
            && e.kind() == io::ErrorKind::WouldBlock
        {
            self.clear(dir | ERROR);
        }
        r
    }

    /// 印が立つのを待って `f` を呼ぶことを、`WouldBlock` でなくなるまで繰り返す。
    pub fn poll_io<R>(
        &self,
        cx: &mut Context<'_>,
        dir: u8,
        mut f: impl FnMut(&S) -> io::Result<R>,
    ) -> Poll<io::Result<R>> {
        loop {
            if self.poll_ready(cx, dir).is_pending() {
                return Poll::Pending;
            }
            match self.try_io(dir, &mut f) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                r => return Poll::Ready(r),
            }
        }
    }
}

impl<S: Source> Drop for Async<S> {
    fn drop(&mut self) {
        try_with_core(|c| {
            let _ = c.registry.deregister(&mut self.io);
            c.io.borrow_mut().remove(self.slot);
        });
    }
}

impl Async<mio::net::UdpSocket> {
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| self.poll_io(cx, READABLE, |s| s.recv_from(buf))).await
    }

    pub async fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_io(cx, WRITABLE, |s| s.send_to(buf, to))).await
    }
}

impl Async<mio::net::TcpStream> {
    /// 非同期の connect。書ける準備を待ち、誤りと相手のアドレスで繋がったかを確かめる (mio の文書の手順)。
    ///
    /// # Errors
    ///
    /// connect の誤りを返す。
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let s = Self::new(mio::net::TcpStream::connect(addr)?)?;
        loop {
            s.ready(WRITABLE).await;
            if let Some(e) = s.io.take_error()? {
                return Err(e);
            }
            match s.io.peer_addr() {
                Ok(_) => return Ok(s),
                Err(e) if e.kind() == io::ErrorKind::NotConnected => s.clear(WRITABLE),
                Err(e) => return Err(e),
            }
        }
    }
}

// tokio の io の trait を自前の型に実装する。trait は実行環境を要らない
impl tokio::io::AsyncRead for Async<mio::net::TcpStream> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let dst = buf.initialize_unfilled();
        match this.poll_io(cx, READABLE, |mut s| s.read(dst)) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for Async<mio::net::TcpStream> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_io(cx, WRITABLE, |mut s| s.write(src))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.io.shutdown(std::net::Shutdown::Write))
    }
}
