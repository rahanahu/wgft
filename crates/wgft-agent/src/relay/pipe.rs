//! 中継の写し。トンネルの側の wgstack の接続と、LAN の側のカーネルの TCP ソケットの間を両方の向きに
//! 写す。Go の `internal/netpipe` の `pipe` と `copyConn` を写す。
//!
//! - ハーフクローズ:片方の向きの EOF は、反対側の送る向きを閉じて伝え、もう一方の向きは続ける
//! - 誤り:片方の向きが読み書きの誤りで終われば、もう一方の向きも止めて誤りを返す。ハーフクローズとして
//!   扱うと、黙ったままの相手を読み続けて中継が終わらないためである
//! - バッファ:向きごとに小さいバッファを持ち、読みがそれを満たしたら大きいバッファを借りる。大きい
//!   バッファは、データが [`BULK_WAIT`] の間途切れたら返す。開いたまま黙っている接続の費用を抑えるため。
//!   どちらもデータプレーンのスレッドごとの置き場から借り、接続が終わったら返す。置き場から借りた
//!   バッファは零で埋め直さない。接続が見られるのは、その接続が読みで書いた範囲 `[..n]` だけなので、
//!   前の接続の内容は見えない (`Buf` の注釈)
//!
//! 2 つの向きは同じ task の中で交互に進み、トンネルの側の接続の借用は 1 回の poll の中だけで取る。

use std::cell::RefCell;
use std::future::poll_fn;
use std::io;
use std::net::Shutdown;
use std::time::Duration;

use socket2::SockRef;
use tokio::net::TcpStream as LanStream;
use tokio::time::Instant;
use wgft_netstack::{Access, TcpStream};

/// The buffer a direction holds while idle (Go's `idleBufSize`).
pub(crate) const IDLE_BUF: usize = 2048;

/// The buffer a direction borrows while data flows (Go's `bulkBufSize`).
pub(crate) const BULK_BUF: usize = 32 << 10;

/// How long a direction keeps the bulk buffer without data before it gives it back (Go's
/// `bulkWait`).
pub(crate) const BULK_WAIT: Duration = Duration::from_millis(200);

/// 1 つの向きのバッファ。
///
/// `idle` と `bulk` は置き場から借りるので、前の接続の内容を持つことがある。読みの経路は、読みが返した
/// 長さ `n` の `space()[..n]` だけを使う (`tun_to_lan`、`lan_to_tun`)。読みは `&mut [u8]` に書くだけで
/// 読まず、`n` を超えて返さないので、`[..n]` は今の接続が書いた byte だけである。`after_read` は長さ
/// だけを見る。ほかに `idle` と `bulk` を読む経路は無い。
struct Buf {
    idle: Box<[u8]>,
    bulk: Option<Box<[u8]>>,
}

impl Buf {
    fn new() -> Self {
        Self {
            idle: borrow_idle(),
            bulk: None,
        }
    }

    fn space(&mut self) -> &mut [u8] {
        match &mut self.bulk {
            Some(b) => b,
            None => &mut self.idle,
        }
    }

    /// 読みが小さいバッファを満たしたら大きいバッファを借りる。
    fn after_read(&mut self, n: usize) {
        if self.bulk.is_none() && n == IDLE_BUF {
            self.bulk = Some(borrow());
        }
    }

    /// 大きいバッファを置き場に返す。
    fn release(&mut self) {
        if let Some(b) = self.bulk.take() {
            give_back(b);
        }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        self.release();
        // 空の Box は確保を持たない。`idle` を読む経路は drop の後に無い
        give_back_idle(std::mem::take(&mut self.idle));
    }
}

/// The most idle buffers a data plane thread keeps for reuse; beyond it, returned buffers are
/// freed. A connection holds two while it lives.
pub(crate) const IDLE_KEEP: usize = 64;

/// The most bulk buffers a data plane thread keeps for reuse; beyond it, returned buffers are
/// freed.
pub(crate) const BULK_KEEP: usize = 16;

thread_local! {
    /// スレッドごとの大きいバッファの置き場。データが流れ始めるたびに確保と解放を繰り返さないため。
    static BULK_FREE: std::cell::RefCell<Vec<Box<[u8]>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The bulk buffers alive on all threads, lent or kept for reuse. The memory bound's test reads it.
#[cfg(test)]
pub(super) static BULK_ALIVE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

thread_local! {
    /// スレッドごとの小さいバッファの置き場。接続の確立のたびに零埋めの確保をしないため。
    static IDLE_FREE: std::cell::RefCell<Vec<Box<[u8]>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The idle buffers alive on all threads, lent or kept for reuse. The memory bound's test reads it.
#[cfg(test)]
pub(super) static IDLE_ALIVE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The idle buffers lent out right now on all threads: borrowed and not yet back in a free list
/// or freed. The memory bound's test asserts it is 0 once every relay has closed.
#[cfg(test)]
pub(super) static IDLE_LENT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// 置き場から借りる。内容は前の借り手のままで、零埋めしない。新しく確保した時だけ零で始まる。
fn borrow_idle() -> Box<[u8]> {
    #[cfg(test)]
    IDLE_LENT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    IDLE_FREE.with_borrow_mut(Vec::pop).unwrap_or_else(|| {
        #[cfg(test)]
        IDLE_ALIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vec![0; IDLE_BUF].into_boxed_slice()
    })
}

fn give_back_idle(b: Box<[u8]>) {
    #[cfg(test)]
    IDLE_LENT.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    IDLE_FREE.with_borrow_mut(|free| {
        if free.len() < IDLE_KEEP {
            free.push(b);
        } else {
            drop(b);
            #[cfg(test)]
            IDLE_ALIVE.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
}

fn borrow() -> Box<[u8]> {
    BULK_FREE.with_borrow_mut(Vec::pop).unwrap_or_else(|| {
        #[cfg(test)]
        BULK_ALIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vec![0; BULK_BUF].into_boxed_slice()
    })
}

fn give_back(b: Box<[u8]>) {
    BULK_FREE.with_borrow_mut(|free| {
        if free.len() < BULK_KEEP {
            free.push(b);
        } else {
            drop(b);
            #[cfg(test)]
            BULK_ALIVE.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
}

impl Buf {
    /// 大きいバッファを返す期限。持っていなければ無い。
    fn deadline(&self) -> Option<Instant> {
        self.bulk.as_ref().map(|_| Instant::now() + BULK_WAIT)
    }
}

/// Copies both ways between the tunnel side `tun` and the LAN side `lan` until both directions
/// have ended. An end of stream on one side closes the other side's sending direction; an error
/// in either direction ends both and is returned.
///
/// # Errors
///
/// Returns the first read or write error of either side.
pub(super) async fn pipe<A: Access>(tun: &mut TcpStream<A>, lan: &LanStream) -> io::Result<()> {
    let tun = RefCell::new(tun);
    let up = tun_to_lan(&tun, lan);
    let down = lan_to_tun(&tun, lan);
    tokio::try_join!(up, down).map(|_| ())
}

/// トンネルの側から LAN の側へ。
async fn tun_to_lan<A: Access>(
    tun: &RefCell<&mut TcpStream<A>>,
    lan: &LanStream,
) -> io::Result<()> {
    let mut buf = Buf::new();
    loop {
        let deadline = buf.deadline();
        let read = poll_fn(|cx| tun.borrow_mut().poll_read_bytes(cx, buf_space(&mut buf)));
        let n = tokio::select! {
            biased;
            r = read => r?,
            () = sleep_until(deadline) => {
                buf.release();
                continue;
            }
        };
        if n == 0 {
            // 相手の FIN を LAN の側に伝える。失敗しても読む向きは続ける (Go の CloseWrite)
            let _ = SockRef::from(lan).shutdown(Shutdown::Write);
            return Ok(());
        }
        write_lan(lan, &buf.space()[..n]).await?;
        buf.after_read(n);
    }
}

/// LAN の側からトンネルの側へ。
async fn lan_to_tun<A: Access>(
    tun: &RefCell<&mut TcpStream<A>>,
    lan: &LanStream,
) -> io::Result<()> {
    let mut buf = Buf::new();
    loop {
        let deadline = buf.deadline();
        let n = tokio::select! {
            biased;
            r = read_lan(lan, buf_space(&mut buf)) => r?,
            () = sleep_until(deadline) => {
                buf.release();
                continue;
            }
        };
        if n == 0 {
            let _ = tun.borrow_mut().close_write();
            return Ok(());
        }
        let mut rest = &buf.space()[..n];
        while !rest.is_empty() {
            let w = poll_fn(|cx| tun.borrow_mut().poll_write_bytes(cx, rest)).await?;
            if w == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            rest = &rest[w..];
        }
        buf.after_read(n);
    }
}

fn buf_space(buf: &mut Buf) -> &mut [u8] {
    buf.space()
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

async fn read_lan(lan: &LanStream, dst: &mut [u8]) -> io::Result<usize> {
    loop {
        lan.readable().await?;
        match lan.try_read(dst) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            r => return r,
        }
    }
}

async fn write_lan(lan: &LanStream, mut src: &[u8]) -> io::Result<()> {
    while !src.is_empty() {
        lan.writable().await?;
        match lan.try_write(src) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => src = &src[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle_free_len() -> usize {
        IDLE_FREE.with_borrow(Vec::len)
    }

    fn bulk_free_len() -> usize {
        BULK_FREE.with_borrow(Vec::len)
    }

    /// Fills both of the buffer's slices with `x` the way a previous connection's data would.
    fn dirty(buf: &mut Buf, x: u8) {
        buf.space().fill(x);
        buf.bulk = Some(borrow());
        buf.space().fill(x);
    }

    #[test]
    fn a_new_buffer_reuses_the_returned_one() {
        let mut a = Buf::new();
        dirty(&mut a, 0xAA);
        drop(a);
        assert_eq!(idle_free_len(), 1);
        assert_eq!(bulk_free_len(), 1);
        let mut b = Buf::new();
        assert_eq!(idle_free_len(), 0, "the buffer came from the free list");
        assert_eq!(b.space().len(), IDLE_BUF);
        // 零埋めしない: 前の内容が残っている。読みの経路が `[..n]` だけを使うことが漏れを防ぐ
        assert!(b.space().iter().all(|&x| x == 0xAA));
    }

    #[test]
    fn the_idle_free_list_is_bounded() {
        let bufs: Vec<Buf> = (0..IDLE_KEEP + 8).map(|_| Buf::new()).collect();
        drop(bufs);
        assert_eq!(idle_free_len(), IDLE_KEEP, "the rest were freed");
        // 借りれば減り、返せば上限まで戻る
        let held: Vec<Buf> = (0..10).map(|_| Buf::new()).collect();
        assert_eq!(idle_free_len(), IDLE_KEEP - 10);
        drop(held);
        assert_eq!(idle_free_len(), IDLE_KEEP);
    }

    #[test]
    fn the_bulk_free_list_stays_bounded_beside_the_idle_one() {
        let bufs: Vec<Buf> = (0..BULK_KEEP + 4)
            .map(|_| {
                let mut b = Buf::new();
                b.bulk = Some(borrow());
                b
            })
            .collect();
        drop(bufs);
        assert_eq!(bulk_free_len(), BULK_KEEP);
        assert_eq!(idle_free_len(), BULK_KEEP + 4);
    }
}
