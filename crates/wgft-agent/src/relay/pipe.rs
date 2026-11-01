//! 中継の写し。トンネルの側の wgstack の接続と、LAN の側のカーネルの TCP ソケットの間を両方の向きに
//! 写す。Go の `internal/netpipe` の `pipe` と `copyConn` を写す。
//!
//! - ハーフクローズ:片方の向きの EOF は、反対側の送る向きを閉じて伝え、もう一方の向きは続ける
//! - 誤り:片方の向きが読み書きの誤りで終われば、もう一方の向きも止めて誤りを返す。ハーフクローズとして
//!   扱うと、黙ったままの相手を読み続けて中継が終わらないためである
//! - バッファ:向きごとに小さいバッファを持ち、読みがそれを満たしたら大きいバッファを借りる。大きい
//!   バッファは、データが [`BULK_WAIT`] の間途切れたら返す。開いたまま黙っている接続の費用を抑えるため
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
pub const IDLE_BUF: usize = 2048;

/// The buffer a direction borrows while data flows (Go's `bulkBufSize`).
pub const BULK_BUF: usize = 32 << 10;

/// How long a direction keeps the bulk buffer without data before it gives it back (Go's
/// `bulkWait`).
pub const BULK_WAIT: Duration = Duration::from_millis(200);

/// 1 つの向きのバッファ。
struct Buf {
    idle: [u8; IDLE_BUF],
    bulk: Option<Box<[u8]>>,
}

impl Buf {
    fn new() -> Self {
        Self {
            idle: [0; IDLE_BUF],
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
    }
}

/// The most bulk buffers a data plane thread keeps for reuse; beyond it, returned buffers are
/// freed.
pub const BULK_KEEP: usize = 16;

thread_local! {
    /// スレッドごとの大きいバッファの置き場。データが流れ始めるたびに確保と解放を繰り返さないため。
    static BULK_FREE: std::cell::RefCell<Vec<Box<[u8]>>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn borrow() -> Box<[u8]> {
    BULK_FREE
        .with_borrow_mut(Vec::pop)
        .unwrap_or_else(|| vec![0; BULK_BUF].into_boxed_slice())
}

fn give_back(b: Box<[u8]>) {
    BULK_FREE.with_borrow_mut(|free| {
        if free.len() < BULK_KEEP {
            free.push(b);
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
