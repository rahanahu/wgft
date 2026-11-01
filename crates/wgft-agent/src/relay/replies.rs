//! UDP の応答のバッファの枠 (agent-parity.md の「応答のバッファの枠」、Go の `replyPool`)。
//!
//! 宛先からの応答を読むバッファを、プロセス全体で同時に [`REPLY_SLOTS`] 個までしか貸さない。枠は
//! `tokio::sync::Semaphore` の許可で数え、バッファの置き場はプロセスで 1 つにする。データプレーンの
//! スレッドはトンネルの世代ごとに替わるので、置き場はスレッドの外の static に置き、世代の間で数を保つ。
//!
//! バッファは枠を持つ者だけが作るので、作るバッファは [`REPLY_SLOTS`] 個を超えない。返されたバッファは
//! 置き場が持ち続け、次の借り手に渡す。Go の pool は返されたバッファの回収を GC に任せたが、Rust では
//! 置き場も上界に入れて数える (保持は貸している分と置き場の分を合わせて `REPLY_SLOTS` × [`UDP_BUF`])。
//!
//! 待ちの観測 (回数、時間、取り消し) は内部で数えるだけで、ログ、`agent doctor`、wire には出さない。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Instant;

use tokio::sync::{Semaphore, SemaphorePermit};

/// The reply buffers lent at once across the process (Go's `replySlots`).
pub const REPLY_SLOTS: usize = 64;

/// The size of one UDP buffer: a reply buffer and a listener's receive buffer (Go's `udpBufMax`).
pub const UDP_BUF: usize = 65535;

/// プロセス全体の枠。どの世代の中継もこれを使う。
pub(crate) static REPLIES: LazyLock<Replies> = LazyLock::new(|| Replies::new(REPLY_SLOTS));

/// 応答のバッファの枠と置き場。
#[derive(Debug)]
pub(crate) struct Replies {
    slots: Semaphore,
    /// 返されて誰も借りていないバッファ。
    spare: Mutex<Vec<Box<[u8]>>>,
    /// 枠が無くて待った回数。取り消された待ちを含む。
    waits: AtomicU64,
    /// 待ちのうち、セッションか待ち受けを閉じて取り消された回数。
    cancelled: AtomicU64,
    /// 枠を得た待ちの時間の合計。取り消された待ちは含めない。
    wait_nanos: AtomicU64,
    /// 枠を得た待ちの最長。
    max_wait_nanos: AtomicU64,
}

/// 待ちの観測の読み。試験だけが読む。
#[cfg_attr(not(test), expect(dead_code, reason = "read only by tests"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Waits {
    pub(crate) count: u64,
    pub(crate) cancelled: u64,
    pub(crate) wait_nanos: u64,
    pub(crate) max_wait_nanos: u64,
}

impl Replies {
    pub(crate) fn new(slots: usize) -> Self {
        Self {
            slots: Semaphore::new(slots),
            spare: Mutex::new(Vec::with_capacity(slots)),
            waits: AtomicU64::new(0),
            cancelled: AtomicU64::new(0),
            wait_nanos: AtomicU64::new(0),
            max_wait_nanos: AtomicU64::new(0),
        }
    }

    /// 枠を 1 つ取り、バッファを貸す。枠が無ければ空くまで待つ。待ちは future を落とすと取り消され、
    /// 回数だけを数える (セッションか待ち受けを閉じたとき)。
    pub(crate) async fn acquire(&self) -> Reply<'_> {
        let permit = if let Ok(p) = self.slots.try_acquire() {
            p
        } else {
            self.waits.fetch_add(1, Ordering::Relaxed);
            let start = Instant::now();
            let mut cancel = Cancelled(Some(&self.cancelled));
            // 枠の Semaphore は閉じないので、誤りは返らない
            let Ok(p) = self.slots.acquire().await else {
                unreachable!("the reply slots are never closed")
            };
            cancel.0 = None;
            let ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            self.wait_nanos.fetch_add(ns, Ordering::Relaxed);
            self.max_wait_nanos.fetch_max(ns, Ordering::Relaxed);
            p
        };
        let buf = self
            .spare
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_else(|| vec![0; UDP_BUF].into_boxed_slice());
        Reply {
            pool: self,
            buf: Some(buf),
            _permit: permit,
        }
    }

    /// 今の待ちの観測。
    #[cfg_attr(not(test), expect(dead_code, reason = "read only by tests"))]
    pub(crate) fn waits(&self) -> Waits {
        Waits {
            count: self.waits.load(Ordering::Relaxed),
            cancelled: self.cancelled.load(Ordering::Relaxed),
            wait_nanos: self.wait_nanos.load(Ordering::Relaxed),
            max_wait_nanos: self.max_wait_nanos.load(Ordering::Relaxed),
        }
    }

    /// 作ったバッファのうち、今誰も借りていない数。
    #[cfg_attr(not(test), expect(dead_code, reason = "read only by tests"))]
    pub(crate) fn spare(&self) -> usize {
        self.spare
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// 今空いている枠の数。
    #[cfg_attr(not(test), expect(dead_code, reason = "read only by tests"))]
    pub(crate) fn available(&self) -> usize {
        self.slots.available_permits()
    }
}

/// 落とされた待ちを数える。枠を得たら外す。
struct Cancelled<'a>(Option<&'a AtomicU64>);

impl Drop for Cancelled<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.0 {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// 貸した 1 つのバッファと枠。落とすと、バッファを置き場に返してから枠を返す。
#[derive(Debug)]
pub(crate) struct Reply<'a> {
    pool: &'a Replies,
    buf: Option<Box<[u8]>>,
    _permit: SemaphorePermit<'a>,
}

impl Reply<'_> {
    /// 貸したバッファ。長さは [`UDP_BUF`]。
    pub(crate) fn buf(&mut self) -> &mut [u8] {
        self.buf.as_deref_mut().unwrap_or_default()
    }
}

impl Drop for Reply<'_> {
    fn drop(&mut self) {
        // 枠 (`_permit`) はこの後に欄として落ちるので、バッファが先に置き場に戻る
        if let Some(b) = self.buf.take() {
            self.pool
                .spare
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn lends_at_most_the_slots_and_keeps_what_it_made() {
        let p = Replies::new(2);
        let mut a = p.acquire().await;
        let b = p.acquire().await;
        assert_eq!(a.buf().len(), UDP_BUF);
        assert_eq!(p.available(), 0);
        // 3 つ目は待つ
        let third = tokio::time::timeout(Duration::from_millis(50), p.acquire()).await;
        assert!(third.is_err(), "a third reply buffer was lent");
        assert_eq!(
            p.waits(),
            Waits {
                count: 1,
                cancelled: 1,
                ..Waits::default()
            }
        );
        drop(a);
        drop(b);
        assert_eq!((p.available(), p.spare()), (2, 2));
        // 返されたバッファを使い回し、新しく作らない
        let _c = p.acquire().await;
        let _d = p.acquire().await;
        assert_eq!((p.available(), p.spare()), (0, 0));
    }

    #[tokio::test]
    async fn a_waiter_gets_the_slot_a_reply_gives_back() {
        let p: &'static Replies = Box::leak(Box::new(Replies::new(1)));
        let a = p.acquire().await;
        let waiter = tokio::spawn(async move {
            let _r = p.acquire().await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        drop(a);
        waiter.await.unwrap();
        let w = p.waits();
        assert_eq!((w.count, w.cancelled), (1, 0));
        assert!(w.wait_nanos > 0 && w.max_wait_nanos <= w.wait_nanos);
    }
}
