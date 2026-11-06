//! タイマーの置き場:期限の二分ヒープと、取り消しを O(1) にする slot の表。
//!
//! 取り消した項はヒープに残り、期限が来て取り出された時に世代の違いで捨てられる (遅延の削除)。最も早い
//! 期限を `Poll::poll` の timeout にする。mio は epoll の timeout を ms に切り上げるので、早くは起きない。

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crate::exec::{try_with_core, with_core};

#[derive(Default)]
struct Slot {
    generation: u32,
    waker: Option<Waker>,
    fired: bool,
}

#[derive(Default)]
pub(crate) struct Timers {
    heap: BinaryHeap<Reverse<(Instant, u32, u32)>>,
    slots: Vec<Slot>,
    free: Vec<u32>,
}

impl Timers {
    fn insert(&mut self, at: Instant, waker: Waker) -> (u32, u32) {
        let slot = self.free.pop().unwrap_or_else(|| {
            self.slots.push(Slot::default());
            u32::try_from(self.slots.len() - 1).expect("fewer than 2^32 timers")
        });
        let s = &mut self.slots[slot as usize];
        s.waker = Some(waker);
        s.fired = false;
        let generation = s.generation;
        self.heap.push(Reverse((at, slot, generation)));
        (slot, generation)
    }

    fn remove(&mut self, slot: u32, generation: u32) {
        let s = &mut self.slots[slot as usize];
        if s.generation == generation {
            s.generation = s.generation.wrapping_add(1);
            s.waker = None;
            self.free.push(slot);
        }
    }

    /// 生きている最も早い期限。先頭の取り消した項を捨てる。
    pub(crate) fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(Reverse((at, slot, generation))) = self.heap.peek().copied() {
            let s = &self.slots[slot as usize];
            if s.generation == generation && !s.fired {
                return Some(at);
            }
            self.heap.pop();
        }
        None
    }

    /// `now` までの期限を起こし、起こした数を返す。
    pub(crate) fn fire(&mut self, now: Instant) -> u64 {
        let mut n = 0;
        while let Some(Reverse((at, slot, generation))) = self.heap.peek().copied() {
            if at > now {
                break;
            }
            self.heap.pop();
            let s = &mut self.slots[slot as usize];
            if s.generation == generation && !s.fired {
                s.fired = true;
                if let Some(w) = s.waker.take() {
                    w.wake();
                    n += 1;
                }
            }
        }
        n
    }

    /// ヒープに残る項の数 (取り消した項を含む)。
    pub(crate) fn heap_len(&self) -> usize {
        self.heap.len()
    }
}

/// 期限まで待つ future。落とすと取り消す。
#[derive(Debug)]
pub struct Sleep {
    at: Instant,
    key: Option<(u32, u32)>,
}

impl Sleep {
    pub fn deadline(&self) -> Instant {
        self.at
    }
}

pub fn sleep_until(at: Instant) -> Sleep {
    Sleep { at, key: None }
}

pub fn sleep(d: Duration) -> Sleep {
    sleep_until(Instant::now() + d)
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // 時計で決める。発火の印だけでは決めない (期限より早くは終わらない)
        if Instant::now() >= self.at {
            if let Some((slot, generation)) = self.key.take() {
                with_core(|c| c.timers.borrow_mut().remove(slot, generation));
            }
            return Poll::Ready(());
        }
        let at = self.at;
        match self.key {
            None => {
                self.key = Some(with_core(|c| {
                    c.timers.borrow_mut().insert(at, cx.waker().clone())
                }));
            }
            Some((slot, generation)) => with_core(|c| {
                let mut t = c.timers.borrow_mut();
                let s = &mut t.slots[slot as usize];
                if s.generation == generation {
                    if s.fired {
                        // 時計の揺れで今の読みが期限に届かなかった:登録し直す
                        t.remove(slot, generation);
                        self.key = Some(t.insert(at, cx.waker().clone()));
                    } else if !s.waker.as_ref().is_some_and(|w| w.will_wake(cx.waker())) {
                        s.waker = Some(cx.waker().clone());
                    }
                }
            }),
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some((slot, generation)) = self.key.take() {
            // 実行器が先に落ちた後は何もしない
            try_with_core(|c| c.timers.borrow_mut().remove(slot, generation));
        }
    }
}

/// 期限を過ぎたら `Err(Elapsed)` を返す (tokio の `timeout_at` に当たる)。
pub async fn timeout_at<F: Future>(at: Instant, fut: F) -> Result<F::Output, Elapsed> {
    let mut fut = std::pin::pin!(fut);
    let mut sleep = std::pin::pin!(sleep_until(at));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        }
        sleep.as_mut().poll(cx).map(|()| Err(Elapsed))
    })
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

/// ヒープの長さ (取り消した項を含む)。測定の確かめに使う。
pub fn heap_len() -> usize {
    with_core(|c| c.timers.borrow().heap_len())
}
