//! handle が核に届く道 (wgstack-rs.md の「スレッドと所有」と「操作の知らせ」)。
//!
//! 核は 1 つのスレッドの値で、駆動の task と handle を持つ local の task が同じ `RefCell` の中の値を交互に
//! 借用します。借用は同期の区間の中だけで取り、`.await` をまたいで持ちません。

use std::cell::{Cell, RefCell, RefMut};
use std::fmt;
use std::rc::Rc;

use tokio::sync::Notify;
use wgft_wgstack::{Hook, NoHook};

use crate::Netstack;

/// How the handles reach the [`Netstack`] on the data plane thread.
///
/// The agent's data plane implements it over its own shared value, which also holds the
/// WireGuard device; [`LocalNetstack`] implements it for a netstack on its own, for tests and for
/// other drivers. Every call happens on the data plane thread.
pub trait Access: Clone + Unpin {
    /// The core's boost hook.
    type Hook: Hook;

    /// Calls `f` with the netstack. The borrow ends when `f` returns, so `f` must not call back
    /// into the handles.
    fn with<R>(&self, f: impl FnOnce(&mut Netstack<Self::Hook>) -> R) -> R;

    /// Wakes the driver after an operation that may have produced output, so that it sends it
    /// without waiting for the socket or a timer.
    fn wake_driver(&self);

    /// Whether a panic inside the core has ended this generation. The handles then fail every
    /// operation and leave the core alone, because its state may be broken.
    fn is_poisoned(&self) -> bool;
}

struct Shared<H: Hook> {
    ns: RefCell<Netstack<H>>,
    poisoned: Cell<bool>,
    notify: Notify,
}

/// A [`Netstack`] shared by a driver task and the handles on one thread.
///
/// A panic while the netstack is borrowed poisons it, as the agent's data plane does: the core's
/// state may be broken half way, so the handles stop using it and the driver should end. Tasks
/// that wait on a handle when the poison is set are never woken; whoever runs them drops them,
/// as the agent's data plane drops all its local tasks when the generation ends.
pub struct LocalNetstack<H: Hook = NoHook>(Rc<Shared<H>>);

impl<H: Hook> Clone for LocalNetstack<H> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

impl<H: Hook> fmt::Debug for LocalNetstack<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalNetstack")
            .field("poisoned", &self.0.poisoned.get())
            .finish_non_exhaustive()
    }
}

/// 借用の中で巻き戻しが起きたら毒の印を付けて駆動の task を起こします。借用の前から巻き戻しの途中だった
/// 場合 (巻き戻しで落ちる handle の `Drop`) は印を付けません。
struct Guard<'a, H: Hook> {
    ns: RefMut<'a, Netstack<H>>,
    shared: &'a Shared<H>,
    panicking: bool,
}

impl<H: Hook> Drop for Guard<'_, H> {
    fn drop(&mut self) {
        if !self.panicking && std::thread::panicking() {
            self.shared.poisoned.set(true);
            self.shared.notify.notify_one();
        }
    }
}

impl<H: Hook> LocalNetstack<H> {
    /// Shares `ns`.
    pub fn new(ns: Netstack<H>) -> Self {
        Self(Rc::new(Shared {
            ns: RefCell::new(ns),
            poisoned: Cell::new(false),
            notify: Notify::new(),
        }))
    }

    /// Resolves after a handle has woken the driver since the last time this resolved. A wake-up
    /// while nobody waits is kept, so none is lost between two waits.
    pub async fn driver_woken(&self) {
        self.0.notify.notified().await;
    }

    /// Takes the netstack back, for closing it, when no handle holds it any more.
    ///
    /// # Errors
    ///
    /// Gives `self` back while another clone is alive.
    pub fn into_inner(self) -> Result<Netstack<H>, Self> {
        Rc::try_unwrap(self.0)
            .map(|s| s.ns.into_inner())
            .map_err(Self)
    }
}

impl<H: Hook> Access for LocalNetstack<H> {
    type Hook = H;

    fn with<R>(&self, f: impl FnOnce(&mut Netstack<H>) -> R) -> R {
        let mut guard = Guard {
            ns: self.0.ns.borrow_mut(),
            shared: &self.0,
            panicking: std::thread::panicking(),
        };
        f(&mut guard.ns)
    }

    fn wake_driver(&self) {
        self.0.notify.notify_one();
    }

    fn is_poisoned(&self) -> bool {
        self.0.poisoned.get()
    }
}
