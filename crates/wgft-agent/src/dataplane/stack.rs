//! 核との継ぎ目。Rust の wgstack の核と waker の表 (`wgft_netstack::Netstack`) を上の層 ([`Upper`]) に
//! し、handle の層が核に届く道 (`wgft_netstack::Access`) を [`Local`] に実装する。
//!
//! 継ぎ目の規則は `docs/design/v2/agent-parity.md` の「核との継ぎ目」に書く。
//!
//! - 作成:[`make`] がデータプレーンのスレッドの上で核を作る。予算が無ければ新しく作る。確保の失敗は
//!   受けた予算を [`UpperError`] で返し、データプレーンの作成の失敗にする
//! - 時計:handle の操作の時刻は、駆動と同じデータプレーンの時計 ([`clock::now`]) から取る
//! - hook:LAN 側のソケットの表 (`LanSockets`) を作成の時に接続の枠の数だけ確保し、中継が使う

use std::io;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Waker;
use std::time::Instant;

use wgft_netstack::{Access, LanHook, LanSocket, LanSockets, Netstack};
use wgft_wgstack::{BoostPool, Budget, Config, Hook, Limits, Partition};

use super::{Local, Upper, UpperError, UpperInit, clock};

impl<H: Hook + 'static> Upper for Netstack<H> {
    type Budget = Budget;

    fn handle_packet(&mut self, now: Instant, packet: &[u8]) {
        Netstack::handle_packet(self, now, packet);
    }

    fn handle_timeout(&mut self, now: Instant) {
        Netstack::handle_timeout(self, now);
    }

    fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        Netstack::poll_transmit(self, now, buf)
    }

    fn poll_timeout(&self) -> Option<Instant> {
        Netstack::poll_timeout(self)
    }

    fn poll_wakers(&mut self, wake: &mut Vec<Waker>) {
        Netstack::poll_wakers(self, wake);
    }

    fn poll_log(&mut self) -> Option<String> {
        Netstack::poll_log(self)
    }

    fn close(self, now: Instant) -> Budget {
        Netstack::close(self, now).budget
    }

    fn release_wanted(&mut self, now: Instant) -> usize {
        let t = self.time(now);
        self.core_mut().release_wanted(t)
    }

    fn take_boost_wanted(&mut self) -> bool {
        self.core_mut().take_boost_wanted()
    }

    fn sync_boost(&mut self) {
        self.core_mut().sync_boost();
    }
}

impl<H: Hook + 'static> Access for Local<Netstack<H>> {
    type Hook = H;

    fn with<R>(&self, f: impl FnOnce(&mut Netstack<H>) -> R) -> R {
        Local::with(self, f)
    }

    fn wake_driver(&self) {
        self.0.wake.wake();
    }

    fn is_poisoned(&self) -> bool {
        Local::is_poisoned(self)
    }
}

/// What the agent's core is made from, besides what the data plane passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackSettings {
    /// The tunnel address, the only address the core accepts.
    pub addr: Ipv4Addr,
    /// The table sizes; production uses [`Limits::with_max_flows`] with `WGFT_MAX_TCP_FLOWS`.
    pub limits: Limits,
}

/// Makes the core over the hook `LanHook<T>` with a fresh table of LAN sockets, on the data plane
/// thread. The budget is the previous generation's, or a new one.
///
/// # Errors
///
/// Fails when the configuration is refused or the tables cannot be allocated; the error carries
/// the budget it was given.
pub(crate) fn make<T: LanSocket + 'static>(
    settings: StackSettings,
    init: UpperInit<Budget>,
) -> Result<Netstack<LanHook<T>>, UpperError<Budget>> {
    let budget = match init.budget {
        Some(b) => b,
        None => Budget::new().map_err(|e| UpperError {
            error: io::Error::other(format!("allocate the TCP/IP memory budget: {e}")),
            budget: None,
        })?,
    };
    let config = Config {
        limits: settings.limits,
        ..Config::new(settings.addr, init.mtu)
    };
    let mut seed = [0u8; 64];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed).is_err() {
        return Err(UpperError {
            error: io::Error::other("no randomness for the TCP/IP seed"),
            budget: Some(budget),
        });
    }
    let hook = LanHook::new(LanSockets::new(settings.limits.conns()));
    Netstack::new(config, budget, &seed, hook, init.now, clock::now).map_err(|e| {
        let error = io::Error::other(format!("make the TCP/IP core: {e}"));
        UpperError {
            error,
            budget: Some(e.into_budget()),
        }
    })
}

/// Makes partition `part.index` of a Hash S core (prototype): its share of the tables
/// ([`part_limits`]), its own seed, the keys from `part.shared_seed`, and a budget that takes its
/// boost slots from `pool`.
///
/// # Errors
///
/// As for [`make`]; the error carries no budget, since the pool keeps the slots.
pub(crate) fn make_part<T: LanSocket + 'static>(
    settings: StackSettings,
    now: Instant,
    mtu: usize,
    part: Partition,
    pool: &Arc<BoostPool>,
) -> Result<Netstack<LanHook<T>>, io::Error> {
    let budget = pool
        .view()
        .map_err(|e| io::Error::other(format!("allocate the TCP/IP memory budget: {e}")))?;
    let limits = part_limits(settings.limits, usize::from(part.index), usize::from(part.count));
    let config = Config {
        limits,
        partition: Some(part),
        ..Config::new(settings.addr, mtu)
    };
    let mut seed = [0u8; 64];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed).is_err() {
        return Err(io::Error::other("no randomness for the TCP/IP seed"));
    }
    let hook = LanHook::shared(LanSockets::new(limits.conns()), Arc::clone(pool));
    Netstack::new(config, budget, &seed, hook, now, clock::now)
        .map_err(|e| io::Error::other(format!("make the TCP/IP core of partition {}: {e}", part.index)))
}

/// The tables of partition `k` of `parts` (Hash S prototype): the connection slots, the accept
/// queue, the half-open rows and the TIME_WAIT rows divided by P, rounded up. Partition 0 keeps
/// reassembly and UDP; the others get the smallest tables the core accepts, since no UDP and no
/// fragment reaches them.
pub(crate) fn part_limits(l: Limits, k: usize, parts: usize) -> Limits {
    let parts = parts.max(1);
    let share = |n: usize| n.div_ceil(parts).max(1);
    let mut p = Limits {
        max_flows: share(l.max_flows),
        accept_queue: share(l.accept_queue).max(2),
        syn_rows: share(l.syn_rows).max(2),
        tw_rows: share(l.tw_rows),
        ..l
    };
    if k > 0 {
        p.udp_rx_datagrams = 1;
        p.udp_tx_datagrams = 1;
    }
    p
}

/// The LAN socket table of a core made by [`make`].
pub(crate) fn lan_sockets<T: LanSocket + 'static>(
    local: &Local<Netstack<LanHook<T>>>,
) -> Rc<LanSockets<T>> {
    local.with(|ns| Rc::clone(ns.core().hook().sockets()))
}
