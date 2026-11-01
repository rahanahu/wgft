//! 核と waker の表を 1 つの値にしたもの。データプレーンの駆動はこの値を 1 つの借用の中で呼びます。

use std::fmt;
use std::task::Waker;
use std::time::{Duration, Instant};

use wgft_wgstack::{
    Budget, Closed, Config, Hook, LogKind, LogLine, MIN_MSS, NewErrorKind, NoHook, Stack, Time,
    UDP_ENDPOINT_SHARE, UDP_RX_BYTES,
};

use crate::wakers::Wakers;

/// Why a [`Netstack`] could not be made, with the budget that was passed in.
#[derive(Debug)]
pub struct NetstackError {
    kind: NewErrorKind,
    budget: Budget,
}

impl NetstackError {
    /// Why it failed: the core's configuration, or an allocation of the core's tables or the
    /// waker table.
    pub fn kind(&self) -> NewErrorKind {
        self.kind
    }

    /// The budget that was passed in.
    pub fn into_budget(self) -> Budget {
        self.budget
    }
}

impl fmt::Display for NetstackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            NewErrorKind::Config(e) => write!(f, "invalid wgstack configuration: {e}"),
            NewErrorKind::Alloc => f.write_str("cannot allocate the wgstack tables"),
        }
    }
}

impl std::error::Error for NetstackError {}

/// The wgstack core together with the waker table of the handles over it.
///
/// It is the value the data plane drives, in the shape of the agent's `dataplane::Upper`: packets
/// and timeouts go in with the data plane's [`Instant`]; packets, the next wake-up time, the
/// wakers to wake and log lines come out. The handles reach it through an [`Access`](crate::Access)
/// and read the time from the `clock` given at creation, which must be the clock the driver
/// uses.
pub struct Netstack<H: Hook = NoHook> {
    core: Stack<H>,
    pub(crate) wakers: Wakers,
    epoch: Instant,
    clock: fn() -> Instant,
}

impl<H: Hook> fmt::Debug for Netstack<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Netstack")
            .field("core", &self.core)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl<H: Hook> Netstack<H> {
    /// Makes the core and the waker table. `now` is the time of creation on `clock`; the core's
    /// time is the time elapsed since then.
    ///
    /// # Errors
    ///
    /// Fails as [`Stack::new`] does, and when the waker table cannot be allocated; the error
    /// gives the budget back.
    pub fn new(
        config: Config,
        budget: Budget,
        seed: &[u8; 64],
        hook: H,
        now: Instant,
        clock: fn() -> Instant,
    ) -> Result<Self, NetstackError> {
        let Ok(wakers) = Wakers::new(config.limits.conns()) else {
            return Err(NetstackError {
                kind: NewErrorKind::Alloc,
                budget,
            });
        };
        let core = Stack::new(config, budget, seed, hook).map_err(|e| NetstackError {
            kind: e.kind(),
            budget: e.into_budget(),
        })?;
        Ok(Self {
            core,
            wakers,
            epoch: now,
            clock,
        })
    }

    /// The core, for its state: [`Stack::stats`], [`Stack::held`], [`Stack::bound`],
    /// [`Stack::udp_receive_fault`] and the hook.
    pub fn core(&self) -> &Stack<H> {
        &self.core
    }

    /// The core, for operations the handles do not cover. An operation that may produce output
    /// must wake the driver afterwards ([`Access::wake_driver`](crate::Access::wake_driver)).
    pub fn core_mut(&mut self) -> &mut Stack<H> {
        &mut self.core
    }

    /// The core's time of `t`.
    pub fn time(&self, t: Instant) -> Time {
        let ns = t.saturating_duration_since(self.epoch).as_nanos();
        Time::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
    }

    /// The core's time now, on the clock given at creation.
    pub fn now(&self) -> Time {
        self.time((self.clock)())
    }

    /// The bytes the waker table holds now. The waker table is outside the core's
    /// [`Stack::bound`]; the agent adds [`Netstack::waker_bound`] and the driver's waker list to
    /// its memory bound.
    pub fn waker_bytes(&self) -> usize {
        self.wakers.heap_bytes()
    }

    /// The most bytes the waker table of a core with `conns` connection slots can hold.
    pub fn waker_bound(conns: usize) -> usize {
        Wakers::bound_bytes(conns)
    }

    /// Takes a packet the device decrypted and checked.
    pub fn handle_packet(&mut self, now: Instant, packet: &[u8]) {
        let now = self.time(now);
        self.core.handle_packet(now, packet);
    }

    /// Runs the timers that are due.
    pub fn handle_timeout(&mut self, now: Instant) {
        let now = self.time(now);
        self.core.handle_timeout(now);
    }

    /// Writes the next packet to send into `buf`, which is at least the MTU long, and returns its
    /// length.
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        let now = self.time(now);
        self.core.poll_transmit(now, buf)
    }

    /// When to call [`Netstack::handle_timeout`] next.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let t = self.core.poll_timeout()?;
        self.epoch.checked_add(Duration::from_nanos(t.as_nanos()))
    }

    /// Moves the wakers of handles whose readiness changed into `wake`. The caller wakes them
    /// after it has released its borrow of this value.
    pub fn poll_wakers(&mut self, wake: &mut Vec<Waker>) {
        let mut udp_writable = false;
        while let Some(ev) = self.core.poll_event() {
            self.wakers.collect(ev, wake, &mut udp_writable);
        }
    }

    /// The next log line, without a timestamp.
    pub fn poll_log(&mut self) -> Option<String> {
        let line = self.core.poll_log()?;
        Some(self.log_text(line))
    }

    /// The English text of a log line.
    fn log_text(&self, line: LogLine) -> String {
        let n = line.count;
        let refused = |what: &str| format!("wgstack: {what}; {n} since the tunnel was built");
        match line.kind {
            LogKind::MssFloor => format!(
                "wgstack: dropped TCP handshakes that advertise an MSS below {MIN_MSS}; {n} dropped since the tunnel was built; peers that advertise a smaller MSS cannot connect through this tunnel"
            ),
            LogKind::SynFull => refused("dropped SYNs because the half-open table was full"),
            LogKind::AcceptOverflow => refused(
                "dropped final handshake ACKs because the accept queue or the connection table was full",
            ),
            LogKind::TwEvicted => {
                refused("evicted the oldest TIME_WAIT rows because the table was full")
            }
            LogKind::CtlDropped => {
                refused("dropped control packets because the control output ring was full")
            }
            LogKind::OooDropped => refused(
                "dropped out-of-order segments that would need more than the fixed number of receive intervals",
            ),
            LogKind::AccountingFault => {
                refused("closed a connection after an internal accounting error")
            }
            LogKind::UdpDropped => {
                let s = self.core.stats();
                let datagrams = self.core.config().limits.udp_rx_datagrams;
                format!(
                    "wgstack: dropped UDP datagrams because receiving sockets are not read fast enough; {} over the per-socket limit of {} bytes and {} datagrams, {} over the tunnel budget of {UDP_RX_BYTES} bytes and {datagrams} datagrams, since the tunnel was built",
                    s.udp_endpoint_full,
                    UDP_RX_BYTES / UDP_ENDPOINT_SHARE,
                    datagrams / UDP_ENDPOINT_SHARE,
                    s.udp_tunnel_full,
                )
            }
            LogKind::UdpFault => match self.core.udp_receive_fault() {
                Some(f) => format!(
                    "wgstack: UDP accounting found an internal inconsistency and stopped all UDP on this tunnel: {f}; restart the agent to recover"
                ),
                None => "wgstack: UDP accounting found an internal inconsistency and stopped all UDP on this tunnel; restart the agent to recover".to_owned(),
            },
            kind => format!("wgstack: {kind:?}; {n} since the tunnel was built"),
        }
    }

    /// Closes everything and returns the budget and the last accounting. The driver drops the
    /// tasks that hold handles first, as the agent's data plane does before it closes the layer
    /// above.
    pub fn close(self, now: Instant) -> Closed {
        let now = self.time(now);
        self.core.close(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn netstack() -> Netstack {
        let config = Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420);
        Netstack::new(
            config,
            Budget::new().unwrap(),
            &[1; 64],
            NoHook,
            Instant::now(),
            Instant::now,
        )
        .unwrap()
    }

    #[test]
    fn times_count_from_creation() {
        let ns = netstack();
        assert_eq!(ns.time(ns.epoch), Time::ZERO);
        assert_eq!(
            ns.time(ns.epoch + Duration::from_millis(3)),
            Time::from_nanos(3_000_000)
        );
        // 作成より前の時刻は 0 にします。核は戻った時刻を前の値で置き換えます。
        if let Some(before) = ns.epoch.checked_sub(Duration::from_secs(1)) {
            assert_eq!(ns.time(before), Time::ZERO);
        }
        assert_eq!(ns.poll_timeout(), None);
    }

    #[test]
    fn log_lines_read_as_the_go_agent_wrote_them() {
        let ns = netstack();
        let kinds = [
            LogKind::MssFloor,
            LogKind::SynFull,
            LogKind::AcceptOverflow,
            LogKind::TwEvicted,
            LogKind::CtlDropped,
            LogKind::OooDropped,
            LogKind::AccountingFault,
            LogKind::UdpDropped,
            LogKind::UdpFault,
        ];
        for kind in kinds {
            let text = ns.log_text(LogLine { kind, count: 7 });
            assert!(text.starts_with("wgstack: "), "{text}");
            assert!(!text.contains(['(', ')']), "{text}");
            assert!(!text.contains("Udp") && !text.contains("Mss"), "{text}");
        }
        assert_eq!(
            ns.log_text(LogLine {
                kind: LogKind::SynFull,
                count: 7
            }),
            "wgstack: dropped SYNs because the half-open table was full; 7 since the tunnel was built"
        );
        assert_eq!(
            ns.log_text(LogLine {
                kind: LogKind::MssFloor,
                count: 2
            }),
            "wgstack: dropped TCP handshakes that advertise an MSS below 536; 2 dropped since the tunnel was built; peers that advertise a smaller MSS cannot connect through this tunnel"
        );
        assert_eq!(
            ns.log_text(LogLine {
                kind: LogKind::UdpDropped,
                count: 0
            }),
            "wgstack: dropped UDP datagrams because receiving sockets are not read fast enough; 0 over the per-socket limit of 1048576 bytes and 1024 datagrams, 0 over the tunnel budget of 4194304 bytes and 4096 datagrams, since the tunnel was built"
        );
    }

    #[test]
    fn the_waker_table_stays_within_its_bound() {
        let mut ns = netstack();
        let conns = ns.core().config().limits.conns();
        let first = ns.waker_bytes();
        assert!(first < Netstack::<NoHook>::waker_bound(conns));
        ns.wakers.open_port(80).unwrap();
        ns.wakers.open_port(81).unwrap();
        assert!(
            ns.waker_bytes() > first,
            "the first port of a page adds the page"
        );
        let one_page = ns.waker_bytes();
        for port in 0..=u16::MAX {
            ns.wakers.open_port(port).unwrap();
        }
        assert!(ns.waker_bytes() > one_page);
        assert_eq!(ns.waker_bytes(), Netstack::<NoHook>::waker_bound(conns));
    }
}
