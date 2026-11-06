//! Throwaway feasibility prototype (A0). Not for merge.
//!
//! A single-threaded executor on mio: a run queue with a per-tick cap, std wakers that are cheap on
//! the owning thread and ring a `mio::Waker` from other threads, a timer heap that feeds
//! `Poll::poll`'s timeout, readiness for edge-triggered sources, and `catch_unwind` around every task
//! poll.

pub mod exec;
pub mod io;
pub mod timer;

pub use exec::{Exec, JoinError, JoinHandle, Stats, spawn, yield_now};
pub use io::Async;
pub use timer::{Sleep, sleep, sleep_until, timeout_at};
