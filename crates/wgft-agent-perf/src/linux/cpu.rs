//! Thread CPU time, CPU pinning and the readiness check.

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::time::Duration;

/// Waits up to `timeout_ms` for `events` on the socket.
pub(super) fn wait(socket: &UdpSocket, events: i16, timeout_ms: i32) -> std::io::Result<bool> {
    let mut fd = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: fd is one valid pollfd that lives through the call and the count is 1.
    let n = unsafe { libc::poll(&raw mut fd, 1, timeout_ms) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(e)
        };
    }
    Ok(n > 0)
}

pub(super) fn pin(cpu: Option<usize>) -> std::io::Result<()> {
    let Some(cpu) = cpu else {
        return Ok(());
    };
    // SAFETY: a zeroed cpu_set_t is the empty set; CPU_SET writes within it for cpu below the
    // set's size, which the check guarantees; sched_setaffinity reads the set for the calling thread.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if cpu >= 8 * size_of::<libc::cpu_set_t>() {
            return Err(std::io::Error::other("cpu number too large"));
        }
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Pins each thread of this process named `name` to the next CPU of `cpus`, in thread id order.
pub(super) fn pin_named(name: &str, cpus: &[usize]) -> std::io::Result<()> {
    for (tid, &cpu) in named_threads(name)?.into_iter().zip(cpus) {
        set_affinity(tid, cpu)?;
    }
    Ok(())
}

/// The ids of this process's threads named `name`, in id order.
fn named_threads(name: &str) -> std::io::Result<Vec<libc::pid_t>> {
    let mut tids = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task")? {
        let entry = entry?;
        let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if comm.trim_end() == name
            && let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse().ok())
        {
            tids.push(tid);
        }
    }
    tids.sort_unstable();
    Ok(tids)
}

/// The CPU time all threads named `name` have run, from the scheduler's statistics.
pub(super) fn named_cpu(name: &str) -> std::io::Result<Duration> {
    let mut ns = 0u64;
    for tid in named_threads(name)? {
        let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/schedstat"))?;
        ns += stat
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
    }
    Ok(Duration::from_nanos(ns))
}

fn set_affinity(tid: libc::pid_t, cpu: usize) -> std::io::Result<()> {
    // SAFETY: as in pin, for the thread tid of this process.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if cpu >= 8 * size_of::<libc::cpu_set_t>() {
            return Err(std::io::Error::other("cpu number too large"));
        }
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(tid, size_of::<libc::cpu_set_t>(), &raw const set) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The calling thread's CPU time.
#[derive(Debug, Clone, Copy)]
pub(super) struct Cpu {
    pub(super) total: Duration,
    pub(super) user: Duration,
    pub(super) sys: Duration,
}

impl Cpu {
    pub(super) const ZERO: Self = Self {
        total: Duration::ZERO,
        user: Duration::ZERO,
        sys: Duration::ZERO,
    };

    pub(super) fn plus(self, other: Self) -> Self {
        Self {
            total: self.total + other.total,
            user: self.user + other.user,
            sys: self.sys + other.sys,
        }
    }

    pub(super) fn now() -> Self {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a valid timespec that lives through the call.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
        let tv = |sec: i64, sub: i64, per: u32| {
            Duration::new(
                u64::try_from(sec).unwrap_or(0),
                u32::try_from(sub).unwrap_or(0) * per,
            )
        };
        // SAFETY: a zeroed rusage is valid for getrusage to fill in.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: ru is a valid rusage that lives through the call.
        unsafe { libc::getrusage(libc::RUSAGE_THREAD, &raw mut ru) };
        Self {
            total: tv(ts.tv_sec, ts.tv_nsec, 1),
            user: tv(ru.ru_utime.tv_sec, ru.ru_utime.tv_usec, 1000),
            sys: tv(ru.ru_stime.tv_sec, ru.ru_stime.tv_usec, 1000),
        }
    }

    pub(super) fn since(self, start: Self) -> Self {
        Self {
            total: self.total.saturating_sub(start.total),
            user: self.user.saturating_sub(start.user),
            sys: self.sys.saturating_sub(start.sys),
        }
    }
}
