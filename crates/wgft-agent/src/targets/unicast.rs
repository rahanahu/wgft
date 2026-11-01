//! ブロードキャストとマルチキャストの宛先の判定 (`docs/design/userspace/targets.md`)。Go の
//! `internal/agent/allowtargets` の `Unicast` を移したもの。agent は、許可一覧の有無に依らず、これらの
//! アドレスへ転送しない。理由の文は Go と同じで、`server doctor` は語 `the agent forwards only to
//! unicast targets` で分類する。

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::hostaddr::HostAddr;
use crate::logf;

/// `server doctor` が分類に使う語。
pub const UNICAST_ONLY: &str = "the agent forwards only to unicast targets";

/// 読んだインタフェースの一覧を読み直さずに使う長さ。接続 1 本ごとにカーネルへ問い合わせないため。
const INTERFACE_CACHE_TTL: Duration = Duration::from_secs(5);

/// ホストのインタフェースの IPv4 のアドレスと帯の長さを読む関数。
pub type ReadPrefixes = Box<dyn Fn() -> std::io::Result<Vec<HostAddr>> + Send + Sync>;

#[derive(Debug, Default)]
struct Cache {
    read_at: Option<Instant>,
    prefixes: Vec<(Ipv4Addr, u8)>,
    /// 直前の読み取りが失敗した。ログを変化のときだけ出す。
    failed: bool,
}

/// 宛先のアドレスへ転送してよいかを判定する。
pub struct Unicast {
    read: ReadPrefixes,
    cache: Mutex<Cache>,
}

impl std::fmt::Debug for Unicast {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unicast").finish_non_exhaustive()
    }
}

impl Default for Unicast {
    fn default() -> Self {
        Unicast::new(Box::new(crate::hostaddr::read))
    }
}

impl Unicast {
    /// `read` でホストの一覧を読む判定を作る。
    #[must_use]
    pub fn new(read: ReadPrefixes) -> Self {
        Unicast {
            read,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// 宛先のアドレス `a` へ転送しない理由を返す。転送してよければ `None`。
    #[must_use]
    pub fn refuse(&self, a: IpAddr) -> Option<String> {
        self.refuse_at(a, Instant::now())
    }

    fn refuse_at(&self, a: IpAddr, now: Instant) -> Option<String> {
        let a = a.to_canonical();
        let shown = super::show_ip(a);
        match a {
            IpAddr::V4(v4) if v4 == Ipv4Addr::BROADCAST => {
                return Some(format!(
                    "target {shown} is the limited broadcast address; {UNICAST_ONLY}"
                ));
            }
            _ if a.is_multicast() => {
                return Some(format!(
                    "target {shown} is a multicast address; {UNICAST_ONLY}"
                ));
            }
            IpAddr::V6(_) => return None,
            IpAddr::V4(_) => {}
        }
        let IpAddr::V4(v4) = a else { return None };
        self.host_prefixes(now).into_iter().find_map(|(addr, bits)| {
            let (net, b) = directed_broadcast(addr, bits)?;
            (b == v4).then(|| {
                format!(
                    "target {shown} is the broadcast address of {net}/{bits} on this host; {UNICAST_ONLY}"
                )
            })
        })
    }

    /// 直近 5 秒の間に読んだ一覧を返す。古ければ読み直す。読めなければ空を返し、帯のブロードキャストの
    /// アドレスの判定を行わない。
    fn host_prefixes(&self, now: Instant) -> Vec<(Ipv4Addr, u8)> {
        let mut c = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if c.read_at
            .is_some_and(|at| now.saturating_duration_since(at) < INTERFACE_CACHE_TTL)
        {
            return c.prefixes.clone();
        }
        c.read_at = Some(now);
        match (self.read)() {
            Ok(hs) => {
                if c.failed {
                    logf!(
                        "reading this host's interface addresses again; broadcast addresses of the host's networks are refused again"
                    );
                }
                c.failed = false;
                c.prefixes = hs.into_iter().map(|h| (h.addr, h.prefix_len)).collect();
            }
            Err(e) => {
                if !c.failed {
                    logf!(
                        "cannot read this host's interface addresses: {e}; broadcast addresses of the host's networks are not refused until they can be read"
                    );
                }
                c.failed = true;
                c.prefixes.clear();
            }
        }
        c.prefixes.clone()
    }
}

/// IPv4 の帯の、帯の先頭のアドレスとブロードキャストのアドレス (帯の末尾)。/31 と /32 の帯は両端を
/// ホストのアドレスとして使うので、ブロードキャストのアドレスを持たない。
fn directed_broadcast(addr: Ipv4Addr, bits: u8) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if bits > 30 {
        return None;
    }
    let host = u32::MAX.checked_shr(u32::from(bits)).unwrap_or(0);
    let net = u32::from(addr) & !host;
    Some((Ipv4Addr::from(net), Ipv4Addr::from(net | host)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn h(addr: [u8; 4], prefix_len: u8) -> HostAddr {
        HostAddr {
            interface: "eth0".into(),
            addr: Ipv4Addr::from(addr),
            prefix_len,
        }
    }

    fn fixed(hs: Vec<HostAddr>) -> Unicast {
        Unicast::new(Box::new(move || Ok(hs.clone())))
    }

    #[test]
    fn refuses_broadcast_and_multicast_with_go_texts() {
        let u = fixed(vec![
            h([192, 168, 1, 7], 24),
            h([10, 0, 0, 1], 23),
            h([172, 16, 0, 1], 31),
            h([127, 0, 0, 1], 8),
        ]);
        let r = |a: &str| u.refuse(a.parse().unwrap());
        assert_eq!(
            r("255.255.255.255").as_deref(),
            Some(
                "target 255.255.255.255 is the limited broadcast address; the agent forwards only to unicast targets"
            )
        );
        assert_eq!(
            r("239.1.2.3").as_deref(),
            Some(
                "target 239.1.2.3 is a multicast address; the agent forwards only to unicast targets"
            )
        );
        assert_eq!(
            r("ff02::1").as_deref(),
            Some(
                "target ff02::1 is a multicast address; the agent forwards only to unicast targets"
            )
        );
        assert_eq!(
            r("::ffff:224.0.0.1").as_deref(),
            Some(
                "target 224.0.0.1 is a multicast address; the agent forwards only to unicast targets"
            )
        );
        assert_eq!(
            r("192.168.1.255").as_deref(),
            Some(
                "target 192.168.1.255 is the broadcast address of 192.168.1.0/24 on this host; the agent forwards only to unicast targets"
            )
        );
        assert!(r("127.255.255.255").is_some());
        // /23 の中ほどの .255 はホストのアドレス
        assert_eq!(r("10.0.0.255"), None);
        assert!(r("10.0.1.255").is_some());
        // /31 の両端は拒まない
        assert_eq!(r("172.16.0.1"), None);
        assert_eq!(r("172.16.0.0"), None);
        // ホストのどの帯の末尾でもない .255
        assert_eq!(r("192.168.2.255"), None);
        assert_eq!(r("192.168.1.10"), None);
        assert_eq!(r("2001:db8::1"), None);
    }

    #[test]
    fn caches_the_interface_list_for_five_seconds_and_survives_read_errors() {
        let reads = Arc::new(AtomicUsize::new(0));
        let n = Arc::clone(&reads);
        let u = Unicast::new(Box::new(move || {
            // 2 回目の読みだけ失敗する
            if n.fetch_add(1, Ordering::SeqCst) == 1 {
                Err(std::io::Error::other("boom"))
            } else {
                Ok(vec![h([192, 168, 1, 7], 24)])
            }
        }));
        let t0 = Instant::now();
        let b: IpAddr = "192.168.1.255".parse().unwrap();
        assert!(u.refuse_at(b, t0).is_some());
        assert!(u.refuse_at(b, t0 + Duration::from_secs(4)).is_some());
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        // 読めない間は帯のブロードキャストを判定しないが、全域とマルチキャストは拒む
        assert_eq!(u.refuse_at(b, t0 + Duration::from_secs(5)), None);
        assert!(
            u.refuse_at(
                "255.255.255.255".parse().unwrap(),
                t0 + Duration::from_secs(6)
            )
            .is_some()
        );
        assert!(u.refuse_at(b, t0 + Duration::from_secs(10)).is_some());
        assert_eq!(reads.load(Ordering::SeqCst), 3);
    }
}
