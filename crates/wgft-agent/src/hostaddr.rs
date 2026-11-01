//! ホストの IPv4 のアドレスとその帯を読む。トンネルのアドレスがホストのアドレスか、ホストに繋がった
//! 帯に重ならないことを確かめるのに使う。

use std::net::Ipv4Addr;

/// ホストの interface の IPv4 のアドレスの 1 つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddr {
    /// interface の名前。
    pub interface: String,
    /// アドレス。
    pub addr: Ipv4Addr,
    /// 帯の長さ。
    pub prefix_len: u8,
}

impl HostAddr {
    /// `a` がこの帯に入るか。/32 の帯はアドレスそのものだけを含む。
    #[must_use]
    pub fn contains(&self, a: Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        u32::from(a) & mask == u32::from(self.addr) & mask
    }
}

/// `tunnel` がホストのアドレスか、ホストに繋がった帯に入るなら、その理由を返す。`skip` の名前の
/// interface (このプロセスの TUN) は見ない。ループバックの interface は見ない (127.0.0.0/8 は別に拒む)。
#[must_use]
pub fn conflict(tunnel: Ipv4Addr, addrs: &[HostAddr], skip: &str) -> Option<String> {
    addrs
        .iter()
        .filter(|h| h.interface != skip && !h.addr.is_loopback())
        .find_map(|h| {
            if h.addr == tunnel {
                Some(format!(
                    "address {tunnel} is already assigned on this host, on {}",
                    h.interface
                ))
            } else if h.contains(tunnel) {
                Some(format!(
                    "address {tunnel} is inside {}/{}, a network this host is connected to on {}",
                    h.addr, h.prefix_len, h.interface
                ))
            } else {
                None
            }
        })
}

/// ホストの IPv4 のアドレスを読む (`getifaddrs`)。
///
/// # Errors
///
/// 読めなければ誤りを返す。
#[cfg(unix)]
pub fn read() -> std::io::Result<Vec<HostAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: head は書き込める場所を指し、成功すれば libc が確保した一覧の先頭が入る
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur は getifaddrs が返した一覧の要素で、freeifaddrs までは有効である
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: ifa_addr は null でない sockaddr を指す
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        // SAFETY: family が AF_INET なので sockaddr_in として読める。netmask も同じ family である
        let (addr, mask) = unsafe {
            let a = &*ifa.ifa_addr.cast::<libc::sockaddr_in>();
            let m = &*ifa.ifa_netmask.cast::<libc::sockaddr_in>();
            (
                u32::from_be(a.sin_addr.s_addr),
                u32::from_be(m.sin_addr.s_addr),
            )
        };
        // SAFETY: ifa_name は NUL で終わる文字列を指す
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        out.push(HostAddr {
            interface: name,
            addr: Ipv4Addr::from(addr),
            prefix_len: u8::try_from(mask.count_ones()).unwrap_or(32),
        });
    }
    // SAFETY: head は getifaddrs が返したもので、ここで 1 回だけ解放する
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Unix でなければ読まない。試作のトンネルは Linux だけで動く。
///
/// # Errors
///
/// 返さない。
#[cfg(not(unix))]
pub fn read() -> std::io::Result<Vec<HostAddr>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(interface: &str, addr: [u8; 4], prefix_len: u8) -> HostAddr {
        HostAddr {
            interface: interface.into(),
            addr: Ipv4Addr::from(addr),
            prefix_len,
        }
    }

    #[test]
    fn finds_assigned_addresses_and_connected_networks() {
        let host = [
            h("lo", [127, 0, 0, 1], 8),
            h("eth0", [192, 168, 1, 5], 24),
            h("wgftrs0", [10, 200, 0, 2], 32),
        ];
        assert!(
            conflict(Ipv4Addr::new(192, 168, 1, 5), &host, "wgftrs0")
                .unwrap()
                .contains("already assigned")
        );
        assert!(
            conflict(Ipv4Addr::new(192, 168, 1, 77), &host, "wgftrs0")
                .unwrap()
                .contains("connected to on eth0")
        );
        // 自分の TUN は見ない
        assert_eq!(
            conflict(Ipv4Addr::new(10, 200, 0, 2), &host, "wgftrs0"),
            None
        );
        assert_eq!(
            conflict(Ipv4Addr::new(10, 200, 0, 2), &host, "other"),
            Some("address 10.200.0.2 is already assigned on this host, on wgftrs0".into())
        );
        assert_eq!(conflict(Ipv4Addr::new(10, 9, 9, 9), &host, "wgftrs0"), None);
    }

    #[cfg(unix)]
    #[test]
    fn reads_this_host() {
        let addrs = read().unwrap();
        // ループバックの interface は Linux と macOS のどちらにもある
        assert!(addrs.iter().any(|a| a.addr.is_loopback()), "{addrs:?}");
    }
}
