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

/// ホストの IPv4 のアドレスを読む (`GetAdaptersAddresses`)。interface の名前は adapter の
/// FriendlyName である。
///
/// # Errors
///
/// 読めなければ誤りを返す。
#[cfg(windows)]
pub fn read() -> std::io::Result<Vec<HostAddr>> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // 一覧は構造体の境界に揃えた領域に書かれる。足りなければ必要な長さが返るので取り直す
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: buf は size byte 以上の書き込める領域で、境界は構造体に足りる
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &raw mut size,
            )
        };
        match rc {
            ERROR_SUCCESS => break,
            // adapter が 1 つも無いホスト
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW if tries < 4 => tries += 1,
            e => return Err(std::io::Error::from_raw_os_error(e.cast_signed())),
        }
    }
    let mut out = Vec::new();
    let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        // SAFETY: adapter は GetAdaptersAddresses が buf の中に作った一覧の要素である
        let a = unsafe { &*adapter };
        adapter = a.Next;
        let name = if a.FriendlyName.is_null() {
            String::new()
        } else {
            // SAFETY: FriendlyName は NUL で終わる UTF-16 の文字列を指す
            unsafe { crate::platform::utf16z_to_string(a.FriendlyName) }
        };
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: u は一覧の要素である
            let ua = unsafe { &*u };
            u = ua.Next;
            let sa = ua.Address.lpSockaddr;
            // SAFETY: lpSockaddr は null か有効な sockaddr を指す
            if sa.is_null() || unsafe { (*sa).sa_family } != AF_INET {
                continue;
            }
            // SAFETY: family が AF_INET なので sockaddr_in で、4 byte 目から IPv4 のアドレスが続く。
            // 境界 1 の配列として読む
            let octets = unsafe { sa.cast::<u8>().add(4).cast::<[u8; 4]>().read() };
            out.push(HostAddr {
                interface: name.clone(),
                addr: Ipv4Addr::from(octets),
                prefix_len: ua.OnLinkPrefixLength.min(32),
            });
        }
    }
    Ok(out)
}

/// このホストのネットワークのインタフェース 1 つ (Go の `net.Interface` と `Addrs`)。`agent doctor` の
/// `host.interfaces` が示す。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Interface {
    /// 名前。Windows では adapter の FriendlyName。
    pub name: String,
    /// up か。
    pub up: bool,
    /// ループバックか。
    pub loopback: bool,
    /// アドレスと帯の長さ (`192.0.2.1/24` の形)。IPv4 と IPv6 の両方。
    pub addrs: Vec<String>,
}

fn prefix_of(addr: std::net::IpAddr, prefix_len: u32) -> String {
    format!("{addr}/{prefix_len}")
}

/// このホストのインタフェースを、OS が返す順に読む (`getifaddrs`)。アドレスを持たないインタフェースも
/// 数える。
///
/// # Errors
///
/// 読めなければ誤りを返す。
#[cfg(unix)]
pub fn interfaces() -> std::io::Result<Vec<Interface>> {
    use std::net::{IpAddr, Ipv6Addr};

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: head は書き込める場所を指し、成功すれば libc が確保した一覧の先頭が入る
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out: Vec<Interface> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur は getifaddrs が返した一覧の要素で、freeifaddrs までは有効である
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        // SAFETY: ifa_name は NUL で終わる文字列を指す
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let i = if let Some(i) = out.iter().position(|x| x.name == name) {
            i
        } else {
            out.push(Interface {
                name,
                ..Interface::default()
            });
            out.len() - 1
        };
        let flags = ifa.ifa_flags;
        let entry = &mut out[i];
        entry.up |= flags & (libc::IFF_UP as libc::c_uint) != 0;
        entry.loopback |= flags & (libc::IFF_LOOPBACK as libc::c_uint) != 0;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: ifa_addr は null でない sockaddr を指す
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        let addr = match family {
            libc::AF_INET => {
                // SAFETY: family が AF_INET なので sockaddr_in として読める。netmask も同じ family である
                let (a, m) = unsafe {
                    (
                        (*ifa.ifa_addr.cast::<libc::sockaddr_in>()).sin_addr.s_addr,
                        (*ifa.ifa_netmask.cast::<libc::sockaddr_in>())
                            .sin_addr
                            .s_addr,
                    )
                };
                prefix_of(IpAddr::V4(Ipv4Addr::from(u32::from_be(a))), m.count_ones())
            }
            libc::AF_INET6 => {
                // SAFETY: family が AF_INET6 なので sockaddr_in6 として読める。netmask も同じ family である
                let (a, m) = unsafe {
                    (
                        (*ifa.ifa_addr.cast::<libc::sockaddr_in6>())
                            .sin6_addr
                            .s6_addr,
                        (*ifa.ifa_netmask.cast::<libc::sockaddr_in6>())
                            .sin6_addr
                            .s6_addr,
                    )
                };
                let bits = m.iter().map(|b| b.count_ones()).sum();
                prefix_of(IpAddr::V6(Ipv6Addr::from(a)), bits)
            }
            _ => continue,
        };
        entry.addrs.push(addr);
    }
    // SAFETY: head は getifaddrs が返したもので、ここで 1 回だけ解放する
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// このホストのインタフェースを読む (`GetAdaptersAddresses`)。名前は adapter の FriendlyName である。
///
/// # Errors
///
/// 読めなければ誤りを返す。
#[cfg(windows)]
pub fn interfaces() -> std::io::Result<Vec<Interface>> {
    use std::net::{IpAddr, Ipv6Addr};
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: buf は size byte 以上の書き込める領域で、境界は構造体に足りる
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &raw mut size,
            )
        };
        match rc {
            ERROR_SUCCESS => break,
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW if tries < 4 => tries += 1,
            e => return Err(std::io::Error::from_raw_os_error(e.cast_signed())),
        }
    }
    let mut out = Vec::new();
    let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        // SAFETY: adapter は GetAdaptersAddresses が buf の中に作った一覧の要素である
        let a = unsafe { &*adapter };
        adapter = a.Next;
        let name = if a.FriendlyName.is_null() {
            String::new()
        } else {
            // SAFETY: FriendlyName は NUL で終わる UTF-16 の文字列を指す
            unsafe { crate::platform::utf16z_to_string(a.FriendlyName) }
        };
        let mut ifc = Interface {
            name,
            up: a.OperStatus == IfOperStatusUp,
            loopback: a.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
            addrs: Vec::new(),
        };
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: u は一覧の要素である
            let ua = unsafe { &*u };
            u = ua.Next;
            let sa = ua.Address.lpSockaddr;
            if sa.is_null() {
                continue;
            }
            // SAFETY: lpSockaddr は有効な sockaddr を指す
            let family = unsafe { (*sa).sa_family };
            let ip = if family == AF_INET {
                // SAFETY: sockaddr_in で、4 byte 目から IPv4 のアドレスが続く。境界 1 の配列として読む
                IpAddr::V4(Ipv4Addr::from(unsafe {
                    sa.cast::<u8>().add(4).cast::<[u8; 4]>().read()
                }))
            } else if family == AF_INET6 {
                // SAFETY: sockaddr_in6 で、8 byte 目から IPv6 のアドレスが続く。境界 1 の配列として読む
                IpAddr::V6(Ipv6Addr::from(unsafe {
                    sa.cast::<u8>().add(8).cast::<[u8; 16]>().read()
                }))
            } else {
                continue;
            };
            ifc.addrs
                .push(prefix_of(ip, u32::from(ua.OnLinkPrefixLength)));
        }
        out.push(ifc);
    }
    Ok(out)
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

    #[cfg(any(unix, windows))]
    #[test]
    fn lists_this_hosts_interfaces_with_a_loopback() {
        let ifs = interfaces().unwrap();
        assert!(ifs.iter().any(|i| i.loopback), "{ifs:?}");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn reads_this_host() {
        let addrs = read().unwrap();
        // ループバックの interface は Linux、macOS、Windows のどれにもある
        assert!(addrs.iter().any(|a| a.addr.is_loopback()), "{addrs:?}");
    }
}
