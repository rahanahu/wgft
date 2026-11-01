//! ホストの IPv4 のアドレスとその帯と、interface の一覧を読む。宛先のユニキャストの判定
//! (`targets::unicast`) と `agent doctor` が使う。

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

/// `getifaddrs` が返した sockaddr を `T` (`sockaddr_in` か `sockaddr_in6`) として読む。
///
/// BSD 系 (macOS を含む) の netmask は `sa_len` が `T` より短いことがあり (例:`255.255.0.0` を
/// 6 byte で表す)、`T` の大きさの参照として読むと確保の外を読む。このため参照を作らず、`sa_len` と
/// `T` の大きさの小さい方の byte だけを 0 で埋めた `T` へ写し、足りない byte は 0 とする。`sa_len`
/// を持たない OS (Linux) の `getifaddrs` は族の大きさの sockaddr を返すので、`T` の大きさを写す。
///
/// # Safety
///
/// `p` は null でなく、`sa_len` を持つ OS では `sa_len` byte、持たない OS では `T` の大きさの
/// byte を読める sockaddr を指すこと。
#[cfg(unix)]
unsafe fn read_sockaddr<T: Copy>(p: *const libc::sockaddr) -> T {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    // SAFETY: 呼び手が p を読める sockaddr として渡し、sa_len は先頭の 1 byte である
    let len = usize::from(unsafe { (&raw const (*p).sa_len).read() });
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    let len = size_of::<T>();
    // SAFETY: 呼び手の約束のとおり p から len byte を読める
    unsafe { copy_sockaddr(p.cast::<u8>(), len) }
}

/// `p` の先頭 `min(len, T の大きさ)` byte を 0 で埋めた `T` に写す。
///
/// # Safety
///
/// `p` から `min(len, T の大きさ)` byte を読めること。`T` はすべての byte が 0 の値を持てる
/// 平たい C の構造体であること。
#[cfg(unix)]
unsafe fn copy_sockaddr<T: Copy>(p: *const u8, len: usize) -> T {
    let mut out = std::mem::MaybeUninit::<T>::zeroed();
    let n = len.min(size_of::<T>());
    // SAFETY: p から n byte を読め、out は T の大きさの書ける領域で、両者は重ならない
    unsafe { std::ptr::copy_nonoverlapping(p, out.as_mut_ptr().cast::<u8>(), n) };
    // SAFETY: 0 で埋めた後に byte を写した平たい C の構造体はどの byte の並びでも値である
    unsafe { out.assume_init() }
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
        // SAFETY: どちらも getifaddrs が返した null でない sockaddr で、freeifaddrs までは有効である
        let (addr, mask) = unsafe {
            let a = read_sockaddr::<libc::sockaddr_in>(ifa.ifa_addr);
            let m = read_sockaddr::<libc::sockaddr_in>(ifa.ifa_netmask);
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

/// BSD 系 (macOS を含む) の `getifaddrs` が link-local の IPv6 のアドレス (`fe80::/10`) の 3 byte 目と
/// 4 byte 目に埋めるインタフェースの番号 (KAME の埋め込みの scope) を 0 に戻す。Go の `net.Interfaces`
/// も同じく消すので、一覧のアドレスが Go と同じ形になる。
#[cfg_attr(
    not(any(
        test,
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )),
    expect(dead_code, reason = "only BSD-derived systems embed the scope")
)]
fn strip_kame_scope(mut a: [u8; 16]) -> [u8; 16] {
    if a[0] == 0xfe && a[1] & 0xc0 == 0x80 {
        a[2] = 0;
        a[3] = 0;
    }
    a
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
                // SAFETY: どちらも getifaddrs が返した null でない sockaddr で、freeifaddrs までは有効である
                let (a, m) = unsafe {
                    (
                        read_sockaddr::<libc::sockaddr_in>(ifa.ifa_addr)
                            .sin_addr
                            .s_addr,
                        read_sockaddr::<libc::sockaddr_in>(ifa.ifa_netmask)
                            .sin_addr
                            .s_addr,
                    )
                };
                prefix_of(IpAddr::V4(Ipv4Addr::from(u32::from_be(a))), m.count_ones())
            }
            libc::AF_INET6 => {
                // SAFETY: どちらも getifaddrs が返した null でない sockaddr で、freeifaddrs までは有効である
                let (a, m) = unsafe {
                    (
                        read_sockaddr::<libc::sockaddr_in6>(ifa.ifa_addr)
                            .sin6_addr
                            .s6_addr,
                        read_sockaddr::<libc::sockaddr_in6>(ifa.ifa_netmask)
                            .sin6_addr
                            .s6_addr,
                    )
                };
                let bits = m.iter().map(|b| b.count_ones()).sum();
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly"
                ))]
                let a = strip_kame_scope(a);
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
    fn a_band_contains_its_addresses() {
        let eth = h("eth0", [192, 168, 1, 5], 24);
        assert!(eth.contains(Ipv4Addr::new(192, 168, 1, 77)));
        assert!(!eth.contains(Ipv4Addr::new(192, 168, 2, 5)));
        let one = h("wg0", [10, 200, 0, 2], 32);
        assert!(one.contains(Ipv4Addr::new(10, 200, 0, 2)));
        assert!(!one.contains(Ipv4Addr::new(10, 200, 0, 3)));
        assert!(h("any", [0, 0, 0, 0], 0).contains(Ipv4Addr::new(203, 0, 113, 1)));
    }

    /// link-local のアドレスに埋めたインタフェースの番号だけを消し、他のアドレスは変えない。
    #[test]
    fn the_kame_scope_is_stripped_from_link_local_addresses() {
        use std::net::Ipv6Addr;
        let embedded: Ipv6Addr = "fe80:4::1".parse().unwrap();
        assert_eq!(
            Ipv6Addr::from(strip_kame_scope(embedded.octets())),
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        );
        for other in ["2001:db8:4::1", "fec0:4::1", "ff02:4::1"] {
            let a: Ipv6Addr = other.parse().unwrap();
            assert_eq!(Ipv6Addr::from(strip_kame_scope(a.octets())), a, "{other}");
        }
    }

    /// BSD 系の短い netmask (`255.255.0.0` を `sa_len` 6 で表したもの) は、`sa_len` の外の byte を
    /// 読まずに、足りない byte を 0 として読む。
    #[cfg(unix)]
    #[test]
    fn a_short_netmask_reads_only_its_own_bytes() {
        // sa_len、family、port の 2 byte、アドレスの先頭 2 byte。後ろは確保の外の代わりの印
        let mut raw = [0xAAu8; 32];
        raw[..6].copy_from_slice(&[6, 0, 0, 0, 255, 255]);
        // SAFETY: raw は 32 byte を読め、6 byte だけを写す
        let m: libc::sockaddr_in = unsafe { copy_sockaddr(raw.as_ptr(), 6) };
        assert_eq!(u32::from_be(m.sin_addr.s_addr), 0xFFFF_0000);
        assert_eq!(u32::from_be(m.sin_addr.s_addr).count_ones(), 16);
        // IPv6 の /64 を 16 byte で表したもの
        let mut raw6 = [0xAAu8; 40];
        raw6[..16].copy_from_slice(&[
            16, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
        ]);
        // SAFETY: raw6 は 40 byte を読め、16 byte だけを写す
        let m6: libc::sockaddr_in6 = unsafe { copy_sockaddr(raw6.as_ptr(), 16) };
        let bits: u32 = m6.sin6_addr.s6_addr.iter().map(|b| b.count_ones()).sum();
        assert_eq!(bits, 64);
        // sa_len が型より長くても、型の大きさまでしか写さない
        // SAFETY: raw は 32 byte を読め、sockaddr_in の 16 byte だけを写す
        let full: libc::sockaddr_in = unsafe { copy_sockaddr(raw.as_ptr(), 255) };
        assert_eq!(u32::from_be(full.sin_addr.s_addr), 0xFFFF_AAAA);
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
