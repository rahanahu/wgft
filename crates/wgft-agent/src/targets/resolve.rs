//! 名前の解決 (`docs/design/v2/agent-parity.md` の「名前の解決」)。
//!
//! OS の `getaddrinfo` を、引く名前ごとに 1 本の OS のスレッドで呼ぶ。同じ名前を引いている途中の呼び手は、
//! 新しく引かずにその結果を待つ (Go の `net.Resolver` と同じ相乗り)。同時に引く名前の数を許可の数で抑え、
//! 宛先の名前は 8 つまで、WireGuard のエンドポイントの名前は別の許可 2 つで引く。宛先の解決が許可を
//! 使い切っても、トンネルの名前の引き直しは止まらない。
//!
//! 呼び手はそれぞれの期限で待ち、期限を過ぎれば誤りを受けて去る。スレッドは `getaddrinfo` が戻るまで
//! 動き続け、結果を待っている呼び手に配ってから許可を返す。
//!
//! tokio の `spawn_blocking` を使わないのは、実行環境を落とすときに blocking のタスクの終わりを待つため
//! である。応答しない resolver があると、トンネルの世代を閉じる処理がそこで止まる。
//!
//! 宛先の名前は、Go の resolver と同じ RFC 6724 の宛先の規則で並べ直す。`getaddrinfo` の順は libc と
//! 設定 (`gai.conf`) で変わるためである。エンドポイントの名前は A レコードだけを引く。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

/// 宛先の名前を同時に引く数。
pub const TARGET_PERMITS: usize = 8;
/// WireGuard のエンドポイントの名前を同時に引く数。期限で去った引き直しが応答しない resolver に
/// 許可を握られても、次の引き直しが 1 つ残る。
pub const ENDPOINT_PERMITS: usize = 2;

/// 引くアドレスの族。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// A と AAAA。
    Any,
    /// A だけ。
    V4,
}

/// 名前を引く関数。OS の resolver を呼ぶ既定の関数を、試験が差し替える。
pub type LookupFn = Arc<dyn Fn(&str, Family) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

/// 1 回の解決の結果。誤りは `lookup <名前>: ` で始まる文。
type Outcome = Result<Vec<IpAddr>, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Target,
    Endpoint,
}

type Key = (Kind, String);

/// 結果を待つための受け手。結果が出るまで `None`。
type Waiter = watch::Receiver<Option<Outcome>>;

/// 引いている途中の名前の表。値は解決の番号と受け手。
#[derive(Default)]
struct Flights {
    map: Mutex<HashMap<Key, (u64, Waiter)>>,
    next: AtomicU64,
}

impl Flights {
    fn remove(&self, key: &Key, id: u64) {
        let mut m = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if m.get(key).is_some_and(|(i, _)| *i == id) {
            m.remove(key);
        }
    }
}

/// 1 つの名前の解決。結果を配る前に表から外し、配った後の呼び手は新しく引く。結果を配らずに落ちた
/// (実行環境が落ちた、スレッドを作れなかった) ときも表から外し、待っている呼び手は誤りを受ける。
struct Flight {
    flights: Arc<Flights>,
    key: Key,
    id: u64,
    tx: watch::Sender<Option<Outcome>>,
}

impl Flight {
    fn finish(self, r: Outcome) {
        self.flights.remove(&self.key, self.id);
        self.tx.send_replace(Some(r));
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        self.flights.remove(&self.key, self.id);
    }
}

/// 上限のある resolver。プロセスで 1 つを [`Resolver::shared`] で分け合う。トンネルの世代をまたいで
/// 許可の数と相乗りの表を保つためである。
pub struct Resolver {
    targets: Arc<Semaphore>,
    endpoint: Arc<Semaphore>,
    lookup: LookupFn,
    flights: Arc<Flights>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("targets", &self.targets.available_permits())
            .field("endpoint", &self.endpoint.available_permits())
            .finish_non_exhaustive()
    }
}

static SHARED: LazyLock<Arc<Resolver>> = LazyLock::new(|| {
    Arc::new(Resolver::with_lookup(
        TARGET_PERMITS,
        ENDPOINT_PERMITS,
        Arc::new(os_lookup),
    ))
});

/// OS の resolver で引く。
fn os_lookup(host: &str, family: Family) -> std::io::Result<Vec<IpAddr>> {
    match family {
        Family::Any => (host, 0)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect()),
        Family::V4 => sys::lookup_v4(host),
    }
}

impl Resolver {
    /// プロセスで 1 つの resolver。
    #[must_use]
    pub fn shared() -> Arc<Resolver> {
        Arc::clone(&SHARED)
    }

    /// 許可の数と引く関数を決めて作る。
    #[must_use]
    pub fn with_lookup(targets: usize, endpoint: usize, lookup: LookupFn) -> Resolver {
        Resolver {
            targets: Arc::new(Semaphore::new(targets)),
            endpoint: Arc::new(Semaphore::new(endpoint)),
            lookup,
            flights: Arc::default(),
        }
    }

    /// 宛先の名前を引き、RFC 6724 の順に並べる。
    ///
    /// # Errors
    ///
    /// 期限までに引けなければ、`lookup <名前>: ` で始まる誤りの文を返す。
    pub async fn lookup_target(&self, host: &str, deadline: Instant) -> Outcome {
        self.lookup(Kind::Target, host, deadline).await
    }

    /// WireGuard のエンドポイントの名前の A レコードを、宛先とは別の許可で引く。順は並べ直さない。
    ///
    /// # Errors
    ///
    /// 期限までに引けなければ、`lookup <名前>: ` で始まる誤りの文を返す。
    pub async fn lookup_endpoint(&self, host: &str, deadline: Instant) -> Outcome {
        self.lookup(Kind::Endpoint, host, deadline).await
    }

    async fn lookup(&self, kind: Kind, host: &str, deadline: Instant) -> Outcome {
        let mut rx = self.join(kind, host);
        // Go の resolver が期限で打ち切ったときと同じ語にする
        match tokio::time::timeout_at(deadline, rx.wait_for(Option::is_some)).await {
            Err(_) => Err(format!("lookup {host}: i/o timeout")),
            Ok(Err(_)) => Err(format!("lookup {host}: the resolver could not run")),
            Ok(Ok(v)) => v
                .clone()
                .unwrap_or_else(|| Err(format!("lookup {host}: no result"))),
        }
    }

    /// 同じ名前を引いている途中なら、その結果の受け手を返す。無ければ新しく引き始める。
    fn join(&self, kind: Kind, host: &str) -> Waiter {
        let key = (kind, host.to_owned());
        let mut m = self
            .flights
            .map
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((_, rx)) = m.get(&key) {
            return rx.clone();
        }
        let (tx, rx) = watch::channel(None);
        let id = self.flights.next.fetch_add(1, AtomicOrdering::Relaxed);
        m.insert(key.clone(), (id, rx.clone()));
        drop(m);
        let flight = Flight {
            flights: Arc::clone(&self.flights),
            key,
            id,
            tx,
        };
        let (sem, family, sort) = match kind {
            Kind::Target => (Arc::clone(&self.targets), Family::Any, true),
            Kind::Endpoint => (Arc::clone(&self.endpoint), Family::V4, false),
        };
        let lookup = Arc::clone(&self.lookup);
        // 許可を待つのは呼び手でなくこのタスクで、呼び手はそれぞれの期限で結果を待つ
        tokio::spawn(async move {
            let Ok(permit) = sem.acquire_owned().await else {
                return;
            };
            // スレッドを作れなければ、閉包と一緒に flight が落ち、待っている呼び手は誤りを受ける
            let _ = std::thread::Builder::new()
                .name("wgft-resolve".into())
                .spawn(move || {
                    let host = flight.key.1.clone();
                    let r = lookup(&host, family)
                        .map(|mut v| {
                            dedup(&mut v);
                            if sort {
                                sort_by_rfc6724(&mut v);
                            }
                            v
                        })
                        .map_err(|e| format!("lookup {host}: {}", lookup_error_text(&e)));
                    flight.finish(r);
                    drop(permit);
                });
        });
        rx
    }
}

/// `std` の `getaddrinfo` の誤りは `failed to lookup address information: ` で始まるので、その前置きを
/// 落とす。
fn lookup_error_text(e: &std::io::Error) -> String {
    let s = e.to_string();
    s.strip_prefix("failed to lookup address information: ")
        .map_or(s.clone(), str::to_owned)
}

/// 順を保って重複を除く。`getaddrinfo` は socktype ごとに同じアドレスを返しうる。
fn dedup(v: &mut Vec<IpAddr>) {
    let mut seen = Vec::with_capacity(v.len());
    v.retain(|a| {
        let a = a.to_canonical();
        if seen.contains(&a) {
            return false;
        }
        seen.push(a);
        true
    });
    for a in v.iter_mut() {
        *a = a.to_canonical();
    }
}

#[cfg(unix)]
mod sys {
    use std::ffi::{CStr, CString};
    use std::net::{IpAddr, Ipv4Addr};

    /// `getaddrinfo` を `AF_INET` で呼び、A レコードだけを引く。
    pub(super) fn lookup_v4(host: &str) -> std::io::Result<Vec<IpAddr>> {
        let name = CString::new(host)
            .map_err(|_| std::io::Error::other("the name contains a NUL byte"))?;
        // SAFETY: addrinfo は C の構造体で、すべて 0 の値が正しい初期値である
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = libc::AF_INET;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        // SAFETY: name は NUL で終わり、hints と res は書き込める場所を指す
        let rc = unsafe {
            libc::getaddrinfo(
                name.as_ptr(),
                std::ptr::null(),
                &raw const hints,
                &raw mut res,
            )
        };
        if rc != 0 {
            if rc == libc::EAI_SYSTEM {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: gai_strerror は静的な NUL 終わりの文を返す
            let msg = unsafe { CStr::from_ptr(libc::gai_strerror(rc)) };
            return Err(std::io::Error::other(msg.to_string_lossy().into_owned()));
        }
        let mut out = Vec::new();
        let mut cur = res;
        while !cur.is_null() {
            // SAFETY: cur は getaddrinfo が返した一覧の要素で、freeaddrinfo までは有効である
            let ai = unsafe { &*cur };
            cur = ai.ai_next;
            if ai.ai_family != libc::AF_INET || ai.ai_addr.is_null() {
                continue;
            }
            // SAFETY: family が AF_INET なので ai_addr は sockaddr_in を指す
            let sin = unsafe { ai.ai_addr.cast::<libc::sockaddr_in>().read_unaligned() };
            out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))));
        }
        // SAFETY: res は getaddrinfo が返した一覧で、ここで 1 回だけ解放する
        unsafe { libc::freeaddrinfo(res) };
        Ok(out)
    }
}

#[cfg(windows)]
mod sys {
    use std::ffi::CString;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Once;

    use windows_sys::Win32::Networking::WinSock::{
        ADDRINFOA, AF_INET, SOCK_STREAM, SOCKADDR_IN, WSADATA, WSAStartup, freeaddrinfo,
        getaddrinfo,
    };

    /// `getaddrinfo` を `AF_INET` で呼び、A レコードだけを引く。
    pub(super) fn lookup_v4(host: &str) -> std::io::Result<Vec<IpAddr>> {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            // SAFETY: WSADATA は C の構造体で、すべて 0 の値が正しい初期値である
            let mut data: WSADATA = unsafe { std::mem::zeroed() };
            // SAFETY: data は書き込める場所を指す。Winsock の初期化は回数を数えるので、std の初期化と
            // 重なってもよい。std と同じく後始末は呼ばない
            let _ = unsafe { WSAStartup(0x202, &raw mut data) };
        });
        let name = CString::new(host)
            .map_err(|_| std::io::Error::other("the name contains a NUL byte"))?;
        let hints = ADDRINFOA {
            ai_family: i32::from(AF_INET),
            ai_socktype: SOCK_STREAM,
            ..ADDRINFOA::default()
        };
        let mut res: *mut ADDRINFOA = std::ptr::null_mut();
        // SAFETY: name は NUL で終わり、hints と res は書き込める場所を指す
        let rc = unsafe {
            getaddrinfo(
                name.as_ptr().cast(),
                std::ptr::null(),
                &raw const hints,
                &raw mut res,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        let mut out = Vec::new();
        let mut cur = res;
        while !cur.is_null() {
            // SAFETY: cur は getaddrinfo が返した一覧の要素で、freeaddrinfo までは有効である
            let ai = unsafe { &*cur };
            cur = ai.ai_next;
            if ai.ai_family != i32::from(AF_INET) || ai.ai_addr.is_null() {
                continue;
            }
            // SAFETY: family が AF_INET なので ai_addr は SOCKADDR_IN を指す
            let sin = unsafe { ai.ai_addr.cast::<SOCKADDR_IN>().read_unaligned() };
            // SAFETY: IN_ADDR の共用体はどの読み方も同じ 4 byte である
            let a = unsafe { sin.sin_addr.S_un.S_addr };
            out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(a))));
        }
        // SAFETY: res は getaddrinfo が返した一覧で、ここで 1 回だけ解放する
        unsafe { freeaddrinfo(res) };
        Ok(out)
    }
}

#[cfg(not(any(unix, windows)))]
mod sys {
    use std::net::{IpAddr, ToSocketAddrs};

    /// 他の OS では族を指定できないので、引いた後に IPv4 だけを残す。
    pub(super) fn lookup_v4(host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok((host, 0)
            .to_socket_addrs()?
            .map(|a| a.ip())
            .filter(IpAddr::is_ipv4)
            .collect())
    }
}

/// RFC 6724 の宛先の規則で並べる。Go の `net` の `sortByRFC6724` と同じく、送信元のアドレスは宛先へ UDP の
/// ソケットを接続して求める (packet は送らない)。
pub(crate) fn sort_by_rfc6724(addrs: &mut [IpAddr]) {
    if addrs.len() < 2 {
        return;
    }
    let srcs: Vec<Option<IpAddr>> = addrs.iter().map(|a| source_for(*a)).collect();
    sort_with_sources(addrs, &srcs);
}

fn source_for(dst: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match dst {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let s = UdpSocket::bind(bind).ok()?;
    s.connect((dst, 53)).ok()?;
    Some(s.local_addr().ok()?.ip().to_canonical())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Attr {
    scope: u8,
    precedence: u8,
    label: u8,
}

/// RFC 6724 の 2.1 節の表。帯の長い順に並べ、最初に当たった行を使う。
const POLICY: [(u128, u8, u8, u8); 9] = [
    // (帯, 長さ, precedence, label)
    (1, 128, 50, 0),
    (0xffff_0000_0000, 96, 35, 4),
    (0, 96, 1, 3),
    (0x2001 << 112, 32, 5, 5),
    (0x2002 << 112, 16, 30, 2),
    (0x3ffe << 112, 16, 1, 12),
    (0xfec0 << 112, 10, 1, 11),
    (0xfc00 << 112, 7, 3, 13),
    (0, 0, 40, 1),
];

fn as_v6_bits(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

const SCOPE_LINK_LOCAL: u8 = 0x2;
const SCOPE_SITE_LOCAL: u8 = 0x5;
const SCOPE_GLOBAL: u8 = 0xe;

fn classify_scope(a: IpAddr) -> u8 {
    match a {
        IpAddr::V4(v4) if v4.is_loopback() || v4.is_link_local() => SCOPE_LINK_LOCAL,
        IpAddr::V4(_) => SCOPE_GLOBAL,
        IpAddr::V6(v6) => {
            let o = v6.octets();
            if v6.is_loopback() || v6.is_unicast_link_local() {
                SCOPE_LINK_LOCAL
            } else if v6.is_multicast() {
                o[1] & 0xf
            } else if o[0] == 0xfe && o[1] & 0xc0 == 0xc0 {
                SCOPE_SITE_LOCAL
            } else {
                SCOPE_GLOBAL
            }
        }
    }
}

fn attr_of(a: Option<IpAddr>) -> Attr {
    let Some(a) = a else {
        return Attr::default();
    };
    let bits = as_v6_bits(a);
    let (_, _, precedence, label) = POLICY
        .iter()
        .copied()
        .find(|(p, len, _, _)| {
            let mask = u128::MAX.checked_shl(128 - u32::from(*len)).unwrap_or(0);
            bits & mask == *p
        })
        .unwrap_or_default();
    Attr {
        scope: classify_scope(a),
        precedence,
        label,
    }
}

/// 送信元 `src` と宛先 `dst` の共通の接頭辞の長さ。IPv6 は前の 64 bit までを見る。族が違えば 0。
fn common_prefix_len(src: IpAddr, dst: IpAddr) -> u32 {
    match (src, dst) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) ^ u32::from(b)).leading_zeros(),
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let x = (u128::from(a) ^ u128::from(b)) >> 64;
            x.leading_zeros().saturating_sub(64).min(64)
        }
        _ => 0,
    }
}

fn compare(a: (IpAddr, Option<IpAddr>), b: (IpAddr, Option<IpAddr>)) -> Ordering {
    use Ordering::{Equal, Greater, Less};
    let (da, sa) = a;
    let (db, sb) = b;
    // 規則 1:使えない宛先を避ける
    match (sa, sb) {
        (None, None) => return Equal,
        (Some(_), None) => return Less,
        (None, Some(_)) => return Greater,
        _ => {}
    }
    let (ada, asa) = (attr_of(Some(da)), attr_of(sa));
    let (adb, asb) = (attr_of(Some(db)), attr_of(sb));
    // 規則 2:scope の一致を選ぶ
    match (ada.scope == asa.scope, adb.scope == asb.scope) {
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => {}
    }
    // 規則 5:label の一致を選ぶ
    match (asa.label == ada.label, asb.label == adb.label) {
        (true, false) => return Less,
        (false, true) => return Greater,
        _ => {}
    }
    // 規則 6:precedence の高い方
    match ada.precedence.cmp(&adb.precedence) {
        Equal => {}
        o => return o.reverse(),
    }
    // 規則 8:scope の小さい方
    match ada.scope.cmp(&adb.scope) {
        Equal => {}
        o => return o,
    }
    // 規則 9:最長一致。Go と同じく IPv6 どうしだけに当てる
    if let (IpAddr::V6(_), IpAddr::V6(_), Some(sa), Some(sb)) = (da, db, sa, sb) {
        match common_prefix_len(sa, da).cmp(&common_prefix_len(sb, db)) {
            Equal => {}
            o => return o.reverse(),
        }
    }
    // 規則 10:元の順を保つ
    Equal
}

fn sort_with_sources(addrs: &mut [IpAddr], srcs: &[Option<IpAddr>]) {
    let mut pairs: Vec<(IpAddr, Option<IpAddr>)> =
        addrs.iter().copied().zip(srcs.iter().copied()).collect();
    pairs.sort_by(|a, b| compare(*a, *b));
    for (slot, (a, _)) in addrs.iter_mut().zip(pairs) {
        *slot = a;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Go の `TestSortByRFC6724` の例 (RFC 6724 の 10.2 節と Go の issue 13283)。
    #[test]
    fn sorts_like_go() {
        type Case<'a> = (&'a [&'a str], &'a [&'a str], &'a [&'a str], bool);
        let cases: [Case<'_>; 5] = [
            (
                &["2001:db8:1::1", "198.51.100.121"],
                &["2001:db8:1::2", "169.254.13.78"],
                &["2001:db8:1::1", "198.51.100.121"],
                true,
            ),
            (
                &["2001:db8:1::1", "198.51.100.121"],
                &["fe80::1", "198.51.100.117"],
                &["198.51.100.121", "2001:db8:1::1"],
                true,
            ),
            (
                &["2001:db8:1::1", "10.1.2.3"],
                &["2001:db8:1::2", "10.1.2.4"],
                &["2001:db8:1::1", "10.1.2.3"],
                true,
            ),
            (
                &["2001:db8:1::1", "fe80::1"],
                &["2001:db8:1::2", "fe80::2"],
                &["fe80::1", "2001:db8:1::1"],
                true,
            ),
            (
                &[
                    "54.83.193.112",
                    "184.72.238.214",
                    "23.23.172.185",
                    "75.101.148.21",
                    "23.23.134.56",
                    "23.21.50.150",
                ],
                &["10.2.3.4"; 6],
                &[
                    "54.83.193.112",
                    "184.72.238.214",
                    "23.23.172.185",
                    "75.101.148.21",
                    "23.23.134.56",
                    "23.21.50.150",
                ],
                false,
            ),
        ];
        for (i, (input, srcs, want, reverse)) in cases.into_iter().enumerate() {
            let mut a: Vec<IpAddr> = input.iter().map(|s| ip(s)).collect();
            let mut s: Vec<Option<IpAddr>> = srcs.iter().map(|s| Some(ip(s))).collect();
            let want: Vec<IpAddr> = want.iter().map(|s| ip(s)).collect();
            sort_with_sources(&mut a, &s);
            assert_eq!(a, want, "case {i}");
            if reverse {
                let mut a: Vec<IpAddr> = input.iter().rev().map(|s| ip(s)).collect();
                s.reverse();
                sort_with_sources(&mut a, &s);
                assert_eq!(a, want, "case {i} reversed");
            }
        }
        // 送信元の無い宛先は後ろへ
        let mut a = vec![ip("2001:db8::1"), ip("192.0.2.1")];
        sort_with_sources(&mut a, &[None, Some(ip("192.0.2.9"))]);
        assert_eq!(a, vec![ip("192.0.2.1"), ip("2001:db8::1")]);
    }

    #[test]
    fn common_prefix_matches_go() {
        assert_eq!(common_prefix_len(ip("10.0.0.1"), ip("10.0.0.1")), 32);
        assert_eq!(common_prefix_len(ip("10.0.0.1"), ip("10.0.0.0")), 31);
        assert_eq!(common_prefix_len(ip("2001:db8::1"), ip("2001:db8::2")), 64);
        assert_eq!(common_prefix_len(ip("2001:db8::1"), ip("2001:db9::1")), 31);
        assert_eq!(common_prefix_len(ip("2001:db8::1"), ip("10.0.0.1")), 0);
    }

    fn slow(started: Arc<AtomicUsize>, wait: Duration) -> LookupFn {
        Arc::new(move |h: &str, family| {
            started.fetch_add(1, AtomicOrdering::SeqCst);
            std::thread::sleep(wait);
            if h == "missing" {
                return Err(std::io::Error::other(
                    "failed to lookup address information: Name or service not known",
                ));
            }
            let mut v = vec![ip("192.0.2.1"), ip("::ffff:192.0.2.1"), ip("192.0.2.2")];
            if family == Family::Any {
                v.push(ip("2001:db8::1"));
            }
            Ok(v)
        })
    }

    #[tokio::test]
    async fn returns_deduplicated_addresses_and_strips_the_std_prefix() {
        let r = Resolver::with_lookup(2, 1, slow(Arc::default(), Duration::ZERO));
        let soon = Instant::now() + Duration::from_secs(2);
        // エンドポイントは A レコードだけを引く
        let got = r.lookup_endpoint("h", soon).await.unwrap();
        assert_eq!(got, vec![ip("192.0.2.1"), ip("192.0.2.2")]);
        let got = r.lookup_target("h", soon).await.unwrap();
        assert_eq!(got.len(), 3, "{got:?}");
        assert_eq!(
            r.lookup_target("missing", soon).await.unwrap_err(),
            "lookup missing: Name or service not known"
        );
    }

    #[tokio::test]
    async fn the_deadline_abandons_the_lookup_and_the_permit_returns_later() {
        let started = Arc::new(AtomicUsize::new(0));
        let r = Resolver::with_lookup(1, 1, slow(Arc::clone(&started), Duration::from_millis(300)));
        let t0 = Instant::now();
        let e = r
            .lookup_target("h", t0 + Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(e, "lookup h: i/o timeout");
        assert!(t0.elapsed() < Duration::from_millis(250));
        // スレッドが戻るまで許可は返らないので、別の名前の解決は許可を待って期限で失敗する
        let e = r
            .lookup_target("h2", Instant::now() + Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(e, "lookup h2: i/o timeout");
        assert_eq!(started.load(AtomicOrdering::SeqCst), 1);
        // エンドポイントの許可は別なので待たない
        let ep = r
            .lookup_endpoint("h", Instant::now() + Duration::from_secs(2))
            .await;
        assert!(ep.is_ok(), "{ep:?}");
        // 最初のスレッドが戻れば許可が返り、待っていた名前も引かれる
        assert!(
            r.lookup_target("h2", Instant::now() + Duration::from_secs(2))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn at_most_the_permits_run_at_once() {
        let started = Arc::new(AtomicUsize::new(0));
        let r = Arc::new(Resolver::with_lookup(
            3,
            1,
            slow(Arc::clone(&started), Duration::from_millis(200)),
        ));
        let deadline = Instant::now() + Duration::from_millis(100);
        let tasks: Vec<_> = (0..6)
            .map(|i| {
                let r = Arc::clone(&r);
                tokio::spawn(async move { r.lookup_target(&format!("h{i}"), deadline).await })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap().is_err());
        }
        assert_eq!(started.load(AtomicOrdering::SeqCst), 3);
    }

    /// 32 ポートの範囲のルールが 1 つの名前を同時に引いても、問い合わせは 1 回で、遅い DNS でも全部が
    /// 期限の中で結果を受ける。
    #[tokio::test]
    async fn concurrent_lookups_of_one_name_share_one_query() {
        let started = Arc::new(AtomicUsize::new(0));
        let r = Arc::new(Resolver::with_lookup(
            8,
            2,
            slow(Arc::clone(&started), Duration::from_millis(600)),
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let r = Arc::clone(&r);
                tokio::spawn(async move { r.lookup_target("nas.lan", deadline).await })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap().is_ok());
        }
        assert_eq!(started.load(AtomicOrdering::SeqCst), 1);
        // 終わった後の呼び手は新しく引く
        r.lookup_target("nas.lan", Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(started.load(AtomicOrdering::SeqCst), 2);
    }

    /// 1 つの名前への接続のフラッドは許可を 1 つしか使わないので、他の名前の解決は待たない。
    #[tokio::test]
    async fn a_flood_on_one_name_does_not_starve_another() {
        let r = Arc::new(Resolver::with_lookup(
            2,
            1,
            Arc::new(|h: &str, _| {
                if h == "busy" {
                    std::thread::sleep(Duration::from_millis(500));
                }
                Ok(vec![ip("192.0.2.1")])
            }),
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        let flood: Vec<_> = (0..100)
            .map(|_| {
                let r = Arc::clone(&r);
                tokio::spawn(async move { r.lookup_target("busy", deadline).await })
            })
            .collect();
        tokio::task::yield_now().await;
        let t0 = Instant::now();
        r.lookup_target("other", deadline).await.unwrap();
        assert!(
            t0.elapsed() < Duration::from_millis(300),
            "{:?}",
            t0.elapsed()
        );
        for t in flood {
            assert!(t.await.unwrap().is_ok());
        }
    }

    #[test]
    fn the_os_resolver_returns_only_a_records_for_the_endpoint() {
        let got = os_lookup("localhost", Family::V4).unwrap();
        assert!(
            !got.is_empty() && got.iter().all(|a| a.is_ipv4() && a.is_loopback()),
            "{got:?}"
        );
    }

    #[tokio::test]
    async fn the_os_resolver_finds_localhost() {
        let got = Resolver::shared()
            .lookup_target("localhost", Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(got.iter().all(IpAddr::is_loopback), "{got:?}");
    }
}
