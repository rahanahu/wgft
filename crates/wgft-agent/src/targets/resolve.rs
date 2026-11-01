//! 名前の解決 (`docs/design/v2/agent-parity.md` の「名前の解決」)。
//!
//! OS の `getaddrinfo` (`std::net::ToSocketAddrs`) を、引く名前ごとに 1 本の OS のスレッドで呼ぶ。
//! スレッドの数は許可の数で抑える。宛先の名前は同時に 8 つまで、WireGuard のエンドポイントの名前は
//! 別の許可 1 つで引くので、宛先の解決が許可を使い切ってもトンネルの名前の引き直しは止まらない。
//! 許可を待つ時間も期限に含める。期限を過ぎた呼び手は誤りを受けて結果を待たず、スレッドは
//! `getaddrinfo` が戻るまで動き続け、結果を捨ててから許可を返す。
//!
//! tokio の `spawn_blocking` を使わないのは、実行環境を落とすときに blocking のタスクの終わりを待つため
//! である。応答しない resolver があると、トンネルの世代を閉じる処理がそこで止まる。
//!
//! 宛先の名前は、Go の resolver と同じ RFC 6724 の宛先の規則で並べ直す。`getaddrinfo` の順は libc と
//! 設定 (`gai.conf`) で変わるためである。

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, LazyLock};

use tokio::sync::{Semaphore, oneshot};
use tokio::time::Instant;

/// 宛先の名前を同時に引く数。
pub const TARGET_PERMITS: usize = 8;
/// WireGuard のエンドポイントの名前を同時に引く数。
pub const ENDPOINT_PERMITS: usize = 1;

/// 名前を引く関数。OS の resolver を呼ぶ既定の関数を、試験が差し替える。
pub type LookupFn = Arc<dyn Fn(&str) -> std::io::Result<Vec<IpAddr>> + Send + Sync>;

/// 上限のある resolver。プロセスで 1 つを [`Resolver::shared`] で分け合う。トンネルの世代をまたいで
/// 許可の数を保つためである。
pub struct Resolver {
    targets: Arc<Semaphore>,
    endpoint: Arc<Semaphore>,
    lookup: LookupFn,
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

/// OS の resolver で引く。`getaddrinfo` の誤りの文の前置きは落とす。
fn os_lookup(host: &str) -> std::io::Result<Vec<IpAddr>> {
    (host, 0)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
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
        }
    }

    /// 宛先の名前を引き、RFC 6724 の順に並べる。
    ///
    /// # Errors
    ///
    /// 期限までに引けなければ、`lookup <名前>: ` で始まる誤りの文を返す。
    pub async fn lookup_target(
        &self,
        host: &str,
        deadline: Instant,
    ) -> Result<Vec<IpAddr>, String> {
        self.lookup(&self.targets, host, deadline, true).await
    }

    /// WireGuard のエンドポイントの名前を、宛先とは別の許可で引く。順は並べ直さない。
    ///
    /// # Errors
    ///
    /// 期限までに引けなければ、`lookup <名前>: ` で始まる誤りの文を返す。
    pub async fn lookup_endpoint(
        &self,
        host: &str,
        deadline: Instant,
    ) -> Result<Vec<IpAddr>, String> {
        self.lookup(&self.endpoint, host, deadline, false).await
    }

    async fn lookup(
        &self,
        sem: &Arc<Semaphore>,
        host: &str,
        deadline: Instant,
        sort: bool,
    ) -> Result<Vec<IpAddr>, String> {
        // Go の resolver が期限で打ち切ったときと同じ語にする
        let timeout = || format!("lookup {host}: i/o timeout");
        let permit = tokio::time::timeout_at(deadline, Arc::clone(sem).acquire_owned())
            .await
            .map_err(|_| timeout())?
            .map_err(|_| format!("lookup {host}: the resolver is closed"))?;
        let (tx, rx) = oneshot::channel();
        let lookup = Arc::clone(&self.lookup);
        let name = host.to_owned();
        std::thread::Builder::new()
            .name("wgft-resolve".into())
            .spawn(move || {
                let r = lookup(&name).map(|mut v| {
                    dedup(&mut v);
                    if sort {
                        sort_by_rfc6724(&mut v);
                    }
                    v
                });
                // 呼び手が期限で去っていれば結果は捨てられる。許可は送った後に返す
                let _ = tx.send(r);
                drop(permit);
            })
            .map_err(|e| format!("lookup {host}: cannot start a resolver thread: {e}"))?;
        match tokio::time::timeout_at(deadline, rx).await {
            Err(_) => Err(timeout()),
            Ok(Err(_)) => Err(format!("lookup {host}: the resolver thread ended")),
            Ok(Ok(Err(e))) => Err(format!("lookup {host}: {}", lookup_error_text(&e))),
            Ok(Ok(Ok(v))) => Ok(v),
        }
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
        Arc::new(move |h: &str| {
            started.fetch_add(1, AtomicOrdering::SeqCst);
            std::thread::sleep(wait);
            if h == "missing" {
                return Err(std::io::Error::other(
                    "failed to lookup address information: Name or service not known",
                ));
            }
            Ok(vec![
                ip("192.0.2.1"),
                ip("::ffff:192.0.2.1"),
                ip("192.0.2.2"),
            ])
        })
    }

    #[tokio::test]
    async fn returns_deduplicated_addresses_and_strips_the_std_prefix() {
        let r = Resolver::with_lookup(2, 1, slow(Arc::default(), Duration::ZERO));
        let soon = Instant::now() + Duration::from_secs(2);
        let got = r.lookup_endpoint("h", soon).await.unwrap();
        assert_eq!(got, vec![ip("192.0.2.1"), ip("192.0.2.2")]);
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
        // スレッドが戻るまで許可は返らないので、次の解決は許可を待って期限で失敗する
        let e = r
            .lookup_target("h", Instant::now() + Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(e, "lookup h: i/o timeout");
        assert_eq!(started.load(AtomicOrdering::SeqCst), 1);
        // エンドポイントの許可は別なので待たない
        let ep = r
            .lookup_endpoint("h", Instant::now() + Duration::from_secs(2))
            .await;
        assert!(ep.is_ok(), "{ep:?}");
        // 最初のスレッドが戻れば許可が返る
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            r.lookup_target("h", Instant::now() + Duration::from_secs(2))
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
            .map(|_| {
                let r = Arc::clone(&r);
                tokio::spawn(async move { r.lookup_target("h", deadline).await })
            })
            .collect();
        for t in tasks {
            assert!(t.await.unwrap().is_err());
        }
        assert_eq!(started.load(AtomicOrdering::SeqCst), 3);
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
