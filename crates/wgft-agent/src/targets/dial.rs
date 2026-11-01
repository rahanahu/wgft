//! 宛先への接続の試し方 (仕様 `tunnel.md` の「Go の性質:宛先への接続の試し方」)。
//!
//! TCP では、解決の結果の先頭のアドレスと同じ族のアドレスを先に試し、300 ミリ秒のうちに繋がらなければ
//! もう一方の族のアドレスも並行して試し始め、先に繋がった接続を使う。同じ族の中では解決の結果の順に
//! 1 つずつ試し、期限の残りをまだ試していないアドレスの数で分ける。1 つのアドレスの持ち分は 2 秒を
//! 下回らない。UDP は族を分けずに順に試す。Go の `net.Dialer` の `dialParallel` と `dialSerial` と同じ
//! 規則である。
//!
//! 接続そのものは呼び手の関数に任せるので、この規則はソケットの種類 (TCP、接続した UDP) に依らない。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::Instant;

/// もう一方の族を試し始めるまでの待ち。Go の `net.Dialer` の `FallbackDelay` の既定と同じ。
pub const FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// 1 つのアドレスへ与える期限の下限。Go の `net.Dialer` と同じ。
pub const MIN_ADDR_TIMEOUT: Duration = Duration::from_secs(2);

/// LAN の側の TCP の keepalive。Go の `net.Dialer` の既定と同じく、無通信 15 秒、間隔 15 秒、9 回。
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
/// keepalive の間隔。
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// keepalive の回数。
pub const KEEPALIVE_COUNT: u32 = 9;

/// 残り `remaining` 個のアドレスを試すときの、次の 1 つの期限。
fn addr_deadline(now: Instant, deadline: Instant, remaining: usize) -> Instant {
    let left = deadline.saturating_duration_since(now);
    let per = left / u32::try_from(remaining.max(1)).unwrap_or(u32::MAX);
    let per = if per < MIN_ADDR_TIMEOUT {
        left.min(MIN_ADDR_TIMEOUT)
    } else {
        per
    };
    now + per
}

/// `addrs` のうち `list` の位置のアドレスを順に試し、最初に繋がった接続を返す。失敗した位置と誤りを
/// `errs` に積む。
async fn serial<C, F, Fut>(
    addrs: &[SocketAddr],
    list: &[usize],
    deadline: Instant,
    connect: &F,
    errs: &mut Vec<(usize, String)>,
) -> Option<C>
where
    F: Fn(SocketAddr, Instant) -> Fut,
    Fut: Future<Output = Result<C, String>>,
{
    for (k, &i) in list.iter().enumerate() {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let per = addr_deadline(now, deadline, list.len() - k);
        match connect(addrs[i], per).await {
            Ok(c) => return Some(c),
            Err(e) => errs.push((i, e)),
        }
    }
    None
}

/// 解決したアドレスへ接続する。`split_families` が真なら TCP の試し方で 2 つの族を競わせる。すべて
/// 失敗した場合は、解決の結果の順で最後に試したアドレスの誤りを返す。
///
/// `connect` はアドレスとそのアドレスの期限を受け、期限までに繋がらなければ誤りを返す。
///
/// # Errors
///
/// どのアドレスにも繋がらなければ誤りの文を返す。
pub async fn race<C, F, Fut>(
    addrs: &[SocketAddr],
    split_families: bool,
    deadline: Instant,
    connect: F,
) -> Result<C, String>
where
    F: Fn(SocketAddr, Instant) -> Fut,
    Fut: Future<Output = Result<C, String>>,
{
    let Some(first) = addrs.first() else {
        return Err("dial: no address to try".to_owned());
    };
    let (primaries, fallbacks): (Vec<usize>, Vec<usize>) =
        (0..addrs.len()).partition(|&i| !split_families || addrs[i].is_ipv4() == first.is_ipv4());
    let mut perr = Vec::new();
    let mut ferr = Vec::new();
    if fallbacks.is_empty() {
        if let Some(c) = serial(addrs, &primaries, deadline, &connect, &mut perr).await {
            return Ok(c);
        }
        return Err(last_err(perr));
    }
    let won = {
        let primary = serial(addrs, &primaries, deadline, &connect, &mut perr);
        let fallback = serial(addrs, &fallbacks, deadline, &connect, &mut ferr);
        tokio::pin!(primary, fallback);
        let delay = tokio::time::sleep(FALLBACK_DELAY);
        tokio::pin!(delay);
        let (mut fallback_started, mut primary_done, mut fallback_done) = (false, false, false);
        loop {
            tokio::select! {
                r = &mut primary, if !primary_done => {
                    if r.is_some() {
                        break r;
                    }
                    primary_done = true;
                    // 先の族がすべて失敗した。待たずにもう一方の族を試す
                    fallback_started = true;
                }
                () = &mut delay, if !fallback_started => fallback_started = true,
                r = &mut fallback, if fallback_started && !fallback_done => {
                    if r.is_some() {
                        break r;
                    }
                    fallback_done = true;
                }
            }
            if primary_done && fallback_done {
                break None;
            }
        }
    };
    if let Some(c) = won {
        return Ok(c);
    }
    perr.extend(ferr);
    Err(last_err(perr))
}

/// 解決の結果の順で最後に試したアドレスの誤り。どのアドレスも試す前に期限が来た場合は期限切れの誤り。
fn last_err(mut errs: Vec<(usize, String)>) -> String {
    errs.sort_by_key(|(i, _)| *i);
    errs.pop().map_or_else(
        || "dial: timed out before trying any address".to_owned(),
        |(_, e)| e,
    )
}

/// TCP で 1 つのアドレスへ `deadline` までに接続し、LAN の側の keepalive を付ける。誤りの文は Go の
/// `net` の形 (`dial tcp <アドレス>: connect: <理由>`、期限切れは `dial tcp <アドレス>: i/o timeout`)
/// にする。`server doctor` はルールの理由の語で分類するためである。
///
/// # Errors
///
/// 繋がらなければ誤りの文を返す。
pub async fn connect_tcp(addr: SocketAddr, deadline: Instant) -> Result<TcpStream, String> {
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| format!("dial tcp {addr}: socket: {}", errno_text(&e)))?;
    let fut = sock.connect(addr);
    let s = match tokio::time::timeout_at(deadline, fut).await {
        Err(_) => return Err(format!("dial tcp {addr}: i/o timeout")),
        Ok(Err(e)) => return Err(format!("dial tcp {addr}: connect: {}", errno_text(&e))),
        Ok(Ok(s)) => s,
    };
    // Go の net.Dialer と同じく、繋がった後に付ける。付けられなくても接続は使う
    let _ = set_keepalive(&s);
    Ok(s)
}

/// 1 つのアドレスへ接続した UDP のソケットを開く。ソケットは同じ族の任意のアドレスとポートに bind し、
/// 宛先へ `connect` する。UDP の `connect` は packet を送らないので待たず、`deadline` は試し方の部品と
/// 形を揃えるためだけに受ける。誤りの文は Go の `net` の形 (`dial udp <アドレス>: connect: <理由>`) に
/// する。
///
/// # Errors
///
/// ソケットを開けないか接続できなければ誤りの文を返す。
pub async fn connect_udp(addr: SocketAddr, _deadline: Instant) -> Result<UdpSocket, String> {
    let any: SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let open = || -> io::Result<UdpSocket> {
        let s = std::net::UdpSocket::bind(any)?;
        s.set_nonblocking(true)?;
        UdpSocket::from_std(s)
    };
    let s = open().map_err(|e| format!("dial udp {addr}: socket: {}", errno_text(&e)))?;
    s.connect(addr)
        .await
        .map_err(|e| format!("dial udp {addr}: connect: {}", errno_text(&e)))?;
    Ok(s)
}

/// LAN の側の TCP の keepalive を付ける。
pub(crate) fn set_keepalive(s: &TcpStream) -> io::Result<()> {
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_COUNT);
    SockRef::from(s).set_tcp_keepalive(&ka)
}

/// OS の誤りを Go の `syscall.Errno` の文と同じ小文字の形にする。`server doctor` が照らす語
/// (`connection refused`、`no route to host`、`unreachable`、`timed out`) を OS によらず出すため、主な
/// 種類は Unix の文に揃える。
pub(crate) fn errno_text(e: &io::Error) -> String {
    use io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => return "connection refused".to_owned(),
        K::HostUnreachable => return "no route to host".to_owned(),
        K::NetworkUnreachable => return "network is unreachable".to_owned(),
        K::TimedOut => return "connection timed out".to_owned(),
        K::ConnectionReset => return "connection reset by peer".to_owned(),
        K::AddrNotAvailable => return "cannot assign requested address".to_owned(),
        K::PermissionDenied => return "permission denied".to_owned(),
        _ => {}
    }
    crate::oserror::lower_first(&crate::oserror::os_text(e))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn splits_the_deadline_like_go() {
        let now = Instant::now();
        let d = now + Duration::from_secs(10);
        assert_eq!(addr_deadline(now, d, 1), d);
        assert_eq!(addr_deadline(now, d, 2), now + Duration::from_secs(5));
        // 2 秒を下回らない
        assert_eq!(addr_deadline(now, d, 10), now + Duration::from_secs(2));
        // 残りが 2 秒より短ければ残りまで
        let short = now + Duration::from_millis(500);
        assert_eq!(addr_deadline(now, short, 3), short);
    }

    #[test]
    fn errno_texts_carry_the_words_server_doctor_matches() {
        let k = |k| errno_text(&io::Error::from(k));
        assert_eq!(k(io::ErrorKind::ConnectionRefused), "connection refused");
        assert_eq!(k(io::ErrorKind::HostUnreachable), "no route to host");
        assert_eq!(
            k(io::ErrorKind::NetworkUnreachable),
            "network is unreachable"
        );
        assert_eq!(errno_text(&io::Error::other("Odd Thing")), "odd Thing");
        #[cfg(target_os = "linux")]
        assert_eq!(
            errno_text(&io::Error::from_raw_os_error(libc::EPROTO)),
            "protocol error"
        );
    }

    /// 試した順と、各アドレスの結果を決めた接続。`ok` のアドレスは `delay` の後に繋がる。
    fn fake(
        log: Rc<RefCell<Vec<SocketAddr>>>,
        ok: &'static [&'static str],
        delay: Duration,
    ) -> impl Fn(
        SocketAddr,
        Instant,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<SocketAddr, String>>>> {
        move |a, deadline| {
            log.borrow_mut().push(a);
            let good = ok.iter().any(|o| sa(o) == a);
            Box::pin(async move {
                if good {
                    tokio::time::sleep(delay).await;
                    Ok(a)
                } else {
                    // 黙って捨てる宛先は期限まで待つ
                    tokio::time::sleep_until(deadline).await;
                    Err(format!("dial tcp {a}: i/o timeout"))
                }
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_other_family_starts_after_300ms_and_wins() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let addrs = [
            sa("[2001:db8::1]:80"),
            sa("[2001:db8::2]:80"),
            sa("192.0.2.1:80"),
        ];
        let t0 = Instant::now();
        let got = race(
            &addrs,
            true,
            Instant::now() + Duration::from_secs(10),
            fake(Rc::clone(&log), &["192.0.2.1:80"], Duration::from_millis(1)),
        )
        .await;
        assert_eq!(got, Ok(sa("192.0.2.1:80")));
        assert_eq!(*log.borrow(), vec![addrs[0], addrs[2]]);
        let took = t0.elapsed();
        assert!(
            took >= FALLBACK_DELAY && took < Duration::from_millis(400),
            "{took:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn udp_tries_in_order_and_returns_the_last_error() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let addrs = [
            sa("[2001:db8::1]:80"),
            sa("192.0.2.1:80"),
            sa("192.0.2.2:80"),
        ];
        let deadline = Instant::now() + Duration::from_secs(10);
        let got = race(
            &addrs,
            false,
            deadline,
            fake(Rc::clone(&log), &[], Duration::ZERO),
        )
        .await;
        assert_eq!(got, Err("dial tcp 192.0.2.2:80: i/o timeout".to_owned()));
        assert_eq!(*log.borrow(), addrs.to_vec());
    }

    #[tokio::test(start_paused = true)]
    async fn when_the_first_family_fails_fast_the_other_starts_at_once() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let addrs = [sa("192.0.2.1:80"), sa("[2001:db8::1]:80")];
        let l = Rc::clone(&log);
        let t0 = Instant::now();
        let got = race(
            &addrs,
            true,
            Instant::now() + Duration::from_secs(10),
            move |a, _| {
                l.borrow_mut().push(a);
                async move {
                    if a.is_ipv4() {
                        Err(format!("dial tcp {a}: connect: connection refused"))
                    } else {
                        Ok(a)
                    }
                }
            },
        )
        .await;
        assert_eq!(got, Ok(addrs[1]));
        assert!(t0.elapsed() < FALLBACK_DELAY);
        // 両方が失敗すれば、解決の結果の順で最後のアドレスの誤り
        let got = race(
            &addrs,
            true,
            Instant::now() + Duration::from_secs(10),
            |a, _| async move { Err::<SocketAddr, _>(format!("e {a}")) },
        )
        .await;
        assert_eq!(got, Err("e [2001:db8::1]:80".to_owned()));
    }

    #[tokio::test]
    async fn connects_with_keepalive_and_reports_refusal_in_go_words() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let s = connect_tcp(a, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let ka = SockRef::from(&s);
        assert!(ka.keepalive().unwrap());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(ka.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
            assert_eq!(ka.tcp_keepalive_interval().unwrap(), KEEPALIVE_INTERVAL);
            assert_eq!(ka.tcp_keepalive_retries().unwrap(), KEEPALIVE_COUNT);
        }
        drop(l);
        let e = connect_tcp(a, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap_err();
        assert_eq!(e, format!("dial tcp {a}: connect: connection refused"));
    }
}
