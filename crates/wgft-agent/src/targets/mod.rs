//! 中継が LAN の宛先へ接続するときの規則 (仕様 `tunnel.md` の「宛先の扱い」と「宛先の試し接続」、
//! 設計 `docs/design/userspace/targets.md`)。
//!
//! 宛先の許可一覧、ブロードキャストとマルチキャストの拒否、名前の解決、接続の試し方、LAN の側の TCP の
//! keepalive、試し接続を持つ。トンネルの側の作り (TUN の試作、wgstack) に依らないので、中継の土台が
//! wgstack に替わってもそのまま使う。

pub mod dial;
pub mod resolve;
pub mod unicast;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;

use crate::config::allow_targets::{self, AllowList};
use resolve::Resolver;
use unicast::Unicast;

/// 宛先への接続の期限。許可一覧があるときは名前の解決の後から数える。
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// 許可一覧があるときの、名前の解決の期限。
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// 試し接続 1 件の期限。名前の解決も含む。
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// 同時に試す試し接続の数。
pub const PROBE_CONCURRENCY: usize = 32;

/// 宛先へ接続しなかった理由か、接続の失敗。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetError {
    /// ルールの理由とログに出す文。
    pub text: String,
    /// 許可一覧か、ブロードキャストとマルチキャストの拒否で接続しなかった。中継はトンネルの側を RST で
    /// 閉じ、ルールの状態に載せる。偽なら接続を試みて失敗した。
    pub denied: bool,
}

impl TargetError {
    fn failed(text: String) -> Self {
        TargetError {
            text,
            denied: false,
        }
    }

    fn denied(text: String) -> Self {
        TargetError { text, denied: true }
    }
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Go の `netip.Addr.String` と同じ形のアドレス。
fn show_ip(a: IpAddr) -> String {
    match a.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => allow_targets::format_v6(v6.into()),
    }
}

/// Go の `netip.AddrPort.String` と同じ形のアドレスとポート。
fn show_addr_port(a: IpAddr, port: u16) -> String {
    match a.to_canonical() {
        IpAddr::V4(_) => format!("{}:{port}", show_ip(a)),
        IpAddr::V6(_) => format!("[{}]:{port}", show_ip(a)),
    }
}

/// 宛先の規則の全体。プロセスで 1 つ作り、トンネルの世代をまたいで中継が分け合う。
#[derive(Debug)]
pub struct Targets {
    allow: Option<AllowList>,
    unicast: Unicast,
    resolver: Arc<Resolver>,
}

impl Targets {
    /// 許可一覧 `allow` (無ければ制限しない) で作る。ホストのインタフェースの一覧と名前の解決は OS から
    /// 読む。
    #[must_use]
    pub fn new(allow: Option<AllowList>) -> Self {
        Targets::with(allow, Unicast::default(), Resolver::shared())
    }

    /// 部品を指定して作る。試験が使う。
    #[must_use]
    pub fn with(allow: Option<AllowList>, unicast: Unicast, resolver: Arc<Resolver>) -> Self {
        Targets {
            allow,
            unicast,
            resolver,
        }
    }

    /// 宛先 `addr` の `port` へ接続しない理由。ブロードキャストとマルチキャストの拒否を許可一覧より先に
    /// 見る。許可一覧に加えても通らない宛先だからである。
    #[must_use]
    pub fn refuse(&self, addr: IpAddr, port: u16) -> Option<TargetError> {
        if let Some(r) = self.unicast.refuse(addr) {
            return Some(TargetError::denied(r));
        }
        match &self.allow {
            Some(l) if !l.allows(addr, port) => Some(TargetError::denied(format!(
                "target {} is not in {}",
                show_addr_port(addr, port),
                allow_targets::ENV
            ))),
            _ => None,
        }
    }

    /// 適用のときの判定。IP リテラルの宛先だけを判定し、拒めば理由を返す。ホスト名は解決の結果が
    /// 変わりうるので、接続のときに判定する。
    #[must_use]
    pub fn refuse_literal(&self, host: &str, port: u16) -> Option<TargetError> {
        let addr = host.parse::<IpAddr>().ok()?;
        self.refuse(addr, port)
    }

    /// 宛先の名前を解決し、拒まないアドレスと、接続の期限を返す。
    ///
    /// 期限は許可一覧の有無で分ける。許可一覧が無いときは、名前の解決も `limit` の中に入る (Go の
    /// `net.Dialer` に名前を渡す場合と同じ)。許可一覧があるときは、名前の解決に 5 秒の期限を持ち、
    /// `limit` は解決の後から数える。
    async fn addresses(
        &self,
        host: &str,
        port: u16,
        limit: Duration,
    ) -> Result<(Vec<SocketAddr>, Instant), TargetError> {
        let start = Instant::now();
        let (ips, deadline) = if let Ok(a) = host.parse::<IpAddr>() {
            (vec![a.to_canonical()], start + limit)
        } else if self.allow.is_some() {
            let ips = self
                .resolver
                .lookup_target(host, start + LOOKUP_TIMEOUT)
                .await
                .map_err(TargetError::failed)?;
            (ips, Instant::now() + limit)
        } else {
            let deadline = start + limit;
            let ips = self
                .resolver
                .lookup_target(host, deadline)
                .await
                .map_err(TargetError::failed)?;
            (ips, deadline)
        };
        let mut denied = None;
        let mut ok = Vec::with_capacity(ips.len());
        for a in ips {
            match self.refuse(a, port) {
                Some(e) => {
                    denied.get_or_insert(e);
                }
                None => ok.push(SocketAddr::new(a, port)),
            }
        }
        if ok.is_empty() {
            return Err(denied.unwrap_or_else(|| {
                TargetError::failed(format!("host {host:?} resolved to no address"))
            }));
        }
        Ok((ok, deadline))
    }

    /// 宛先へ TCP で接続する。中継が宛先へ接続する唯一の経路で、宛先の判定もここで行う。
    ///
    /// 拒まないアドレスを、[`dial::race`] の試し方で試す。どのアドレスも拒まれた場合は、最初に拒んだ
    /// アドレスの理由を返す。
    ///
    /// # Errors
    ///
    /// 接続しなかった理由か、接続の失敗を返す。
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, TargetError> {
        self.connect_tcp_within(host, port, DIAL_TIMEOUT).await
    }

    async fn connect_tcp_within(
        &self,
        host: &str,
        port: u16,
        limit: Duration,
    ) -> Result<TcpStream, TargetError> {
        let (addrs, deadline) = self.addresses(host, port, limit).await?;
        dial::race(&addrs, true, deadline, dial::connect_tcp)
            .await
            .map_err(TargetError::failed)
    }

    /// 宛先へ接続した UDP のソケットを開く。UDP の中継のセッション 1 つにつき 1 回呼ぶ。名前の解決と
    /// 宛先の判定は [`Targets::connect_tcp`] と同じで、拒まないアドレスを族を分けずに解決の結果の順に
    /// 試す (Go の `net.Dialer` が UDP で行う `dialSerial`)。
    ///
    /// # Errors
    ///
    /// 接続しなかった理由か、接続の失敗を返す。
    pub async fn connect_udp(&self, host: &str, port: u16) -> Result<UdpSocket, TargetError> {
        let (addrs, deadline) = self.addresses(host, port, DIAL_TIMEOUT).await?;
        dial::race(&addrs, false, deadline, dial::connect_udp)
            .await
            .map_err(TargetError::failed)
    }

    /// TCP の宛先への試し接続 1 件。接続してすぐ閉じる。許可一覧とブロードキャストの拒否にも従う。期限は
    /// 名前の解決を含めて 2 秒で、Go の v1 が試し接続の全体を 2 秒で打ち切るのと同じである。
    ///
    /// # Errors
    ///
    /// 届かない理由を返す。期限切れは `did not answer` の語を含む。
    pub async fn probe(&self, host: &str, port: u16) -> Result<(), TargetError> {
        match tokio::time::timeout(
            PROBE_TIMEOUT,
            self.connect_tcp_within(host, port, DIAL_TIMEOUT),
        )
        .await
        {
            Ok(Ok(_conn)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(TargetError::failed(format!(
                "target {} did not answer within {}s",
                join_host_port(host, port),
                PROBE_TIMEOUT.as_secs()
            ))),
        }
    }

    /// 試し接続をまとめて行う。同時に試すのは 32 件までで、結果は `list` と同じ順で返す。試し接続の
    /// future は走らせる分だけを作るので、待ち受けの数によらず保持は 32 件分である。
    pub async fn probe_all(
        self: Arc<Self>,
        list: Vec<(String, u16)>,
    ) -> Vec<Result<(), TargetError>> {
        // 値を持ち込む閉包にする。借用を持つ閉包では、future の Send の判定が寿命について一般化できない
        futures_util::stream::iter(list)
            .map(move |(h, p)| {
                let t = Arc::clone(&self);
                async move { t.probe(&h, p).await }
            })
            .buffered(PROBE_CONCURRENCY)
            .collect()
            .await
    }
}

/// Go の `net.JoinHostPort` と同じく、`:` を含むホストを角括弧で囲んで `host:port` にする。
#[must_use]
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::hostaddr::HostAddr;

    fn unicast_lan() -> Unicast {
        Unicast::new(Box::new(|| {
            Ok(vec![HostAddr {
                interface: "eth0".into(),
                addr: "192.168.1.7".parse().unwrap(),
                prefix_len: 24,
            }])
        }))
    }

    fn table(names: Vec<(&'static str, Vec<&'static str>)>) -> Arc<Resolver> {
        Arc::new(Resolver::with_lookup(
            8,
            1,
            Arc::new(move |h: &str, _| {
                names
                    .iter()
                    .find(|(n, _)| *n == h)
                    .map(|(_, v)| v.iter().map(|a| a.parse().unwrap()).collect())
                    .ok_or_else(|| std::io::Error::other("Name or service not known"))
            }),
        ))
    }

    fn allow(s: &str) -> Option<AllowList> {
        allow_targets::parse(s).unwrap()
    }

    #[test]
    fn refusals_name_the_setting_and_the_unicast_rule() {
        let t = Targets::with(allow("10.0.0.0/8:80"), unicast_lan(), table(vec![]));
        assert_eq!(t.refuse_literal("10.1.2.3", 80), None);
        assert_eq!(
            t.refuse_literal("10.1.2.3", 81),
            Some(TargetError::denied(
                "target 10.1.2.3:81 is not in WGFT_AGENT_ALLOW_TARGETS".into()
            ))
        );
        assert_eq!(
            t.refuse("2001:db8::1".parse().unwrap(), 80).map(|e| e.text),
            Some("target [2001:db8::1]:80 is not in WGFT_AGENT_ALLOW_TARGETS".into())
        );
        // ブロードキャストは許可一覧より先に拒む
        let all = Targets::with(allow("0.0.0.0/0"), unicast_lan(), table(vec![]));
        let e = all.refuse_literal("192.168.1.255", 9).unwrap();
        assert!(e.denied && e.text.ends_with(unicast::UNICAST_ONLY), "{e}");
        // ホスト名は適用のときに判定しない
        assert_eq!(t.refuse_literal("nas.lan", 81), None);
        // 許可一覧が無ければユニキャストの判定だけ
        let none = Targets::with(None, unicast_lan(), table(vec![]));
        assert_eq!(none.refuse_literal("8.8.8.8", 53), None);
        assert!(none.refuse_literal("224.0.0.251", 5353).is_some());
    }

    async fn echo() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                drop(s);
            }
        });
        a
    }

    #[tokio::test]
    async fn connects_only_to_resolved_addresses_the_rules_allow() {
        let up = echo().await;
        let t = Targets::with(
            allow("127.0.0.1/32"),
            unicast_lan(),
            table(vec![
                ("mixed", vec!["192.168.1.255", "10.9.9.9", "127.0.0.1"]),
                ("outside", vec!["10.9.9.9", "10.9.9.10"]),
                ("bcast", vec!["192.168.1.255", "10.9.9.9"]),
            ]),
        );
        // 拒まれたアドレスを飛ばし、通るアドレスへ繋ぐ
        assert!(t.connect_tcp("mixed", up.port()).await.is_ok());
        // どれも通らなければ、最初に拒んだアドレスの理由
        let e = t.connect_tcp("outside", up.port()).await.unwrap_err();
        assert!(e.denied);
        assert_eq!(
            e.text,
            format!(
                "target 10.9.9.9:{} is not in WGFT_AGENT_ALLOW_TARGETS",
                up.port()
            )
        );
        let e = t.connect_tcp("bcast", up.port()).await.unwrap_err();
        assert!(e.denied && e.text.contains("broadcast address of 192.168.1.0/24"));
        // 名前の解決の失敗は `lookup ` の語を持ち、拒否ではない
        let e = t.connect_tcp("nope", up.port()).await.unwrap_err();
        assert!(!e.denied);
        assert_eq!(e.text, "lookup nope: Name or service not known");
    }

    #[tokio::test]
    async fn without_an_allowlist_unicast_refusals_still_apply_to_resolved_names() {
        let up = echo().await;
        let t = Targets::with(
            None,
            unicast_lan(),
            table(vec![
                ("multi", vec!["239.0.0.1", "127.0.0.1"]),
                ("only", vec!["239.0.0.1"]),
            ]),
        );
        assert!(t.connect_tcp("multi", up.port()).await.is_ok());
        let e = t.connect_tcp("only", up.port()).await.unwrap_err();
        assert!(
            e.denied
                && e.text
                    .starts_with("target 239.0.0.1 is a multicast address")
        );
    }

    #[tokio::test]
    async fn probes_report_refusal_and_success() {
        let up = echo().await;
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let t = Targets::with(None, unicast_lan(), table(vec![]));
        let t = Arc::new(t);
        let got = t
            .probe_all(vec![
                ("127.0.0.1".into(), up.port()),
                ("127.0.0.1".into(), dead),
            ])
            .await;
        assert_eq!(got[0], Ok(()));
        let e = got[1].clone().unwrap_err();
        assert!(!e.denied);
        // Windows はループバックの拒否にも SYN を送り直すので、2 秒の期限に届くことがある
        #[cfg(not(windows))]
        assert_eq!(
            e.text,
            format!("dial tcp 127.0.0.1:{dead}: connect: connection refused")
        );
    }

    #[test]
    fn join_host_port_brackets_ipv6_like_go() {
        assert_eq!(join_host_port("nas.lan", 80), "nas.lan:80");
        assert_eq!(join_host_port("10.0.0.1", 80), "10.0.0.1:80");
        assert_eq!(
            join_host_port("::ffff:10.0.0.1", 80),
            "[::ffff:10.0.0.1]:80"
        );
    }

    /// 32 の待ち受けが 1 つの名前を宛先にし、DNS が 600 ミリ秒かかっても、名前の解決を相乗りするので、
    /// 32 件の試し接続がすべて 2 秒の期限の中で届く。宛先はどれも待ち受けているポートにして、閉じたポートの
    /// 扱いの OS の違い (Windows はループバックの拒否にも SYN を送り直す) と、隣のポートを他の試験が
    /// 使うことに依らないようにする。
    #[tokio::test]
    async fn probes_of_a_port_range_share_one_slow_lookup() {
        let mut ups = Vec::new();
        for _ in 0..32 {
            ups.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        }
        let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&lookups);
        let resolver = Arc::new(Resolver::with_lookup(
            8,
            1,
            Arc::new(move |_h: &str, _| {
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(600));
                Ok(vec!["127.0.0.1".parse().unwrap()])
            }),
        ));
        let t = Arc::new(Targets::with(None, unicast_lan(), resolver));
        let list: Vec<(String, u16)> = ups
            .iter()
            .map(|l| ("nas.lan".to_owned(), l.local_addr().unwrap().port()))
            .collect();
        let got = t.probe_all(list).await;
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
        for g in got {
            assert_eq!(g, Ok(()));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_that_hangs_did_not_answer_within_2s() {
        // 応えない resolver で、試し接続の全体が 2 秒で打ち切られることを確かめる
        let release = Arc::new(AtomicBool::new(false));
        let r_flag = Arc::clone(&release);
        let r = Arc::new(Resolver::with_lookup(
            8,
            1,
            Arc::new(move |_h: &str, _| {
                while !r_flag.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(vec![])
            }),
        ));
        let t = Targets::with(allow("10.0.0.0/8"), unicast_lan(), r);
        let e = t.probe("nas.lan", 80).await.unwrap_err();
        assert_eq!(e.text, "target nas.lan:80 did not answer within 2s");
        assert!(!e.denied);
        release.store(true, Ordering::Release);
    }
}
