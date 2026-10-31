//! トンネル。WireGuard の device の層 (`wgft-wireguard`) を扱うのはこの module だけである。
//!
//! 試作のトンネルは Linux の TUN とカーネルの TCP/IP を使う。device の層が TUN と UDP のソケットを持ち、
//! この module は全体状態の wg の節から device の設定を作り、keepalive の ping とハンドシェイクの監視を
//! 行い、状態を読む。中継はカーネルのソケットをトンネルのアドレスに bind する (`relay`)。

use crate::logf;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::task::JoinHandle;
use wgft_proto::WgConfig;

/// keepalive の既定 (秒の値が範囲の外のとき)。
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);

/// keepalive の秒の上限 (Go の `agentdp.KeepaliveMaxSeconds`)。
pub const KEEPALIVE_MAX_SECONDS: i64 = 65535;

/// 全体状態の wg の節から作るトンネルの宣言。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// server の公開鍵 (base64)。
    pub server_public_key: String,
    /// server の `host:port`。
    pub endpoint: String,
    /// 自分のアドレス。
    pub address: Ipv4Addr,
    /// 自分のアドレスの帯の長さ。
    pub prefix_len: u8,
    /// server のアドレス。帯の先頭の次 (`10.200.0.1`)。AllowedIPs はこの /32 だけ。
    pub server_address: Ipv4Addr,
    /// MTU。
    pub mtu: u16,
    /// persistent keepalive の間隔。
    pub keepalive: Duration,
}

impl Config {
    /// 全体状態の wg の節から作る (Go の `usermode.tunnelConfig`)。
    ///
    /// # Errors
    ///
    /// 公開鍵かアドレスが読めなければ誤りを返す。
    pub fn from_wg(w: &WgConfig) -> Result<Config, String> {
        decode_key(&w.server_pubkey).map_err(|e| format!("server_pubkey: {e}"))?;
        let bad = || format!("address {:?} is not an IPv4 CIDR", w.address);
        let (a, l) = w.address.split_once('/').ok_or_else(bad)?;
        let address: Ipv4Addr = a.parse().map_err(|_| bad())?;
        let prefix_len: u8 = l.parse().map_err(|_| bad())?;
        if prefix_len > 32 {
            return Err(bad());
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let server_address = Ipv4Addr::from((u32::from(address) & mask).wrapping_add(1));
        let keepalive = match u64::try_from(w.keepalive) {
            Ok(s) if (1..=KEEPALIVE_MAX_SECONDS.unsigned_abs()).contains(&s) => {
                Duration::from_secs(s)
            }
            _ => {
                if w.keepalive != 0 {
                    logf!(
                        "wg.keepalive {} is out of the accepted range 1-{KEEPALIVE_MAX_SECONDS} seconds; using the default {}s instead",
                        w.keepalive,
                        DEFAULT_KEEPALIVE.as_secs()
                    );
                }
                DEFAULT_KEEPALIVE
            }
        };
        let mtu = u16::try_from(w.mtu)
            .ok()
            .filter(|m| (576..=9000).contains(m))
            .unwrap_or(1420);
        Ok(Config {
            server_public_key: w.server_pubkey.clone(),
            endpoint: w.endpoint.clone(),
            address,
            prefix_len,
            server_address,
            mtu,
            keepalive,
        })
    }
}

/// WireGuard の鍵を base64 から 32 byte にする。
///
/// # Errors
///
/// base64 として読めないか、32 byte でなければ誤りを返す。
pub fn decode_key(s: &str) -> Result<[u8; 32], String> {
    let b = STANDARD.decode(s).map_err(|e| e.to_string())?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| "key is not 32 bytes".to_owned())
}

/// 新しい秘密鍵 (base64)。`wg genkey` と同じく clamp する。
///
/// # Errors
///
/// 乱数を読めなければ誤りを返す。
pub fn generate_private_key() -> Result<String, String> {
    let mut b = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b)
        .map_err(|_| "no randomness".to_owned())?;
    Ok(wgft_wireguard::PrivateKey::generate(b)
        .to_base64()
        .to_string())
}

/// 秘密鍵 (base64) から公開鍵 (base64)。
///
/// # Errors
///
/// 秘密鍵が読めなければ誤りを返す。
pub fn public_key(private_b64: &str) -> Result<String, String> {
    let k = wgft_wireguard::PrivateKey::from_base64(private_b64)
        .map_err(|e| format!("wg_private_key: {e}"))?;
    Ok(k.public_key().to_base64())
}

/// トンネルの状態の読み。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reading {
    /// 解決したエンドポイント。
    pub endpoint: Option<SocketAddr>,
    /// 最終ハンドシェイク。
    pub last_handshake: Option<SystemTime>,
    /// 受信したバイト数。
    pub rx_bytes: u64,
    /// 送信したバイト数。
    pub tx_bytes: u64,
    /// 名前の解決の失敗などの誤り。
    pub err: Option<String>,
}

/// 動いているトンネル。
#[derive(Debug)]
pub struct Tunnel {
    cfg: Config,
    shared: Arc<Mutex<Reading>>,
    device: Arc<wgft_wireguard_tun::Handle>,
    monitor: JoinHandle<()>,
}

impl Tunnel {
    /// トンネルを立てる。TUN の名前は `tun_name`。エンドポイントの名前を解決できなくても立て、
    /// 引き直しに任せる。
    ///
    /// # Errors
    ///
    /// device か TUN を作れなければ誤りを返す。
    pub async fn start(private_key: &str, tun_name: &str, cfg: Config) -> Result<Tunnel, String> {
        let shared = Arc::new(Mutex::new(Reading::default()));
        let ep = resolve(&cfg.endpoint).await;
        set_endpoint(&shared, ep.clone());
        let device = Arc::new(device::start(private_key, tun_name, &cfg, ep.ok()).await?);
        logf!(
            "tunnel: up addr={} mtu={} endpoint={} tun={tun_name}",
            cfg.address,
            cfg.mtu,
            cfg.endpoint
        );
        let monitor = tokio::spawn(monitor(
            cfg.clone(),
            Arc::clone(&shared),
            Arc::clone(&device),
        ));
        Ok(Tunnel {
            cfg,
            shared,
            device,
            monitor,
        })
    }

    /// 自分のトンネルのアドレス。
    #[must_use]
    pub fn address(&self) -> Ipv4Addr {
        self.cfg.address
    }

    /// 宣言。
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// 状態を 1 回読む。
    pub async fn read(&self) -> Reading {
        let mut r = lock(&self.shared).clone();
        match device::read(&self.device).await {
            Ok(d) => {
                r.last_handshake = d.last_handshake;
                r.rx_bytes = d.rx_bytes;
                r.tx_bytes = d.tx_bytes;
            }
            Err(e) => r.err = Some(e),
        }
        r
    }

    /// 閉じる。TUN を消す。
    pub async fn close(self) {
        self.monitor.abort();
        let _ = self.monitor.await;
        match Arc::try_unwrap(self.device) {
            Ok(h) => {
                if let Err(e) = h.stop().await {
                    logf!("tunnel: stop: {e}");
                }
            }
            Err(_) => logf!("tunnel: stop: the device is still shared"),
        }
    }
}

fn lock(m: &Mutex<Reading>) -> std::sync::MutexGuard<'_, Reading> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn set_endpoint(shared: &Mutex<Reading>, ep: Result<SocketAddrV4, String>) {
    let mut r = lock(shared);
    match ep {
        Ok(a) => {
            r.endpoint = Some(SocketAddr::V4(a));
            r.err = None;
        }
        Err(e) => r.err = Some(e),
    }
}

/// keepalive ごとに、ハンドシェイクが keepalive の 5 倍の間成功していなければエンドポイントを引き直し、
/// server のアドレスへ ICMP echo を 1 つ送る (Go の `tunnel.Run`)。ping はデータのパケットなので、
/// server がセッションを失っていれば鍵の寿命を待たずに新しいハンドシェイクが始まる。
async fn monitor(cfg: Config, shared: Arc<Mutex<Reading>>, dev: Arc<wgft_wireguard_tun::Handle>) {
    let mut tick = tokio::time::interval(cfg.keepalive);
    tick.tick().await;
    let mut pinged: Option<bool> = None;
    loop {
        tick.tick().await;
        let hs = device::read(&dev).await.ok().and_then(|d| d.last_handshake);
        let stale = hs.is_none_or(|t| t.elapsed().unwrap_or_default() > cfg.keepalive * 5);
        if stale {
            let before = lock(&shared).endpoint;
            let ep = resolve(&cfg.endpoint).await;
            if let Ok(a) = &ep
                && before != Some(SocketAddr::V4(*a))
            {
                logf!("tunnel: changed endpoint {before:?} -> {a}");
                if let Err(e) = dev.set_endpoint(SocketAddr::V4(*a)).await {
                    logf!("tunnel: set endpoint {a}: {e}");
                }
            }
            if let Err(e) = &ep {
                logf!("tunnel: re-resolve endpoint: {e}");
            }
            set_endpoint(&shared, ep);
        }
        // 答えの有無が変わったときだけ 1 行出す
        let answered = match ping(cfg.address, cfg.server_address, Duration::from_secs(2)).await {
            Ok(rtt) => {
                if pinged != Some(true) {
                    logf!(
                        "tunnel: the server at {} answers pings; round trip {}ms",
                        cfg.server_address,
                        rtt.as_millis()
                    );
                }
                true
            }
            Err(e) => {
                if pinged != Some(false) {
                    if e.ends_with("timed out") {
                        // カーネルモードの server は wg0 から入る新しいフローを落とすので答えない。
                        // ping は答えが無くてもハンドシェイクを促す
                        logf!(
                            "tunnel: the server at {} does not answer pings; a kernel-mode server drops them, and the ping still prompts a handshake",
                            cfg.server_address
                        );
                    } else {
                        logf!("tunnel: ping to {}: {e}", cfg.server_address);
                    }
                }
                false
            }
        };
        pinged = Some(answered);
    }
}

/// `host:port` を IPv4 の `SocketAddrV4` にする。ホスト名は A レコードを引き、決まった順で先頭を選ぶ。
async fn resolve(endpoint: &str) -> Result<SocketAddrV4, String> {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Err(format!("{endpoint:?} is not in host:port form"));
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{endpoint:?} has an invalid port"))?;
    if let Ok(a) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(a, port));
    }
    if host.starts_with('[') {
        return Err("IPv6 endpoints are not supported".into());
    }
    let fut = tokio::net::lookup_host((host, port));
    let addrs = tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .map_err(|_| format!("lookup {host}: timed out"))?
        .map_err(|e| format!("lookup {host}: {e}"))?;
    let mut v4: Vec<SocketAddrV4> = addrs
        .filter_map(|a| match a {
            SocketAddr::V4(a) => Some(a),
            SocketAddr::V6(_) => None,
        })
        .collect();
    v4.sort();
    v4.first()
        .copied()
        .ok_or_else(|| format!("no A record for {host}"))
}

/// server のトンネルのアドレスへ ICMP echo を 1 つ送り、往復時間を返す。カーネルの ICMP の
/// データグラムのソケットをトンネルのアドレスに bind する。
///
/// # Errors
///
/// ソケットを作れないか、期限までに答えが無ければ誤りを返す。
pub async fn ping(from: Ipv4Addr, to: Ipv4Addr, timeout: Duration) -> Result<Duration, String> {
    tokio::task::spawn_blocking(move || ping_blocking(from, to, timeout))
        .await
        .map_err(|e| e.to_string())?
}

fn ping_blocking(from: Ipv4Addr, to: Ipv4Addr, timeout: Duration) -> Result<Duration, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    // ICMP のデータグラムのソケットは net.ipv4.ping_group_range が許す group だけが作れる。この値は
    // network namespace ごとで、新しい namespace の既定は誰も許さないので、作れなければ raw の
    // ソケットに切り替える (root か CAP_NET_RAW が要る。トンネルの TUN も同じ特権で作る)
    let (s, raw) = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
        Ok(s) => (s, false),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => (
            Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(|e| format!("icmp socket: {e}"))?,
            true,
        ),
        Err(e) => return Err(format!("icmp socket: {e}")),
    };
    s.bind(&SockAddr::from(SocketAddrV4::new(from, 0)))
        .map_err(|e| format!("icmp bind {from}: {e}"))?;
    let seq = u16::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            & 0xffff,
    )
    .unwrap_or(0);
    let id = u16::try_from(std::process::id() & 0xffff).unwrap_or(1);
    // type 8 code 0、チェックサム、ID (データグラムのソケットではカーネルが付け直す)、seq、本文 "wgft"
    let mut msg = [8u8, 0, 0, 0, 0, 0, 0, 0, b'w', b'g', b'f', b't'];
    msg[4..6].copy_from_slice(&id.to_be_bytes());
    msg[6..8].copy_from_slice(&seq.to_be_bytes());
    let sum = checksum(&msg);
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    let start = std::time::Instant::now();
    s.send_to(&msg, &SockAddr::from(SocketAddrV4::new(to, 0)))
        .map_err(|e| format!("icmp send: {e}"))?;
    loop {
        let left = timeout
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("icmp receive: timed out")?;
        s.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 1500];
        let n = std::io::Read::read(&mut &s, &mut buf).map_err(|e| match e.kind() {
            // 読みの期限の切れは WouldBlock か TimedOut で返る
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                "icmp receive: timed out".to_owned()
            }
            _ => format!("icmp receive: {e}"),
        })?;
        if !raw || is_echo_reply(&buf[..n], to, id, seq) {
            return Ok(start.elapsed());
        }
    }
}

/// raw のソケットで受けた IPv4 の packet が、`from` からの id と seq の echo reply かどうか。
fn is_echo_reply(b: &[u8], from: Ipv4Addr, id: u16, seq: u16) -> bool {
    let Some(&vihl) = b.first() else { return false };
    if b.get(12..16) != Some(&from.octets()[..]) {
        return false;
    }
    let ihl = usize::from(vihl & 0x0f) * 4;
    let Some(icmp) = b.get(ihl..) else {
        return false;
    };
    icmp.len() >= 8
        && icmp[0] == 0
        && icmp[4..6] == id.to_be_bytes()
        && icmp[6..8] == seq.to_be_bytes()
}

fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in b.chunks(2) {
        let w = u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0));
        sum = sum.wrapping_add(w);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(u16::try_from(sum).unwrap_or(0))
}

/// device の層との接続部分。`wgft-wireguard` の device を、`wgft-wireguard-tun` の Linux の TUN の外殻で
/// 動かす。
mod device {
    use std::net::{SocketAddr, SocketAddrV4};
    use std::time::{Instant, SystemTime};

    use wgft_wireguard::{DeviceConfig, PrivateKey, PublicKey};
    use wgft_wireguard_tun::{Handle, TunSettings};

    use super::Config;

    #[derive(Default)]
    pub(super) struct DeviceReading {
        pub(super) last_handshake: Option<SystemTime>,
        pub(super) rx_bytes: u64,
        pub(super) tx_bytes: u64,
    }

    pub(super) async fn start(
        private_key: &str,
        tun_name: &str,
        cfg: &Config,
        endpoint: Option<SocketAddrV4>,
    ) -> Result<Handle, String> {
        let key =
            PrivateKey::from_base64(private_key).map_err(|e| format!("wg_private_key: {e}"))?;
        let server = PublicKey::from_base64(&cfg.server_public_key)
            .map_err(|e| format!("server_pubkey: {e}"))?;
        let mut dc = DeviceConfig::agent(
            key,
            server,
            endpoint.map(SocketAddr::V4),
            cfg.server_address,
            cfg.keepalive,
        );
        dc.mtu = cfg.mtu;
        let tun = TunSettings {
            name: tun_name.to_owned(),
            address: cfg.address,
            prefix_len: cfg.prefix_len,
            mtu: cfg.mtu,
        };
        let mut seed = wgft_wireguard::Zeroizing::new([0u8; 32]);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed[..])
            .map_err(|_| "no randomness for the device seed".to_owned())?;
        let unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        wgft_wireguard_tun::spawn(dc, tun, SocketAddr::from(([0, 0, 0, 0], 0)), seed, unix)
            .await
            .map_err(|e| format!("start the tunnel device {tun_name}: {e}"))
    }

    pub(super) async fn read(h: &Handle) -> Result<DeviceReading, String> {
        let st = h
            .status()
            .await
            .map_err(|e| format!("read the tunnel device: {e}"))?;
        let Some(p) = st.peer else {
            return Ok(DeviceReading::default());
        };
        // 単調な時計の値を壁時計に直す
        let last_handshake = p.last_handshake.and_then(|t| {
            SystemTime::now().checked_sub(Instant::now().saturating_duration_since(t))
        });
        Ok(DeviceReading {
            last_handshake,
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wg(address: &str, keepalive: i64) -> WgConfig {
        WgConfig {
            server_pubkey: STANDARD.encode([7u8; 32]),
            endpoint: "203.0.113.1:51820".into(),
            address: address.into(),
            mtu: 1420,
            keepalive,
            udp_timeout: 30,
            udp_timeout_stream: 120,
        }
    }

    #[test]
    fn server_address_is_the_first_host_of_the_band() {
        let c = Config::from_wg(&wg("10.200.0.7/24", 25)).unwrap();
        assert_eq!(c.address, Ipv4Addr::new(10, 200, 0, 7));
        assert_eq!(c.server_address, Ipv4Addr::new(10, 200, 0, 1));
        assert_eq!(c.keepalive, Duration::from_secs(25));
    }

    #[test]
    fn out_of_range_keepalive_falls_back() {
        assert_eq!(
            Config::from_wg(&wg("10.200.0.7/24", 0)).unwrap().keepalive,
            DEFAULT_KEEPALIVE
        );
        assert_eq!(
            Config::from_wg(&wg("10.200.0.7/24", -5)).unwrap().keepalive,
            DEFAULT_KEEPALIVE
        );
        assert_eq!(
            Config::from_wg(&wg("10.200.0.7/24", 1 << 40))
                .unwrap()
                .keepalive,
            DEFAULT_KEEPALIVE
        );
    }

    #[test]
    fn rejects_bad_addresses() {
        assert!(Config::from_wg(&wg("10.200.0.7", 25)).is_err());
        assert!(Config::from_wg(&wg("fd00::1/64", 25)).is_err());
        assert!(Config::from_wg(&wg("10.200.0.7/33", 25)).is_err());
    }

    #[test]
    fn public_key_of_a_known_private_key() {
        // RFC 7748 6.1 の Alice の鍵
        let private = STANDARD.encode(
            <[u8; 32]>::try_from(hex_bytes(
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            ))
            .unwrap(),
        );
        let public = STANDARD.encode(
            <[u8; 32]>::try_from(hex_bytes(
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            ))
            .unwrap(),
        );
        assert_eq!(public_key(&private).unwrap(), public);
        let g = generate_private_key().unwrap();
        assert_eq!(decode_key(&g).unwrap().len(), 32);
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn echo_reply_match() {
        let server = Ipv4Addr::new(10, 200, 0, 1);
        let mut p = vec![0x45u8; 20];
        p[12..16].copy_from_slice(&server.octets());
        p.extend_from_slice(&[0, 0, 0, 0, 0x12, 0x34, 0, 7]);
        assert!(is_echo_reply(&p, server, 0x1234, 7));
        assert!(!is_echo_reply(&p, server, 0x1234, 8));
        assert!(!is_echo_reply(&p, Ipv4Addr::new(10, 200, 0, 9), 0x1234, 7));
        p[20] = 8;
        assert!(!is_echo_reply(&p, server, 0x1234, 7));
    }

    #[test]
    fn icmp_checksum() {
        let mut m = [8u8, 0, 0, 0, 0, 1, 0, 1];
        let c = checksum(&m);
        m[2..4].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&m), 0);
    }
}
