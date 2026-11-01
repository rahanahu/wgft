//! トンネル。WireGuard の device の層 (`wgft-wireguard`) を扱うのはこの module だけである。
//!
//! トンネルは TUN を使わない。データプレーン (`dataplane`) のスレッドが device の層と WireGuard の UDP の
//! ソケットと Rust の wgstack の核を動かし、トンネルの packet はプロセスの中で終わる。root も
//! `CAP_NET_ADMIN` も要らない。この module は全体状態の wg の節から device の設定を作り、データプレーンの
//! 世代を立て、keepalive の ping とハンドシェイクの監視を行い、状態を読む。中継は核の待ち受けと接続を
//! データプレーンのスレッドで動かす (`relay`)。

use crate::batching::Batching;
use crate::dataplane::stack::StackSettings;
use crate::dataplane::{self, Dataplane, Handle, Local, Settings};
use crate::logf;
use crate::relay::LanConn;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use zeroize::Zeroizing;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::task::JoinHandle;
use wgft_netstack::{LanHook, Netstack, Ping};
use wgft_proto::WgConfig;
use wgft_wgstack::Limits;
use wgft_wireguard::{DeviceConfig, PrivateKey, PublicKey};

/// keepalive の既定 (秒の値が範囲の外のとき)。
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);

/// MTU の既定 (値が範囲の外のとき)。
pub const DEFAULT_MTU: u16 = 1420;

/// 受け付ける MTU の範囲。server が送る範囲で、wgstack の核が受け付ける範囲と同じ。
const MIN_MTU: usize = wgft_wgstack::MIN_MTU;
const MAX_MTU: usize = wgft_wgstack::MAX_MTU;

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
        // 帯は server と agent の 2 つのアドレスを入れられる長さが要る。/31 と /32 は帯が経路に
        // ならず、帯の先頭の次を server とする決まりも成り立たない
        if prefix_len > 30 {
            return Err(format!(
                "address {:?} has a prefix longer than /30",
                w.address
            ));
        }
        // 特別な帯のアドレスはトンネルに使わない
        let first_octet = address.octets()[0];
        if first_octet == 0 || address.is_loopback() || address.is_multicast() || first_octet >= 240
        {
            return Err(format!(
                "address {:?} is in 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4 or 240.0.0.0/4",
                w.address
            ));
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let network = u32::from(address) & mask;
        let server_address = Ipv4Addr::from(network.wrapping_add(1));
        let broadcast = Ipv4Addr::from(network | !mask);
        if address == Ipv4Addr::from(network) || address == server_address || address == broadcast {
            return Err(format!(
                "address {:?} is the network, server or broadcast address of its band",
                w.address
            ));
        }
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
        // server が送る範囲を wgstack の核にそのまま渡し、外の値だけを既定にする
        let mtu = u16::try_from(w.mtu)
            .ok()
            .filter(|m| (MIN_MTU..=MAX_MTU).contains(&usize::from(*m)))
            .unwrap_or(DEFAULT_MTU);
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

/// 新しい秘密鍵 (base64)。`wg genkey` と同じく clamp する。乱数と文字列は捨てるときに 0 で消す。
///
/// # Errors
///
/// 乱数を読めなければ誤りを返す。
pub fn generate_private_key() -> Result<Zeroizing<String>, String> {
    let mut b = Zeroizing::new([0u8; 32]);
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b[..])
        .map_err(|_| "no randomness".to_owned())?;
    Ok(wgft_wireguard::PrivateKey::generate(&b).to_base64())
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
    /// 最終ハンドシェイクのデータプレーンの時計の時刻。device が持つ値で、壁時計が動いても変わらない。
    pub handshake_observed_at: Option<Instant>,
    /// WireGuard の UDP のソケットのバッファ。データプレーンがソケットを開いたときに測った値。
    pub socket_buffers: Option<dataplane::SocketBuffers>,
}

/// The agent's TCP/IP core: the Rust wgstack and its waker table, with the relay's LAN sockets
/// as the boost hook.
pub type Stack = Netstack<LanHook<LanConn>>;

/// The relay tasks' access to the core on the data plane thread.
pub type Net = Local<Stack>;

/// The data plane generations of the agent's tunnels.
pub type Generations = dataplane::Generations<Stack>;

/// 動いているトンネル。
#[derive(Debug)]
pub struct Tunnel {
    cfg: Config,
    shared: Arc<Mutex<Reading>>,
    dataplane: Handle<Stack>,
    monitor: JoinHandle<()>,
    slot_watch: JoinHandle<()>,
    /// トンネルを立てた時刻。データプレーンの時計の値。
    started_at: Instant,
    clock: Option<PathBuf>,
    /// device の時計の始まりの値。device は下限より 1 秒新しい値と壁時計の大きい方から数える。
    clock_base: Duration,
}

impl Tunnel {
    /// トンネルを立てる。データプレーンの次の世代を `generations` で始め、その上で Rust の wgstack を
    /// 動かす。エンドポイントの名前を解決できなくても立て、引き直しに任せる。
    ///
    /// # Errors
    ///
    /// 鍵が読めないか、データプレーン (UDP のソケット、スレッド、核) を作れなければ誤りを返す。
    pub async fn start(
        private_key: &str,
        cfg: Config,
        generations: &mut Generations,
        limits: Limits,
        batching: Batching,
        clock: Option<&Path>,
        dead: Arc<tokio::sync::Notify>,
    ) -> Result<Tunnel, String> {
        let key =
            PrivateKey::from_base64(private_key).map_err(|e| format!("wg_private_key: {e}"))?;
        let server = PublicKey::from_base64(&cfg.server_public_key)
            .map_err(|e| format!("server_pubkey: {e}"))?;
        let shared = Arc::new(Mutex::new(Reading::default()));
        let ep = resolve(&cfg.endpoint).await;
        set_endpoint(&shared, ep.clone());
        let floor = stamp::floor(clock).await;
        let wall = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        generations.raise_floor(floor);
        let clock_base = wall.max(generations.unix_high_water() + Duration::from_secs(1));
        let mut dc = DeviceConfig::agent(
            key,
            server,
            ep.ok().map(SocketAddr::V4),
            cfg.server_address,
            cfg.keepalive,
        );
        dc.mtu = cfg.mtu;
        let stack = StackSettings {
            addr: cfg.address,
            limits,
        };
        // 核の設定はここで確かめる。データプレーンのスレッドの上の作成で失敗しうるのは確保だけにする
        wgft_wgstack::Config {
            limits,
            ..wgft_wgstack::Config::new(cfg.address, usize::from(cfg.mtu))
        }
        .validate()
        .map_err(|e| format!("TCP/IP settings: {e}"))?;
        generations
            .start(
                dc,
                Settings {
                    batching,
                    ..Settings::default()
                },
                move |init| dataplane::stack::make(stack, init),
            )
            .await
            .map_err(|e| format!("start the tunnel data plane: {e}"))?;
        let dataplane = generations
            .current()
            .map(Dataplane::handle)
            .ok_or("the tunnel data plane did not start")?;
        logf!(
            "tunnel: up addr={} mtu={} endpoint={}",
            cfg.address,
            cfg.mtu,
            cfg.endpoint
        );
        let monitor = tokio::spawn(monitor(
            cfg.clone(),
            Arc::clone(&shared),
            dataplane.clone(),
            dead,
        ));
        let slot_watch = tokio::spawn(slot_watch(dataplane.clone(), limits));
        Ok(Tunnel {
            cfg,
            shared,
            dataplane,
            monitor,
            slot_watch,
            started_at: dataplane::clock::now(),
            clock: clock.map(Path::to_path_buf),
            clock_base,
        })
    }

    /// トンネルを立てた時刻 (データプレーンの時計)。
    #[must_use]
    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    /// データプレーンのスレッドが終わっているか。終わっていればトンネルは動いていない。
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.dataplane.is_finished()
    }

    /// データプレーンへの handle。中継が待ち受けと接続をデータプレーンのスレッドで動かすのに使う。
    #[must_use]
    pub fn dataplane(&self) -> &Handle<Stack> {
        &self.dataplane
    }

    /// handshake の時刻の印の高い水位をファイルに残す。
    ///
    /// 残す値は、device が使った印の高い水位と、device の時計の今の値の大きい方である。印は handshake の
    /// ときにしか進まないので今の値で測り、keepalive の間隔が長くても次の印が残した値を超えないように
    /// する。
    pub async fn persist_clock(&self) {
        stamp::record(self.clock.as_deref(), self.clock_now().await, true).await;
    }

    async fn clock_now(&self) -> Duration {
        let hw = self
            .dataplane
            .status()
            .await
            .map(|s| s.unix_high_water)
            .unwrap_or_default();
        let elapsed = dataplane::clock::now().saturating_duration_since(self.started_at);
        hw.max(self.clock_base + elapsed)
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
        match self.dataplane.status().await {
            Ok(st) => {
                r.socket_buffers = Some(st.socket_buffers);
                if let Some(p) = st.peer {
                    r.handshake_observed_at = p.last_handshake;
                    r.last_handshake = p.last_handshake.and_then(wall_time);
                    r.rx_bytes = p.rx_bytes;
                    r.tx_bytes = p.tx_bytes;
                }
            }
            Err(e) => r.err = Some(format!("read the tunnel data plane: {e}")),
        }
        r
    }

    /// wgstack の UDP の受信の会計の故障。会計が不変条件の違反で止まっていれば、最初の違反の文を返す。
    /// `Err` はデータプレーンが止まっていて読めなかったことを示す。
    pub async fn udp_fault(&self) -> Result<Option<String>, String> {
        self.dataplane
            .call(|net| net.with(|ns| ns.core().udp_receive_fault().map(|f| f.to_string())))
            .await
            .map_err(|e| e.to_string())
    }

    /// 閉じる。中継は先に閉じておく。データプレーンを止め、核の予算を `generations` に残す。時刻の印の
    /// 水位を残す。`exiting` はプロセスが終わるときだけ真にし、そのときだけ水位に余裕を足さずに残す。
    /// プロセスの中の作り直しでは、次の device がファイルを読み直さずに印を使うので、余裕を足したまま
    /// 残す。
    pub async fn close(self, generations: &mut Generations, exiting: bool) {
        stamp::record(self.clock.as_deref(), self.clock_now().await, !exiting).await;
        self.monitor.abort();
        let _ = self.monitor.await;
        self.slot_watch.abort();
        let _ = self.slot_watch.await;
        generations.stop().await;
    }
}

/// データプレーンの時計の時刻を壁時計に直す。
fn wall_time(t: Instant) -> Option<SystemTime> {
    SystemTime::now().checked_sub(dataplane::clock::now().saturating_duration_since(t))
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

/// 使ったことのある接続の枠の数を書く行の刻みの下限です。
const SLOT_STEP_MIN: usize = 64;

/// 行の数の上限です。`slot_watch` は `Tunnel::start` ごとに最後に書いた値 `shown` を 0 から始めるので、トンネルを立てるたびに最大この行数です。刻みは接続の枠の数をこの値で割って決めます。
const SLOT_LINES_MAX: usize = 32;

/// 使ったことのある接続の枠の数を書く行の刻みです。接続の枠の数を [`SLOT_LINES_MAX`] で割って切り上げた値と
/// [`SLOT_STEP_MIN`] の大きい方を、64 の倍数に切り上げます。行は数をこの倍数に切り上げて書くので、行の値は
/// 数の上界で、行の数はトンネルを立てるたびに、上限によらず [`SLOT_LINES_MAX`] までです (洪水で数が一気に増えても行が増えすぎない)。
const fn slot_step(conns: usize) -> usize {
    let want = conns.div_ceil(SLOT_LINES_MAX);
    let want = if want > SLOT_STEP_MIN {
        want
    } else {
        SLOT_STEP_MIN
    };
    want.next_multiple_of(SLOT_STEP_MIN)
}

/// 核の接続の枠のうち floor の配列を持つ枠 (核を作ってから使ったことのある枠) の数を 1 秒ごとに読み (核が数えて
/// 持つ値で、枠をたどらない)、
/// [`slot_step`] の倍数に切り上げた値が増えたときだけ、その値と配列の byte を 1 行に書く。配列は枠が持ち続けるので、
/// 数は減らない。ラボの `lifecycle.sh` の check 5 と 5b は、洪水が満たした配列の量をこの行から読む
/// (agent-parity.md の「メモリの上界の行」)。行の形は保証の外。
async fn slot_watch(dp: Handle<Stack>, limits: Limits) {
    let conns = limits.conns();
    let arrays = wgft_wgstack::Bound::for_limits(&limits, wgft_wgstack::MAX_MTU).floor_arrays;
    let per_slot = usize::try_from(arrays).unwrap_or(usize::MAX) / conns.max(1);
    let step = slot_step(conns);
    let mut shown = 0;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let Ok(used) = dp.call(|net| net.with(|ns| ns.core().slots_used())).await else {
            return;
        };
        let up = used.next_multiple_of(step).min(conns);
        if up > shown {
            shown = up;
            logf!(
                "memory: connection slots used so far: at most {up} of {conns}; their floor arrays hold {} KiB",
                (up * per_slot).div_ceil(1 << 10)
            );
        }
    }
}

/// keepalive ごとに、ハンドシェイクが keepalive の 5 倍の間成功していなければエンドポイントを引き直し、
/// server のアドレスへ ICMP echo を 1 つ送る (Go の `tunnel.Run`)。ping はデータのパケットなので、
/// server がセッションを失っていれば鍵の寿命を待たずに新しいハンドシェイクが始まる。ping は wgstack の
/// ping の endpoint から送る。
async fn monitor(
    cfg: Config,
    shared: Arc<Mutex<Reading>>,
    dp: Handle<Stack>,
    dead: Arc<tokio::sync::Notify>,
) {
    let mut tick = tokio::time::interval(cfg.keepalive);
    tick.tick().await;
    let mut pinged: Option<bool> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = dp.finished() => {
                // データプレーンのスレッドが終わった。agent に作り直させる
                logf!("tunnel: the tunnel data plane stopped");
                dead.notify_one();
                return;
            }
        }
        let hs = dp
            .status()
            .await
            .ok()
            .and_then(|s| s.peer)
            .and_then(|p| p.last_handshake);
        let stale = hs.is_none_or(|t| {
            dataplane::clock::now().saturating_duration_since(t) > cfg.keepalive * 5
        });
        if stale {
            let before = lock(&shared).endpoint;
            let ep = resolve(&cfg.endpoint).await;
            if let Ok(a) = &ep
                && before != Some(SocketAddr::V4(*a))
            {
                logf!("tunnel: changed endpoint {before:?} -> {a}");
                if let Err(e) = dp.set_endpoint(SocketAddr::V4(*a)).await {
                    logf!("tunnel: set endpoint {a}: {e}");
                }
            }
            if let Err(e) = &ep {
                logf!("tunnel: re-resolve endpoint: {e}");
            }
            set_endpoint(&shared, ep);
        }
        // 答えの有無が変わったときだけ 1 行出す
        let answered = match ping(&dp, cfg.server_address, Duration::from_secs(2)).await {
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

/// server のトンネルのアドレスへ ICMP echo を 1 つ送り、往復時間を返す。wgstack の ping の endpoint を
/// データプレーンのスレッドの local の task で開き、答えか期限まで待つ。
///
/// # Errors
///
/// endpoint を開けないか、送れないか、期限までに答えが無ければ誤りを返す。期限切れの文は
/// `timed out` で終わる。
pub async fn ping(dp: &Handle<Stack>, to: Ipv4Addr, timeout: Duration) -> Result<Duration, String> {
    let reply = dp
        .call(move |net| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let net = net.clone();
            tokio::task::spawn_local(async move {
                let _ = tx.send(ping_on(&net, to, timeout).await);
            });
            rx
        })
        .await
        .map_err(|e| format!("icmp: {e}"))?;
    reply
        .await
        .map_err(|_| "icmp: the tunnel data plane stopped".to_owned())?
}

/// ping の本体。データプレーンのスレッドで動く。
async fn ping_on(net: &Net, to: Ipv4Addr, timeout: Duration) -> Result<Duration, String> {
    let mut p = Ping::open(net, to).map_err(|e| format!("icmp open: {e}"))?;
    let seq = u16::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            & 0xffff,
    )
    .unwrap_or(0);
    // type 8 code 0、チェックサムと識別子 (核が書く)、seq、本文 "wgft"
    let mut msg = [8u8, 0, 0, 0, 0, 0, 0, 0, b'w', b'g', b'f', b't'];
    msg[6..8].copy_from_slice(&seq.to_be_bytes());
    let start = dataplane::clock::now();
    let deadline = tokio::time::Instant::now() + timeout;
    p.send(&msg).map_err(|e| format!("icmp send: {e}"))?;
    let mut buf = [0u8; 64];
    loop {
        let n = tokio::time::timeout_at(deadline, p.recv(&mut buf))
            .await
            .map_err(|_| "icmp receive: timed out".to_owned())?
            .map_err(|e| format!("icmp receive: {e}"))?;
        // 前の ping の遅れた答えは捨てる
        if n >= 8 && buf[0] == 0 && buf[6..8] == seq.to_be_bytes() {
            return Ok(dataplane::clock::now().saturating_duration_since(start));
        }
    }
}

/// `wg.endpoint` の読み (仕様 tunnel.md のエンドポイントの解決)。
#[derive(Debug, PartialEq, Eq)]
enum Endpoint {
    /// IPv4 のアドレス。角括弧に入った IPv4 も受ける。
    Addr(SocketAddrV4),
    /// ホスト名。A レコードを引く。
    Name(String, u16),
}

fn parse_endpoint(endpoint: &str) -> Result<Endpoint, String> {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return Err(format!("{endpoint:?} is not in host:port form"));
    };
    // ポートは 10 進の数字だけ。符号とサービス名は拒み、先頭の 0 は受ける
    if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("{endpoint:?} has an invalid port"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("{endpoint:?} has an invalid port"))?;
    let inner = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    if let Some(h) = inner {
        return match h.parse::<Ipv4Addr>() {
            Ok(a) => Ok(Endpoint::Addr(SocketAddrV4::new(a, port))),
            Err(_) => Err("IPv6 endpoints are not supported".into()),
        };
    }
    if host.is_empty() {
        return Err(format!("{endpoint:?} has no host"));
    }
    if let Ok(a) = host.parse::<Ipv4Addr>() {
        return Ok(Endpoint::Addr(SocketAddrV4::new(a, port)));
    }
    if host.contains(':') {
        return Err(format!("{endpoint:?} is not in host:port form"));
    }
    Ok(Endpoint::Name(host.to_owned(), port))
}

/// A レコードの一覧から、アドレスの小さい順で先頭を選ぶ。
fn pick(host: &str, port: u16, mut v4: Vec<Ipv4Addr>) -> Result<SocketAddrV4, String> {
    v4.sort();
    v4.first()
        .map(|a| SocketAddrV4::new(*a, port))
        .ok_or_else(|| format!("no A record for {host}"))
}

/// `host:port` を IPv4 の `SocketAddrV4` にする。ホスト名は A レコードを 5 秒の期限で引く。宛先の名前とは
/// 別の許可で引くので、宛先の名前の解決が詰まってもエンドポイントの引き直しは止まらない。
async fn resolve(endpoint: &str) -> Result<SocketAddrV4, String> {
    let (host, port) = match parse_endpoint(endpoint)? {
        Endpoint::Addr(a) => return Ok(a),
        Endpoint::Name(h, p) => (h, p),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let addrs = crate::targets::resolve::Resolver::shared()
        .lookup_endpoint(&host, deadline)
        .await?;
    let v4 = addrs
        .into_iter()
        .filter_map(|a| match a {
            std::net::IpAddr::V4(a) => Some(a),
            std::net::IpAddr::V6(_) => None,
        })
        .collect();
    pick(&host, port, v4)
}

/// handshake の時刻の印 (TAI64N) の高い水位。
///
/// device は handshake の初めの送信に時刻の印を付け、相手の WireGuard (Linux と wireguard-go) は前に
/// 受けた印より古い印の handshake を捨てる。壁時計が前の device より戻っていると (RTC の無いホストの
/// NTP の前、時計の巻き戻し)、handshake が通らなくなる。device は作るときに渡した下限より 1 秒新しい
/// 値と壁時計の大きい方から印を作り、使った印の高い水位を返す。この module は、プロセスの中で見た
/// 最も高い水位と、データディレクトリのファイルに残した水位の大きい方を下限として渡す。ファイルは
/// agent.json と分ける。Go の agent が agent.json を書き直すと、知らないキーを捨てるためである。
///
/// ファイルは 1 行の秒の値を、前の版の単位で持つ。前の版は sanstun の基準 (2^62 + 37) のまま印を
/// 付けたので、同じ値の下限でも印が今の版より 27 秒進む。今の版は [`FILE_BEHIND`] を引いて書き、足して
/// 読む。こうすると、前の版と今の版のどちらが書いたファイルを、どちらが読んでも、次の印は相手が前に
/// 受けた印を下回らない。前の版が読むと印は 27 秒進むだけで、戻らない。
mod stamp {
    use std::io::Read;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::credentials;

    /// 定期に残す値に足す余裕。水位は 30 秒ごとに残すので、それより長くする。前に残してから落ちる
    /// までに使った印も、次の下限が超えるようにするためである。
    pub(super) const SAVE_MARGIN: Duration = Duration::from_mins(1);

    /// device が受ける下限の上限。これ以上の値は壊れた記録として捨てる。
    const FLOOR_LIMIT: u64 = 1 << 40;

    /// ファイルの大きさの上限。`<秒>\n` の 1 行で足りる。
    const FILE_LIMIT: u64 = 64;

    /// ファイルの値と、今の版の下限 (本当の Unix 時刻) の差。前の版の印が標準の印より進んでいた秒で、
    /// ファイルの値は今の版の下限よりこれだけ小さい。
    const FILE_BEHIND: u64 = 27;

    /// プロセスの中で見た最も高い水位。
    static HIGH: Mutex<Duration> = Mutex::new(Duration::ZERO);

    /// ファイルへの書き込みを 1 つずつにする。書く値は書く時点の [`HIGH`] から決めるので、後に始めた
    /// 書き込みが先に始めた書き込みより低い値を残さない。
    static WRITING: Mutex<()> = Mutex::new(());

    fn high() -> Duration {
        *HIGH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 残した値。無ければ `Ok(None)`。symlink を辿らず、通常のファイルでないもの (FIFO を含む) と
    /// 大きすぎるものは開いた記述子で拒む (認証情報ファイルと同じ読み)。
    fn read(file: &Path) -> Result<Option<Duration>, String> {
        let (f, meta) = match credentials::open_regular_read(file) {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if meta.len() > FILE_LIMIT {
            return Err(format!("{} bytes is too long", meta.len()));
        }
        let mut text = String::new();
        f.take(FILE_LIMIT)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        let secs = text
            .trim()
            .parse::<u64>()
            .map_err(|_| "not a number of seconds".to_owned())?;
        secs.checked_add(FILE_BEHIND)
            .map(|s| Some(Duration::from_secs(s)))
            .ok_or_else(|| "out of range".into())
    }

    /// 新しい device に渡す下限。プロセスの中の水位と、残した値の大きい方である。残した値が読めないか
    /// 大きすぎれば、1 行を出して壁時計から始める。ファイルは消さず、次の記録が置き換える。通常の
    /// ファイルでなければ、記録は置き換えずに書けない旨を出す。ファイルの読みは blocking の
    /// スレッドで行う。
    pub(super) async fn floor(file: Option<&Path>) -> Duration {
        let high = high();
        let Some(file) = file.map(Path::to_path_buf) else {
            return high;
        };
        let saved = tokio::task::spawn_blocking(move || match read(&file) {
            Ok(Some(s)) if s.as_secs() < FLOOR_LIMIT => s,
            Ok(None) => Duration::ZERO,
            r => {
                let why = match r {
                    Err(e) => e,
                    _ => "out of range".into(),
                };
                // 開けないファイルの誤りの文はパスを含むので、行にパスを重ねない
                let path = file.display().to_string();
                if why.contains(&path) {
                    crate::logf!(
                        "the handshake clock is unreadable: {why}; starting from the wall clock"
                    );
                } else {
                    crate::logf!(
                        "the handshake clock in {path} is unreadable: {why}; starting from the wall clock"
                    );
                }
                Duration::ZERO
            }
        })
        .await
        .unwrap_or_default();
        high.max(saved)
    }

    /// device が返した高い水位を覚え、ファイルに残す。`margin` が真なら [`SAVE_MARGIN`] を足す (定期の
    /// 保存とプロセスの中のトンネルの作り直し)。偽なら水位そのものを残す (プロセスの終わり)。偽は、
    /// その後にこのプロセスが印を使わないときだけ渡す。作り直しの後の device はファイルを読み直さずに
    /// 印を使い、次の定期の保存の前に落ちると、余裕の無い値が使った印より低い下限になるためである。
    /// ファイルの書き込みは blocking のスレッドで行い、書けなくても動作は続ける。
    pub(super) async fn record(file: Option<&Path>, high_water: Duration, margin: bool) {
        {
            let mut h = HIGH
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *h = (*h).max(high_water);
        }
        let Some(file) = file.map(Path::to_path_buf) else {
            return;
        };
        let _ = tokio::task::spawn_blocking(move || write(&file, margin)).await;
    }

    fn write(file: &Path, margin: bool) {
        let _one = WRITING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let high = high();
        // 秒を切り上げ、下限が使った印より古くならないようにする
        let mut secs = high.as_secs() + u64::from(high.subsec_nanos() > 0);
        if margin {
            secs += SAVE_MARGIN.as_secs();
        }
        // ファイルは前の版の単位で持つので、読み返した値は 27 秒を足した値になる
        let r = if read(file)
            .is_ok_and(|saved| saved.is_some_and(|s| s.as_secs() == secs.max(FILE_BEHIND)))
        {
            Ok(())
        } else {
            let text = encode(secs);
            credentials::replace_private_file(file, "handshake clock", FILE_LIMIT, |w| {
                w.write_all(text.as_bytes())
            })
        };
        let mut failing = FAILING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(line) = record_line(&mut failing, file, r) {
            crate::logf!("{line}");
        }
    }

    /// ファイルの中身。`secs` は今の版の下限 (切り上げた秒)。
    fn encode(secs: u64) -> String {
        format!("{}\n", secs.saturating_sub(FILE_BEHIND))
    }

    /// 記録の失敗の文。定期の保存は 30 秒ごとに書くので、同じ失敗を毎回出さない。
    static FAILING: Mutex<Option<String>> = Mutex::new(None);

    /// 記録の結果 `r` のうち、ログに出す行。失敗が始まったときと失敗の文が変わったとき、失敗から戻った
    /// ときだけ返す。`last` は前の失敗の文で、ここで更新する。
    fn record_line(
        last: &mut Option<String>,
        file: &Path,
        r: Result<(), String>,
    ) -> Option<String> {
        match r {
            Ok(()) => last.take().map(|_| {
                format!(
                    "the handshake clock in {} is recorded again",
                    file.display()
                )
            }),
            Err(e) if last.as_deref() == Some(e.as_str()) => None,
            Err(e) => {
                let line = format!(
                    "cannot record the handshake clock in {}: {e}",
                    file.display()
                );
                *last = Some(e);
                Some(line)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn the_floor_never_goes_back() {
            let dir = tempfile::tempdir().unwrap();
            let f = dir.path().join("agent.json.clock");
            let future = Duration::from_secs(4_000_000_000);
            record(Some(&f), future + Duration::from_millis(500), true).await;
            let saved = future + Duration::from_secs(1) + SAVE_MARGIN;
            assert_eq!(read(&f), Ok(Some(saved)));
            assert!(floor(Some(&f)).await >= saved);
            // 一時ファイルは残らない
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
            // プロセスの終わりは余裕を足さない。プロセスの中の水位は下がらない
            record(Some(&f), Duration::from_secs(10), false).await;
            assert_eq!(read(&f), Ok(Some(future + Duration::from_secs(1))));
            assert!(floor(Some(&f)).await >= future);
            // 壊れた記録は使わず、次の記録が置き換える
            std::fs::write(&f, format!("{}\n", 1u64 << 41)).unwrap();
            assert!(floor(Some(&f)).await < Duration::from_secs(1 << 40));
            record(Some(&f), Duration::from_secs(10), true).await;
            assert!(read(&f).unwrap().unwrap() < Duration::from_secs(1 << 40));
            std::fs::write(&f, "100 other-format\n").unwrap();
            assert!(read(&f).is_err());
            // ファイルの値は前の版の単位
            record(Some(&f), future + Duration::from_secs(5), false).await;
            assert_eq!(
                std::fs::read_to_string(&f).unwrap(),
                format!("{}\n", future.as_secs() + 5 - 27)
            );
        }

        #[test]
        fn the_file_keeps_the_earlier_builds_units() {
            // 前の版は値 N の下限から 2^62 + 37 + N + 1 秒以上の印を付けた。今の版は 27 秒足して読み、
            // 2^62 + 10 + (N + 27) + 1 秒以上の印を付けるので、同じ値から同じ印の下限になる
            let dir = tempfile::tempdir().unwrap();
            let f = dir.path().join("agent.json.clock");
            std::fs::write(&f, "4100000000\n").unwrap();
            let floor = read(&f).unwrap().unwrap();
            assert_eq!(floor, Duration::from_secs(4_100_000_027));
            // 今の版が書いた値を前の版が読めば、印は 27 秒進むだけで戻らない
            assert_eq!(encode(4_100_000_027), "4100000000\n");
            std::fs::write(&f, encode(4_100_000_027)).unwrap();
            assert_eq!(read(&f), Ok(Some(floor)));
        }

        /// 記録の失敗の行は、失敗が始まったときと文が変わったとき、戻ったときだけ出す。
        #[test]
        fn a_failing_record_is_logged_once_per_change() {
            let f = Path::new("/data/agent.json.clock");
            let mut last = None;
            let fail = |e: &str| Err(e.to_owned());
            assert_eq!(record_line(&mut last, f, Ok(())), None);
            assert_eq!(
                record_line(&mut last, f, fail("disk full")).as_deref(),
                Some("cannot record the handshake clock in /data/agent.json.clock: disk full")
            );
            assert_eq!(record_line(&mut last, f, fail("disk full")), None);
            assert!(record_line(&mut last, f, fail("read-only")).is_some());
            assert_eq!(
                record_line(&mut last, f, Ok(())).as_deref(),
                Some("the handshake clock in /data/agent.json.clock is recorded again")
            );
            assert_eq!(record_line(&mut last, f, Ok(())), None);
        }

        /// 記録のファイルの場所にある通常のファイルでないものは、読まずに使わず、置き換えもしない。FIFO
        /// を開いて止まらない。
        #[cfg(unix)]
        #[tokio::test]
        async fn irregular_files_are_neither_read_nor_replaced() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("elsewhere");
            std::fs::write(&target, "5000000000\n").unwrap();
            let link = dir.path().join("link.clock");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let fifo = dir.path().join("fifo.clock");
            let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: 有効な NUL 終端のパスを渡すだけである
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            let big = dir.path().join("big.clock");
            std::fs::write(&big, "1".repeat(100)).unwrap();
            for f in [&link, &fifo, &big] {
                let got = tokio::time::timeout(Duration::from_secs(2), floor(Some(f)))
                    .await
                    .expect("reading the clock does not block");
                assert!(got < Duration::from_secs(5_000_000_000), "{}", f.display());
            }
            record(Some(&link), Duration::from_secs(10), true).await;
            record(Some(&fifo), Duration::from_secs(10), true).await;
            assert!(
                std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "5000000000\n");
        }
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
    fn slot_step_scales_and_bounds_the_lines() {
        assert_eq!(slot_step(1), 64);
        assert_eq!(slot_step(2048), 64);
        assert_eq!(slot_step(65_536), 2048);
        for conns in [
            1,
            63,
            64,
            1000,
            2048,
            2049,
            4096,
            10_000,
            65_536,
            65_600,
            100_000,
            1 << 20,
        ] {
            let step = slot_step(conns);
            assert!(
                step >= 64 && step.is_multiple_of(64),
                "conns {conns} step {step}"
            );
            // 数が 0 から上限まで 1 ずつ増えたときに書く行の数
            let (mut shown, mut lines) = (0, 0);
            for used in 0..=conns {
                let up = used.next_multiple_of(step).min(conns);
                if up > shown {
                    shown = up;
                    lines += 1;
                }
            }
            assert!(lines <= SLOT_LINES_MAX, "conns {conns} wrote {lines} lines");
            assert_eq!(shown, conns);
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

    #[derive(serde::Deserialize)]
    struct EndpointCase {
        name: String,
        endpoint: String,
        lookup: Option<Vec<Ipv4Addr>>,
        #[serde(default)]
        want: String,
        #[serde(default)]
        error: bool,
    }

    #[derive(serde::Deserialize)]
    struct EndpointFixture {
        cases: Vec<EndpointCase>,
    }

    /// 仕様の fixture `testdata/spec/tunnel/endpoint.json` と照らす。名前の解決は fixture の一覧で置き換える。
    #[test]
    fn endpoints_follow_the_spec() {
        let path = format!(
            "{}/../../testdata/spec/tunnel/endpoint.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let f: EndpointFixture =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for c in f.cases {
            let got = parse_endpoint(&c.endpoint).and_then(|e| match e {
                Endpoint::Addr(a) => Ok(a),
                Endpoint::Name(h, p) => pick(&h, p, c.lookup.clone().unwrap_or_default()),
            });
            if c.error {
                assert!(got.is_err(), "{}: {got:?}", c.name);
            } else {
                assert_eq!(got.map(|a| a.to_string()), Ok(c.want.clone()), "{}", c.name);
            }
        }
    }

    #[test]
    fn rejects_addresses_that_cannot_hold_agent_and_server() {
        for a in [
            "0.0.0.2/24",
            "127.0.0.2/24",
            "224.0.0.2/24",
            "240.0.0.2/24",
            "255.255.255.255/24",
        ] {
            assert!(Config::from_wg(&wg(a, 25)).is_err(), "{a}");
        }
        for a in [
            "10.200.0.0/24",
            "10.200.0.1/24",
            "10.200.0.255/24",
            "10.200.0.2/31",
            "10.200.0.2/32",
        ] {
            assert!(Config::from_wg(&wg(a, 25)).is_err(), "{a}");
        }
        assert!(Config::from_wg(&wg("10.200.0.2/30", 25)).is_ok());
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
}
