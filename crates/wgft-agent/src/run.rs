//! agent の起動と、全体状態の適用とハートビートの組み立て。

use crate::logf;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{Mutex, Notify};
use wgft_proto::{GoTime, Heartbeat, Join, STATUS_ERROR, STATUS_OK, State, TunnelStatus, WgConfig};
use zeroize::Zeroizing;

use crate::credentials::{self, Credentials};
use crate::enroll::{register, token_hash};
use crate::error::{AgentError, Refusal};
use crate::relay::{Manager, OpenPorts};
use crate::stream;
use crate::tunnel::{self, Tunnel};

/// トンネルはあるがハンドシェイクがまだ済んでいないときの理由 (Go の `controlapi`)。
pub(crate) const REASON_HANDSHAKE_PENDING: &str = "handshake not established";
const REASON_NO_TUNNEL: &str = "no tunnel";
const REASON_NO_TUNNEL_BUILD_RETRYING: &str = "no tunnel; building it failed and will be retried";
const REASON_NO_TUNNEL_FULL_STATE_PENDING: &str = "no tunnel; full state not received";

/// トンネルの作成に失敗したときの立て直しの間隔。最初は 30 秒、その後は 300、600、900 秒で、
/// 900 秒の後は 900 秒ごと (仕様 tunnel.md のトンネルの作り直し)。
const REBUILD_BACKOFF: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_mins(5),
    Duration::from_mins(10),
    Duration::from_mins(15),
];

/// agent の起動の設定。値の検査は `wgft` のコマンドが済ませてから渡す。
#[derive(Clone, Default)]
pub struct Options {
    /// データディレクトリ。`agent.json` を置く。
    pub data_dir: PathBuf,
    /// 接続文字列。初回の登録と登録のし直しに使う。秘密。
    pub join: String,
    /// エージェント名。任意。
    pub name: String,
    /// 起動ログに出す版。
    pub version: String,
    /// トンネルの TUN の名前。試作は `WGFT_WG_INTERFACE` から取る。
    pub tun_name: String,
}

// 接続文字列は秘密なので Debug に出さない
impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("data_dir", &self.data_dir)
            .field(
                "join",
                &if self.join.is_empty() {
                    ""
                } else {
                    "<redacted>"
                },
            )
            .field("name", &self.name)
            .field("version", &self.version)
            .field("tun_name", &self.tun_name)
            .finish()
    }
}

impl Options {
    /// handshake の時刻の印の高い水位を残すファイル。agent.json の隣に置く。
    pub(crate) fn clock_path(&self) -> PathBuf {
        self.data_dir.join("agent.json.clock")
    }

    pub(crate) fn credentials_path(&self) -> PathBuf {
        self.data_dir.join(credentials::FILE_NAME)
    }
}

/// 動いている agent の状態。全体状態の適用の間じゅう排他を持つ。
pub(crate) struct Agent {
    pub(crate) opts: Options,
    pub(crate) creds: Credentials,
    pub(crate) private_key: Zeroizing<String>,
    tunnel: Option<Tunnel>,
    relay: Option<Manager>,
    wg: Option<WgConfig>,
    pub(crate) generation: u64,
    /// トンネルの作成に失敗した全体状態と、次に立て直す時刻と、失敗の回数。
    retry: Option<State>,
    retry_at: Option<Instant>,
    retry_failures: usize,
    /// トンネルの作り直しの閾値と、最後に見た最終ハンドシェイク (単調な時計) と、それを見た時刻。
    rebuild_after: Duration,
    seen_handshake: Option<Instant>,
    seen_at: Option<Instant>,
    /// 入口の検査で捨てた数を前にログに出した値と時刻。
    refused_logged: (u64, Option<Instant>),
    /// stream の外の経路 (トンネルの立て直し) が状態を変えたことを、接続中の stream に伝え、
    /// ハートビートを 1 回送らせる。
    pub(crate) state_changed: Arc<Notify>,
}

// 鍵と恒久トークンを Debug に出さない
impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("opts", &self.opts)
            .field("name", &self.creds.name)
            .field("tunnel", &self.tunnel)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

pub(crate) type Shared = Arc<Mutex<Agent>>;

impl Agent {
    pub(crate) fn save(&self) -> Result<(), AgentError> {
        self.creds
            .save(&self.opts.credentials_path())
            .map_err(|e| AgentError::Other(e.to_string()))
    }

    /// 全体状態を適用する。wg の設定が変わればトンネルを立て直し、ルールは変わったものだけを開閉する。
    /// トンネルが立った後は、ルールの一部が失敗しても世代を進めて保存する。
    pub(crate) async fn apply(&mut self, st: &State) -> Result<(), String> {
        if self.tunnel.is_none() || self.wg.as_ref() != Some(&st.wg) {
            if self.tunnel.is_some() {
                logf!("wg config changed; rebuilding tunnel");
            }
            self.close().await;
            let cfg = tunnel::Config::from_wg(&st.wg).map_err(|e| format!("wireguard: {e}"))?;
            let open = OpenPorts::default();
            let server = cfg.server_address;
            let clock = self.opts.clock_path();
            match Tunnel::start(
                &self.private_key,
                &self.opts.tun_name,
                cfg,
                open.clone(),
                Some(&clock),
            )
            .await
            {
                Ok(t) => {
                    self.relay = Some(Manager::new(
                        t.address(),
                        server,
                        Some(self.opts.tun_name.clone()),
                        open,
                    ));
                    self.tunnel = Some(t);
                    self.wg = Some(st.wg.clone());
                    self.retry = None;
                    self.retry_at = None;
                    self.retry_failures = 0;
                }
                Err(e) => {
                    let wait = REBUILD_BACKOFF[self.retry_failures.min(REBUILD_BACKOFF.len() - 1)];
                    self.retry = Some(st.clone());
                    self.retry_at = Some(Instant::now() + wait);
                    self.retry_failures += 1;
                    return Err(format!("wireguard: {e}; retrying in {}s", wait.as_secs()));
                }
            }
        }
        let relay = self.relay.as_mut().ok_or("no relay")?;
        let actions = relay.apply(&st.rules).await;
        let listening = relay.listening();
        self.generation = st.generation;
        self.creds.last_state = Some(st.clone());
        self.record_tunnel_address(&st.wg.address);
        let saved = self.save();
        logf!(
            "applied generation {}: {actions} actions, {listening} listeners",
            st.generation
        );
        saved.map_err(|e| format!("save credentials file: {e}"))
    }

    /// 適用が済んだ全体状態のトンネルのアドレスを記録する。記録が無いか、アドレスだけを記録していれば
    /// 帯の長さまで記録する。違うアドレスは記録を変えずに使う (ユーザー空間モードの扱い)。
    fn record_tunnel_address(&mut self, address: &str) {
        let rec = &self.creds.tunnel_address;
        let addr_only = address.split('/').next().unwrap_or_default();
        if rec.is_empty() || (!rec.contains('/') && rec == addr_only) {
            address.clone_into(&mut self.creds.tunnel_address);
        } else if rec != address {
            logf!(
                "warning: the server sent the tunnel address {address}, but agent.json records {rec}, the address this agent was registered with"
            );
        }
    }

    /// 最後に適用した全体状態と世代も中身も同じかどうか。
    pub(crate) fn already_applied(&self, st: &State) -> bool {
        self.tunnel.is_some()
            && self.retry.is_none()
            && st.generation == self.generation
            && self.creds.last_state.as_ref() == Some(st)
    }

    pub(crate) async fn close(&mut self) {
        // 中継の接続を先に RST で切り、リスナーを閉じてからトンネルを閉じる
        if let Some(mut r) = self.relay.take() {
            r.close().await;
        }
        if let Some(t) = self.tunnel.take() {
            t.close().await;
        }
        self.wg = None;
    }

    /// 最終ハンドシェイクが新しいか。壁時計の値と、その値を最初に観測してからの単調な時計の経過の
    /// どちらも 180 秒より短いときだけ新しいとする (仕様 stream.md の再接続の待ち)。
    pub(crate) async fn handshake_fresh(&self) -> bool {
        const FRESH_FOR: Duration = Duration::from_secs(180);
        let Some(t) = &self.tunnel else { return false };
        let r = t.read().await;
        let wall = r
            .last_handshake
            .and_then(|h| SystemTime::now().duration_since(h).ok())
            .is_some_and(|d| d < FRESH_FOR);
        let mono = r
            .handshake_observed_at
            .is_some_and(|o| o.elapsed() < FRESH_FOR);
        wall && mono
    }

    /// ハートビートの中身 (理由の整形の前)。
    pub(crate) async fn heartbeat(&self) -> Heartbeat {
        let mut hb = Heartbeat {
            generation: self.generation,
            ..Heartbeat::default()
        };
        let Some(t) = &self.tunnel else {
            let reason = if self.retry.is_some() {
                REASON_NO_TUNNEL_BUILD_RETRYING
            } else if self.creds.last_state.is_none() {
                REASON_NO_TUNNEL_FULL_STATE_PENDING
            } else {
                REASON_NO_TUNNEL
            };
            hb.tunnel = TunnelStatus {
                state: STATUS_ERROR.into(),
                reason: reason.into(),
                ..TunnelStatus::default()
            };
            return hb;
        };
        let r = t.read().await;
        hb.tunnel = TunnelStatus {
            state: STATUS_OK.into(),
            reason: String::new(),
            endpoint: r.endpoint.map(|e| e.to_string()).unwrap_or_default(),
            last_handshake: r.last_handshake.map_or(GoTime::ZERO, GoTime::from_system),
        };
        if let Some(e) = r.err {
            hb.tunnel.state = STATUS_ERROR.into();
            hb.tunnel.reason = e;
        } else if r.last_handshake.is_none() {
            hb.tunnel.state = STATUS_ERROR.into();
            hb.tunnel.reason = REASON_HANDSHAKE_PENDING.into();
        }
        if let Some(relay) = &self.relay {
            hb.rules = relay.status();
        }
        hb
    }

    /// 30 秒ごとの見回り。作成に失敗したトンネルを時刻が来たら立て直し、開けなかったリスナーを
    /// 開き直す。立て直せたら、接続中の stream にハートビートを送らせる。
    async fn tick(&mut self) {
        self.watch_tunnel().await;
        if let Some(st) = self.retry.clone()
            && self.retry_at.is_none_or(|at| Instant::now() >= at)
        {
            match self.apply(&st).await {
                Ok(()) => {
                    logf!("tunnel: rebuilt for generation {}", st.generation);
                    self.state_changed.notify_one();
                }
                Err(e) => logf!("tunnel: rebuilding for generation {}: {e}", st.generation),
            }
        }
        if let Some(r) = self.relay.as_mut() {
            r.retry();
        }
    }
}

impl Agent {
    /// トンネルの見張り (仕様 tunnel.md のハンドシェイクの監視と作り直し)。新しいハンドシェイクが
    /// 無い時間が閾値を超えるか、device を動かす外殻が止まっていれば、同じ全体状態でトンネルを作り直す。
    /// 時間は、最後に見たハンドシェイクを観測した時刻とトンネルを立てた時刻の遅い方から単調な時計で
    /// 測る。閾値は 300 秒で、作り直すたびに 2 倍にし、900 秒で止める。新しいハンドシェイクを見たら
    /// 300 秒に戻す。あわせて、時刻の印の高い水位を残し、入口の検査が捨てた数をログに出す。
    async fn watch_tunnel(&mut self) {
        let Some(t) = &self.tunnel else { return };
        t.persist_clock().await;
        let counts = t.filter_counts();
        let finished = t.is_finished();
        let started = t.started_at();
        let hs = t.read().await.handshake_observed_at;
        let now = Instant::now();
        if hs.is_some() && hs != self.seen_handshake {
            self.seen_handshake = hs;
            self.seen_at = Some(now);
            self.rebuild_after = REBUILD_AFTER_MIN;
        }
        let since = self.seen_at.map_or(started, |s| s.max(started));
        let reason = if finished {
            Some("the tunnel device stopped".to_owned())
        } else if now.duration_since(since) > self.rebuild_after {
            Some(format!(
                "no new wireguard handshake for {}s",
                now.duration_since(since).as_secs()
            ))
        } else {
            None
        };
        self.log_refused(counts);
        let Some(reason) = reason else { return };
        let Some(st) = self.creds.last_state.clone() else {
            return;
        };
        logf!("tunnel: {reason}; rebuilding it");
        self.rebuild_after = (self.rebuild_after * 2).min(REBUILD_AFTER_MAX);
        self.close().await;
        match self.apply(&st).await {
            Ok(()) => self.state_changed.notify_one(),
            Err(e) => logf!("tunnel: rebuilding: {e}"),
        }
    }

    /// 入口の検査が捨てた数が増えていれば、1 分に 1 回までログに出す。server の正しい作りは捨てられる
    /// packet を送らないので、増え続けるのは server が乗っ取られている兆候でありうる。
    fn log_refused(&mut self, c: crate::inbound::CountsSnapshot) {
        let (last, at) = self.refused_logged;
        if c.refused() > last && at.is_none_or(|a| a.elapsed() >= Duration::from_mins(1)) {
            logf!(
                "tunnel: the inbound filter refused {} packets from the server so far: {} not for this agent, {} fragments, {} to ports without a rule ({} answered with a reset), {} other",
                c.refused(),
                c.not_for_agent,
                c.fragments,
                c.closed_port,
                c.resets,
                c.other
            );
            self.refused_logged = (c.refused(), Some(Instant::now()));
        }
    }
}

const REBUILD_AFTER_MIN: Duration = Duration::from_mins(5);
const REBUILD_AFTER_MAX: Duration = Duration::from_mins(15);

/// agent を動かす。シグナルか、復帰できない誤りまで戻らない。
///
/// # Errors
///
/// 起動の拒否と、復帰できない誤りを返す。
pub fn run(opts: Options) -> Result<(), AgentError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| AgentError::Other(format!("start the async runtime: {e}")))?;
    rt.block_on(run_async(opts))
}

async fn run_async(opts: Options) -> Result<(), AgentError> {
    let path = opts.credentials_path();
    // 二重起動の検出。Go の agent と同じロックなので、同じデータディレクトリの Go の agent とも排他になる
    credentials::ensure_data_dir(&opts.data_dir).map_err(|e| {
        AgentError::Other(format!("create data dir {}: {e}", opts.data_dir.display()))
    })?;
    let _lock = credentials::acquire(&path).map_err(|e| AgentError::Other(e.to_string()))?;
    credentials::remove_leftover_temps(&path);
    let (creds, private_key) = prepare(&opts).await?;
    let agent = Arc::new(Mutex::new(Agent {
        opts,
        creds,
        private_key,
        tunnel: None,
        relay: None,
        wg: None,
        generation: 0,
        retry: None,
        retry_at: None,
        retry_failures: 0,
        rebuild_after: REBUILD_AFTER_MIN,
        seen_handshake: None,
        seen_at: None,
        refused_logged: (0, None),
        state_changed: Arc::new(Notify::new()),
    }));
    {
        let mut a = agent.lock().await;
        // server が止まっていても、server の側にピアが残っていれば転送が戻るよう、先に立てる
        if let Some(st) = a.creds.last_state.clone() {
            if let Err(e) = a.apply(&st).await {
                logf!(
                    "apply saved generation {}: {e}; waiting for full state from stream",
                    st.generation
                );
            }
        } else {
            logf!("no saved full state; waiting for full state from stream");
        }
    }
    let mut stream_task = tokio::spawn(stream::stream_loop(Arc::clone(&agent)));
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.tick().await;
    let mut last_status = String::new();
    let result = loop {
        tokio::select! {
            () = shutdown_signal() => {
                logf!("shutting down");
                break Ok(());
            }
            r = &mut stream_task => {
                break match r {
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(())) => Ok(()),
                    Err(e) => Err(AgentError::Other(format!("stream task: {e}"))),
                };
            }
            _ = tick.tick() => {
                let mut a = agent.lock().await;
                a.tick().await;
                let hb = a.heartbeat().await;
                let mut s = format!("generation {} tunnel={} {} endpoint={}", hb.generation, hb.tunnel.state, hb.tunnel.reason, hb.tunnel.endpoint);
                for r in &hb.rules {
                    let _ = write!(s, "\nrule {} {} {}", r.id, r.state, r.reason);
                }
                if s != last_status {
                    for l in s.lines() {
                        logf!("{l}");
                    }
                    last_status = s;
                }
            }
        }
    };
    stream_task.abort();
    agent.lock().await.close().await;
    result
}

/// 認証情報を読み、モードを確かめ、鍵を用意し、未登録なら登録する。呼び手がロックを持つ。
async fn prepare(opts: &Options) -> Result<(Credentials, Zeroizing<String>), AgentError> {
    let path = opts.credentials_path();
    let mut creds =
        Credentials::load_or_new(&path).map_err(|e| AgentError::Other(e.to_string()))?;
    if creds.recorded_mode() != "userspace" {
        return Err(Refusal::mode_gate(
            "WGFT_MODE",
            format!(
                "agent.json records {} mode, and this Rust agent prototype runs userspace mode only; start the Go agent for this data directory",
                creds.recorded_mode()
            ),
        )
        .into());
    }
    let name = if creds.name.is_empty() {
        "not registered yet"
    } else {
        creds.name.as_str()
    };
    logf!(
        "wgft {} agent starting: name {name}, mode userspace, data dir {}",
        if opts.version.is_empty() {
            "dev"
        } else {
            &opts.version
        },
        opts.data_dir.display()
    );
    let private_key = if creds.wg_private_key.is_empty() {
        let k = tunnel::generate_private_key().map_err(AgentError::Other)?;
        creds.wg_private_key.clone_from(&k);
        creds
            .save(&path)
            .map_err(|e| AgentError::Other(e.to_string()))?;
        logf!(
            "generated wg key pair; public key: {}",
            tunnel::public_key(&k).map_err(AgentError::Other)?
        );
        k
    } else {
        tunnel::public_key(&creds.wg_private_key).map_err(AgentError::Other)?;
        Zeroizing::new(creds.wg_private_key.clone())
    };
    ensure_registered(&mut creds, opts).await?;

    Ok((creds, private_key))
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// 初回の登録。恒久トークンがあれば何もしない。使用済みの接続文字列は黙って無視する。
async fn ensure_registered(creds: &mut Credentials, opts: &Options) -> Result<(), AgentError> {
    if !creds.permanent_token.is_empty() {
        if !opts.name.is_empty() && opts.name != creds.name {
            logf!(
                "WGFT_NAME={} differs from the registered name {}; keeping {}",
                opts.name,
                creds.name,
                creds.name
            );
        }
        if !opts.join.is_empty()
            && let Ok(j) = Join::parse(&opts.join)
            && token_hash(&j) != creds.used_join_token_sha256
        {
            logf!(
                "already registered; ignoring the provided join string and using the existing permanent token"
            );
        }
        return Ok(());
    }
    if opts.join.is_empty() {
        return Err(Refusal::config(
            "WGFT_JOIN",
            "not registered and no join string; provide via WGFT_JOIN or --join",
        )
        .into());
    }
    let j = Join::parse(&opts.join).map_err(|e| Refusal::config("WGFT_JOIN", e.to_string()))?;
    if token_hash(&j) == creds.used_join_token_sha256 {
        return Err(Refusal::conflict(
            "WGFT_JOIN",
            "this join string is already used; issue a new join string",
        )
        .into());
    }
    let resp = register(&j, &opts.name).await?;
    record(creds, &j, &resp.permanent_token, &resp.address, &resp.name);
    creds
        .save(&opts.credentials_path())
        .map_err(|e| AgentError::Other(e.to_string()))?;
    logf!(
        "registered as agent {}; assigned {}, API {}",
        resp.name,
        resp.address,
        j.endpoint
    );
    Ok(())
}

/// 登録の結果を認証情報に写す (Go の `enroll.Record`)。
pub(crate) fn record(creds: &mut Credentials, j: &Join, token: &str, address: &str, name: &str) {
    name.clone_into(&mut creds.name);
    creds.endpoint.clone_from(&j.endpoint);
    token.clone_into(&mut creds.permanent_token);
    creds.cert_sha256 = j.pin_hex();
    creds.used_join_token_sha256 = token_hash(j);
    creds.tunnel_address = registered_tunnel_address(address);
}

/// 登録の応答のアドレスを `tunnel_address` の値にする。IPv4 のアドレスか帯の付いた形だけを受ける。
fn registered_tunnel_address(addr: &str) -> String {
    let (a, len) = match addr.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (addr, None),
    };
    let Ok(ip) = a.parse::<std::net::Ipv4Addr>() else {
        return String::new();
    };
    match len {
        None => ip.to_string(),
        Some(l) => match l.parse::<u8>() {
            Ok(n) if n <= 32 => format!("{ip}/{n}"),
            _ => String::new(),
        },
    }
}

/// 登録のし直し (stream の認証が拒まれたとき)。WGFT_JOIN があり、使用済みでなければ登録し直す。
pub(crate) async fn recover(agent: &Shared) -> Result<(), AgentError> {
    let (join, name) = {
        let a = agent.lock().await;
        (a.opts.join.clone(), a.opts.name.clone())
    };
    if join.is_empty() {
        return Err(Refusal::config(
            "WGFT_JOIN",
            "permanent token was revoked; provide a new join string via WGFT_JOIN and restart",
        )
        .into());
    }
    let j = Join::parse(&join).map_err(|e| Refusal::config("WGFT_JOIN", e.to_string()))?;
    if token_hash(&j) == agent.lock().await.creds.used_join_token_sha256 {
        return Err(Refusal::conflict(
            "WGFT_JOIN",
            "permanent token was revoked and the local join string is already used; issue a new join string and replace WGFT_JOIN",
        )
        .into());
    }
    let resp = register(&j, &name).await.map_err(|e| match e {
        AgentError::Other(s) => AgentError::Other(format!("re-register failed: {s}")),
        AgentError::Refused(r) => AgentError::Refused(r.context("re-register failed")),
    })?;
    let mut a = agent.lock().await;
    record(
        &mut a.creds,
        &j,
        &resp.permanent_token,
        &resp.address,
        &resp.name,
    );
    a.save()?;
    logf!(
        "re-registered as agent {}; assigned {}",
        resp.name,
        resp.address
    );
    Ok(())
}

/// ピンの不一致からの登録のし直しに使える接続文字列があるか。未使用で、ピンが記録と違うものだけ。
pub(crate) async fn join_for_new_pin(agent: &Shared) -> bool {
    let a = agent.lock().await;
    let Ok(j) = Join::parse(&a.opts.join) else {
        return false;
    };
    token_hash(&j) != a.creds.used_join_token_sha256 && j.pin_hex() != a.creds.cert_sha256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_address_forms() {
        assert_eq!(registered_tunnel_address("10.200.0.2"), "10.200.0.2");
        assert_eq!(registered_tunnel_address("10.200.0.2/24"), "10.200.0.2/24");
        assert_eq!(registered_tunnel_address("fd00::2"), "");
        assert_eq!(registered_tunnel_address("10.200.0.2/40"), "");
    }

    fn agent() -> Agent {
        Agent {
            opts: Options::default(),
            creds: Credentials::default(),
            private_key: Zeroizing::new(String::new()),
            tunnel: None,
            relay: None,
            wg: None,
            generation: 0,
            retry: None,
            retry_at: None,
            retry_failures: 0,
            rebuild_after: REBUILD_AFTER_MIN,
            seen_handshake: None,
            seen_at: None,
            refused_logged: (0, None),
            state_changed: Arc::new(Notify::new()),
        }
    }

    #[tokio::test]
    async fn heartbeat_without_tunnel() {
        let a = agent();
        let hb = a.heartbeat().await;
        assert_eq!(hb.tunnel.state, "error");
        assert_eq!(hb.tunnel.reason, REASON_NO_TUNNEL_FULL_STATE_PENDING);
        assert_eq!(hb.rules, vec![]);
    }

    #[test]
    fn tunnel_address_record_takes_the_prefix_once() {
        let mut a = agent();
        a.creds.tunnel_address = "10.200.0.2".into();
        a.record_tunnel_address("10.200.0.2/24");
        assert_eq!(a.creds.tunnel_address, "10.200.0.2/24");
        a.record_tunnel_address("10.200.0.9/24");
        assert_eq!(a.creds.tunnel_address, "10.200.0.2/24");
    }
}
