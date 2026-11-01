//! agent の起動と、全体状態の適用とハートビートの組み立て。

use crate::logf;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{Mutex, Notify, watch};
use wgft_proto::{GoTime, Heartbeat, Join, STATUS_ERROR, STATUS_OK, State, TunnelStatus, WgConfig};
use zeroize::Zeroizing;

use crate::config::allow_targets::AllowList;
use crate::credentials::{self, Credentials};
use crate::ctlserver;
use crate::enroll::{register, token_hash};
use crate::error::{AgentError, Refusal};
use crate::flowpool::Limits;
use crate::relay::{Manager, ProbeRound};
use crate::stream::{self, SharedObs};
use crate::targets::Targets;
use crate::tunnel::{self, Generations, Tunnel};

pub(crate) use crate::controlapi::REASON_HANDSHAKE_PENDING;
use crate::controlapi::{
    REASON_NO_TUNNEL, REASON_NO_TUNNEL_BUILD_RETRYING, REASON_NO_TUNNEL_FULL_STATE_PENDING,
};

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
    /// 宛先の許可一覧 (`WGFT_AGENT_ALLOW_TARGETS`)。`None` は制限しない。
    pub allow_targets: Option<AllowList>,
    /// フロー数の上限 (`WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS`)。
    pub limits: Limits,
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
            .field("allow_targets", &self.allow_targets)
            .field("limits", &self.limits)
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
    pub(crate) tunnel: Option<Tunnel>,
    pub(crate) relay: Option<Manager>,
    /// データプレーンの世代。核の予算とハンドシェイクの時刻の高い水位を、トンネルの作り直しの間も持つ。
    pub(crate) dataplane: Generations,
    /// 宛先の規則。トンネルの世代をまたいで分け合う。
    targets: Arc<Targets>,
    wg: Option<WgConfig>,
    pub(crate) generation: u64,
    /// トンネルの作成に失敗した全体状態と、次に立て直す時刻と、失敗の回数。
    retry: Option<State>,
    pub(crate) retry_at: Option<Instant>,
    retry_failures: usize,
    /// 最後にメモリの上界の行に書いた TCP と UDP のリスナーの数。
    bound_listeners: (usize, usize),
    /// トンネルの作り直しの閾値と、最後に見た最終ハンドシェイク (単調な時計) と、それを見た時刻。
    pub(crate) rebuild_after: Duration,
    seen_handshake: Option<Instant>,
    seen_at: Option<Instant>,
    /// stream の外の経路 (トンネルの立て直し) が状態を変えたことを、接続中の stream に伝え、
    /// ハートビートを 1 回送らせる。
    pub(crate) state_changed: Arc<Notify>,
    /// トンネルの外殻のループが終わったことを、見張りに伝える。
    tunnel_dead: Arc<Notify>,
    /// 見張りが新しいハンドシェイクを観測するたびに増やす。stream は再接続の待ちをこれで打ち切る
    /// (仕様 stream.md の再接続)。
    pub(crate) handshake_seen: watch::Sender<u64>,
    /// 制御の stream の観測。stream のタスクが書き、制御ソケットの `doctor` が読む。
    pub(crate) stream_obs: SharedObs,
    /// `rotate-key` が増やす。stream は接続を終え、新しい公開鍵で繋ぎ直す。
    pub(crate) reconnect: watch::Sender<u64>,
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
    /// トンネルが立った後は、ルールの一部が失敗しても世代を進めて保存する。全体状態は値で受け、適用が
    /// 済めば `last_state` に、トンネルを立てられなければ立て直しの控えに、写さずに移す。全体状態は 1 通で
    /// 入力の十数倍まで持ちうるので、同時に持つ写しの数を増やさないためである (メモリの上界の全体状態の項)。
    pub(crate) async fn apply(&mut self, st: State) -> Result<(), String> {
        if self.tunnel.is_none() || self.wg.as_ref() != Some(&st.wg) {
            if self.tunnel.is_some() {
                logf!("wg config changed; rebuilding tunnel");
            }
            self.close().await;
            let cfg = tunnel::Config::from_wg(&st.wg).map_err(|e| format!("wireguard: {e}"))?;
            let clock = self.opts.clock_path();
            match Tunnel::start(
                &self.private_key,
                cfg,
                &mut self.dataplane,
                wgft_wgstack::Limits::with_max_flows(self.opts.limits.tcp),
                Some(&clock),
                Arc::clone(&self.tunnel_dead),
            )
            .await
            {
                Ok(t) => {
                    self.relay = Some(Manager::new(
                        t.address(),
                        t.dataplane().clone(),
                        Arc::clone(&self.targets),
                        self.opts.limits,
                        crate::relay::udp_idle_timeout(st.wg.udp_timeout_stream),
                    ));
                    self.tunnel = Some(t);
                    self.wg = Some(st.wg.clone());
                    self.retry = None;
                    self.retry_at = None;
                    self.retry_failures = 0;
                }
                Err(e) => return Err(self.schedule_retry(st, &e)),
            }
        }
        let relay = self.relay.as_mut().ok_or("no relay")?;
        let actions = relay.apply(&st.rules).await;
        let listening = relay.listening();
        let counts = relay.listener_counts();
        let generation = st.generation;
        self.generation = generation;
        self.record_tunnel_address(&st.wg.address);
        self.creds.last_state = Some(st);
        let saved = self.save();
        logf!("applied generation {generation}: {actions} actions, {listening} listeners");
        if counts != self.bound_listeners {
            self.bound_listeners = counts;
            let (tcp, udp) = counts;
            let bound =
                crate::memory::MemoryBound::for_limits(self.opts.limits).with_listeners(tcp, udp);
            logf!("{}", bound.listeners_line(tcp, udp));
        }
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

    /// トンネルを立てられなかった全体状態を控え、立て直しの時刻を決めて、誤りの文言を返す。
    fn schedule_retry(&mut self, st: State, why: &str) -> String {
        let wait = REBUILD_BACKOFF[self.retry_failures.min(REBUILD_BACKOFF.len() - 1)];
        self.retry = Some(st);
        self.retry_at = Some(Instant::now() + wait);
        self.retry_failures += 1;
        format!("wireguard: {why}; retrying in {}s", wait.as_secs())
    }

    pub(crate) async fn close(&mut self) {
        // 中継の接続を先に RST で切り、リスナーを閉じてからトンネルを閉じる
        if let Some(mut r) = self.relay.take() {
            r.close().await;
        }
        if let Some(t) = self.tunnel.take() {
            t.close(&mut self.dataplane).await;
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
        let mono = r.handshake_observed_at.is_some_and(|o| {
            crate::dataplane::clock::now().saturating_duration_since(o) < FRESH_FOR
        });
        wall && mono
    }

    /// ハートビートの中身 (理由の整形の前)。
    pub(crate) async fn heartbeat(&self) -> Heartbeat {
        let mut hb = Heartbeat {
            generation: self.generation,
            tunnel: self.tunnel_status().await,
            ..Heartbeat::default()
        };
        if self.tunnel.is_some()
            && let Some(relay) = &self.relay
        {
            hb.rules = relay.status();
        }
        hb
    }

    /// ハートビートのトンネルの状態。`agent doctor` はルールの状態を中継のリスナーの 1 回の読みから
    /// 自分で作るので、この部分だけを使う。
    pub(crate) async fn tunnel_status(&self) -> TunnelStatus {
        let Some(t) = &self.tunnel else {
            let reason = if self.retry.is_some() {
                REASON_NO_TUNNEL_BUILD_RETRYING
            } else if self.creds.last_state.is_none() {
                REASON_NO_TUNNEL_FULL_STATE_PENDING
            } else {
                REASON_NO_TUNNEL
            };
            return TunnelStatus {
                state: STATUS_ERROR.into(),
                reason: reason.into(),
                ..TunnelStatus::default()
            };
        };
        let r = t.read().await;
        let mut ts = TunnelStatus {
            state: STATUS_OK.into(),
            reason: String::new(),
            endpoint: r.endpoint.map(|e| e.to_string()).unwrap_or_default(),
            last_handshake: r.last_handshake.map_or(GoTime::ZERO, GoTime::from_system),
        };
        if let Some(e) = r.err {
            ts.state = STATUS_ERROR.into();
            ts.reason = e;
        } else if r.last_handshake.is_none() {
            ts.state = STATUS_ERROR.into();
            ts.reason = REASON_HANDSHAKE_PENDING.into();
        }
        ts
    }

    /// 30 秒ごとの見回りのうち排他の中で行う部分。作成に失敗したトンネルを時刻が来たら立て直し、
    /// 開けなかったリスナーを開き直す。立て直せたら、接続中の stream にハートビートを送らせる。宛先の
    /// 試し接続の 1 周を返し、呼び手は排他を放してから走らせる ([`tick_round`])。
    async fn tick(&mut self) -> Option<ProbeRound> {
        self.watch_tunnel(false).await;
        if self.retry_at.is_none_or(|at| Instant::now() >= at)
            && let Some(st) = self.retry.take()
        {
            let generation = st.generation;
            match self.apply(st).await {
                Ok(()) => {
                    logf!("tunnel: rebuilt for generation {generation}");
                    self.state_changed.notify_one();
                }
                Err(e) => logf!("tunnel: rebuilding for generation {generation}: {e}"),
            }
        }
        match self.relay.as_mut() {
            Some(r) => Some(r.retry_round().await),
            None => None,
        }
    }
}

impl Agent {
    /// トンネルの見張り (仕様 tunnel.md のハンドシェイクの監視と作り直し)。新しいハンドシェイクが
    /// 無い時間が閾値を超えるか、device を動かす外殻が止まっていれば、同じ全体状態でトンネルを作り直す。
    /// 時間は、最後に見たハンドシェイクを観測した時刻とトンネルを立てた時刻の遅い方から単調な時計で
    /// 測る。閾値は 300 秒で、作り直すたびに 2 倍にし、900 秒で止める。新しいハンドシェイクを見たら
    /// 300 秒に戻す。あわせて、時刻の印の高い水位を残す。時刻はすべてデータプレーンの時計で測る。
    async fn watch_tunnel(&mut self, stopped: bool) {
        let Some(t) = &self.tunnel else { return };
        t.persist_clock().await;
        let finished = stopped || t.is_finished();
        let started = t.started_at();
        let hs = t.read().await.handshake_observed_at;
        let now = crate::dataplane::clock::now();
        if hs.is_some() && hs != self.seen_handshake {
            self.handshake_seen.send_modify(|n| *n += 1);
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
        let Some(reason) = reason else { return };
        let Some(st) = self.creds.last_state.clone() else {
            return;
        };
        logf!("tunnel: {reason}; rebuilding it");
        self.rebuild_after = (self.rebuild_after * 2).min(REBUILD_AFTER_MAX);
        self.close().await;
        match self.apply(st).await {
            Ok(()) => self.state_changed.notify_one(),
            Err(e) => logf!("tunnel: rebuilding: {e}"),
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
    let result = rt.block_on(run_async(opts));
    // 止める手順を打ち切ったとき、待ちの残り (データプレーンのスレッドの join や名前の解決のような
    // spawn_blocking の仕事) を待たずに終わる。runtime の drop はそれらの終わりを待つので、打ち切りが
    // 効かなくなる。手順が終わっていれば、残るのは結果を待つ者のいない仕事だけである
    rt.shutdown_background();
    result
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
    // 止める合図の受け口は、登録の後、保存した全体状態の適用の前に作る (Go の agent と同じ位置)。
    // 適用の間に届いた合図は失わず、主なループがすぐに止める
    let shutdown = shutdown_signal();
    let targets = Arc::new(Targets::new(opts.allow_targets.clone()));
    let agent = Arc::new(Mutex::new(Agent {
        opts,
        creds,
        private_key,
        tunnel: None,
        relay: None,
        dataplane: Generations::new(std::time::Duration::ZERO),
        targets,
        wg: None,
        generation: 0,
        retry: None,
        retry_at: None,
        retry_failures: 0,
        bound_listeners: (0, 0),
        rebuild_after: REBUILD_AFTER_MIN,
        seen_handshake: None,
        seen_at: None,
        state_changed: Arc::new(Notify::new()),
        tunnel_dead: Arc::new(Notify::new()),
        handshake_seen: watch::Sender::new(0),
        stream_obs: SharedObs::default(),
        reconnect: watch::Sender::new(0),
    }));
    {
        let mut a = agent.lock().await;
        // server が止まっていても、server の側にピアが残っていれば転送が戻るよう、先に立てる
        if let Some(st) = a.creds.last_state.clone() {
            let generation = st.generation;
            if let Err(e) = a.apply(st).await {
                logf!(
                    "apply saved generation {generation}: {e}; waiting for full state from stream"
                );
            }
        } else {
            logf!("no saved full state; waiting for full state from stream");
        }
    }
    let tunnel_dead = Arc::clone(&agent.lock().await.tunnel_dead);
    // 制御ソケットは認証情報のロックを持つ間だけ開く。止めるのはロックを手放す前である
    let (doctor_tx, doctor_rx) = tokio::sync::mpsc::channel(4);
    let (rotate_tx, rotate_rx) = tokio::sync::mpsc::channel(1);
    let control = ctlserver::Server::start(
        &path,
        ctlserver::Senders {
            doctor: doctor_tx,
            rotate_key: rotate_tx,
        },
    );
    let ctx = {
        let a = agent.lock().await;
        crate::control::Context {
            agent: Arc::clone(&agent),
            obs: Arc::clone(&a.stream_obs),
            allow_targets: a.opts.allow_targets.as_ref().map(ToString::to_string),
        }
    };
    crate::control::spawn_doctor(ctx.clone(), doctor_rx);
    let stream_task = tokio::spawn(stream::stream_loop(Arc::clone(&agent)));
    main_loop(
        Loop {
            agent,
            stream_task,
            tunnel_dead,
            rotate_rx,
            ctx,
            control,
            tick_every: TICK,
        },
        shutdown,
    )
    .await
}

/// 30 秒ごとの見回りの間隔。
const TICK: Duration = Duration::from_secs(30);

/// 止める合図から終わるまでの上限。超えたら、残りを待たずに終わる。Go の agent の止める手順に上限は
/// 無いが、止まった段が監督の SIGKILL まで終わりを延ばさないように置く。値は止める側の待ちのうち最も
/// 短いラボの `kill_all` の 5 秒より短くする。同梱の systemd の unit は TimeoutStopSec を置かないので
/// systemd の既定の 90 秒、Docker は 10 秒、launchd の plist は ExitTimeOut を置かないので system の既定を待つ。
/// 打ち切れるのは await の点だけで、同期の段 (制御ソケットのスレッドを起こして待つこと) は打ち切らない。
pub(crate) const SHUTDOWN_LIMIT: Duration = Duration::from_secs(3);

/// 止める途中の 1 つの段がこれより長ければ、ログに出す。
const SLOW_STEP: Duration = Duration::from_secs(1);

/// 主なループが持つもの。
pub(crate) struct Loop {
    pub(crate) agent: Shared,
    pub(crate) stream_task: tokio::task::JoinHandle<Result<(), AgentError>>,
    pub(crate) tunnel_dead: Arc<Notify>,
    pub(crate) rotate_rx: tokio::sync::mpsc::Receiver<crate::ctlserver::RotateKeyRequest>,
    pub(crate) ctx: crate::control::Context,
    pub(crate) control: Option<ctlserver::Server>,
    pub(crate) tick_every: Duration,
}

/// 主なループ。止める合図 `shutdown` はいつでも効く。長い仕事 (30 秒ごとの見回りの試し接続の 1 周、
/// トンネルの作り直し) は合図と並べて待ち、合図が来たら落とす。`rotate-key` は鍵を保存した後に落とす場合
/// でも応答を返す ([`crate::control::serve_rotate_key`])。止めるときは stream の task を落とし、終わるのを
/// 待ってから agent の排他を待つので、適用の途中 (試し接続の待ちを含む) で排他を持つ task がいても、
/// 排他はその前に空く。stream の task が自分で終わっていれば、その誤り (認証の拒否など) を返す。止める
/// 手順の全体は [`SHUTDOWN_LIMIT`] で打ち切り、打ち切ると中継の残りの RST とデータプレーンの停止は
/// 行わずに終わる。
pub(crate) async fn main_loop(
    l: Loop,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), AgentError> {
    let Loop {
        agent,
        mut stream_task,
        tunnel_dead,
        mut rotate_rx,
        ctx,
        control,
        tick_every,
    } = l;
    let mut shutdown = std::pin::pin!(shutdown);
    let mut tick = tokio::time::interval(tick_every);
    tick.tick().await;
    let mut last_status = String::new();
    // 終わった JoinHandle をもう一度待つと panic するので、stream の task が終わったかを覚える
    let mut stream_done = false;
    let result = 'main: loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            r = &mut stream_task => {
                stream_done = true;
                break match r {
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(())) => Ok(()),
                    Err(e) => Err(AgentError::Other(format!("stream task: {e}"))),
                };
            }
            () = tunnel_dead.notified() => {
                let work = async { agent.lock().await.watch_tunnel(true).await };
                tokio::select! {
                    () = &mut shutdown => break 'main Ok(()),
                    () = work => {}
                }
            }
            Some(req) = rotate_rx.recv() => {
                if crate::control::serve_rotate_key(&ctx.agent, req, &mut shutdown).await {
                    break 'main Ok(());
                }
            }
            _ = tick.tick() => {
                tokio::select! {
                    () = &mut shutdown => break 'main Ok(()),
                    () = tick_and_report(&agent, &mut last_status) => {}
                }
            }
        }
    };
    logf!("shutting down");
    let done = tokio::time::timeout(SHUTDOWN_LIMIT, async {
        // stream の task を落とし、終わるのを待つ。適用の途中なら、その排他もここで返る
        if !stream_done {
            stream_task.abort();
            let _ = (&mut stream_task).await;
        }
        // 待っている要求の応答の送り手を落としてから、制御ソケットのスレッドを止める。待ち受けのスレッドは
        // 起こせばすぐに終わるので、巻き戻しで drop する経路も止まらない
        drop(rotate_rx);
        if let Some(c) = control {
            timed("stop the control socket", async { c.stop() }).await;
        }
        let mut a = timed("take the agent lock", agent.lock()).await;
        timed("close the relays and the tunnel", a.close()).await;
    })
    .await;
    if done.is_err() {
        logf!(
            "shutting down took longer than {}s; exiting without waiting for the rest",
            SHUTDOWN_LIMIT.as_secs()
        );
    }
    result
}

/// 止める手順の 1 段を走らせ、[`SLOW_STEP`] より長ければログに出す。
async fn timed<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    let start = Instant::now();
    let r = f.await;
    let took = start.elapsed();
    if took > SLOW_STEP {
        logf!("shutting down: {what} took {}ms", took.as_millis());
    }
    r
}

/// 30 秒ごとの見回りと、状態が変わったときの状態の行。
async fn tick_and_report(agent: &Shared, last_status: &mut String) {
    tick_round(agent).await;
    let a = agent.lock().await;
    let hb = a.heartbeat().await;
    let mut s = format!(
        "generation {} tunnel={} {} endpoint={}",
        hb.generation, hb.tunnel.state, hb.tunnel.reason, hb.tunnel.endpoint
    );
    for r in &hb.rules {
        let _ = write!(s, "\nrule {} {} {}", r.id, r.state, r.reason);
    }
    if s != *last_status {
        for l in s.lines() {
            logf!("{l}");
        }
        *last_status = s;
    }
}

/// 30 秒ごとの見回り。排他の中で見回りの前半を行い、宛先の試し接続は排他を放して走らせ、結果を
/// 書くときだけ排他を取り直す。試し接続の 1 周は応えない宛先が多いと長くなり、その間に stream の
/// ハートビートと適用を止めないためである。走らせている間にトンネルを作り直していれば、結果は捨てる。
async fn tick_round(agent: &Shared) {
    let round = agent.lock().await.tick().await;
    let Some(round) = round.filter(|r| !r.is_empty()) else {
        return;
    };
    let done = round.run().await;
    if let Some(r) = &agent.lock().await.relay {
        r.finish_probes(done);
    }
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

/// 止める合図を待つ future を返す。受け口は呼んだときに作るので、作った後に届いた合図は、待ち始める
/// 前に届いても失わない。Unix は SIGTERM と SIGINT、Windows は Go の `os/signal` が SIGINT と SIGTERM に
/// 当てる知らせ (Ctrl+C、Ctrl+Break、コンソールを閉じる、ログオフ、シャットダウン) である。作れない受け口
/// はログに出し、残りを待つ。
fn shutdown_signal() -> impl std::future::Future<Output = ()> + Send + use<> {
    // 受け口を作り、作れなければログに出して、その合図は来ないものとして待つ
    macro_rules! listen {
        ($what:literal, $make:expr) => {{
            let made = $make;
            if let Err(e) = &made {
                logf!(
                    "cannot listen for {}: {e}; the agent stops only on the other signals",
                    $what
                );
            }
            async move {
                match made {
                    Ok(mut s) => {
                        let _ = s.recv().await;
                    }
                    Err(_) => std::future::pending::<()>().await,
                }
            }
        }};
    }
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let term = listen!("SIGTERM", signal(SignalKind::terminate()));
        let int = listen!("SIGINT", signal(SignalKind::interrupt()));
        async move {
            tokio::select! {
                () = term => {}
                () = int => {}
            }
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let c = listen!("Ctrl+C", windows::ctrl_c());
        let brk = listen!("Ctrl+Break", windows::ctrl_break());
        let close = listen!("the console close event", windows::ctrl_close());
        let logoff = listen!("the logoff event", windows::ctrl_logoff());
        let shut = listen!("the shutdown event", windows::ctrl_shutdown());
        async move {
            tokio::select! {
                () = c => {}
                () = brk => {}
                () = close => {}
                () = logoff => {}
                () = shut => {}
            }
        }
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

/// 試験のための、トンネルの無い agent。
#[cfg(test)]
pub(crate) fn test_agent() -> Agent {
    tests::agent()
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

    pub(super) fn agent() -> Agent {
        Agent {
            opts: Options::default(),
            creds: Credentials::default(),
            private_key: Zeroizing::new(String::new()),
            tunnel: None,
            relay: None,
            targets: Arc::new(Targets::new(None)),
            wg: None,
            generation: 0,
            retry: None,
            retry_at: None,
            retry_failures: 0,
            bound_listeners: (0, 0),
            rebuild_after: REBUILD_AFTER_MIN,
            seen_handshake: None,
            seen_at: None,
            dataplane: Generations::new(Duration::ZERO),
            state_changed: Arc::new(Notify::new()),
            tunnel_dead: Arc::new(Notify::new()),
            handshake_seen: watch::Sender::new(0),
            stream_obs: SharedObs::default(),
            reconnect: watch::Sender::new(0),
        }
    }

    /// agent が全体状態を適用すると、TUN も root も使わずにトンネルと中継が立ち、server の側からの
    /// 接続が LAN の宛先へ届く。wg の変更で作り直しても核の予算は次の世代に渡り、閉じると予算が残る。
    #[tokio::test]
    async fn the_agent_relays_over_the_wgstack_and_rebuilds_with_the_budget() {
        use crate::relay::testpeer::{AGENT_IP, Peer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use wgft_proto::{AgentRule, Proto};
        let (peer, agent_key) = Peer::server().await;
        let lan = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = lan.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = lan.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let mut a = agent();
        a.opts.data_dir = dir.path().to_path_buf();
        a.private_key = agent_key.to_base64();
        let mut st = State {
            generation: 1,
            wg: WgConfig {
                server_pubkey: peer.server_public_key().to_base64(),
                endpoint: peer.endpoint().to_string(),
                address: format!("{AGENT_IP}/24"),
                mtu: 1420,
                keepalive: 25,
                udp_timeout: 30,
                udp_timeout_stream: 120,
            },
            rules: vec![AgentRule {
                id: "r_a".into(),
                proto: Proto::Tcp,
                listen_port: "80".parse().unwrap(),
                target: target.to_string(),
                enabled: true,
            }],
            ..State::default()
        };
        a.apply(st.clone()).await.unwrap();
        let mut c = peer.connect(80).await.unwrap();
        c.send(b"through the tunnel");
        assert_eq!(c.read_exact(18).await.unwrap(), b"through the tunnel");
        let hb = a.heartbeat().await;
        assert_eq!(hb.tunnel.state, STATUS_OK, "{:?}", hb.tunnel);
        assert_eq!(hb.rules[0].state, STATUS_OK);
        let r = a.tunnel.as_ref().unwrap().read().await;
        assert!(r.rx_bytes > 0 && r.tx_bytes > 0, "{r:?}");
        assert!(r.socket_buffers.is_some());
        // agent doctor の値:ソケットのバッファと UDP の会計を載せる
        let doc = crate::control::runtime_state(&a).await;
        let bufs = doc.tunnel.socket_buffers.as_ref().unwrap();
        assert_eq!(bufs.supported, cfg!(target_os = "linux"), "{bufs:?}");
        let acct = doc.tunnel.udp_accounting.as_ref().unwrap();
        assert!(!acct.stopped && acct.error.is_empty(), "{acct:?}");
        assert_ne!(doc.tunnel.started_at, GoTime::ZERO);
        // wg の変更はトンネルを作り直す。古い接続は RST で切られ、新しいトンネルでまた繋がる
        st.generation = 2;
        st.wg.keepalive = 20;
        a.apply(st.clone()).await.unwrap();
        assert_eq!(
            c.outcome(Duration::from_secs(5)).await,
            crate::relay::testpeer::Outcome::Reset
        );
        let mut c = peer.connect(80).await.unwrap();
        c.send(b"again");
        assert_eq!(c.read_exact(5).await.unwrap(), b"again");
        a.close().await;
        assert!(
            a.dataplane.has_budget(),
            "the core's budget waits for the next tunnel"
        );
        assert!(dir.path().join("agent.json.clock").exists());
    }

    #[tokio::test]
    async fn heartbeat_without_tunnel() {
        let a = agent();
        let hb = a.heartbeat().await;
        assert_eq!(hb.tunnel.state, "error");
        assert_eq!(hb.tunnel.reason, REASON_NO_TUNNEL_FULL_STATE_PENDING);
        assert_eq!(hb.rules, vec![]);
    }

    /// 見回りの試し接続は agent の排他を放して走り、その間に変わったリスナーには古い結果を書かない。
    #[tokio::test]
    async fn the_probe_round_runs_without_the_agent_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use wgft_proto::{AgentRule, Proto};

        use crate::flowpool::Limits;
        use crate::targets::resolve::Resolver;
        use crate::targets::unicast::Unicast;

        let slow = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let (s, r) = (Arc::clone(&slow), Arc::clone(&release));
        let resolver = Resolver::with_lookup(
            8,
            2,
            Arc::new(move |_h: &str, _| {
                while s.load(Ordering::SeqCst) && !r.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(vec!["127.0.0.1".parse().unwrap()])
            }),
        );
        let targets = Arc::new(Targets::with(
            None,
            Unicast::new(Box::new(|| Ok(Vec::new()))),
            Arc::new(resolver),
        ));
        let free = || {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        let (port, dead) = (free(), free());
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rule = |target: String| AgentRule {
            id: "r_a".into(),
            proto: Proto::Tcp,
            listen_port: port.to_string().parse().unwrap(),
            target,
            enabled: true,
        };
        let peer = crate::relay::testpeer::Peer::start().await;
        let mut m = Manager::new(
            crate::relay::testpeer::AGENT_IP,
            peer.agent().handle(),
            Arc::clone(&targets),
            Limits::default(),
            crate::relay::DEFAULT_UDP_IDLE,
        );
        m.apply(&[rule(format!("nas.lan:{dead}"))]).await;
        let mut a = agent();
        a.targets = targets;
        a.relay = Some(m);
        let shared: Shared = Arc::new(Mutex::new(a));
        slow.store(true, Ordering::SeqCst);
        let round = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move { tick_round(&shared).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        // 試し接続が名前の解決で止まっている間も、排他は取れる。宛先を変えると待ち受けは開き直される
        {
            let mut a = tokio::time::timeout(Duration::from_millis(200), shared.lock())
                .await
                .expect("the agent lock is free during the probe round");
            let target = up.local_addr().unwrap().to_string();
            a.relay.as_mut().unwrap().apply(&[rule(target)]).await;
            assert_eq!(a.relay.as_ref().unwrap().status()[0].state, "ok");
        }
        release.store(true, Ordering::SeqCst);
        round.await.unwrap();
        // 開き直す前のリスナーの結果 (閉じたポートへの拒否) は書かれない
        let st = shared.lock().await.relay.as_ref().unwrap().status();
        assert_eq!(st[0].state, "ok", "{st:?}");
    }

    /// 名前の解決を止められる宛先の規則。[`Gate::hold`] の後の解決は、`Gate` を落とすまで止まり、止まる
    /// たびに知らせる。
    struct Gate {
        slow: Arc<std::sync::atomic::AtomicBool>,
        release: Arc<std::sync::atomic::AtomicBool>,
        entered: Arc<Notify>,
    }

    impl Gate {
        fn hold(&self) {
            self.slow.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        /// 試し接続が名前の解決で止まるのを待つ。
        async fn entered(&self) {
            tokio::time::timeout(Duration::from_secs(5), self.entered.notified())
                .await
                .expect("a probe waits in name resolution");
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            self.release
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn gated_targets() -> (Arc<Targets>, Gate) {
        use std::sync::atomic::{AtomicBool, Ordering};

        use crate::targets::resolve::Resolver;
        use crate::targets::unicast::Unicast;
        let gate = Gate {
            slow: Arc::new(AtomicBool::new(false)),
            release: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(Notify::new()),
        };
        let (s, r, e) = (
            Arc::clone(&gate.slow),
            Arc::clone(&gate.release),
            Arc::clone(&gate.entered),
        );
        let resolver = Resolver::with_lookup(
            8,
            2,
            Arc::new(move |_h: &str, _| {
                if s.load(Ordering::SeqCst) {
                    e.notify_one();
                }
                while s.load(Ordering::SeqCst) && !r.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(vec!["127.0.0.1".parse().unwrap()])
            }),
        );
        let targets = Arc::new(Targets::with(
            None,
            Unicast::new(Box::new(|| Ok(Vec::new()))),
            Arc::new(resolver),
        ));
        (targets, gate)
    }

    /// 閉じたポート。名前の解決が通れば、試し接続はすぐに拒まれる。
    fn closed_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// 止める合図の試験の材料。範囲のルールの 300 の待ち受けが、名前の解決を止めた宛先を指す。試し接続は
    /// 名前の解決で止まり、1 周は 32 件ずつ 2 秒で 20 秒かかる。
    async fn slow_agent() -> (
        Shared,
        Gate,
        crate::relay::testpeer::Peer,
        Vec<wgft_proto::AgentRule>,
    ) {
        use wgft_proto::{AgentRule, Proto};
        let (targets, gate) = gated_targets();
        // 範囲のルールは宛先のポートを待ち受けの順にずらし、65535 を越える宛先のルールは待ち受けを開かない。
        // OS が割り当てるポートは 65535 に近いことがある (Windows は 49152 から) ので、最後の待ち受けが
        // 閉じたポートを指すように始めを下げる
        let first = closed_port().saturating_sub(299).max(1);
        let rules = vec![AgentRule {
            id: "r_a".into(),
            proto: Proto::Tcp,
            listen_port: "20000-20299".parse().unwrap(),
            target: format!("nas.lan:{first}"),
            enabled: true,
        }];
        let peer = crate::relay::testpeer::Peer::start().await;
        let mut m = Manager::new(
            crate::relay::testpeer::AGENT_IP,
            peer.agent().handle(),
            Arc::clone(&targets),
            Limits::default(),
            crate::relay::DEFAULT_UDP_IDLE,
        );
        m.apply(&rules).await;
        assert_eq!(m.listening(), 300);
        let mut a = agent();
        a.targets = targets;
        a.relay = Some(m);
        gate.hold();
        (Arc::new(Mutex::new(a)), gate, peer, rules)
    }

    /// トンネルが立ち、全体状態を保存した agent。ルールの宛先は名前の解決を止められるので、
    /// [`Gate::hold`] の後の適用 (トンネルの作り直しと `rotate-key`) は試し接続で止まる。
    async fn tunnel_agent() -> (
        Shared,
        Gate,
        crate::relay::testpeer::Peer,
        tempfile::TempDir,
    ) {
        use crate::relay::testpeer::{AGENT_IP, Peer};
        use wgft_proto::{AgentRule, Proto};
        let (peer, agent_key) = Peer::server().await;
        let (targets, gate) = gated_targets();
        let dir = tempfile::tempdir().unwrap();
        let mut a = agent();
        a.opts.data_dir = dir.path().to_path_buf();
        a.private_key = agent_key.to_base64();
        a.targets = targets;
        let st = State {
            generation: 1,
            wg: WgConfig {
                server_pubkey: peer.server_public_key().to_base64(),
                endpoint: peer.endpoint().to_string(),
                address: format!("{AGENT_IP}/24"),
                mtu: 1420,
                keepalive: 25,
                udp_timeout: 30,
                udp_timeout_stream: 120,
            },
            rules: vec![AgentRule {
                id: "r_a".into(),
                proto: Proto::Tcp,
                listen_port: "80".parse().unwrap(),
                target: format!("nas.lan:{}", closed_port()),
                enabled: true,
            }],
            ..State::default()
        };
        a.apply(st.clone()).await.unwrap();
        assert!(a.tunnel.is_some());
        (Arc::new(Mutex::new(a)), gate, peer, dir)
    }

    fn test_loop(
        agent: &Shared,
        stream_task: tokio::task::JoinHandle<Result<(), AgentError>>,
        tick_every: Duration,
    ) -> Loop {
        let (_rotate_tx, rotate_rx) = tokio::sync::mpsc::channel(1);
        Loop {
            agent: Arc::clone(agent),
            stream_task,
            tunnel_dead: Arc::new(Notify::new()),
            rotate_rx,
            ctx: crate::control::Context {
                agent: Arc::clone(agent),
                obs: SharedObs::default(),
                allow_targets: None,
            },
            control: None,
            tick_every,
        }
    }

    /// 動かない stream の task。
    fn idle_stream() -> tokio::task::JoinHandle<Result<(), AgentError>> {
        tokio::spawn(std::future::pending())
    }

    /// 合図を送ると終わる、止める合図の代わり。
    fn stop_switch() -> (
        tokio::sync::oneshot::Sender<()>,
        impl std::future::Future<Output = ()> + Send,
    ) {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        (stop, async {
            let _ = stopped.await;
        })
    }

    /// 止める合図の後、主なループが 2 秒以内に終わることを確かめる。
    async fn ends_within_2s(
        run: tokio::task::JoinHandle<Result<(), AgentError>>,
        during: &str,
    ) -> Result<(), AgentError> {
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .unwrap_or_else(|_| panic!("the agent stops within 2 s during {during}"))
            .unwrap()
    }

    /// stream の task が自分で終われば (恒久トークンの失効の後に登録し直せないときの起動の拒否など)、
    /// 主なループはその誤りを返し、中継とトンネルを閉じる。終わった task をもう一度待って panic しない。
    #[tokio::test]
    async fn a_stream_task_that_ends_with_an_error_ends_the_loop_with_it() {
        let refusal = Refusal::config(
            "WGFT_JOIN",
            "permanent token was revoked; provide a new join string via WGFT_JOIN and restart",
        );
        for (err, code) in [
            (AgentError::Refused(refusal), 3),
            (AgentError::Other("rejected".into()), 1),
        ] {
            let want = err.to_string();
            let peer = crate::relay::testpeer::Peer::start().await;
            let mut a = agent();
            a.relay = Some(Manager::new(
                crate::relay::testpeer::AGENT_IP,
                peer.agent().handle(),
                Arc::new(Targets::new(None)),
                Limits::default(),
                crate::relay::DEFAULT_UDP_IDLE,
            ));
            let agent: Shared = Arc::new(Mutex::new(a));
            let stream = tokio::spawn(async move { Err(err) });
            // 止める合図は来ない
            let got = tokio::time::timeout(
                Duration::from_secs(2),
                main_loop(
                    test_loop(&agent, stream, Duration::from_secs(30)),
                    std::future::pending(),
                ),
            )
            .await
            .expect("the loop ends when the stream task ends")
            .expect_err("the loop returns the stream task's error");
            assert_eq!(got.to_string(), want);
            assert_eq!(got.exit_code(), code);
            assert!(agent.lock().await.relay.is_none(), "the close ran");
        }
    }

    /// 止める合図は、30 秒ごとの見回りの長い試し接続の 1 周の途中でも効き、2 秒以内に終わる。
    #[tokio::test]
    async fn shutdown_cuts_a_long_probe_round() {
        let (agent, gate, _peer, _) = slow_agent().await;
        let (stop, stopped) = stop_switch();
        let run = tokio::spawn(main_loop(
            test_loop(&agent, idle_stream(), Duration::from_millis(50)),
            stopped,
        ));
        gate.entered().await;
        assert!(!run.is_finished());
        stop.send(()).unwrap();
        ends_within_2s(run, "a probe round").await.unwrap();
        assert!(agent.lock().await.relay.is_none());
    }

    /// 本物の SIGTERM も、見回りの試し接続の 1 周の途中で効く。合図の受け口はループの間じゅう 1 つなので、
    /// 枝の仕事の間に届いた合図を失わない。
    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_cuts_a_long_probe_round() {
        let _one = SIGTERM_TESTS.lock().await;
        let (agent, gate, _peer, _) = slow_agent().await;
        // 受け口はここで作られるので、この後の SIGTERM はプロセスを終わらせない
        let signal = shutdown_signal();
        let run = tokio::spawn(main_loop(
            test_loop(&agent, idle_stream(), Duration::from_millis(50)),
            signal,
        ));
        gate.entered().await;
        assert!(!run.is_finished());
        // SAFETY: 自分のプロセスに SIGTERM を送るだけで、メモリには触れない
        let rc = unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        assert_eq!(rc, 0);
        ends_within_2s(run, "a probe round").await.unwrap();
        assert!(agent.lock().await.relay.is_none());
    }

    /// 合図の受け口は作ったときにでき、待ち始める前に届いた SIGTERM も失わない。保存した全体状態の適用の
    /// 間に届いた合図は、主なループが始まるとすぐに効く。
    /// SIGTERM はプロセスのすべての受け口に届くので、`cargo test` が同じプロセスで並べても、SIGTERM を
    /// 送る試験は 1 つずつ走らせる。
    #[cfg(unix)]
    static SIGTERM_TESTS: Mutex<()> = Mutex::const_new(());

    #[cfg(unix)]
    #[tokio::test]
    async fn a_sigterm_before_the_wait_starts_is_kept() {
        let _one = SIGTERM_TESTS.lock().await;
        let signal = shutdown_signal();
        // SAFETY: 自分のプロセスに SIGTERM を送るだけで、メモリには触れない
        let rc = unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        assert_eq!(rc, 0);
        tokio::time::timeout(Duration::from_secs(2), signal)
            .await
            .expect("the SIGTERM sent before the wait is seen");
    }

    /// 止める合図は、stream の task が排他を持って適用の試し接続を待つ間も効き、2 秒以内に終わる。
    #[tokio::test]
    async fn shutdown_cuts_an_apply_that_holds_the_lock() {
        let (agent, gate, _peer, rules) = slow_agent().await;
        // 宛先を変えて開き直させ、適用が新しい待ち受けの試し接続を待つ間、排他を持ち続ける
        let mut moved = rules.clone();
        moved[0].target = "nas.lan:9".into();
        let applying = tokio::spawn({
            let agent = Arc::clone(&agent);
            async move {
                let mut a = agent.lock().await;
                a.relay.as_mut().unwrap().apply(&moved).await;
                Ok(())
            }
        });
        let (stop, stopped) = stop_switch();
        let run = tokio::spawn(main_loop(
            test_loop(&agent, applying, Duration::from_secs(30)),
            stopped,
        ));
        gate.entered().await;
        assert!(
            agent.try_lock().is_err(),
            "the apply holds the agent lock while it probes"
        );
        stop.send(()).unwrap();
        ends_within_2s(run, "an apply").await.unwrap();
        assert!(agent.lock().await.relay.is_none());
    }

    /// 止める合図は、トンネルの外殻の停止による作り直しの途中 (適用の試し接続の待ち) でも効く。
    #[tokio::test]
    async fn shutdown_cuts_a_rebuild_after_the_tunnel_stops() {
        let (agent, gate, _peer, _dir) = tunnel_agent().await;
        let mut l = test_loop(&agent, idle_stream(), Duration::from_secs(30));
        l.tunnel_dead = Arc::clone(&agent.lock().await.tunnel_dead);
        let (stop, stopped) = stop_switch();
        gate.hold();
        l.tunnel_dead.notify_one();
        let run = tokio::spawn(main_loop(l, stopped));
        gate.entered().await;
        assert!(
            agent.try_lock().is_err(),
            "the rebuild holds the agent lock"
        );
        stop.send(()).unwrap();
        ends_within_2s(run, "a tunnel rebuild").await.unwrap();
        let a = agent.lock().await;
        assert!(a.relay.is_none() && a.tunnel.is_none());
    }

    /// 主なループに送る `rotate-key` の要求と、その応答の受け手。
    struct RotateCall {
        tx: tokio::sync::mpsc::Sender<ctlserver::RotateKeyRequest>,
        req: ctlserver::RotateKeyRequest,
        replies: std::sync::mpsc::Receiver<Result<String, String>>,
        state: Arc<ctlserver::RotateState>,
    }

    /// 主なループの `rotate-key` の受け口を差し替え、送る要求を作る。
    fn rotate_request(l: &mut Loop) -> RotateCall {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        l.rotate_rx = rx;
        let (reply, replies) = std::sync::mpsc::sync_channel(1);
        let state = Arc::new(ctlserver::RotateState::default());
        let req = ctlserver::RotateKeyRequest {
            reply,
            state: Arc::clone(&state),
        };
        RotateCall {
            tx,
            req,
            replies,
            state,
        }
    }

    /// `rotate-key` が排他を待つ間に止める合図が来れば、鍵を変えずに止まり、応答を返さない。受け口は応答の
    /// 前に止まったと返し、それは正しい。
    #[tokio::test]
    async fn shutdown_while_rotate_key_waits_for_the_lock_keeps_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = agent();
        a.opts.data_dir = dir.path().to_path_buf();
        let agent: Shared = Arc::new(Mutex::new(a));
        let mut l = test_loop(&agent, idle_stream(), Duration::from_secs(30));
        let RotateCall {
            tx,
            req,
            replies,
            state,
        } = rotate_request(&mut l);
        let (stop, stopped) = stop_switch();
        let held = agent.lock().await;
        let run = tokio::spawn(main_loop(l, stopped));
        tx.send(req).await.unwrap();
        // ループが要求を受け取れば枠が空く。受け取った後は排他を待っている
        while tx.capacity() == 0 {
            tokio::task::yield_now().await;
        }
        stop.send(()).unwrap();
        drop(held);
        ends_within_2s(run, "a rotate-key that waits for the lock")
            .await
            .unwrap();
        assert_eq!(
            replies.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        );
        assert!(state.start(), "the rotation never started");
        assert!(!dir.path().join("agent.json").exists());
        assert_eq!(agent.lock().await.creds.wg_private_key, "");
    }

    /// 鍵を保存した後のトンネルの作り直しの途中で止める合図が来れば、作り直しを落として止まり、新しい公開鍵を
    /// 応答する。鍵は保存済みで、次の起動が使う。
    #[tokio::test]
    async fn shutdown_during_the_rebuild_after_rotate_key_still_answers() {
        let (agent, gate, _peer, dir) = tunnel_agent().await;
        let mut l = test_loop(&agent, idle_stream(), Duration::from_secs(30));
        let RotateCall {
            tx, req, replies, ..
        } = rotate_request(&mut l);
        let (stop, stopped) = stop_switch();
        gate.hold();
        let run = tokio::spawn(main_loop(l, stopped));
        tx.send(req).await.unwrap();
        gate.entered().await;
        assert!(
            replies.try_recv().is_err(),
            "no answer before the rebuild ends"
        );
        stop.send(()).unwrap();
        ends_within_2s(run, "the rebuild after rotate-key")
            .await
            .unwrap();
        let public = replies
            .try_recv()
            .expect("an answer for the saved key")
            .unwrap();
        let saved = crate::credentials::Credentials::load(&dir.path().join("agent.json")).unwrap();
        assert_eq!(tunnel::public_key(&saved.wg_private_key).unwrap(), public);
    }

    /// 止める手順が終わらなければ (誰かが排他を持ち続ける)、[`SHUTDOWN_LIMIT`] で打ち切って終わる。
    #[tokio::test(start_paused = true)]
    async fn shutdown_gives_up_after_the_limit() {
        let agent: Shared = Arc::new(Mutex::new(agent()));
        let held = Arc::clone(&agent).lock_owned().await;
        let start = tokio::time::Instant::now();
        tokio::time::timeout(
            SHUTDOWN_LIMIT * 2,
            main_loop(
                test_loop(&agent, idle_stream(), Duration::from_secs(30)),
                async {},
            ),
        )
        .await
        .expect("the shutdown gives up at its limit")
        .unwrap();
        let took = start.elapsed();
        assert!(
            took >= SHUTDOWN_LIMIT && took < SHUTDOWN_LIMIT + Duration::from_millis(100),
            "{took:?}"
        );
        drop(held);
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
