//! stream (`GET /api/v1/agents/stream` の WebSocket)。
//!
//! 接続ごとに、公開鍵と版の範囲を最初に送り、全体状態を受けて適用し、30 秒ごとと適用の直後に
//! ハートビートを送る。経路の生死は WebSocket の ping と pong の期限で測る。切れたら指数の待ちで
//! 繋ぎ直す。

use crate::logf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use futures_util::{SinkExt, StreamExt};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode as WsCloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message as WsMessage};
use wgft_proto::join::decode_hex32;
use wgft_proto::textsafe::sanitize_and_clip;
use wgft_proto::{
    CLOSE_POLICY_VIOLATION, CloseCode, Heartbeat, Message, MessageType, REASON_MAX_BYTES,
    RECONNECT_BACKOFF_MAX, STATUS_ERROR, SUPPORTED_CAPABILITIES, SUPPORTED_PROTOCOL, State,
};

use crate::enroll::{PIN_MISMATCH, connect_pinned};
use crate::error::AgentError;
use crate::run::{REASON_HANDSHAKE_PENDING, Shared, join_for_new_pin, recover};
use crate::tunnel;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// 1 通の大きさの上限。全体状態はこの 1 通に収まる。
pub(crate) const STREAM_READ_LIMIT: usize = 4 << 20;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PONG_TIMEOUT: Duration = Duration::from_secs(20);
const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const HANDSHAKE_RETRY_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_FRESH_MAX: Duration = Duration::from_secs(10);
const CONNECT_DEADLINE: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// server が鍵の変更の頻度の上限で拒むときの close の理由 (Go の `reasontext.KeyChangeLimited`)。
pub(crate) const KEY_CHANGE_LIMITED: &str = "public key changes are limited; retry later";

/// 制御の stream の観測 (Go の `streamObservation`)。`agent doctor` の `stream.*` の検査が読む値を、
/// 稼働中のプロセスの中に保つ。書き手は stream のタスクだけで、読み手は制御ソケットの応答を組むタスクで
/// ある。agent の排他とは別の排他で守り、全体状態の適用の後ろで読みが待たないようにする。排他を
/// 持つ区間は値の代入と写しだけである。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the observation the doctor reply carries as is"
)]
pub(crate) struct StreamObs {
    /// 公開鍵を送り終えてから、その接続が終わるまで真。
    pub(crate) connected: bool,
    /// 直近の接続か試みが終わった時刻と理由。
    pub(crate) disconnected_at: Option<SystemTime>,
    pub(crate) disconnect_reason: String,
    /// 直近の終わりが証明書のピンとの不一致だったか。
    pub(crate) pin_mismatch: bool,
    /// 直近の試みが server の鍵の変更の頻度の上限で拒まれたか。
    pub(crate) key_change_limited: bool,
    /// 直近に待った再接続の間隔と、待っている間の次に試す時刻。
    pub(crate) backoff: Duration,
    pub(crate) retry_at: Option<SystemTime>,
    /// 接続ごとの ping と pong の観測。接続が成立した時点で消す。
    pub(crate) last_ping_at: Option<SystemTime>,
    pub(crate) last_pong_at: Option<SystemTime>,
    pub(crate) awaiting_pong: bool,
}

/// 観測の置き場。
pub(crate) type SharedObs = Arc<Mutex<StreamObs>>;

fn note(obs: &SharedObs, f: impl FnOnce(&mut StreamObs)) {
    f(&mut obs.lock().unwrap_or_else(PoisonError::into_inner));
}

/// 再接続の待ちに入るたびの 1 行を間引く。前の行と違う行はすぐに出し、同じ行は 1 分に 1 行までにして、
/// 間引いた数を次に出す行に添える (Go の agent の `reconnectLog`)。
#[derive(Default)]
struct ReconnectLog {
    last: String,
    last_at: Option<Instant>,
    suppressed: u32,
}

impl ReconnectLog {
    fn print(&mut self, msg: String) {
        if msg == self.last
            && self
                .last_at
                .is_some_and(|t| t.elapsed() < Duration::from_mins(1))
        {
            self.suppressed += 1;
            return;
        }
        if self.suppressed > 0 {
            logf!(
                "{msg}; {} repeat(s) of the previous line not logged",
                self.suppressed
            );
        } else {
            logf!("{msg}");
        }
        self.suppressed = 0;
        self.last = msg;
        self.last_at = Some(Instant::now());
    }

    /// 次の行を前の行と比べずに出させる (Go の `reconnectLog.reset`)。
    fn reset(&mut self) {
        self.last.clear();
    }
}

/// 接続の試みを終えてから、見張りの観測の受け手を作る。接続していた間の観測は再接続の待ちを
/// 打ち切らない (仕様 stream.md の再接続)。
async fn attempt<T>(
    handshakes: &watch::Sender<u64>,
    attempt: impl Future<Output = T>,
) -> (T, watch::Receiver<u64>) {
    let end = attempt.await;
    (end, handshakes.subscribe())
}

/// 再接続の待ち。待ちの間に見張りが新しいハンドシェイクを観測したら、残りを打ち切って `true` を返す
/// (仕様 stream.md の再接続)。観測の送り手が無くなったら、残りを待ち切る。
async fn wait_or_handshake(backoff: Duration, seen: &mut watch::Receiver<u64>) -> bool {
    let deadline = tokio::time::Instant::now() + backoff;
    tokio::select! {
        () = tokio::time::sleep_until(deadline) => false,
        changed = seen.changed() => {
            if changed.is_ok() {
                return true;
            }
            tokio::time::sleep_until(deadline).await;
            false
        }
    }
}

/// 1 本の接続の終わり方。
#[derive(Debug)]
enum End {
    /// 恒久トークンが拒まれた (HTTP 401)。
    Unauthorized,
    /// 証明書がピンと一致しない。
    PinMismatch(String),
    /// server が close のフレームで閉じた。
    Closed(u16, String),
    /// server が選んだ版を受け入れられない。
    ProtocolVersion(String),
    /// `rotate-key` が新しい鍵で繋ぎ直させた。
    Reconnect,
    /// それ以外。
    Other(String),
}

impl End {
    /// 再接続の待ちに、トンネルが新しい間の上限を当てるか (Go の `capsWhileFresh`)。
    fn caps_while_fresh(&self) -> bool {
        match self {
            End::Unauthorized | End::PinMismatch(_) | End::ProtocolVersion(_) | End::Reconnect => {
                false
            }
            End::Closed(c, _) => {
                !matches!(
                    CloseCode::from_code(*c),
                    Some(CloseCode::Superseded | CloseCode::Revoked | CloseCode::ProtocolMismatch)
                ) && *c != CLOSE_POLICY_VIOLATION
            }
            End::Other(_) => true,
        }
    }
}

impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            End::Unauthorized => f.write_str(
                "stream authentication rejected: the permanent token may have been revoked",
            ),
            End::PinMismatch(s) | End::ProtocolVersion(s) | End::Other(s) => f.write_str(s),
            End::Closed(c, r) => write!(f, "closed by the server: status {c} reason {r:?}"),
            End::Reconnect => f.write_str("reconnecting to announce a new public key"),
        }
    }
}

impl End {
    /// server が鍵の変更の頻度の上限で拒んだか。server は公開鍵の拒否と同じ 1008 で閉じるので、理由の
    /// 文言で見分ける。
    fn key_change_limited(&self) -> bool {
        matches!(self, End::Closed(c, r) if *c == CLOSE_POLICY_VIOLATION && r == KEY_CHANGE_LIMITED)
    }
}

/// stream に繋ぎ続ける。復帰できない認証の拒否のときだけ誤りを返して終わる。
pub(crate) async fn stream_loop(agent: Shared) -> Result<(), AgentError> {
    let mut backoff = BACKOFF_MIN;
    let mut waits = ReconnectLog::default();
    let (handshakes, obs, reconnect) = {
        let a = agent.lock().await;
        (
            a.handshake_seen.clone(),
            Arc::clone(&a.stream_obs),
            a.reconnect.clone(),
        )
    };
    loop {
        let started = Instant::now();
        // 待ちを抜けて接続を試み始めた。この記録は再接続の流れを変えない
        note(&obs, |o| o.retry_at = None);
        let (end, mut seen) = attempt(
            &handshakes,
            Box::pin(stream_once(&agent, &obs, reconnect.subscribe())),
        )
        .await;
        let end_text = end.to_string();
        note(&obs, |o| {
            o.connected = false;
            o.awaiting_pong = false;
            o.disconnected_at = Some(SystemTime::now());
            o.disconnect_reason.clone_from(&end_text);
            o.pin_mismatch = matches!(end, End::PinMismatch(_));
            o.key_change_limited = end.key_change_limited();
        });
        if matches!(end, End::Reconnect) {
            logf!("stream: reconnecting");
            backoff = BACKOFF_MIN;
            continue;
        }
        if started.elapsed() > Duration::from_mins(1) {
            backoff = BACKOFF_MIN;
        }
        let fresh = agent.lock().await.handshake_fresh().await;
        if backoff > BACKOFF_FRESH_MAX && end.caps_while_fresh() && fresh {
            backoff = BACKOFF_FRESH_MAX;
        }
        let msg = match &end {
            End::Unauthorized => {
                recover(&agent).await?;
                backoff = BACKOFF_MIN;
                continue;
            }
            End::PinMismatch(e) => {
                if join_for_new_pin(&agent).await {
                    match recover(&agent).await {
                        Ok(()) => {
                            backoff = BACKOFF_MIN;
                            continue;
                        }
                        Err(r) => format!(
                            "stream: {e}; re-registration with the provided join string failed: {r}; retrying in {}s",
                            backoff.as_secs()
                        ),
                    }
                } else {
                    format!(
                        "stream: {e}; if the server was rebuilt with teardown --purge, issue a new join string and restart with it in WGFT_JOIN; retrying in {}s",
                        backoff.as_secs()
                    )
                }
            }
            End::Closed(c, _) if *c == CloseCode::Superseded.code() => format!(
                "stream: superseded by another connection for the same agent: double start or copied agent.json credentials; reconnecting in {}s",
                backoff.as_secs()
            ),
            End::Closed(c, _) if *c == CloseCode::Revoked.code() => {
                format!(
                    "stream: permanent token was revoked; retrying in {}s",
                    backoff.as_secs()
                )
            }
            End::Closed(c, _) if *c == CloseCode::ProtocolMismatch.code() => format!(
                "stream: {end}; the agent or server needs an upgrade to share a protocol version; retrying in {}s",
                backoff.as_secs()
            ),
            _ => format!(
                "stream: disconnected: {end}; reconnecting in {}s",
                backoff.as_secs()
            ),
        };
        waits.print(msg);
        note(&obs, |o| {
            o.backoff = backoff;
            o.retry_at = Some(SystemTime::now() + backoff);
        });
        if wait_or_handshake(backoff, &mut seen).await {
            logf!(
                "stream: a new wireguard handshake shows the server is reachable; reconnecting now"
            );
            waits.reset();
            backoff = BACKOFF_MIN;
            continue;
        }
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// 認証して接続し、公開鍵と版の範囲を送る。
async fn connect(agent: &Shared, obs: &SharedObs) -> Result<Ws, End> {
    let (endpoint, pin_hex, token, private_key) = {
        let a = agent.lock().await;
        (
            a.creds.endpoint.clone(),
            a.creds.cert_sha256.clone(),
            a.creds.permanent_token.clone(),
            a.private_key.clone(),
        )
    };
    let Some(pin) = decode_hex32(&pin_hex) else {
        return Err(End::Other(
            "credentials file: cert_sha256 is invalid".into(),
        ));
    };
    let public_key = tunnel::public_key(&private_key).map_err(End::Other)?;
    // Go の agent の pinned client の 15 秒の期限が、TLS と WebSocket の握手の全体にかかる
    let deadline = tokio::time::Instant::now() + CONNECT_DEADLINE;
    let tls = connect_pinned(&endpoint, pin, CONNECT_DEADLINE)
        .await
        .map_err(|e| {
            if e.starts_with(PIN_MISMATCH) {
                End::PinMismatch(e)
            } else {
                End::Other(e)
            }
        })?;
    let mut req = format!("wss://{endpoint}/api/v1/agents/stream")
        .into_client_request()
        .map_err(|e| End::Other(e.to_string()))?;
    // HeaderValue の中の写しは消せないので、印を付けてログと Debug に出さないことだけを守る
    let mut auth = HeaderValue::from_str(&zeroize::Zeroizing::new(format!(
        "Bearer {}",
        token.as_str()
    )))
    .map_err(|_| End::Other("credentials file: permanent_token is invalid".into()))?;
    auth.set_sensitive(true);
    req.headers_mut().insert("Authorization", auth);
    let config = WebSocketConfig::default()
        .max_message_size(Some(STREAM_READ_LIMIT))
        .max_frame_size(Some(STREAM_READ_LIMIT));
    let handshake = tokio_tungstenite::client_async_with_config(req, tls, Some(config));
    let mut ws = match tokio::time::timeout_at(deadline, handshake).await {
        Err(_) => return Err(End::Other("websocket handshake timed out".into())),
        Ok(Err(WsError::Http(resp))) if resp.status().as_u16() == 401 => {
            return Err(End::Unauthorized);
        }
        Ok(Err(WsError::Http(resp))) => {
            return Err(End::Other(format!(
                "websocket handshake: HTTP {}",
                resp.status().as_u16()
            )));
        }
        Ok(Err(e)) => return Err(End::Other(format!("websocket handshake: {e}"))),
        Ok(Ok((ws, _))) => ws,
    };

    // 版の交渉。版の範囲を毎回宣言する。capability は今は語彙が無いので常に空の配列を送り、
    // legacy v0 (宣言が無いこと) と区別する
    let hello = Message {
        kind: MessageType::PublicKey.as_str().into(),
        public_key,
        protocol_min: Some(SUPPORTED_PROTOCOL.min),
        protocol_max: Some(SUPPORTED_PROTOCOL.max),
        capabilities: Some(
            SUPPORTED_CAPABILITIES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        ),
        ..Message::default()
    };
    send(&mut ws, &hello).await.map_err(End::Other)?;
    note(obs, |o| {
        o.connected = true;
        o.retry_at = None;
        o.last_ping_at = None;
        o.last_pong_at = None;
        o.awaiting_pong = false;
    });
    logf!("stream: connected to {endpoint}; public key sent");
    Ok(ws)
}

/// 1 本の接続の寿命。`reconnect` が変われば、新しい公開鍵を送るために接続を終える。
async fn stream_once(agent: &Shared, obs: &SharedObs, mut reconnect: watch::Receiver<u64>) -> End {
    let mut ws = match connect(agent, obs).await {
        Ok(ws) => ws,
        Err(e) => return e,
    };
    let mut first = true;
    let mut heartbeat_tick = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat_tick.tick().await;
    let state_changed = Arc::clone(&agent.lock().await.state_changed);
    let mut ping_tick = tokio::time::interval(PING_INTERVAL);
    ping_tick.tick().await;
    let mut pong_deadline: Option<tokio::time::Instant> = None;
    // 適用の直後のハートビートがハンドシェイク待ちを報告したら、済むまで 1 秒ごとに 10 秒まで送り直す
    let mut follow_up_until: Option<Instant> = None;
    let mut follow_tick = tokio::time::interval(HANDSHAKE_RETRY_INTERVAL);
    loop {
        let pong_wait = async {
            match pong_deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            m = ws.next() => {
                let m = match m {
                    None => return End::Other("connection closed".into()),
                    Some(Err(e)) => return End::Other(e.to_string()),
                    Some(Ok(m)) => m,
                };
                match m {
                    WsMessage::Text(t) => {
                        let Some(st) = parse_state(t.as_str()) else { continue };
                        if first {
                            if let Err(e) = check_server_protocol_version(&st) {
                                return End::ProtocolVersion(e);
                            }
                            logf!("stream: server selected protocol {}", protocol_label(&st));
                        }
                        let mut a = agent.lock().await;
                        if !first && st.generation < a.generation {
                            logf!("stream: generation {} is older than local {}; dropping", st.generation, a.generation);
                            continue;
                        }
                        if !first && a.already_applied(&st) {
                            continue;
                        }
                        first = false;
                        let generation = st.generation;
                        if let Err(e) = a.apply(st).await {
                            logf!("stream: applying generation {generation}: {e}");
                        }
                        let hb = a.heartbeat().await;
                        drop(a);
                        // 適用の間は読みが止まり pong を読めないので、ping の判定を測り直す
                        pong_deadline = None;
                        if let Err(e) = send_heartbeat(&mut ws, hb.clone()).await {
                            return End::Other(e);
                        }
                        if needs_follow_up(&hb) {
                            follow_up_until = Some(Instant::now() + HANDSHAKE_RETRY_TIMEOUT);
                            follow_tick.reset();
                        }
                    }
                    WsMessage::Pong(_) => {
                        pong_deadline = None;
                        note(obs, |o| {
                            o.last_pong_at = Some(SystemTime::now());
                            o.awaiting_pong = false;
                        });
                    }
                    WsMessage::Close(frame) => {
                        return match frame {
                            Some(f) => End::Closed(u16::from(f.code), f.reason.to_string()),
                            None => End::Closed(u16::from(WsCloseCode::Status), String::new()),
                        };
                    }
                    _ => {}
                }
            }
            () = state_changed.notified() => {
                let hb = heartbeat_after_wait(agent, &mut pong_deadline).await;
                if let Err(e) = send_heartbeat(&mut ws, hb).await {
                    return End::Other(e);
                }
            }
            _ = heartbeat_tick.tick() => {
                let hb = heartbeat_after_wait(agent, &mut pong_deadline).await;
                if let Err(e) = send_heartbeat(&mut ws, hb).await {
                    return End::Other(e);
                }
            }
            _ = follow_tick.tick(), if follow_up_until.is_some() => {
                let hb = heartbeat_after_wait(agent, &mut pong_deadline).await;
                if let Err(e) = send_heartbeat(&mut ws, hb.clone()).await {
                    return End::Other(e);
                }
                if !needs_follow_up(&hb) || follow_up_until.is_some_and(|u| Instant::now() >= u) {
                    follow_up_until = None;
                }
            }
            _ = ping_tick.tick() => {
                if pong_deadline.is_none() {
                    match tokio::time::timeout(WRITE_TIMEOUT, ws.send(WsMessage::Ping(Vec::new().into()))).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return End::Other(e.to_string()),
                        Err(_) => return End::Other("ping write timed out".into()),
                    }
                    pong_deadline = Some(tokio::time::Instant::now() + PONG_TIMEOUT);
                    note(obs, |o| {
                        o.last_ping_at = Some(SystemTime::now());
                        o.awaiting_pong = true;
                    });
                }
            }
            Ok(()) = reconnect.changed() => {
                return End::Reconnect;
            }
            () = pong_wait => {
                logf!("stream: the server did not answer a ping within {}s; the connection is dead, closing it", PONG_TIMEOUT.as_secs());
                return End::Other("ping timed out".into());
            }
        }
    }
}

/// agent の排他を待ってハートビートを組む。待つ間は stream を読めず pong を受け取れないので、待った
/// 長さだけ pong の期限を延ばす。延ばすのは待った長さだけなので、死んだ接続はやはり見つかる。
async fn heartbeat_after_wait(
    agent: &Shared,
    pong_deadline: &mut Option<tokio::time::Instant>,
) -> Heartbeat {
    let t0 = tokio::time::Instant::now();
    let a = agent.lock().await;
    extend_deadline(pong_deadline, t0.elapsed());
    a.heartbeat().await
}

fn extend_deadline(d: &mut Option<tokio::time::Instant>, waited: Duration) {
    if let Some(at) = d.as_mut() {
        *at += waited;
    }
}

fn needs_follow_up(hb: &Heartbeat) -> bool {
    hb.tunnel.state == STATUS_ERROR && hb.tunnel.reason == REASON_HANDSHAKE_PENDING
}

/// `state` のメッセージなら全体状態を返す。読めないメッセージは、仕様の「拒んでよい形」と同じく
/// Go の agent と同じ経路で、ログに出して読み飛ばす。
fn parse_state(text: &str) -> Option<State> {
    match Message::decode(text) {
        Ok(m) if m.is(MessageType::State) => m.state,
        Ok(_) => None,
        Err(e) => {
            logf!("stream: invalid message: {e}");
            None
        }
    }
}

/// server が選んだ版が 1 以上で、agent の範囲に入ることを確かめる。無ければ legacy v0 の server。
fn check_server_protocol_version(st: &State) -> Result<(), String> {
    let Some(v) = st.server_protocol_version else {
        return Ok(());
    };
    if v < 1 {
        return Err(format!(
            "server selected protocol version {v}, which is not a valid numbered version; versions start at 1"
        ));
    }
    if !SUPPORTED_PROTOCOL.contains(v) {
        return Err(format!(
            "server selected protocol version {v}, outside the agent's supported range [{},{}]",
            SUPPORTED_PROTOCOL.min, SUPPORTED_PROTOCOL.max
        ));
    }
    Ok(())
}

fn protocol_label(st: &State) -> String {
    st.server_protocol_version
        .map_or_else(|| "legacy v0".to_owned(), |v| format!("v{v}"))
}

/// ハートビートの理由を、server の受け口と同じ整形と長さの上限にかけてから送る。
async fn send_heartbeat<S>(ws: &mut S, mut hb: Heartbeat) -> Result<(), String>
where
    S: SinkExt<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    hb.tunnel.reason = sanitize_and_clip(&hb.tunnel.reason, REASON_MAX_BYTES);
    for r in &mut hb.rules {
        r.reason = sanitize_and_clip(&r.reason, REASON_MAX_BYTES);
    }
    let m = Message {
        kind: MessageType::Heartbeat.as_str().into(),
        heartbeat: Some(hb),
        ..Message::default()
    };
    send(ws, &m).await
}

async fn send<S>(ws: &mut S, m: &Message) -> Result<(), String>
where
    S: SinkExt<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    let text = serde_json::to_string(m).map_err(|e| e.to_string())?;
    match tokio::time::timeout(WRITE_TIMEOUT, ws.send(WsMessage::Text(text.into()))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("write timed out".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 排他を待った長さだけ pong の期限を延ばし、ping を待っていなければ何もしない。
    #[test]
    fn a_lock_wait_extends_the_pong_deadline_by_the_wait() {
        let now = tokio::time::Instant::now();
        let mut d = Some(now + Duration::from_secs(10));
        extend_deadline(&mut d, Duration::from_secs(22));
        assert_eq!(d, Some(now + Duration::from_secs(32)));
        let mut none = None;
        extend_deadline(&mut none, Duration::from_secs(22));
        assert_eq!(none, None);
    }

    #[test]
    fn version_checks() {
        let st = |v| State {
            server_protocol_version: v,
            ..State::default()
        };
        assert!(check_server_protocol_version(&st(None)).is_ok());
        assert!(check_server_protocol_version(&st(Some(1))).is_ok());
        assert!(
            check_server_protocol_version(&st(Some(0)))
                .unwrap_err()
                .contains("not a valid numbered version")
        );
        assert!(
            check_server_protocol_version(&st(Some(2)))
                .unwrap_err()
                .contains("outside the agent's supported range [1,1]")
        );
        assert_eq!(protocol_label(&st(None)), "legacy v0");
    }

    #[test]
    fn caps_while_fresh_matches_go() {
        assert!(!End::Unauthorized.caps_while_fresh());
        assert!(!End::Closed(4000, String::new()).caps_while_fresh());
        assert!(!End::Closed(1008, String::new()).caps_while_fresh());
        assert!(End::Closed(4002, String::new()).caps_while_fresh());
        assert!(End::Closed(4004, String::new()).caps_while_fresh());
        assert!(End::Other("x".into()).caps_while_fresh());
    }

    #[tokio::test]
    async fn a_new_handshake_ends_the_reconnect_wait() {
        let seen = watch::Sender::new(0u64);
        // 接続していた間の観測は、試みの後に作る受け手には届かない
        let ((), mut rx) = attempt(&seen, async {
            seen.send_modify(|n| *n += 1);
        })
        .await;
        let start = Instant::now();
        assert!(!wait_or_handshake(Duration::from_millis(20), &mut rx).await);
        assert!(start.elapsed() >= Duration::from_millis(20));
        let bump = seen.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            bump.send_modify(|n| *n += 1);
        });
        let start = Instant::now();
        assert!(wait_or_handshake(Duration::from_secs(30), &mut rx).await);
        assert!(start.elapsed() < Duration::from_secs(5));
        // 送り手が無くなっても、待ちを縮めない
        drop(seen);
        let start = Instant::now();
        assert!(!wait_or_handshake(Duration::from_millis(30), &mut rx).await);
        assert!(start.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn the_reconnect_log_repeats_a_line_after_a_reset() {
        let mut log = ReconnectLog::default();
        log.print("stream: disconnected".into());
        log.print("stream: disconnected".into());
        assert_eq!(log.suppressed, 1);
        log.reset();
        log.print("stream: disconnected".into());
        assert_eq!(log.suppressed, 0);
    }

    #[test]
    fn state_messages_only() {
        assert!(parse_state(r#"{"type":"state","state":{"generation":1,"rules":[]}}"#).is_some());
        assert!(parse_state(r#"{"type":"heartbeat"}"#).is_none());
        assert!(parse_state("not json").is_none());
        // Go なら case folding で state に当てるキーは、別の値に読まないよう拒む
        assert!(parse_state(r#"{"type":"state","State":{"generation":1}}"#).is_none());
    }
}
