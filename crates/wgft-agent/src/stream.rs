//! stream (`GET /api/v1/agents/stream` の WebSocket)。
//!
//! 接続ごとに、公開鍵と版の範囲を最初に送り、全体状態を受けて適用し、30 秒ごとと適用の直後に
//! ハートビートを送る。経路の生死は WebSocket の ping と pong の期限で測る。切れたら指数の待ちで
//! 繋ぎ直す。

use crate::logf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
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
    /// それ以外。
    Other(String),
}

impl End {
    /// 再接続の待ちに、トンネルが新しい間の上限を当てるか (Go の `capsWhileFresh`)。
    fn caps_while_fresh(&self) -> bool {
        match self {
            End::Unauthorized | End::PinMismatch(_) | End::ProtocolVersion(_) => false,
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
        }
    }
}

/// stream に繋ぎ続ける。復帰できない認証の拒否のときだけ誤りを返して終わる。
pub(crate) async fn stream_loop(agent: Shared) -> Result<(), AgentError> {
    let mut backoff = BACKOFF_MIN;
    let mut waits = ReconnectLog::default();
    loop {
        let started = Instant::now();
        let end = stream_once(&agent).await;
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
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// 認証して接続し、公開鍵と版の範囲を送る。
async fn connect(agent: &Shared) -> Result<Ws, End> {
    let (endpoint, pin_hex, token, private_key) = {
        let a = agent.lock().await;
        (
            a.creds.endpoint.clone(),
            a.creds.cert_sha256.clone(),
            zeroize::Zeroizing::new(a.creds.permanent_token.clone()),
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
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
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
    logf!("stream: connected to {endpoint}; public key sent");
    Ok(ws)
}

/// 1 本の接続の寿命。
async fn stream_once(agent: &Shared) -> End {
    let mut ws = match connect(agent).await {
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
                        if let Err(e) = a.apply(&st).await {
                            logf!("stream: applying generation {}: {e}", st.generation);
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
                    WsMessage::Pong(_) => pong_deadline = None,
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
                let hb = agent.lock().await.heartbeat().await;
                if let Err(e) = send_heartbeat(&mut ws, hb).await {
                    return End::Other(e);
                }
            }
            _ = heartbeat_tick.tick() => {
                let hb = agent.lock().await.heartbeat().await;
                if let Err(e) = send_heartbeat(&mut ws, hb).await {
                    return End::Other(e);
                }
            }
            _ = follow_tick.tick(), if follow_up_until.is_some() => {
                let hb = agent.lock().await.heartbeat().await;
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
                }
            }
            () = pong_wait => {
                logf!("stream: the server did not answer a ping within {}s; the connection is dead, closing it", PONG_TIMEOUT.as_secs());
                return End::Other("ping timed out".into());
            }
        }
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

    #[test]
    fn state_messages_only() {
        assert!(parse_state(r#"{"type":"state","state":{"generation":1,"rules":[]}}"#).is_some());
        assert!(parse_state(r#"{"type":"heartbeat"}"#).is_none());
        assert!(parse_state("not json").is_none());
        // Go なら case folding で state に当てるキーは、別の値に読まないよう拒む
        assert!(parse_state(r#"{"type":"state","State":{"generation":1}}"#).is_none());
    }
}
