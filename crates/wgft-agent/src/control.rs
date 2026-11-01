//! 制御ソケットの要求を実行時の側で処理する。受け口のスレッドは `ctlserver` にある。
//!
//! `doctor` は専用の受け渡しのタスクが受け、要求ごとに別のタスクで組む。実行時のループが全体状態の適用や
//! 見回りを処理している間も受け取るので、排他を待つ 2 秒の期限がそのまま効く。組むタスクの panic は応答の
//! 送り手が消える形で受け口に届き、受け口は `{"error": ...}` の 1 行を返すので、転送は止まらない。
//!
//! `rotate-key` は実行時のループの中で処理し、panic を受け止めない。鍵の保存とトンネルの作り直しの途中で
//! 落ちた状態のまま動き続けるより、プロセスが落ちて同梱の unit が立て直すほうがよいためである (Go の v1 と
//! 同じ判断)。受け口が待つのを諦めた要求は処理しない。

use std::sync::PoisonError;
use std::time::{Duration, Instant, SystemTime};

use wgft_proto::GoTime;

use crate::controlapi::{
    DOCTOR_LOCK_WAIT, DoctorAllowTargets, DoctorProcess, DoctorResponse, DoctorRule,
    DoctorRuntimeState, DoctorStream, DoctorTunnel, DoctorWatchdog, clip_text,
};
use crate::ctlserver::{DoctorRequest, RotateKeyRequest, RotateState};
use crate::logf;
use crate::relay::ListenerStat;
use crate::run::{Agent, Shared};
use crate::stream::{SharedObs, StreamObs};
use crate::tunnel;

/// 宛先の許可一覧を渡す設定の名前。
const ALLOW_TARGETS_ENV: &str = crate::config::allow_targets::ENV;

/// 制御ソケットの要求を処理するのに要るもの。stream の観測と宛先の許可一覧は agent の排他の外に置き、
/// 全体状態の適用の後ろで `doctor` が待たないようにする。
#[derive(Clone, Debug)]
pub(crate) struct Context {
    pub(crate) agent: Shared,
    pub(crate) obs: SharedObs,
    pub(crate) allow_targets: Option<String>,
}

/// `doctor` の要求を受け渡すタスクを立てる。要求ごとに応答を組むタスクを立て、待たずに次を受ける。
pub(crate) fn spawn_doctor(ctx: Context, mut rx: tokio::sync::mpsc::Receiver<DoctorRequest>) {
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let line = collect(&ctx, DOCTOR_LOCK_WAIT).await.to_line();
                let _ = req.reply.send(line);
            });
        }
    });
}

/// `rotate-key` の要求を 1 つ処理する。受け口が取り下げた要求は、鍵を変えずに捨てる。
pub(crate) async fn serve_rotate_key(agent: &Shared, req: RotateKeyRequest) {
    if req.state.abandoned() {
        return;
    }
    if let Some(r) = rotate_key(agent, &req.state).await {
        let _ = req.reply.send(r);
    }
}

/// 鍵の対を作り直して保存し、トンネルを新しい鍵で作り直し、stream に新しい公開鍵で繋ぎ直させる。
/// 取り下げられていれば `None` を返し、何も変えない。
async fn rotate_key(agent: &Shared, state: &RotateState) -> Option<Result<String, String>> {
    let mut a = agent.lock().await;
    // 排他を取った後に始める。受け口が先に取り下げていれば、鍵を変えない
    if !state.start() {
        return None;
    }
    Some(rotate_key_locked(&mut a).await)
}

async fn rotate_key_locked(a: &mut Agent) -> Result<String, String> {
    let key = tunnel::generate_private_key()?;
    let public = tunnel::public_key(&key)?;
    let (old, old_prev) = (
        a.creds.wg_private_key.clone(),
        a.creds.previous_wg_private_key.clone(),
    );
    a.creds.keep_previous_key();
    a.creds.wg_private_key.clone_from(&key);
    if let Err(e) = a.save() {
        // メモリの上の 2 つの鍵も元に戻す。使われていない新しい鍵を今の鍵に残さない
        a.creds.wg_private_key = old;
        a.creds.previous_wg_private_key = old_prev;
        return Err(e.to_string());
    }
    a.private_key = key;
    let last = a.creds.last_state.clone();
    a.close().await;
    logf!("regenerated wg key pair; public key: {public}");
    if let Some(st) = last {
        match a.apply(&st).await {
            Ok(()) => logf!("wireguard: tunnel rebuilt with the new key"),
            Err(e) => logf!("wireguard: rebuild tunnel with the new key: {e}"),
        }
    }
    // stream を張り直すと、新しい公開鍵を送る
    a.reconnect.send_modify(|n| *n = n.wrapping_add(1));
    Ok(public)
}

/// `doctor` の応答を組む。実行時の排他は `wait` まで待ち、取れなければ `runtime_state` を欠いた応答を
/// 返す。黙って待たない。
pub(crate) async fn collect(ctx: &Context, wait: Duration) -> DoctorResponse {
    let mut res = DoctorResponse {
        allow_targets: Some(allow_targets(ctx.allow_targets.as_deref())),
        stream: Some(stream(&ctx.obs)),
        process: Some(process()),
        ..DoctorResponse::default()
    };
    match tokio::time::timeout(wait, ctx.agent.lock()).await {
        Ok(a) => res.runtime_state = Some(runtime_state(&a).await),
        Err(_) => res.runtime_state_timeout = nanos(wait),
    }
    res
}

fn allow_targets(list: Option<&str>) -> DoctorAllowTargets {
    DoctorAllowTargets {
        set: list.is_some(),
        list: list.map(clip_text).unwrap_or_default(),
        env: ALLOW_TARGETS_ENV.to_owned(),
    }
}

fn process() -> DoctorProcess {
    use crate::platform::procinfo;
    let uid = procinfo::uid();
    DoctorProcess {
        uid,
        user: procinfo::user_name(uid).unwrap_or_default(),
        cap_net_admin: procinfo::net_admin(),
    }
}

fn go_time(t: Option<SystemTime>) -> GoTime {
    t.map_or(GoTime::ZERO, GoTime::from_system)
}

fn nanos(d: Duration) -> i64 {
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}

/// 単調な時計の時刻を、今の壁時計に写す。
fn wall(at: Instant) -> SystemTime {
    let now = Instant::now();
    if at <= now {
        SystemTime::now() - (now - at)
    } else {
        SystemTime::now() + (at - now)
    }
}

fn stream(obs: &SharedObs) -> DoctorStream {
    let o: StreamObs = obs.lock().unwrap_or_else(PoisonError::into_inner).clone();
    DoctorStream {
        connected: o.connected,
        disconnected_at: go_time(o.disconnected_at),
        disconnect_reason: clip_text(&o.disconnect_reason),
        pin_mismatch: o.pin_mismatch,
        key_change_limited: o.key_change_limited,
        backoff: nanos(o.backoff),
        retry_at: go_time(o.retry_at),
        last_ping_at: go_time(o.last_ping_at),
        last_pong_at: go_time(o.last_pong_at),
        awaiting_pong: o.awaiting_pong,
    }
}

/// 実行時の状態を 1 回に読む。トンネルの状態はハートビートと同じ値で、doctor のための 2 つ目の判定を
/// 持たない。
async fn runtime_state(a: &Agent) -> DoctorRuntimeState {
    let hb = a.heartbeat().await;
    let mut st = DoctorRuntimeState {
        generation: a.generation,
        agent_disabled: a
            .creds
            .last_state
            .as_ref()
            .is_some_and(|s| s.agent_disabled),
        ..DoctorRuntimeState::default()
    };
    st.tunnel = DoctorTunnel {
        present: a.tunnel.is_some(),
        state: hb.tunnel.state.clone(),
        reason: clip_text(&hb.tunnel.reason),
        endpoint: hb.tunnel.endpoint.clone(),
        last_handshake: hb.tunnel.last_handshake,
        watchdog: DoctorWatchdog {
            rebuild_interval: nanos(a.rebuild_after),
            retry_at: go_time(a.retry_at.map(wall)),
        },
        ..DoctorTunnel::default()
    };
    if let Some(t) = &a.tunnel {
        let r = t.read().await;
        st.tunnel.rx_bytes = i64::try_from(r.rx_bytes).unwrap_or(i64::MAX);
        st.tunnel.tx_bytes = i64::try_from(r.tx_bytes).unwrap_or(i64::MAX);
        st.tunnel.started_at = GoTime::from_system(wall(t.started_at()));
    }
    if let Some(relay) = &a.relay {
        st.rules = rules(&hb.rules, &relay.listener_stats());
    }
    st
}

/// リスナーの状態をルール単位にまとめる。リスナー 1 つずつは並べない。
fn rules(states: &[wgft_proto::RuleStatus], listeners: &[ListenerStat]) -> Vec<DoctorRule> {
    let mut out: Vec<DoctorRule> = states
        .iter()
        .map(|s| DoctorRule {
            id: s.id.clone(),
            state: s.state.clone(),
            reason: clip_text(&s.reason),
            ..DoctorRule::default()
        })
        .collect();
    for l in listeners {
        let Some(r) = out.iter_mut().find(|r| r.id == l.rule_id) else {
            continue;
        };
        "tcp".clone_into(&mut r.proto);
        r.listeners += 1;
        if l.listening {
            r.listening += 1;
        } else {
            r.bind_errors += 1;
            if r.bind_error.is_empty()
                && let Some(e) = &l.err
            {
                r.bind_error = clip_text(&format!("{}: {e}", l.key));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_count_listeners_per_rule() {
        let states = vec![
            wgft_proto::RuleStatus {
                id: "r_a".into(),
                state: "ok".into(),
                reason: String::new(),
            },
            wgft_proto::RuleStatus {
                id: "r_b".into(),
                state: "error".into(),
                reason: "tcp/2: bind tcp 10.0.0.2:2: in use".into(),
            },
        ];
        let ls = vec![
            ListenerStat {
                rule_id: "r_a".into(),
                key: "tcp/1".into(),
                listening: true,
                err: None,
            },
            ListenerStat {
                rule_id: "r_b".into(),
                key: "tcp/2".into(),
                listening: false,
                err: Some("bind tcp 10.0.0.2:2: in use".into()),
            },
            ListenerStat {
                rule_id: "r_b".into(),
                key: "tcp/3".into(),
                listening: true,
                err: None,
            },
        ];
        let got = rules(&states, &ls);
        assert_eq!(got[0].listeners, 1);
        assert_eq!(got[0].listening, 1);
        assert_eq!(got[0].proto, "tcp");
        assert_eq!(got[1].listeners, 2);
        assert_eq!(got[1].bind_errors, 1);
        assert_eq!(got[1].bind_error, "tcp/2: bind tcp 10.0.0.2:2: in use");

        // 後の開けなかったリスナーは、最初の理由を上書きしない
        let mut more = ls.clone();
        more.push(ListenerStat {
            rule_id: "r_b".into(),
            key: "tcp/4".into(),
            listening: false,
            err: Some("bind tcp 10.0.0.2:4: other".into()),
        });
        let got = rules(&states, &more);
        assert_eq!(got[1].bind_errors, 2);
        assert_eq!(got[1].bind_error, "tcp/2: bind tcp 10.0.0.2:2: in use");
    }

    fn context(agent: Agent) -> Context {
        let obs = std::sync::Arc::clone(&agent.stream_obs);
        Context {
            agent: std::sync::Arc::new(tokio::sync::Mutex::new(agent)),
            obs,
            allow_targets: None,
        }
    }

    #[tokio::test]
    async fn doctor_reads_the_runtime_state_or_says_it_waited() {
        let ctx = context(crate::run::test_agent());
        let r = collect(&ctx, Duration::from_secs(2)).await;
        let st = r.runtime_state.as_ref().unwrap();
        assert!(!st.tunnel.present);
        assert_eq!(st.tunnel.state, "error");
        assert_eq!(st.tunnel.reason, "no tunnel; full state not received");
        assert_eq!(st.tunnel.watchdog.rebuild_interval, 300_000_000_000);
        let a = r.allow_targets.as_ref().unwrap();
        assert!(!a.set && a.env == "WGFT_AGENT_ALLOW_TARGETS");
        assert!(
            r.process
                .as_ref()
                .is_some_and(|p| p.uid != 0 || p.user == "root")
        );
        let line = String::from_utf8(r.to_line()).unwrap();
        assert!(
            line.ends_with("}\n") && !line.contains("\"mode\""),
            "{line}"
        );

        // 実行時の排他を誰かが持ち続ける
        let held = ctx.agent.lock().await;
        let r = collect(&ctx, Duration::from_millis(30)).await;
        drop(held);
        assert!(r.runtime_state.is_none());
        assert_eq!(r.runtime_state_timeout, 30_000_000);
        assert!(r.stream.is_some() && r.allow_targets.is_some() && r.process.is_some());
    }

    #[tokio::test]
    async fn rotate_key_saves_a_new_key_and_asks_the_stream_to_reconnect() {
        let d = tempfile::tempdir().unwrap();
        let mut a = crate::run::test_agent();
        a.opts.data_dir = d.path().to_owned();
        let ctx = context(a);
        let mut seen = ctx.agent.lock().await.reconnect.subscribe();
        let public = rotate_key(&ctx.agent, &RotateState::default())
            .await
            .unwrap()
            .unwrap();
        assert!(seen.has_changed().unwrap());
        seen.mark_unchanged();
        let saved = crate::credentials::Credentials::load(&d.path().join("agent.json")).unwrap();
        assert_eq!(tunnel::public_key(&saved.wg_private_key).unwrap(), public);
        assert_eq!(*ctx.agent.lock().await.private_key, saved.wg_private_key);

        // 保存に失敗すれば、メモリの上の 2 つの鍵も元に戻す。1 つ前の鍵を移すのはカーネルモードの記録を
        // 持つときだけなので、その記録で確かめる
        let before = saved.wg_private_key.clone();
        {
            let mut a = ctx.agent.lock().await;
            a.opts.data_dir = d.path().join("missing");
            a.creds.mode = "kernel".into();
            a.creds.previous_wg_private_key = "PREVIOUS".into();
        }
        assert!(
            rotate_key(&ctx.agent, &RotateState::default())
                .await
                .unwrap()
                .is_err()
        );
        let a = ctx.agent.lock().await;
        assert_eq!(a.creds.wg_private_key, before);
        assert_eq!(a.creds.previous_wg_private_key, "PREVIOUS");
        assert_eq!(*a.private_key, before);
        drop(a);
        assert!(!seen.has_changed().unwrap());
    }

    /// 受け口が取り下げた要求は、鍵を変えずに捨てる。排他を待つ間に取り下げられた場合も同じである。
    #[tokio::test]
    async fn an_abandoned_rotate_key_request_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let mut a = crate::run::test_agent();
        a.opts.data_dir = d.path().to_owned();
        let ctx = context(a);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let state = std::sync::Arc::new(RotateState::default());
        // 受け口の取り下げは、実行時の側が始める前でなければ通らない
        let held = ctx.agent.lock().await;
        let agent = std::sync::Arc::clone(&ctx.agent);
        let req = RotateKeyRequest {
            reply: tx,
            state: std::sync::Arc::clone(&state),
        };
        let task = tokio::spawn(async move { serve_rotate_key(&agent, req).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // 実行時の側が排他を待つ間に、受け口が取り下げる
        assert!(crate::ctlserver::abandon_for_test(&state));
        drop(held);
        task.await.unwrap();
        assert!(rx.try_recv().is_err(), "no reply for an abandoned request");
        assert!(!d.path().join("agent.json").exists());
        assert_eq!(ctx.agent.lock().await.creds.wg_private_key, "");
    }

    #[test]
    fn stream_times_are_zero_until_observed() {
        let obs = SharedObs::default();
        let s = stream(&obs);
        assert!(s.disconnected_at.is_zero() && s.retry_at.is_zero() && s.last_ping_at.is_zero());
        assert_eq!(s.backoff, 0);
    }
}
