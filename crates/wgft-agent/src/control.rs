//! 制御ソケットの要求を実行時の側で処理する。受け口のスレッドは `ctlserver` にある。
//!
//! `doctor` は専用の受け渡しのタスクが受け、要求ごとに別のタスクで組む。実行時のループが全体状態の適用や
//! 見回りを処理している間も受け取るので、排他を待つ 2 秒の期限がそのまま効く。組むタスクの panic は応答の
//! 送り手が消える形で受け口に届き、受け口は `{"error": ...}` の 1 行を返すので、転送は止まらない。
//!
//! `rotate-key` は実行時のループの中で処理し、panic を受け止めない。鍵の保存とトンネルの作り直しの途中で
//! 落ちた状態のまま動き続けるより、プロセスが落ちて同梱の unit が立て直すほうがよいためである (Go の v1 と
//! 同じ判断)。受け口が待つのを諦めた要求は処理しない。

use std::collections::HashMap;
use std::sync::PoisonError;
use std::time::{Duration, Instant, SystemTime};

use wgft_proto::GoTime;

use crate::controlapi::{
    DOCTOR_LOCK_WAIT, DoctorAllowTargets, DoctorBudget, DoctorProcess, DoctorRefusal,
    DoctorResponse, DoctorRule, DoctorRuntimeState, DoctorSocketBuffers, DoctorStream,
    DoctorTunnel, DoctorUdpAccounting, DoctorWatchdog, clip_text,
};
use crate::ctlserver::{DoctorRequest, RotateKeyRequest};
use crate::flowpool;
use crate::logf;
use crate::relay::{ListenerStat, Manager};
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

/// `rotate-key` の要求を 1 つ処理し、止める合図 `shutdown` で終わったときに真を返す。受け口が取り下げた
/// 要求は、鍵を変えずに捨てる。合図と並べて待つのは、排他の待ちと、鍵を保存した後のトンネルの作り直し
/// だけである。排他を待つ間に合図が来れば、鍵を変えずに応答の送り手を落とし、受け口は応答の前に止まったと
/// 返す。鍵を保存した後に合図が来れば、作り直しを落として新しい公開鍵を応答する。鍵は保存済みで、次の
/// 起動がその鍵でトンネルを立て、次の stream の接続で server に届くので、鍵が変わったのに止まったとは
/// 返さない。排他を取ってから保存までに await は無い。
pub(crate) async fn serve_rotate_key(
    agent: &Shared,
    req: RotateKeyRequest,
    shutdown: &mut (impl Future<Output = ()> + Unpin),
) -> bool {
    if req.state.abandoned() {
        return false;
    }
    // どちらも準備ができていれば、合図を先に見る
    let mut a = tokio::select! {
        biased;
        () = &mut *shutdown => return true,
        a = agent.lock() => a,
    };
    // 排他を取った後に始める。受け口が先に取り下げていれば、鍵を変えない
    if !req.state.start() {
        return false;
    }
    let public = match save_new_key(&mut a) {
        Ok(p) => p,
        Err(e) => {
            let _ = req.reply.send(Err(e));
            return false;
        }
    };
    let stopped = tokio::select! {
        biased;
        () = &mut *shutdown => true,
        () = rebuild_with_new_key(&mut a) => false,
    };
    let _ = req.reply.send(Ok(public));
    stopped
}

/// 鍵の対を作り直して保存し、今の鍵にする。新しい公開鍵を返す。保存に失敗すれば、メモリの上の 2 つの
/// 鍵も元に戻す。使われていない新しい鍵を今の鍵に残さない。
fn save_new_key(a: &mut Agent) -> Result<String, String> {
    let key = tunnel::generate_private_key()?;
    let public = tunnel::public_key(&key)?;
    let (old, old_prev) = (
        a.creds.wg_private_key.clone(),
        a.creds.previous_wg_private_key.clone(),
    );
    a.creds.keep_previous_key();
    a.creds.wg_private_key.clone_from(&key);
    if let Err(e) = a.save() {
        a.creds.wg_private_key = old;
        a.creds.previous_wg_private_key = old_prev;
        return Err(e.to_string());
    }
    a.private_key = key;
    logf!("regenerated wg key pair; public key: {public}");
    Ok(public)
}

/// 新しい鍵でトンネルを作り直し、stream に新しい公開鍵で繋ぎ直させる。
async fn rebuild_with_new_key(a: &mut Agent) {
    let last = a.creds.last_state.clone();
    a.close().await;
    if let Some(st) = last {
        match a.apply(st).await {
            Ok(()) => logf!("wireguard: tunnel rebuilt with the new key"),
            Err(e) => logf!("wireguard: rebuild tunnel with the new key: {e}"),
        }
    }
    // stream を張り直すと、新しい公開鍵を送る
    a.reconnect.send_modify(|n| *n = n.wrapping_add(1));
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
    wall_at(at, Instant::now())
}

/// `now` と同じ時計の時刻 `at` を壁時計に直す。トンネルの時刻はデータプレーンの時計で測る。
fn wall_at(at: Instant, now: Instant) -> SystemTime {
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
pub(crate) async fn runtime_state(a: &Agent) -> DoctorRuntimeState {
    let ts = a.tunnel_status().await;
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
        state: ts.state,
        reason: clip_text(&ts.reason),
        endpoint: ts.endpoint,
        last_handshake: ts.last_handshake,
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
        st.tunnel.started_at =
            GoTime::from_system(wall_at(t.started_at(), crate::dataplane::clock::now()));
        st.tunnel.socket_buffers = r.socket_buffers.as_ref().map(socket_buffers);
        if let Ok(fault) = t.udp_fault().await {
            st.tunnel.udp_accounting = Some(DoctorUdpAccounting {
                stopped: fault.is_some(),
                error: fault.map(|e| clip_text(&e)).unwrap_or_default(),
            });
        }
    }
    if let Some(relay) = &a.relay {
        relay_state(&mut st, relay);
    }
    st
}

/// 測ったソケットのバッファを応答の形に写す (Go の `doctorSocketBuffers`)。
fn socket_buffers(b: &crate::dataplane::SocketBuffers) -> DoctorSocketBuffers {
    if !b.supported {
        return DoctorSocketBuffers::default();
    }
    let mut out = DoctorSocketBuffers {
        supported: true,
        port: b.port,
        required: count(crate::dataplane::REQUIRED),
        ..DoctorSocketBuffers::default()
    };
    if let Some(e) = &b.error {
        out.error = clip_text(e);
        return out;
    }
    out.sockets = 1;
    out.recv = count(b.recv);
    out.send = count(b.send);
    out
}

/// 中継の値を載せる。ルールの状態とリスナーの集計は、リスナーの 1 回の読みから作る (Go の
/// `usermode.Read`)。ハートビートと同じ判定 ([`Manager::status_of`]) を使い、リスナーを 2 度読まない。
fn relay_state(st: &mut DoctorRuntimeState, relay: &Manager) {
    let stats = relay.listener_stats();
    st.rules = rules(&relay.status_of(&stats), &stats);
    // 中継とトンネルは一緒に作り直されるので、拒否の累計の起点はトンネルを立てた時刻である
    st.refusals_since = st.tunnel.started_at;
    st.budgets = vec![
        budget("tcp", relay.tcp_pool().reading()),
        budget("udp", relay.udp_pool().reading()),
    ];
}

fn count(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// 1 つのプロトコルのフロー数の予算 (Go の `doctorBudget`)。拒否の並びは pool の読みがルール ID と理由の
/// 語の順に並べている。
fn budget(proto: &str, r: flowpool::Reading) -> DoctorBudget {
    DoctorBudget {
        proto: proto.to_owned(),
        total: count(r.total),
        in_use: count(r.in_use),
        rule_cap: count(r.rule_cap),
        reserve: count(r.reserve),
        rules: count(r.rules),
        refusals: r
            .refusals
            .into_iter()
            .map(|(rule_id, reason, n)| DoctorRefusal {
                rule_id,
                reason: reason.as_str().to_owned(),
                count: n,
            })
            .collect(),
    }
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
    // 範囲のルールはリスナーが多いので、ルールを ID の表で引く
    let at: HashMap<&str, usize> = states
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i))
        .collect();
    for l in listeners {
        let Some(r) = at.get(&*l.rule_id).map(|&i| &mut out[i]) else {
            continue;
        };
        l.key.kind.as_str().clone_into(&mut r.proto);
        r.listeners += 1;
        r.sessions += count(l.sessions);
        r.flows += count(l.flows);
        match (&l.err, l.listening) {
            // 開けなかった原因はポートの衝突を、届かない原因は宛先の機器を指すので、分けて数える
            (err, false) => {
                r.bind_errors += 1;
                if r.bind_error.is_empty()
                    && let Some(e) = err
                {
                    r.bind_error = clip_text(&format!("{}: {e}", l.key));
                }
            }
            (Some(e), true) => {
                r.listening += 1;
                r.target_errors += 1;
                if r.target_error.is_empty() {
                    r.target_error = clip_text(&format!("{}: {e}", l.key));
                }
            }
            (None, true) => r.listening += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(rule: &str, port: u16, listening: bool, err: Option<&str>) -> ListenerStat {
        ListenerStat {
            rule_id: rule.into(),
            key: crate::relay::Key {
                kind: crate::relay::Kind::Tcp,
                port,
            },
            listening,
            err: err.map(Into::into),
            sessions: 0,
            flows: 0,
        }
    }

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
                sessions: 2,
                flows: 1,
                ..stat("r_a", 1, true, None)
            },
            stat("r_b", 2, false, Some("bind tcp 10.0.0.2:2: in use")),
            ListenerStat {
                sessions: 3,
                flows: 2,
                ..stat("r_b", 3, true, None)
            },
        ];
        let got = rules(&states, &ls);
        assert_eq!(got[0].listeners, 1);
        assert_eq!(got[0].listening, 1);
        assert_eq!(got[0].proto, "tcp");
        assert_eq!((got[0].sessions, got[0].flows), (2, 1));
        assert_eq!(got[1].listeners, 2);
        assert_eq!(got[1].listening, 1);
        assert_eq!(got[1].bind_errors, 1);
        assert_eq!(got[1].bind_error, "tcp/2: bind tcp 10.0.0.2:2: in use");
        assert_eq!((got[1].sessions, got[1].flows), (3, 2));
        assert_eq!(
            (got[1].target_errors, got[1].target_error.as_str()),
            (0, "")
        );

        // 後の開けなかったリスナーは、最初の理由を上書きしない
        let mut more = ls.clone();
        more.push(stat("r_b", 4, false, Some("bind tcp 10.0.0.2:4: other")));
        let got = rules(&states, &more);
        assert_eq!(got[1].bind_errors, 2);
        assert_eq!(got[1].bind_error, "tcp/2: bind tcp 10.0.0.2:2: in use");
    }

    /// 開いている待ち受けの宛先の誤りは、bind の誤りと分けて数える (Go の `doctorRules`)。
    #[test]
    fn rules_count_target_errors_apart_from_bind_errors() {
        let states = vec![wgft_proto::RuleStatus {
            id: "r_a".into(),
            state: "error".into(),
            reason: "tcp/5: bind tcp 10.0.0.2:5: in use".into(),
        }];
        let ls = vec![
            stat("r_a", 5, false, Some("bind tcp 10.0.0.2:5: in use")),
            stat("r_a", 6, true, Some("dial tcp 192.0.2.1:80: refused")),
            stat("r_a", 7, true, Some("dial tcp 192.0.2.1:81: refused")),
            stat("r_a", 8, true, None),
            // 属するルールが状態に無いリスナーは数えない
            stat("r_gone", 9, true, Some("x")),
        ];
        let got = rules(&states, &ls);
        assert_eq!(got.len(), 1);
        let r = &got[0];
        assert_eq!((r.listeners, r.listening), (4, 3));
        assert_eq!(r.bind_errors, 1);
        assert_eq!(r.target_errors, 2);
        assert_eq!(r.target_error, "tcp/6: dial tcp 192.0.2.1:80: refused");
        // 長い理由は応答の上限で切る
        let long = "x".repeat(600);
        let got = rules(&states, &[stat("r_a", 6, true, Some(&long))]);
        assert!(got[0].target_error.len() <= crate::controlapi::DOCTOR_TEXT_MAX_BYTES + 16);
        assert!(got[0].target_error.starts_with("tcp/6: xxx"));
    }

    /// 予算の読みは Go の `doctorBudget` の形に写す。拒否はルール ID と理由の語の順に並ぶ。
    #[test]
    fn budgets_follow_the_pool() {
        use flowpool::{Denied, Pool};
        let pool = Pool::new(16);
        let a = pool.listener("r_b");
        let b = pool.listener("r_a");
        // ルールが 2 本なので、1 本の上限 C は 8
        let mut held = Vec::new();
        while let Ok(l) = a.take() {
            held.push(l);
        }
        assert!(matches!(a.take(), Err(Denied::Refused(_))));
        let _keep = b.take().unwrap();
        let got = budget("tcp", pool.reading());
        assert_eq!(got.proto, "tcp");
        assert_eq!(got.total, 16);
        assert_eq!(got.rules, 2);
        assert_eq!(got.rule_cap, 8);
        assert_eq!(got.in_use, count(held.len() + 1));
        assert_eq!(got.reserve, count(pool.reading().reserve));
        let reasons: Vec<(&str, &str)> = got
            .refusals
            .iter()
            .map(|r| (r.rule_id.as_str(), r.reason.as_str()))
            .collect();
        assert!(
            reasons.iter().all(|(rule, _)| *rule == "r_b"),
            "{reasons:?}"
        );
        assert!(got.refusals.iter().all(|r| r.count > 0));
        let mut sorted = reasons.clone();
        sorted.sort_unstable();
        assert_eq!(reasons, sorted);
        // 拒否の無い予算は refusals を書かない
        let empty = budget("udp", Pool::new(8192).reading());
        assert_eq!(empty.refusals, Vec::<DoctorRefusal>::new());
        let line = serde_json::to_string(&empty).unwrap();
        assert!(!line.contains("refusals"), "{line}");
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

    /// 中継があれば、応答はルールの数と予算を載せる。待ち受けを開けないルールは bind の誤りに数え、
    /// CLI の `relay.listeners` が Go と同じく読める。
    #[tokio::test]
    async fn doctor_carries_the_relay_s_rules_and_budgets() {
        use crate::relay::Manager;
        use crate::relay::testpeer::{AGENT_IP, Peer};
        use crate::targets::Targets;
        use wgft_proto::{AgentRule, Proto};
        let peer = Peer::start().await;
        // 核のポートを先に取り、中継の待ち受けを開けなくする
        let port = 8080u16;
        let addr = std::net::SocketAddrV4::new(AGENT_IP, port);
        let (taken, held) = tokio::sync::oneshot::channel::<()>();
        peer.agent()
            .call(move |net| {
                let l = wgft_netstack::TcpListener::bind(net, addr).unwrap();
                tokio::task::spawn_local(async move {
                    let _ = held.await;
                    drop(l);
                });
            })
            .await
            .unwrap();
        let mut m = Manager::new(
            AGENT_IP,
            peer.agent().handle(),
            std::sync::Arc::new(Targets::new(None)),
            flowpool::Limits { udp: 64, tcp: 32 },
            crate::relay::DEFAULT_UDP_IDLE,
        );
        m.apply(&[AgentRule {
            id: "r_a".into(),
            proto: Proto::Tcp,
            listen_port: port.to_string().parse().unwrap(),
            target: "127.0.0.1:9".into(),
            enabled: true,
        }])
        .await;
        let mut a = crate::run::test_agent();
        a.relay = Some(m);
        let r = collect(&context(a), Duration::from_secs(2)).await;
        let st = r.runtime_state.unwrap();
        assert_eq!(st.rules.len(), 1);
        let rule = &st.rules[0];
        assert_eq!(rule.state, "error");
        assert!(
            rule.reason.starts_with(&format!("tcp/{port}: bind tcp ")),
            "{rule:?}"
        );
        assert_eq!(
            (rule.listeners, rule.listening, rule.bind_errors),
            (1, 0, 1)
        );
        assert_eq!(rule.bind_error, rule.reason);
        let b: Vec<(&str, i64, i64)> = st
            .budgets
            .iter()
            .map(|b| (b.proto.as_str(), b.total, b.rules))
            .collect();
        // 開けなかった待ち受けのルールは予算のルールに数えない
        assert_eq!(b, [("tcp", 32, 0), ("udp", 64, 0)]);
        // トンネルが無い試験の agent では、起点は時刻のゼロ値である
        assert_eq!(st.refusals_since, GoTime::ZERO);
        drop(taken);
    }

    /// 拒否の累計の起点は、中継と一緒に作り直すトンネルを立てた時刻である。
    #[tokio::test]
    async fn refusals_since_is_the_tunnel_s_start() {
        let peer = crate::relay::testpeer::Peer::start().await;
        let m = Manager::new(
            crate::relay::testpeer::AGENT_IP,
            peer.agent().handle(),
            std::sync::Arc::new(crate::targets::Targets::new(None)),
            flowpool::Limits::default(),
            crate::relay::DEFAULT_UDP_IDLE,
        );
        let mut st = DoctorRuntimeState::default();
        st.tunnel.started_at =
            GoTime::from_system(SystemTime::UNIX_EPOCH + Duration::from_hours(500_000));
        relay_state(&mut st, &m);
        assert_ne!(st.refusals_since, GoTime::ZERO);
        assert_eq!(st.refusals_since, st.tunnel.started_at);
        assert_eq!(st.budgets.len(), 2);
    }

    /// `rotate-key` の要求を 1 つ、止める合図の無いまま処理させ、応答を返す。
    async fn rotate(agent: &Shared) -> Option<Result<String, String>> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let req = RotateKeyRequest {
            reply: tx,
            state: std::sync::Arc::new(crate::ctlserver::RotateState::default()),
        };
        assert!(!serve_rotate_key(agent, req, &mut std::future::pending()).await);
        rx.try_recv().ok()
    }

    #[tokio::test]
    async fn rotate_key_saves_a_new_key_and_asks_the_stream_to_reconnect() {
        let d = tempfile::tempdir().unwrap();
        let mut a = crate::run::test_agent();
        a.opts.data_dir = d.path().to_owned();
        let ctx = context(a);
        let mut seen = ctx.agent.lock().await.reconnect.subscribe();
        let public = rotate(&ctx.agent).await.unwrap().unwrap();
        assert!(seen.has_changed().unwrap());
        seen.mark_unchanged();
        let saved = crate::credentials::Credentials::load(&d.path().join("agent.json")).unwrap();
        assert_eq!(tunnel::public_key(&saved.wg_private_key).unwrap(), public);
        assert_eq!(ctx.agent.lock().await.private_key, saved.wg_private_key);

        // 保存に失敗すれば、メモリの上の 2 つの鍵も元に戻す。1 つ前の鍵を移すのはカーネルモードの記録を
        // 持つときだけなので、その記録で確かめる
        let before = saved.wg_private_key.clone();
        {
            let mut a = ctx.agent.lock().await;
            a.opts.data_dir = d.path().join("missing");
            a.creds.mode = "kernel".into();
            a.creds.previous_wg_private_key = String::from("PREVIOUS").into();
        }
        assert!(rotate(&ctx.agent).await.unwrap().is_err());
        let a = ctx.agent.lock().await;
        assert_eq!(a.creds.wg_private_key, before);
        assert_eq!(*a.creds.previous_wg_private_key, "PREVIOUS");
        assert_eq!(a.private_key, before);
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
        let state = std::sync::Arc::new(crate::ctlserver::RotateState::default());
        // 受け口の取り下げは、実行時の側が始める前でなければ通らない
        let held = ctx.agent.lock().await;
        let agent = std::sync::Arc::clone(&ctx.agent);
        let req = RotateKeyRequest {
            reply: tx,
            state: std::sync::Arc::clone(&state),
        };
        let task = tokio::spawn(async move {
            serve_rotate_key(&agent, req, &mut std::future::pending()).await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // 実行時の側が排他を待つ間に、受け口が取り下げる
        assert!(crate::ctlserver::abandon_for_test(&state));
        drop(held);
        assert!(!task.await.unwrap());
        assert!(rx.try_recv().is_err(), "no reply for an abandoned request");
        assert!(!d.path().join("agent.json").exists());
        assert_eq!(*ctx.agent.lock().await.creds.wg_private_key, "");
    }

    #[test]
    fn stream_times_are_zero_until_observed() {
        let obs = SharedObs::default();
        let s = stream(&obs);
        assert!(s.disconnected_at.is_zero() && s.retry_at.is_zero() && s.last_ping_at.is_zero());
        assert_eq!(s.backoff, 0);
    }
}
