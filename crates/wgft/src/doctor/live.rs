//! 稼働中のプロセスの制御ソケットからしか取れない検査 (Go の `cmd/wgft/agentdoctorlive.go`)。
//!
//! 応答の文字列は信頼の境界の外から来る。表示の前の無害化は出力の側でまとめて行う ([`super::output`])。
//! 状態の語と理由の符号は、ここで固定の定数から選ぶので、応答の文字列を経由しない。

use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;

use time::OffsetDateTime;
use wgft_agent::controlapi::{
    self, CONTROL_PATH_LIMIT, DOCTOR_COMMAND, DOCTOR_REPLY_MAX_BYTES, DoctorAllowTargets,
    DoctorResponse, DoctorRule, DoctorRuntimeState, DoctorStream, REASON_FULL_STATE_NOT_RECEIVED,
    REASON_HANDSHAKE_PENDING, REASON_NO_TUNNEL_BUILD_FAILED, REASON_WG_REFUSED,
    UNKNOWN_COMMAND_REPLY, control_path,
};
use wgft_agent::platform::ctlsock;
use wgft_proto::GoTime;

use super::checks::{SAME_PRINCIPAL_NEXT, err_text, or_dash};
use super::output::{go_duration, plural_s, rfc3339};
use super::{
    CHECK_ALLOW_TARGETS, CHECK_CONTROL, CHECK_LISTENERS, CHECK_REFUSALS, CHECK_SESSIONS,
    CHECK_SOCKET_BUFS, CHECK_STREAM_BACKOFF, CHECK_STREAM_CONN, CHECK_STREAM_LIVE, CHECK_TRANSFER,
    CHECK_TUNNEL_LOCAL, CHECK_UDP_ACCT, CHECK_WATCHDOG, Check, Conn, GROUP_CONNECTION, GROUP_RELAY,
    GROUP_TUNNEL, Input, Live, LiveKind, RunState, reason, status,
};

/// 制御ソケットに繋ぐ既定の入口。
pub(crate) fn dial(path: &Path) -> io::Result<Box<dyn Conn>> {
    let mut c = ctlsock::connect(path, super::DIAL_TIMEOUT)?;
    c.set_deadline(super::REPLY_TIMEOUT);
    Ok(Box::new(c))
}

/// 稼働中の agent の制御ソケットから実行時の状態を読む。稼働していない実行と稼働を判定できない実行では
/// 繋ぎに行かない。
pub(crate) fn read(input: &Input, run: &RunState) -> Live {
    if !run.running() {
        return Live::not_attempted();
    }
    let p = control_path(&input.credentials_path);
    let path = p.display().to_string();
    let mut live = Live {
        path: path.clone(),
        ..Live::not_attempted()
    };
    let mut c = match (input.dial)(&p) {
        Ok(c) => c,
        Err(e) => {
            live.kind = dial_failure_kind(&p, &e);
            live.err = format!("dial unix {path}: {}", strip_os(&e));
            return live;
        }
    };
    if let Err(e) = c.write_all(format!("{DOCTOR_COMMAND}\n").as_bytes()) {
        live.kind = LiveKind::ReplyUnreadable;
        live.err = strip_os(&e);
        return live;
    }
    match controlapi::read_control_reply(&mut c, DOCTOR_REPLY_MAX_BYTES) {
        Ok(line) => classify(path, &line),
        Err(e) => {
            live.kind = LiveKind::ReplyUnreadable;
            live.err = if e.kind() == io::ErrorKind::UnexpectedEof {
                "EOF".into()
            } else {
                strip_os(&e)
            };
            live
        }
    }
}

fn strip_os(e: &io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) if s.ends_with(')') => {
            let m = &s[..i];
            let mut cs = m.chars();
            cs.next()
                .map(|c| c.to_lowercase().chain(cs).collect())
                .unwrap_or_default()
        }
        _ => s,
    }
}

/// 繋げなかった理由を、終了コードの分かれる 3 つの場合に振り分ける。
fn dial_failure_kind(path: &Path, e: &io::Error) -> LiveKind {
    if e.kind() == io::ErrorKind::PermissionDenied {
        LiveKind::Denied
    } else if e.kind() == io::ErrorKind::InvalidInput
        && path.as_os_str().as_encoded_bytes().len() > CONTROL_PATH_LIMIT
    {
        LiveKind::PathTooLong
    } else {
        LiveKind::Unreachable
    }
}

/// 応答の 1 行を区分に写す。応答の形だけで 3 つの状態を区別できる。
pub(crate) fn classify(path: String, line: &str) -> Live {
    let text = line.trim();
    let mut live = Live {
        path,
        ..Live::not_attempted()
    };
    if text == UNKNOWN_COMMAND_REPLY {
        live.kind = LiveKind::Unsupported;
        text.clone_into(&mut live.reply);
        return live;
    }
    let resp: DoctorResponse = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(e) => {
            live.kind = LiveKind::ReplyUnreadable;
            live.err = e.to_string();
            text.clone_into(&mut live.reply);
            return live;
        }
    };
    live.kind = if !resp.error.is_empty() {
        LiveKind::AgentError
    } else if resp.runtime_state.is_some() {
        LiveKind::Ok
    } else if resp.runtime_state_timeout > 0 {
        LiveKind::RuntimeBusy
    } else {
        live.kind = LiveKind::ReplyUnreadable;
        "the reply carries neither a runtime state, a timeout nor an error"
            .clone_into(&mut live.err);
        text.clone_into(&mut live.reply);
        return live;
    };
    live.resp = Some(resp);
    live
}

/// 稼働中のプロセスからしか取れない検査の並び。
const LIVE_ONLY: &[(&str, &str, &str, bool, bool)] = &[
    // (id, group, label, verdict, value_only)
    (
        CHECK_CONTROL,
        GROUP_CONNECTION,
        "control socket",
        false,
        false,
    ),
    (
        CHECK_STREAM_CONN,
        GROUP_CONNECTION,
        "control connection",
        false,
        false,
    ),
    (
        CHECK_STREAM_BACKOFF,
        GROUP_CONNECTION,
        "reconnect backoff",
        false,
        true,
    ),
    (CHECK_STREAM_LIVE, GROUP_CONNECTION, "liveness", false, true),
    (CHECK_TUNNEL_LOCAL, GROUP_TUNNEL, "tunnel", true, false),
    (
        CHECK_SOCKET_BUFS,
        GROUP_TUNNEL,
        "socket buffers",
        false,
        false,
    ),
    (CHECK_UDP_ACCT, GROUP_TUNNEL, "UDP accounting", true, false),
    (CHECK_WATCHDOG, GROUP_TUNNEL, "watchdog", false, true),
    (CHECK_TRANSFER, GROUP_TUNNEL, "transfer", false, true),
    (CHECK_LISTENERS, GROUP_RELAY, "listeners", true, false),
    (CHECK_SESSIONS, GROUP_RELAY, "sessions", false, true),
    (CHECK_REFUSALS, GROUP_RELAY, "refusals", false, true),
    (
        CHECK_ALLOW_TARGETS,
        GROUP_RELAY,
        "target allowlist",
        false,
        false,
    ),
];

/// 稼働中のプロセスからしか取れない検査を組み立てる。読めなかった実行でも項目は落とさず SKIPPED にする。
pub(crate) fn checks(input: &Input, run: &RunState, live: &Live, agent_name: &str) -> Vec<Check> {
    LIVE_ONLY
        .iter()
        .map(|&(id, group, label, verdict, value_only)| {
            let mut c = Check::new(id, group, label);
            c.verdict = verdict;
            c.value_only = value_only;
            if id == CHECK_CONTROL {
                control_check(&mut c, run, live);
                return c;
            }
            match live.resp.as_ref() {
                Some(resp) if value_read(id, live) => {
                    value_check(&mut c, input.now, resp, agent_name);
                }
                _ => {
                    skip(&mut c, run, live);
                    if id == CHECK_ALLOW_TARGETS && live.kind == LiveKind::NotAttempted {
                        allow_targets_state(&mut c, run);
                    }
                }
            }
            c
        })
        .collect()
}

/// その検査の値がこの実行で読めたか。排他を取れなかった応答にも `allow_targets` と `stream` は載る。
fn value_read(id: &str, live: &Live) -> bool {
    let Some(r) = live.resp.as_ref() else {
        return false;
    };
    match live.kind {
        LiveKind::Ok => {
            r.runtime_state.is_some() && r.stream.is_some() && r.allow_targets.is_some()
        }
        LiveKind::RuntimeBusy => {
            !needs_runtime_state(id) && r.stream.is_some() && r.allow_targets.is_some()
        }
        _ => false,
    }
}

fn needs_runtime_state(id: &str) -> bool {
    matches!(
        id,
        CHECK_TUNNEL_LOCAL
            | CHECK_SOCKET_BUFS
            | CHECK_UDP_ACCT
            | CHECK_WATCHDOG
            | CHECK_TRANSFER
            | CHECK_LISTENERS
            | CHECK_SESSIONS
            | CHECK_REFUSALS
    )
}

const RESTART_FOR_DOCTOR_NEXT: &str = "the running process was started from an older binary than this one; restart the agent so it runs the installed binary, with systemctl restart wgft-agent, or docker restart for a container";
const DOCTOR_FAILED_NEXT: &str = "the agent logs the failure and its stack; read it with journalctl -u wgft-agent, or docker logs for a container. Forwarding is not stopped by this, so the rules it already holds keep running";
const RUNTIME_BUSY_NEXT: &str = "the agent is alive but busy inside: its 30s round of target checks holds that lock while it dials every target, and a target that never answers stretches the round. Read which targets answer, and run this command again";

/// 値を読めなかった検査を SKIPPED にする。
fn skip(c: &mut Check, run: &RunState, live: &Live) {
    c.status = status::SKIPPED;
    match live.kind {
        LiveKind::NotAttempted => {
            if run.undetermined() {
                c.reason = reason::LOCK_UNREADABLE;
                "whether the agent is running could not be determined, so its live state was not read".clone_into(&mut c.detail);
                return;
            }
            c.reason = reason::NOT_RUNNING;
            "the agent is not running, so its live state was not read".clone_into(&mut c.detail);
        }
        LiveKind::Denied | LiveKind::PathTooLong | LiveKind::Unreachable => {
            c.reason = if live.kind == LiveKind::PathTooLong {
                reason::CONTROL_PATH_TOO_LONG
            } else {
                reason::CONTROL_UNREACHABLE
            };
            "the agent is running, but its control socket could not be reached, so its live state was not read".clone_into(&mut c.detail);
            "the control socket line above says why; this value comes from the running process alone".clone_into(&mut c.next);
        }
        LiveKind::Unsupported => {
            c.reason = reason::DOCTOR_UNSUPPORTED;
            "the running agent does not answer doctor, so its live state was not read"
                .clone_into(&mut c.detail);
            RESTART_FOR_DOCTOR_NEXT.clone_into(&mut c.next);
        }
        LiveKind::AgentError => {
            c.reason = reason::DOCTOR_FAILED;
            "the running agent could not collect its own state, so this value was not read"
                .clone_into(&mut c.detail);
            DOCTOR_FAILED_NEXT.clone_into(&mut c.next);
        }
        LiveKind::ReplyUnreadable => {
            c.reason = reason::DOCTOR_UNREADABLE;
            "the running agent's reply could not be read, so its live state was not read"
                .clone_into(&mut c.detail);
            "the control socket line above says why; run this command again, and read the agent's log if it keeps answering that way".clone_into(&mut c.next);
        }
        LiveKind::RuntimeBusy | LiveKind::Ok => {
            c.reason = reason::RUNTIME_BUSY;
            let wait = live.resp.as_ref().map_or(0, |r| r.runtime_state_timeout);
            c.detail = format!(
                "the running agent did not take the lock that guards its runtime state within {}, so this value was not read",
                go_duration(round(wait, 1_000_000))
            );
            RUNTIME_BUSY_NEXT.clone_into(&mut c.next);
        }
    }
}

/// 宛先の許可一覧だけは、停止中と稼働を判定できない実行で UNKNOWN になる。
fn allow_targets_state(c: &mut Check, run: &RunState) {
    if run.running() {
        return;
    }
    c.status = status::UNKNOWN;
    if run.undetermined() {
        "the allowlist this agent enforces is the one its running process holds, and whether a process holds it now could not be determined".clone_into(&mut c.detail);
        "settle whether an agent is running first: the process check above says why that could not be read here. Once it is settled, the value shown for a running agent is the one it actually enforces, not one rebuilt from the environment".clone_into(&mut c.next);
        return;
    }
    "the allowlist this agent enforces is the one its running process holds, and no process holds it now".clone_into(&mut c.detail);
    "start the agent and re-run this command; the value shown then is the one it actually enforces, not one rebuilt from the environment".clone_into(&mut c.next);
}

/// `agent.control` を組み立てる。総合判定は動かさない。
fn control_check(c: &mut Check, run: &RunState, live: &Live) {
    let path = &live.path;
    match live.kind {
        LiveKind::NotAttempted => skip(c, run, live),
        LiveKind::Ok => {
            c.status = status::OK;
            c.detail = format!("the running agent answered doctor on its control socket at {path}");
        }
        LiveKind::RuntimeBusy => {
            c.status = status::OK;
            c.detail = format!(
                "the running agent answered doctor on its control socket at {path}; its reply left out the runtime state, and the lines below say so"
            );
        }
        LiveKind::Unsupported => {
            c.set(status::UNKNOWN, reason::DOCTOR_UNSUPPORTED);
            c.detail = format!(
                "the control socket at {path} answered, but the running agent does not carry the doctor command: it replied {}",
                live.reply
            );
            RESTART_FOR_DOCTOR_NEXT.clone_into(&mut c.next);
        }
        LiveKind::AgentError => {
            c.set(status::UNKNOWN, reason::DOCTOR_FAILED);
            c.detail = format!(
                "the control socket at {path} answered, but the agent could not collect its own state: {}",
                live.resp.as_ref().map_or("", |r| r.error.as_str())
            );
            DOCTOR_FAILED_NEXT.clone_into(&mut c.next);
        }
        LiveKind::ReplyUnreadable => {
            c.set(status::UNKNOWN, reason::DOCTOR_UNREADABLE);
            c.detail = format!(
                "the control socket at {path} answered, but its reply could not be read: {}",
                err_text(&live.err)
            );
            "run this command again; if the reply stays unreadable, restart the agent so both sides run the installed binary".clone_into(&mut c.next);
        }
        LiveKind::Denied => {
            c.set(status::FAILED, reason::CONTROL_UNREACHABLE);
            c.evidence_unreachable = true;
            c.detail = format!(
                "the agent is running, but its control socket at {path} refuses this command's permissions: {}",
                err_text(&live.err)
            );
            SAME_PRINCIPAL_NEXT.clone_into(&mut c.next);
        }
        LiveKind::PathTooLong => {
            c.set(status::FAILED, reason::CONTROL_PATH_TOO_LONG);
            c.detail = format!(
                "the agent is running, but its control socket path is {} bytes: {path}. Unix socket paths hold at most 107 bytes on Linux and Windows and 103 on macOS, so this path cannot be opened at all",
                path.len()
            );
            "move the data directory to a shorter path and restart the agent; forwarding itself is not affected, only this socket. Set it with WGFT_DATA_DIR, the same way agent rotate-key needs it".clone_into(&mut c.next);
        }
        LiveKind::Unreachable => {
            c.set(status::FAILED, reason::CONTROL_UNREACHABLE);
            c.detail = format!(
                "the agent is running, but its control socket at {path} could not be reached: {}",
                err_text(&live.err)
            );
            "the agent keeps forwarding without this socket, so this is not a forwarding fault. Read its log with journalctl -u wgft-agent, or docker logs for a container: it prints a line when it cannot open the socket. If it printed none, the socket file at that path is a leftover of a process that did not remove it, and restarting the agent replaces it".clone_into(&mut c.next);
        }
    }
}

/// 読めた値を検査に写す。
fn value_check(c: &mut Check, now: OffsetDateTime, resp: &DoctorResponse, agent_name: &str) {
    let rs = resp.runtime_state.as_ref();
    match c.id {
        CHECK_STREAM_CONN => {
            if let Some(s) = &resp.stream {
                stream_conn(c, now, s);
            }
        }
        CHECK_STREAM_BACKOFF => {
            if let Some(s) = &resp.stream {
                stream_backoff(c, now, s);
            }
        }
        CHECK_STREAM_LIVE => {
            if let Some(s) = &resp.stream {
                stream_liveness(c, now, s);
            }
        }
        CHECK_ALLOW_TARGETS => {
            if let Some(a) = &resp.allow_targets {
                allow_targets_value(c, a);
            }
        }
        _ => {
            let Some(st) = rs else { return };
            match c.id {
                CHECK_TUNNEL_LOCAL => tunnel_local(c, now, st),
                CHECK_SOCKET_BUFS => socket_buffers(c, now, st),
                CHECK_UDP_ACCT => udp_accounting(c, st),
                CHECK_WATCHDOG => watchdog(c, now, st),
                CHECK_TRANSFER => transfer(c, now, st),
                CHECK_LISTENERS => listeners(c, st, agent_name),
                CHECK_SESSIONS => sessions(c, st),
                CHECK_REFUSALS => refusals(c, now, st),
                _ => {}
            }
        }
    }
}

// --- Connection 群 ---

/// server が鍵の変更の頻度の上限で拒むときの close の理由 (Go の `reasontext.KeyChangeLimited`)。
const KEY_CHANGE_LIMITED_TEXT: &str = "public key changes are limited; retry later";
/// 証明書のピンとの不一致の文の書き出し (Go の `enroll.ErrPinMismatch`)。
const PIN_MISMATCH_TEXT: &str = wgft_agent::enroll::PIN_MISMATCH;

fn reason_or<'a>(r: &'a str, fallback: &'a str) -> &'a str {
    if r.trim().is_empty() { fallback } else { r }
}

fn stream_conn(c: &mut Check, now: OffsetDateTime, s: &DoctorStream) {
    if s.connected {
        c.status = status::OK;
        "the control stream to the server is up".clone_into(&mut c.detail);
        return;
    }
    let why = reason_or(&s.disconnect_reason, "no reason was recorded");
    if s.pin_mismatch || s.disconnect_reason.contains(PIN_MISMATCH_TEXT) {
        c.set(status::FAILED, reason::SERVER_CERT_MISMATCH);
        c.detail = format!(
            "the control stream to the server is not up, and retrying will not bring it up: the server's certificate does not match the one this agent pinned when it registered; the last attempt ended {}: {why}",
            when(now, s.disconnected_at)
        );
        "if the server was rebuilt, for example with wgft server teardown --purge, issue a new join string on the VPS with wgft agent join-string --name <agent> and restart the agent with WGFT_JOIN set to it; the agent then registers again with the new server. If the server was not rebuilt, something on the path answers TLS in its place; find it before registering again".clone_into(&mut c.next);
        return;
    }
    c.set(status::UNKNOWN, reason::RECONNECTING);
    if s.key_change_limited || s.disconnect_reason.contains(KEY_CHANGE_LIMITED_TEXT) {
        c.set(status::FAILED, reason::KEY_CHANGE_LIMITED);
        c.verdict = true;
        c.detail = format!(
            "the control stream to the server is not up; the last attempt ended {}, refused by the server's key change limit: {why}",
            when(now, s.disconnected_at)
        );
        "the server has not installed the key this agent uses, so this agent forwards nothing until the server accepts it. The agent keeps reconnecting with the same key, and the server accepts it on the first attempt after a change comes back, one every 10 minutes; do not run wgft agent rotate-key again. wgft agent rotate-key --help describes how to recover sooner".clone_into(&mut c.next);
        return;
    }
    c.detail = if s.disconnected_at.is_zero() {
        "the control stream to the server is not up, and no attempt has ended yet".into()
    } else {
        format!(
            "the control stream to the server is not up; the last attempt ended {}: {why}",
            when(now, s.disconnected_at)
        )
    };
    "the agent retries by itself, so this alone is not a fault. Rules it already holds keep being forwarded while the stream is down. If it stays down, read the reason above and the server's log on the VPS".clone_into(&mut c.next);
}

fn stream_backoff(c: &mut Check, now: OffsetDateTime, s: &DoctorStream) {
    c.set(status::UNKNOWN, reason::NO_THRESHOLD);
    let mut parts = vec![if s.backoff > 0 {
        format!(
            "the last reconnect wait was {}",
            go_duration(round(s.backoff, 1_000_000_000))
        )
    } else {
        "no reconnect wait has been recorded on this connection yet".into()
    }];
    parts.push(if s.retry_at.is_zero() {
        "no attempt is waiting now".into()
    } else {
        format!("the next attempt is due {}", due(now, s.retry_at))
    });
    c.detail = parts.join("; ");
    "read it with the control connection above: a wait that keeps growing while the stream stays down points at the server or the line to it, not at this host; a wait that stays at 10s means the WireGuard handshake is recent, so the line works and the server is not accepting the control connection".clone_into(&mut c.next);
}

fn stream_liveness(c: &mut Check, now: OffsetDateTime, s: &DoctorStream) {
    c.set(status::UNKNOWN, reason::NO_THRESHOLD);
    let mut parts = vec![if s.last_ping_at.is_zero() {
        "no ping has been sent on this connection".to_owned()
    } else {
        format!("the last ping went out {}", when(now, s.last_ping_at))
    }];
    parts.push(if s.last_pong_at.is_zero() {
        "no pong has come back on it".to_owned()
    } else {
        format!("the last pong came back {}", when(now, s.last_pong_at))
    });
    if s.awaiting_pong {
        parts.push("a pong is outstanding right now".into());
    }
    c.detail = parts.join("; ");
    "these are the agent's own keepalives on the control stream. They are cleared whenever it reconnects, so an empty pair on a stream that is up means the connection is new".clone_into(&mut c.next);
}

// --- Tunnel 群 ---

fn tunnel_local(c: &mut Check, now: OffsetDateTime, st: &DoctorRuntimeState) {
    let t = &st.tunnel;
    if t.state != "error" {
        c.status = status::OK;
        c.detail = format!(
            "the tunnel is up to {}; {}",
            or_dash(&t.endpoint),
            handshake_text(now, t.last_handshake)
        );
        return;
    }
    if !t.present {
        no_tunnel(c, &t.reason);
        return;
    }
    if t.reason == REASON_HANDSHAKE_PENDING {
        c.set(status::UNKNOWN, reason::HANDSHAKE_PENDING);
        c.detail = format!(
            "the tunnel is up to {}, but no handshake has been established on it yet",
            or_dash(&t.endpoint)
        );
        "a tunnel that was just built always passes through this state. If it stays here, the VPS's WireGuard UDP port, this line's firewall or the ISP may be dropping the tunnel's UDP; run wgft server doctor on the VPS to see the same tunnel from the other side".clone_into(&mut c.next);
        return;
    }
    if t.endpoint.is_empty() {
        c.set(status::FAILED, reason::TUNNEL_ERROR_NO_ENDPOINT);
        c.detail = format!(
            "the tunnel reports an error and holds no resolved endpoint to carry traffic: {}",
            t.reason
        );
        "read the agent's log for what it says while building and driving the tunnel, with journalctl -u wgft-agent, or docker logs for a container. The wg endpoint resolve line above says whether the peer's name resolves from here".clone_into(&mut c.next);
        return;
    }
    c.set(status::UNKNOWN, reason::TUNNEL_ERROR_ENDPOINT_KEPT);
    if t.reason.starts_with(REASON_WG_REFUSED) {
        c.detail = format!(
            "the agent refused the wg configuration the server sent and keeps the interface and rules of the last configuration it applied, with the endpoint {}: {}",
            t.endpoint, t.reason
        );
        "while the server runs with the configuration this agent refused, such as another tunnel address, traffic through the tunnel stops, since the two sides no longer agree. If the server's operator moved the range on purpose, register this agent again with a new join string; otherwise find out who changed the server".clone_into(&mut c.next);
        return;
    }
    c.detail = format!(
        "the tunnel reports an error but still holds the resolved endpoint {}, which can keep carrying traffic: {}",
        t.endpoint, t.reason
    );
    "read the agent's log for the same error with its context, with journalctl -u wgft-agent, or docker logs for a container. Traffic can still flow over the endpoint it resolved earlier, so this is not by itself a stop".clone_into(&mut c.next);
}

fn no_tunnel(c: &mut Check, why: &str) {
    if why.starts_with(REASON_NO_TUNNEL_BUILD_FAILED) {
        c.set(status::FAILED, reason::TUNNEL_BUILD_FAILED);
        c.detail = format!("there is no tunnel: {why}");
        "read why the build failed in the agent's log, with journalctl -u wgft-agent, or docker logs for a container. The wg configuration comes from the server, so wgft rule ls and the server's log on the VPS say what it was told to build".clone_into(&mut c.next);
    } else if why.contains(REASON_FULL_STATE_NOT_RECEIVED) {
        c.set(status::UNKNOWN, reason::FULL_STATE_PENDING);
        c.detail = format!("there is no tunnel yet: {why}");
        "this is where an agent sits until the server answers it. The control connection line above says whether the stream is up".clone_into(&mut c.next);
    } else {
        c.set(status::UNKNOWN, reason::NO_TUNNEL);
        c.detail = format!("there is no tunnel right now: {why}");
        "closing the tunnel is also a normal step, after agent rotate-key or while the agent stops, so this alone is not a fault. Run this command again to see whether one comes back".clone_into(&mut c.next);
    }
}

/// WireGuard のソケットのバッファの条件 (byte)。Linux は要求の 2 倍を返す。
const SOCKBUF_REQUIRED: i64 = 14_680_064;
/// 要求する値 (byte)。
const SOCKBUF_REQUESTED: i64 = 7_340_032;

fn socket_buffers(c: &mut Check, now: OffsetDateTime, st: &DoctorRuntimeState) {
    let t = &st.tunnel;
    if !t.present {
        c.set(status::SKIPPED, reason::NO_TUNNEL);
        "there is no tunnel now, so there are no WireGuard UDP sockets to measure"
            .clone_into(&mut c.detail);
        "the tunnel line above says why there is none; the agent measures its sockets each time it builds the tunnel".clone_into(&mut c.next);
        return;
    }
    let Some(b) = &t.socket_buffers else {
        c.set(status::UNKNOWN, reason::SOCKET_BUFFERS_NOT_REPORTED);
        "the running agent did not report its WireGuard UDP socket buffers"
            .clone_into(&mut c.detail);
        RESTART_FOR_DOCTOR_NEXT.clone_into(&mut c.next);
        return;
    };
    if !b.supported {
        c.set(status::NOT_TESTED, reason::NOT_MEASURED_ON_THIS_OS);
        "the WireGuard UDP socket buffers are measured on Linux only; how this OS sizes them has not been verified".clone_into(&mut c.detail);
        return;
    }
    if !b.error.is_empty() {
        c.set(status::UNKNOWN, reason::SOCKET_BUFFERS_UNREADABLE);
        c.detail = format!(
            "the running agent could not measure its WireGuard UDP socket buffers: {}",
            b.error
        );
        "read the agent's log from the time the tunnel was built, with journalctl -u wgft-agent, or docker logs for a container".clone_into(&mut c.next);
        return;
    }
    let req = if b.required <= 0 {
        SOCKBUF_REQUIRED
    } else {
        b.required
    };
    let measured = format!(
        "the WireGuard UDP sockets on port {} got a receive buffer of {} bytes and a send buffer of {} bytes when the tunnel was built {}",
        b.port,
        b.recv,
        b.send,
        when(now, t.started_at)
    );
    if b.recv >= req && b.send >= req {
        c.status = status::OK;
        c.detail = format!("{measured}; userspace mode requires {req} bytes each");
        return;
    }
    c.set(status::FAILED, reason::SOCKET_BUFFER_SHORT);
    c.detail = format!("{measured}; userspace mode requires at least {req} bytes each");
    c.next = format!(
        "set net.core.rmem_max and net.core.wmem_max to {SOCKBUF_REQUESTED} or more on this host, or on the container host when the agent runs in a container, for example in a file under /etc/sysctl.d applied with sysctl --system, then restart the agent so that it opens new sockets. Linux gives a socket twice the size it asks for, so {SOCKBUF_REQUESTED} in the sysctl reads here as {SOCKBUF_REQUIRED}. wgft never changes these sysctls"
    );
}

fn udp_accounting(c: &mut Check, st: &DoctorRuntimeState) {
    let t = &st.tunnel;
    if !t.present {
        c.set(status::SKIPPED, reason::NO_TUNNEL);
        "there is no tunnel now, so there is no UDP to account for".clone_into(&mut c.detail);
        "the tunnel line above says why there is none".clone_into(&mut c.next);
        return;
    }
    match &t.udp_accounting {
        None => {
            c.set(status::UNKNOWN, reason::UDP_ACCOUNTING_NOT_REPORTED);
            "the running agent did not report its UDP receive accounting".clone_into(&mut c.detail);
            RESTART_FOR_DOCTOR_NEXT.clone_into(&mut c.next);
        }
        Some(u) if u.stopped => {
            c.set(status::FAILED, reason::UDP_ACCOUNTING_STOPPED);
            c.detail = format!(
                "the UDP receive accounting of the tunnel found an internal inconsistency and stopped all UDP on the tunnel: {}; TCP rules keep working",
                u.error
            );
            "restart the agent to resume UDP, and report this as a bug with the agent's log, from journalctl -u wgft-agent or docker logs for a container".clone_into(&mut c.next);
        }
        Some(_) => {
            c.status = status::OK;
            "the UDP receive accounting of the tunnel is consistent".clone_into(&mut c.detail);
        }
    }
}

fn handshake_text(now: OffsetDateTime, h: GoTime) -> String {
    if h.is_zero() {
        "no handshake has been established on it".into()
    } else {
        format!("the last handshake was {}", when(now, h))
    }
}

fn watchdog(c: &mut Check, now: OffsetDateTime, st: &DoctorRuntimeState) {
    c.set(status::UNKNOWN, reason::NO_THRESHOLD);
    let t = &st.tunnel;
    let mut parts = vec![if t.started_at.is_zero() {
        "no tunnel is up to watch".to_owned()
    } else {
        format!("the tunnel in place was built {}", when(now, t.started_at))
    }];
    parts.push(format!(
        "the rebuild interval in force is {}",
        go_duration(round(t.watchdog.rebuild_interval, 1_000_000_000))
    ));
    parts.push(if t.watchdog.retry_at.is_zero() {
        "no rebuild is waiting to be retried".into()
    } else {
        format!(
            "a failed build is due to be retried {}",
            due(now, t.watchdog.retry_at)
        )
    });
    c.detail = parts.join("; ");
    "the interval is the value the agent judges by, not a countdown: the time left is not kept anywhere, so it is not shown. A rebuild pending here means the tunnel line above says why the last build failed".clone_into(&mut c.next);
}

fn transfer(c: &mut Check, now: OffsetDateTime, st: &DoctorRuntimeState) {
    let t = &st.tunnel;
    if !t.present {
        c.set(status::UNKNOWN, reason::NO_TUNNEL);
        "there is no tunnel now, so it carries no counters".clone_into(&mut c.detail);
        "the tunnel line above says why there is none".clone_into(&mut c.next);
        return;
    }
    c.set(status::UNKNOWN, reason::NO_THRESHOLD);
    c.detail = format!(
        "{} bytes received and {} bytes sent on the tunnel built {}",
        t.rx_bytes,
        t.tx_bytes,
        when(now, t.started_at)
    );
    "a tunnel that nobody is using stays at these numbers and is healthy, so this command sets no threshold on them. Run it twice while traffic should be flowing to see whether they move".clone_into(&mut c.next);
}

// --- Relay 群 ---

/// 並べるルールの本数と拒否の組の数の上限。
const MAX_RULE_LINES: usize = 4;
const MAX_REFUSAL_LINES: usize = 6;

fn and_more(rest: usize) -> String {
    format!("and {rest} more")
}

fn listeners(c: &mut Check, st: &DoctorRuntimeState, agent_name: &str) {
    if st.agent_disabled {
        c.set(status::SKIPPED, reason::AGENT_DISABLED);
        c.detail = format!(
            "the server has disabled this agent; it opens no listeners until wgft agent enable {} is run on the VPS",
            or_dash(agent_name)
        );
        return;
    }
    if no_relay(c, st, "which listeners are open") {
        return;
    }
    if st.rules.is_empty() {
        c.status = status::OK;
        "the relay holds no rules, so it opens no listeners".clone_into(&mut c.detail);
        return;
    }
    let (bad, good): (Vec<&DoctorRule>, Vec<&DoctorRule>) =
        st.rules.iter().partition(|r| r.state == "error");
    if bad.is_empty() {
        c.status = status::OK;
        c.detail = format!(
            "{} rule{}, all listening: {}",
            good.len(),
            plural_s(good.len()),
            rule_lines(&good).join("; ")
        );
        return;
    }
    c.set(status::FAILED, reason::LISTENER_ERROR);
    c.detail = format!(
        "{} of {} rule{} cannot serve: {}",
        bad.len(),
        st.rules.len(),
        plural_s(st.rules.len()),
        rule_lines(&bad).join("; ")
    );
    if !good.is_empty() {
        let _ = write!(
            c.detail,
            ". The other {} rule{} listen",
            good.len(),
            plural_s(good.len())
        );
    }
    "a listener that cannot bind names a port another process on this host already holds; free it, or have the server publish another public port. A target that cannot be reached names the LAN service; check that it is up and that this host can reach it".clone_into(&mut c.next);
}

fn count(n: i64) -> usize {
    usize::try_from(n).unwrap_or(0)
}

fn rule_lines(rules: &[&DoctorRule]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        if i == MAX_RULE_LINES {
            out.push(and_more(rules.len() - MAX_RULE_LINES));
            break;
        }
        let mut line = format!(
            "{} {}: {} of {} listener{} open",
            r.id,
            or_dash(&r.proto),
            r.listening,
            r.listeners,
            plural_s(count(r.listeners))
        );
        if r.bind_errors > 0 {
            let _ = write!(line, ", {} cannot bind: {}", r.bind_errors, r.bind_error);
        }
        if r.target_errors > 0 {
            let _ = write!(
                line,
                ", {} cannot reach the target: {}",
                r.target_errors, r.target_error
            );
        }
        if r.bind_errors == 0 && r.target_errors == 0 && !r.reason.is_empty() {
            line.push_str(", ");
            line.push_str(&r.reason);
        }
        out.push(line);
    }
    out
}

fn sessions(c: &mut Check, st: &DoctorRuntimeState) {
    if no_relay(c, st, "how many connections it carries") {
        return;
    }
    c.set(status::UNKNOWN, reason::NO_THRESHOLD);
    let mut parts: Vec<String> = st
        .budgets
        .iter()
        .map(|b| {
            let mut p = format!(
                "{} budget {}, {} in use, {} rule{} admitted",
                b.proto,
                b.total,
                b.in_use,
                b.rules,
                plural_s(count(b.rules))
            );
            if b.rules > 1 {
                let _ = write!(p, ", cap {} per rule, minimum {}", b.rule_cap, b.reserve);
            }
            p
        })
        .collect();
    if st.rules.is_empty() {
        parts.push("the relay holds no rules".into());
    } else {
        let mut lines = Vec::new();
        for (i, r) in st.rules.iter().enumerate() {
            if i == MAX_RULE_LINES {
                lines.push(and_more(st.rules.len() - MAX_RULE_LINES));
                break;
            }
            lines.push(format!(
                "{} {} flow{} in {} session{}",
                r.id,
                r.flows,
                plural_s(count(r.flows)),
                r.sessions,
                plural_s(count(r.sessions))
            ));
        }
        parts.push(lines.join("; "));
    }
    c.detail = parts.join("; ");
    "flows are what the budget counts: one per public-side connection for TCP, one per source address and port for UDP. Sessions count both sides of a TCP relay, so the two numbers differ by design".clone_into(&mut c.next);
}

fn refusals(c: &mut Check, now: OffsetDateTime, st: &DoctorRuntimeState) {
    if no_relay(c, st, "how many flows it refused") {
        return;
    }
    c.set(status::UNKNOWN, reason::NO_THRESHOLD);
    let start = format!(
        "since this tunnel was built {}",
        when(now, st.refusals_since)
    );
    let mut lines = Vec::new();
    let mut total: u64 = 0;
    let mut groups = 0;
    for b in &st.budgets {
        for r in &b.refusals {
            total = total.saturating_add(r.count);
            groups += 1;
            if lines.len() < MAX_REFUSAL_LINES {
                lines.push(format!(
                    "{} {} {} {}",
                    r.rule_id, b.proto, r.reason, r.count
                ));
            }
        }
    }
    if groups > lines.len() {
        lines.push(and_more(groups - lines.len()));
    }
    c.detail = if total == 0 {
        format!("no flow has been refused {start}")
    } else {
        format!(
            "{total} flow{} refused {start}: {}",
            plural_s(usize::try_from(total).unwrap_or(usize::MAX)),
            lines.join("; ")
        )
    };
    "the count starts again at zero whenever the tunnel is rebuilt, so read it against the time above. budget means the whole process was full, rule_cap means that one rule hit its share, reserve means the room left was held for the unfilled minimums of rules, floor means a rule below its minimum left the room to the first flows of other rules and the spare, spare means the room left was kept for a rule added later".clone_into(&mut c.next);
}

/// 中継がまだ無い実行の扱い。フロー数の予算の有無が中継の有無を表す。
fn no_relay(c: &mut Check, st: &DoctorRuntimeState, what: &str) -> bool {
    if !st.budgets.is_empty() {
        return false;
    }
    c.set(status::SKIPPED, reason::NO_RELAY);
    c.detail = format!(
        "there is no relay running, so {what} could not be read: the relay is built with the tunnel, and there is no tunnel now"
    );
    "the tunnel line above says why there is none".clone_into(&mut c.next);
    true
}

fn allow_targets_value(c: &mut Check, a: &DoctorAllowTargets) {
    c.status = status::OK;
    let env = if a.env.is_empty() {
        wgft_agent::config::allow_targets::ENV
    } else {
        a.env.as_str()
    };
    if !a.set {
        "the running agent enforces no target allowlist, so the server can name any target this host can reach".clone_into(&mut c.detail);
        c.next = format!("set {env} on this host and restart the agent to hold it to a list");
        return;
    }
    c.detail = format!("the running agent enforces {env}={}", a.list);
    "a rule whose target is outside this list is refused here, and the server shows that refusal as the rule's reason".clone_into(&mut c.next);
}

// --- 時刻の書き方 ---

/// Go の `time.Duration.Round`。半分は 0 から遠い側へ丸める。
fn round(d: i64, m: i64) -> i64 {
    let r = d % m;
    if d < 0 {
        let r = -r;
        if r + r < m {
            return d + r;
        }
        return d.checked_sub(m - r).unwrap_or(i64::MIN);
    }
    if r + r < m {
        return d - r;
    }
    d.checked_add(m - r).unwrap_or(i64::MAX)
}

fn nanos_between(later: OffsetDateTime, earlier: OffsetDateTime) -> i64 {
    i64::try_from((later - earlier).whole_nanoseconds()).unwrap_or(if later > earlier {
        i64::MAX
    } else {
        i64::MIN
    })
}

/// 過ぎた時刻を、その時刻と今からの隔たりで表す。零の時刻は Go の零の値として扱う。
fn when(now: OffsetDateTime, t: GoTime) -> String {
    let at = go_zero_or(t);
    // Go の doctor.Since: 負なら 0、秒で切り捨てる
    let d = nanos_between(now, at).max(0);
    format!(
        "at {}, {} ago",
        rfc3339(at),
        go_duration(d - d % 1_000_000_000)
    )
}

/// これから来る時刻を、その時刻と今からの隔たりで表す。
fn due(now: OffsetDateTime, t: GoTime) -> String {
    let at = go_zero_or(t);
    let d = nanos_between(at, now);
    let d = d - d % 1_000_000_000;
    if d <= 0 {
        format!("at {}, now", rfc3339(at))
    } else {
        format!("at {}, in {}", rfc3339(at), go_duration(d))
    }
}

fn go_zero_or(t: GoTime) -> OffsetDateTime {
    t.get().unwrap_or_else(|| {
        // Go の零の値 0001-01-01T00:00:00Z
        OffsetDateTime::from_unix_timestamp(-62_135_596_800).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_like_go() {
        assert_eq!(round(1_499_999_999, 1_000_000_000), 1_000_000_000);
        assert_eq!(round(1_500_000_000, 1_000_000_000), 2_000_000_000);
        assert_eq!(round(-1_500_000_000, 1_000_000_000), -2_000_000_000);
        assert_eq!(round(2_000_000_000, 1_000_000), 2_000_000_000);
    }

    #[test]
    fn classifies_replies() {
        assert_eq!(
            classify(String::new(), "error: unknown command\n").kind,
            LiveKind::Unsupported
        );
        assert_eq!(
            classify(String::new(), "{\"error\":\"x\"}\n").kind,
            LiveKind::AgentError
        );
        assert_eq!(
            classify(String::new(), "{\"runtime_state_timeout\":2000000000}").kind,
            LiveKind::RuntimeBusy
        );
        assert_eq!(
            classify(String::new(), "{}").kind,
            LiveKind::ReplyUnreadable
        );
        assert_eq!(
            classify(String::new(), "nope").kind,
            LiveKind::ReplyUnreadable
        );
    }
}
