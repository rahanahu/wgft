//! `wgft agent doctor`。Go の `cmd/wgft/agentdoctor*.go` を移したもので、検査の ID、並び、理由の符号、
//! 総合判定、終了コード、人向けの文は Go と同じにする。仕様は `docs/design/spec/control-socket.md` の
//! `agent doctor --json`、意味は `docs/design/diagnosis/agent-evidence.md` と `agent-judgment.md`、
//! 作りは `docs/design/v2/agent-parity.md` の「agent doctor のコマンド」にある。
//!
//! 検査は副作用を持たない。認証情報ファイルは DACL を付け直さない読みで読み、稼働の判定はロック
//! ファイルを作らない読みで行う。稼働中の agent へは、その制御ソケットに 1 行の `doctor` を送って
//! 読むだけである。カーネルモードの agent は、このビルドがカーネルを読めないので診断せずに拒む。

mod checks;
mod live;
mod os;
mod output;

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use time::OffsetDateTime;
use wgft_agent::controlapi::DoctorResponse;
use wgft_agent::credentials::{Credentials, LockState};
use wgft_agent::hostaddr::Interface;
use wgft_agent::{AgentError, Refusal};

pub use output::{json_report, write_json, write_report};

// 検査の ID。並びは設計の表の順である。
pub(crate) const CHECK_PLATFORM: &str = "host.platform";
pub(crate) const CHECK_PRIVILEGES: &str = "host.privileges";
pub(crate) const CHECK_INTERFACES: &str = "host.interfaces";
pub(crate) const CHECK_HOST_RESOLVE: &str = "host.resolve";
pub(crate) const CHECK_CREDENTIALS: &str = "agent.credentials";
pub(crate) const CHECK_PROCESS: &str = "agent.process";
pub(crate) const CHECK_LAST_STATE: &str = "agent.last_state";
pub(crate) const CHECK_CONTROL: &str = "agent.control";
pub(crate) const CHECK_STREAM_CONN: &str = "stream.connection";
pub(crate) const CHECK_STREAM_BACKOFF: &str = "stream.backoff";
pub(crate) const CHECK_STREAM_LIVE: &str = "stream.liveness";
pub(crate) const CHECK_WG_RESOLVE: &str = "tunnel.resolve";
pub(crate) const CHECK_TUNNEL_LOCAL: &str = "tunnel.local";
pub(crate) const CHECK_SOCKET_BUFS: &str = "tunnel.socket_buffers";
pub(crate) const CHECK_UDP_ACCT: &str = "tunnel.udp_accounting";
pub(crate) const CHECK_WATCHDOG: &str = "tunnel.watchdog";
pub(crate) const CHECK_TRANSFER: &str = "tunnel.transfer";
pub(crate) const CHECK_LISTENERS: &str = "relay.listeners";
pub(crate) const CHECK_SESSIONS: &str = "relay.sessions";
pub(crate) const CHECK_REFUSALS: &str = "relay.refusals";
pub(crate) const CHECK_ALLOW_TARGETS: &str = "relay.allow_targets";
pub(crate) const CHECK_DP_INTERFACE: &str = "dataplane.interface";
pub(crate) const CHECK_DP_TABLE: &str = "dataplane.table";
pub(crate) const CHECK_FORWARDING: &str = "host.forwarding";

/// 設計の表の並び。
pub(crate) const CHECK_ORDER: &[&str] = &[
    CHECK_PLATFORM,
    CHECK_PRIVILEGES,
    CHECK_INTERFACES,
    CHECK_HOST_RESOLVE,
    CHECK_CREDENTIALS,
    CHECK_PROCESS,
    CHECK_LAST_STATE,
    CHECK_CONTROL,
    CHECK_STREAM_CONN,
    CHECK_STREAM_BACKOFF,
    CHECK_STREAM_LIVE,
    CHECK_WG_RESOLVE,
    CHECK_TUNNEL_LOCAL,
    CHECK_SOCKET_BUFS,
    CHECK_UDP_ACCT,
    CHECK_WATCHDOG,
    CHECK_TRANSFER,
    CHECK_LISTENERS,
    CHECK_SESSIONS,
    CHECK_REFUSALS,
    CHECK_ALLOW_TARGETS,
    CHECK_DP_INTERFACE,
    CHECK_DP_TABLE,
    CHECK_FORWARDING,
];

// 群。人向けの出力の見出しになる。
pub(crate) const GROUP_HOST: &str = "Host";
pub(crate) const GROUP_CREDENTIALS: &str = "Credentials";
pub(crate) const GROUP_CONNECTION: &str = "Connection";
pub(crate) const GROUP_TUNNEL: &str = "Tunnel";
pub(crate) const GROUP_RELAY: &str = "Relay";
pub(crate) const GROUP_DATAPLANE: &str = "Dataplane";

/// 理由の符号。JSON の `reason` の値で、機械向けの保証である。1 つの符号は 1 つの事実だけを表す。
/// 一覧は設計の表 (`docs/design/diagnosis/agent-output.md`) にあり、試験が照らす。カーネルモードの検査
/// だけが使う符号は、このビルドがカーネルモードの agent を診断しないので持たない。
pub(crate) mod reason {
    pub(crate) const NOT_RUNNING: &str = "agent_not_running";
    pub(crate) const RESOLVE_FAILED: &str = "resolve_failed";
    pub(crate) const NO_LAST_STATE: &str = "no_last_state";
    pub(crate) const NO_WG_ENDPOINT: &str = "no_wg_endpoint";
    pub(crate) const CREDENTIALS_MISSING: &str = "credentials_missing";
    pub(crate) const CREDENTIALS_UNREADABLE: &str = "credentials_unreadable";
    pub(crate) const DATA_DIR_UNREADABLE: &str = "data_dir_unreadable";
    pub(crate) const CREDENTIALS_MALFORMED: &str = "credentials_malformed";
    pub(crate) const NOT_REGISTERED: &str = "not_registered";
    pub(crate) const LOCK_UNREADABLE: &str = "lock_unreadable";
    pub(crate) const PERMISSION_DENIED: &str = "permission_denied";
    pub(crate) const PERMISSION_NOT_DETERMINED: &str = "permission_not_determined";
    pub(crate) const INTERFACES_UNREADABLE: &str = "interfaces_unreadable";
    pub(crate) const CONFIG_UNREADABLE: &str = "config_unreadable";
    pub(crate) const RUNNING_AS_ROOT: &str = "running_as_root";
    pub(crate) const CONTROL_UNREACHABLE: &str = "control_socket_unreachable";
    pub(crate) const CONTROL_PATH_TOO_LONG: &str = "control_socket_path_too_long";
    pub(crate) const DOCTOR_UNSUPPORTED: &str = "doctor_unsupported";
    pub(crate) const DOCTOR_FAILED: &str = "doctor_failed";
    pub(crate) const DOCTOR_UNREADABLE: &str = "doctor_reply_unreadable";
    pub(crate) const RUNTIME_BUSY: &str = "runtime_state_busy";
    pub(crate) const NO_THRESHOLD: &str = "no_threshold";
    pub(crate) const RECONNECTING: &str = "reconnecting";
    pub(crate) const SERVER_CERT_MISMATCH: &str = "server_cert_mismatch";
    pub(crate) const KEY_CHANGE_LIMITED: &str = "key_change_limited";
    pub(crate) const HANDSHAKE_PENDING: &str = "handshake_pending";
    pub(crate) const NO_TUNNEL: &str = "no_tunnel";
    pub(crate) const FULL_STATE_PENDING: &str = "full_state_pending";
    pub(crate) const TUNNEL_BUILD_FAILED: &str = "tunnel_build_failed";
    pub(crate) const TUNNEL_ERROR_NO_ENDPOINT: &str = "tunnel_error_no_endpoint";
    pub(crate) const TUNNEL_ERROR_ENDPOINT_KEPT: &str = "tunnel_error_endpoint_kept";
    pub(crate) const LISTENER_ERROR: &str = "listener_error";
    pub(crate) const NO_RELAY: &str = "no_relay";
    pub(crate) const AGENT_DISABLED: &str = "agent_disabled";
    pub(crate) const SOCKET_BUFFER_SHORT: &str = "socket_buffer_below_requirement";
    pub(crate) const SOCKET_BUFFERS_UNREADABLE: &str = "socket_buffers_unreadable";
    pub(crate) const SOCKET_BUFFERS_NOT_REPORTED: &str = "socket_buffers_not_reported";
    pub(crate) const NOT_MEASURED_ON_THIS_OS: &str = "not_measured_on_this_os";
    pub(crate) const UDP_ACCOUNTING_STOPPED: &str = "udp_accounting_stopped";
    pub(crate) const UDP_ACCOUNTING_NOT_REPORTED: &str = "udp_accounting_not_reported";
    pub(crate) const USERSPACE_MODE: &str = "userspace_mode";

    /// 試験が設計の表と照らす一覧。
    #[cfg(test)]
    pub(crate) const ALL: &[&str] = &[
        NOT_RUNNING,
        RESOLVE_FAILED,
        NO_LAST_STATE,
        NO_WG_ENDPOINT,
        CREDENTIALS_MISSING,
        CREDENTIALS_UNREADABLE,
        DATA_DIR_UNREADABLE,
        CREDENTIALS_MALFORMED,
        NOT_REGISTERED,
        LOCK_UNREADABLE,
        PERMISSION_DENIED,
        PERMISSION_NOT_DETERMINED,
        INTERFACES_UNREADABLE,
        CONFIG_UNREADABLE,
        RUNNING_AS_ROOT,
        CONTROL_UNREACHABLE,
        CONTROL_PATH_TOO_LONG,
        DOCTOR_UNSUPPORTED,
        DOCTOR_FAILED,
        DOCTOR_UNREADABLE,
        RUNTIME_BUSY,
        NO_THRESHOLD,
        RECONNECTING,
        SERVER_CERT_MISMATCH,
        KEY_CHANGE_LIMITED,
        HANDSHAKE_PENDING,
        NO_TUNNEL,
        FULL_STATE_PENDING,
        TUNNEL_BUILD_FAILED,
        TUNNEL_ERROR_NO_ENDPOINT,
        TUNNEL_ERROR_ENDPOINT_KEPT,
        LISTENER_ERROR,
        NO_RELAY,
        AGENT_DISABLED,
        SOCKET_BUFFER_SHORT,
        SOCKET_BUFFERS_UNREADABLE,
        SOCKET_BUFFERS_NOT_REPORTED,
        NOT_MEASURED_ON_THIS_OS,
        UDP_ACCOUNTING_STOPPED,
        UDP_ACCOUNTING_NOT_REPORTED,
        USERSPACE_MODE,
    ];
}

/// 状態の語。
pub(crate) mod status {
    pub(crate) const OK: &str = "ok";
    pub(crate) const FAILED: &str = "failed";
    pub(crate) const UNKNOWN: &str = "unknown";
    pub(crate) const NOT_TESTED: &str = "not_tested";
    pub(crate) const SKIPPED: &str = "skipped";
}

/// 1 つの検査の結果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Check {
    /// 検査の ID。
    pub id: &'static str,
    /// 群。
    pub group: &'static str,
    /// 人向けの名前。
    pub label: &'static str,
    /// 状態の語。
    pub status: &'static str,
    /// 理由の符号。
    pub reason: &'static str,
    /// 人向けの所見。保証の外。
    pub detail: String,
    /// 人向けの次の手。保証の外。
    pub next: String,
    /// 総合判定と終了コード 1 を動かすか。
    pub verdict: bool,
    /// 呼び出し元が権限で証拠に届かなかったか。終了コード 2 に倒す。
    pub evidence_unreachable: bool,
    /// 値だけを示し合否を持たないか。人向けの出力だけが読む。
    pub value_only: bool,
}

impl Check {
    pub(crate) fn new(id: &'static str, group: &'static str, label: &'static str) -> Check {
        Check {
            id,
            group,
            label,
            ..Check::default()
        }
    }

    pub(crate) fn set(&mut self, status: &'static str, reason: &'static str) {
        self.status = status;
        self.reason = reason;
    }
}

/// 試していない範囲 1 件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotTested {
    /// 名前。
    pub id: &'static str,
    /// 説明。
    pub detail: String,
}

/// 1 回の診断の結果全体。
#[derive(Clone, Debug)]
pub struct Report {
    /// 診断した時刻。
    pub checked_at: OffsetDateTime,
    /// 報告が答えるデータディレクトリ (絶対パス)。
    pub data_dir: String,
    /// 検査。
    pub checks: Vec<Check>,
    /// 履歴の文。
    pub history: String,
    /// 試していない範囲。
    pub not_tested: Vec<NotTested>,
    /// 既定のデータディレクトリを見た実行で、終了の 1 行へ添える句。
    pub default_dir_note: String,
}

/// 権限の判定。副作用なしに判定できない場合を、成功でも失敗でもない値として持つ。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    NotDetermined,
    Allowed,
    Denied,
}

/// 制御ソケットへの接続。
pub(crate) trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

/// 証拠の出どころ。OS を読む入口を差し替えられるので、試験は場面を並べられる。
pub struct Input {
    pub(crate) now: OffsetDateTime,
    pub(crate) data_dir: String,
    pub(crate) credentials_path: PathBuf,
    pub(crate) version: String,
    pub(crate) platform: String,
    pub(crate) max_udp_flows: u32,
    pub(crate) max_tcp_flows: u32,
    pub(crate) user: String,
    pub(crate) config_path: PathBuf,
    /// 設定ファイルがあるのに権限で読めなかった誤り。
    pub(crate) config_unreadable: Option<String>,
    /// 設定ファイルを読めなかったために、データディレクトリを既定値から取ったか。
    pub(crate) data_dir_assumed: bool,
    /// データディレクトリを既定値から取ったか。
    pub(crate) data_dir_default: bool,
    pub(crate) inspect: InspectFn,
    pub(crate) resolve: ResolveFn,
    pub(crate) interfaces: InterfacesFn,
    pub(crate) readable: ReadableFn,
    pub(crate) dir_create_access: AccessFn,
    pub(crate) dial: DialFn,
    pub(crate) euid: Box<dyn Fn() -> i64>,
    pub(crate) is_dir: Box<dyn Fn(&Path) -> bool>,
}

/// ロックファイルの状態を読む入口。
pub(crate) type InspectFn = Box<dyn Fn(&Path) -> io::Result<LockState>>;
/// 名前を解決する入口。
pub(crate) type ResolveFn = Box<dyn Fn(&str) -> Result<Vec<String>, String>>;
/// インタフェースを読む入口。
pub(crate) type InterfacesFn = Box<dyn Fn() -> io::Result<Vec<Interface>>>;
/// 読めるかを判定する入口。
pub(crate) type ReadableFn = Box<dyn Fn(&Path, bool) -> (Access, String)>;
/// 新しいファイルを作れるかを判定する入口。
pub(crate) type AccessFn = Box<dyn Fn(&Path) -> (Access, String)>;
/// 制御ソケットに繋ぐ入口。
pub(crate) type DialFn = Box<dyn Fn(&Path) -> io::Result<Box<dyn Conn>>>;

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("data_dir", &self.data_dir)
            .field("credentials_path", &self.credentials_path)
            .finish_non_exhaustive()
    }
}

impl Input {
    /// OS を読む既定の入口で作る。
    pub(crate) fn for_host(data_dir: String) -> Input {
        let credentials_path = crate::agent_keys::credentials_path(&data_dir);
        Input {
            now: OffsetDateTime::now_utc(),
            data_dir,
            credentials_path,
            version: crate::version(),
            platform: os::platform(),
            max_udp_flows: 8192,
            max_tcp_flows: 2048,
            user: os::running_user_text(),
            config_path: PathBuf::new(),
            config_unreadable: None,
            data_dir_assumed: false,
            data_dir_default: false,
            inspect: Box::new(wgft_agent::credentials::inspect_lock),
            resolve: Box::new(os::resolve),
            interfaces: Box::new(wgft_agent::hostaddr::interfaces),
            readable: Box::new(os::readable),
            dir_create_access: Box::new(os::dir_create_access),
            dial: Box::new(live::dial),
            euid: Box::new(wgft_agent::platform::procinfo::euid),
            is_dir: Box::new(|p| std::fs::metadata(p).is_ok_and(|m| m.is_dir())),
        }
    }
}

/// 認証情報ファイルの読み取りの状態。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredState {
    Ok,
    Missing,
    Unreadable,
    Malformed,
    /// データディレクトリを権限で開けず、ファイルがあるかどうかを判定できない。
    DirUnreadable,
}

/// 認証情報ファイルの読み取りの結果。
#[derive(Clone, Debug)]
pub(crate) struct CredFile {
    pub(crate) state: CredState,
    pub(crate) creds: Option<Credentials>,
    pub(crate) err: String,
    /// JSON として読む前に拒んだか (symlink、通常のファイルでないもの、大きすぎるもの)。
    pub(crate) refused_before_parsing: bool,
    pub(crate) mode: Option<u32>,
}

impl CredFile {
    /// 登録が済んでいるか。恒久トークンの有無で決める。
    pub(crate) fn registered(&self) -> bool {
        self.state == CredState::Ok
            && self
                .creds
                .as_ref()
                .is_some_and(|c| !c.permanent_token.is_empty())
    }
}

/// 稼働の判定。
#[derive(Clone, Debug)]
pub(crate) struct RunState {
    pub(crate) state: Option<LockState>,
    pub(crate) err: String,
    /// ロックファイルを権限で開けなかったか。
    pub(crate) permission_denied: bool,
}

impl RunState {
    pub(crate) fn running(&self) -> bool {
        self.state == Some(LockState::Locked)
    }

    pub(crate) fn undetermined(&self) -> bool {
        self.state.is_none()
    }
}

/// 制御ソケットから読んだ結果の区分。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveKind {
    NotAttempted,
    Ok,
    RuntimeBusy,
    AgentError,
    Unsupported,
    ReplyUnreadable,
    Denied,
    PathTooLong,
    Unreachable,
}

/// 制御ソケットから読んだ実行時の状態。
#[derive(Clone, Debug)]
pub(crate) struct Live {
    pub(crate) kind: LiveKind,
    pub(crate) path: String,
    pub(crate) err: String,
    pub(crate) resp: Option<DoctorResponse>,
    pub(crate) reply: String,
}

impl Live {
    pub(crate) fn not_attempted() -> Live {
        Live {
            kind: LiveKind::NotAttempted,
            path: String::new(),
            err: String::new(),
            resp: None,
            reply: String::new(),
        }
    }
}

/// カーネルモードの agent を診断しない拒否。
pub(crate) fn kernel_mode_refusal() -> Refusal {
    Refusal::prerequisite(
        "WGFT_MODE",
        "this build does not include the agent's kernel mode yet, so it cannot diagnose a kernel-mode agent; use a build that includes it",
    )
    .one_shot()
}

/// `agent.json` が知らないモードを記録しているときの拒否。値を名指す。
pub(crate) fn unknown_mode_refusal(mode: &str) -> Refusal {
    Refusal::prerequisite(
        "WGFT_MODE",
        format!(
            "agent.json records the mode {}, which this build does not know, so it cannot diagnose this agent; use a build that knows it",
            wgft_agent::config::gostd::quote(mode)
        ),
    )
    .one_shot()
}

/// agent のモード。稼働中の agent が答えた値を先に見て、無ければ認証情報ファイルの記録を見る。
fn mode_of(cred: &CredFile, live: &Live) -> String {
    if let Some(rs) = live.resp.as_ref().and_then(|r| r.runtime_state.as_ref()) {
        return if rs.mode == "kernel" {
            "kernel".into()
        } else {
            "userspace".into()
        };
    }
    match (&cred.state, &cred.creds) {
        (CredState::Ok, Some(c)) => c.recorded_mode().to_owned(),
        _ => String::new(),
    }
}

/// 検査一式を組み立てる。カーネルモードの agent なら診断せずに拒む。
///
/// # Errors
///
/// カーネルモードの agent の拒否を返す。
pub fn diagnose(input: &Input) -> Result<Report, AgentError> {
    let cred = checks::read_credentials(&input.credentials_path);
    let run = checks::inspect_process(input);
    let live = live::read(input, &run);
    let mode = mode_of(&cred, &live);
    match mode.as_str() {
        "" | "userspace" => {}
        "kernel" => return Err(kernel_mode_refusal().into()),
        other => return Err(unknown_mode_refusal(other).into()),
    }
    let in_doubt = checks::data_dir_in_doubt(input, &cred);
    let mut privileges = checks::privileges(input, in_doubt);
    checks::privileges_with_agent(&mut privileges, &live);
    let mut out = vec![
        checks::platform(input),
        privileges,
        checks::interfaces(input),
        checks::endpoint_resolve(input, &cred),
        checks::credentials(input, &cred),
        checks::process(input, &run, in_doubt),
        checks::last_state(&cred),
        checks::wg_resolve(input, &cred),
    ];
    out.extend(live::checks(input, &run, &live, display_name(&cred)));
    out.extend(checks::kernel_checks(&cred, &mode));
    out.sort_by_key(|c| CHECK_ORDER.iter().position(|id| *id == c.id));
    Ok(Report {
        checked_at: input.now,
        data_dir: os::abs_data_dir(&input.data_dir),
        checks: out,
        history: "this command only evaluates the current state. To find when this agent stopped working, read its log on this host with journalctl -u wgft-agent, or docker logs for a container, and the server log on the VPS.".into(),
        not_tested: not_tested(),
        default_dir_note: checks::default_dir_exit_note(input, &cred),
    })
}

fn display_name(cred: &CredFile) -> &str {
    cred.creds.as_ref().map_or("", |c| c.name.as_str())
}

/// 総合判定。証拠に届かなかった検査があれば `unknown`、判定に使う検査に `failed` があれば `failed`。
#[must_use]
pub fn verdict(rep: &Report) -> &'static str {
    let mut failed = false;
    for c in &rep.checks {
        if c.evidence_unreachable {
            return status::UNKNOWN;
        }
        if c.verdict && c.status == status::FAILED {
            failed = true;
        }
    }
    if failed { status::FAILED } else { status::OK }
}

/// 報告を終了の誤りに写す。`ok` は誤りなし、`failed` は終了コード 1、`unknown` は 2 である。
#[must_use]
pub fn exit(rep: &Report) -> Option<crate::failure::Failure> {
    let mut failed = Vec::new();
    let mut unreachable = Vec::new();
    for c in &rep.checks {
        if c.evidence_unreachable {
            unreachable.push(c.label);
        }
        if c.verdict && c.status == status::FAILED {
            failed.push(c.label);
        }
    }
    let note = if rep.default_dir_note.is_empty() {
        String::new()
    } else {
        format!("; {}", rep.default_dir_note)
    };
    match verdict(rep) {
        status::UNKNOWN => Some(crate::failure::Failure::unavailable(format!(
            "the diagnosis is incomplete: {} could not be read with this command's permissions{note}; {}",
            unreachable.join(", "),
            checks::SAME_PRINCIPAL_NEXT
        ))),
        status::FAILED => Some(crate::failure::Failure::new(
            format!(
                "this host's agent cannot forward traffic as it stands: {}{note}",
                failed.join(", ")
            ),
            1,
        )),
        _ => None,
    }
}

/// この診断が試していない範囲。何も壊れていない実行でも必ず出す。
fn not_tested() -> Vec<NotTested> {
    vec![
        NotTested {
            id: "the server side",
            detail: "what the server sees: whether it publishes each rule, what it reads from its own WireGuard, and whether the last handshake is healthy. This command never judges that; run wgft server doctor on the VPS for it.".into(),
        },
        NotTested {
            id: "reaching the vps",
            detail: "whether this host's line reaches the VPS's WireGuard UDP port and its agent API port. Nothing is dialled towards the VPS from here, so a blocked home firewall or ISP does not show up.".into(),
        },
        NotTested {
            id: "the targets",
            detail: "the LAN services this agent forwards to. Nothing is dialled from here. A running agent tests TCP targets itself every 30s, and its result is what the listeners line above reports; a UDP target cannot be tested at all, so no line here answers for one.".into(),
        },
        NotTested {
            id: "local settings",
            detail: "the effective value and source of every setting on this host. The agent prints those as its first lines when it starts; read them in its log.".into(),
        },
    ]
}

/// 制御ソケットに繋ぐまでの期限。
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// 要求を書いてから応答の 1 行を読み終えるまでの期限。
pub(crate) const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

pub mod command;

#[cfg(test)]
mod tests;
