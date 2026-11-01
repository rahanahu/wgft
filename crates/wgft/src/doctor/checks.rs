//! agent が止まっていても成立する検査 (Go の `cmd/wgft/agentdoctor.go`)。

use std::fmt::Write as _;
use std::io;
use std::path::Path;

use wgft_agent::credentials::{self, Credentials, LockState, ReadFileError};

use super::{
    Access, CHECK_CREDENTIALS, CHECK_DP_INTERFACE, CHECK_DP_TABLE, CHECK_FORWARDING,
    CHECK_HOST_RESOLVE, CHECK_INTERFACES, CHECK_LAST_STATE, CHECK_PLATFORM, CHECK_PRIVILEGES,
    CHECK_PROCESS, CHECK_WG_RESOLVE, Check, CredFile, CredState, GROUP_CREDENTIALS,
    GROUP_DATAPLANE, GROUP_HOST, GROUP_TUNNEL, Input, Live, RunState, reason, status,
};
use crate::doctor::output::{plural_s, upper_first};

/// 証拠に権限で届かなかった実行の次の手。root での実行し直しは案内しない。
pub(crate) const SAME_PRINCIPAL_NEXT: &str = "run this command as the user the agent runs as; it answers for that user's permissions, so another user's answer does not describe the agent";

/// まだ登録していないホストの次の手。
const JOIN_NEXT: &str = "issue a join string on the VPS with wgft agent join-string --name <agent>, then start the agent with WGFT_JOIN set to it";

/// 認証情報ファイルを読む。DACL を付け直さない読みを使う。
pub(crate) fn read_credentials(path: &Path) -> CredFile {
    let mut out = CredFile {
        state: CredState::Ok,
        creds: None,
        err: String::new(),
        refused_before_parsing: false,
        mode: None,
    };
    let (b, meta) = match credentials::read_file(path) {
        Ok(x) => x,
        Err(ReadFileError::Io(e)) => {
            out.err = go_err("open", path, &e);
            out.state = match e.kind() {
                io::ErrorKind::NotFound => CredState::Missing,
                io::ErrorKind::PermissionDenied => {
                    // ファイル自身の stat は、途中のディレクトリを辿れれば読み取りの権限が無くても通る。
                    // 通らなければ、拒んでいるのはディレクトリで、ファイルの有無は分からない
                    match std::fs::metadata(path) {
                        Err(se) if se.kind() == io::ErrorKind::PermissionDenied => {
                            out.err = go_err("stat", path, &se);
                            CredState::DirUnreadable
                        }
                        _ => CredState::Unreadable,
                    }
                }
                _ => CredState::Malformed,
            };
            return out;
        }
        Err(ReadFileError::Refused(s)) => {
            out.err = s;
            out.state = CredState::Malformed;
            out.refused_before_parsing = true;
            return out;
        }
    };
    out.mode = file_mode(&meta);
    match serde_json::from_slice::<Credentials>(&b) {
        Ok(c) => out.creds = Some(c),
        Err(e) => {
            out.err = e.to_string();
            out.state = CredState::Malformed;
        }
    }
    out
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the version for other systems"
)]
fn file_mode(m: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(m.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(_m: &std::fs::Metadata) -> Option<u32> {
    None
}

/// Go の `*os.PathError` に近い文。
pub(crate) fn go_err(op: &str, path: &Path, e: &io::Error) -> String {
    wgft_agent::config::go_style_path_error(op, path, e)
}

/// 稼働中かどうかを、ロックファイルを作らずに判定する。
pub(crate) fn inspect_process(input: &Input) -> RunState {
    match (input.inspect)(&input.credentials_path) {
        Ok(s) => RunState {
            state: Some(s),
            err: String::new(),
            permission_denied: false,
        },
        Err(e) => RunState {
            state: None,
            permission_denied: e.kind() == io::ErrorKind::PermissionDenied,
            err: format!(
                "lock file: {}",
                go_err("open", &credentials::lock_path(&input.credentials_path), &e)
            ),
        },
    }
}

// --- Host 群 ---

/// OS、アーキテクチャ、版を示す。Go の「memory soft limit」の予測の代わりに、agent が起動の時に書く
/// メモリの上界の行と同じ値を、同じ設定から求めて示す。
pub(crate) fn platform(input: &Input) -> Check {
    let mut c = Check::new(CHECK_PLATFORM, GROUP_HOST, "platform");
    c.status = status::OK;
    let head = format!("{}, wgft {}", input.platform, input.version);
    if input.config_unreadable.is_some() {
        c.set(status::UNKNOWN, reason::CONFIG_UNREADABLE);
        c.detail = format!(
            "{head}; the flow caps are not shown here: {}, which sets them for the agent, could not be read",
            input.config_path.display()
        );
        SAME_PRINCIPAL_NEXT.clone_into(&mut c.next);
        return c;
    }
    let caps = wgft_agent::flowpool::Limits {
        udp: input.max_udp_flows as usize,
        tcp: input.max_tcp_flows as usize,
    };
    let bound = wgft_agent::memory::MemoryBound::for_limits(
        caps,
        wgft_agent::batching::Batching::derived(caps),
    );
    c.detail = format!(
        "{head}; the memory bound would be {} MiB, computed here from the flow caps {} UDP and {} TCP, not read from the running agent",
        bound.mib(),
        input.max_udp_flows,
        input.max_tcp_flows
    );
    c
}

/// エージェント自身が要る権限を、呼び出し元が持つかどうかを見る。
pub(crate) fn privileges(input: &Input, dir_in_doubt: bool) -> Check {
    let mut c = Check::new(CHECK_PRIVILEGES, GROUP_HOST, "privileges");
    let mut have: Vec<String> = Vec::new();
    let mut denied: Vec<String> = Vec::new();
    let mut undetermined: Vec<String> = Vec::new();
    let mut data_dir_denied = false;
    let data_dir = Path::new(&input.data_dir);
    let dir_exists = (input.is_dir)(data_dir);
    if dir_exists {
        match (input.readable)(data_dir, true) {
            (Access::Allowed, _) => have.push("the data directory is readable".into()),
            (Access::Denied, _) => {
                denied.push(format!(
                    "the data directory {} cannot be read",
                    input.data_dir
                ));
                data_dir_denied = true;
            }
            (Access::NotDetermined, e) => undetermined.push(format!(
                "whether the data directory can be read: {}",
                err_text(&e)
            )),
        }
    }
    let (create_dir, create_label) = if dir_exists {
        (data_dir.to_path_buf(), "the data directory".to_owned())
    } else {
        let d = super::os::nearest_existing_dir(data_dir, &*input.is_dir);
        let label = format!(
            "the directory {}, which would hold the data directory",
            d.display()
        );
        (d, label)
    };
    match (input.dir_create_access)(&create_dir) {
        (Access::Allowed, _) => have.push(format!("new files can be created in {create_label}")),
        (Access::Denied, _) => {
            denied.push(format!("no new file can be created in {create_label}"));
            data_dir_denied = true;
        }
        (Access::NotDetermined, e) => undetermined.push(format!(
            "whether new files can be created in {create_label}: {}",
            err_text(&e)
        )),
    }
    if std::fs::metadata(&input.credentials_path).is_ok() {
        match (input.readable)(&input.credentials_path, false) {
            (Access::Allowed, _) => have.push("agent.json is readable".into()),
            (Access::Denied, _) => denied.push("agent.json cannot be read".into()),
            (Access::NotDetermined, e) => {
                undetermined.push(format!("whether agent.json can be read: {}", err_text(&e)));
            }
        }
    }
    let mut saw_config_file = false;
    if let Some(e) = &input.config_unreadable {
        let (facts, saw) = wgft_agent::config::config_file_perm_facts(&input.config_path);
        saw_config_file = saw;
        denied.push(format!(
            "the config file {} cannot be read: {}; {facts}. Its settings were taken from this command's flags, environment and the defaults instead",
            input.config_path.display(),
            e.trim_end_matches(['.', ' '])
        ));
    }
    let mut parts = vec![input.user.clone()];
    parts.extend(have);
    let any_denied = !denied.is_empty();
    parts.extend(denied);
    let any_undetermined = !undetermined.is_empty();
    parts.extend(undetermined);
    c.detail = parts.join("; ");
    if any_denied {
        c.set(status::FAILED, reason::PERMISSION_DENIED);
        c.evidence_unreachable = true;
        SAME_PRINCIPAL_NEXT.clone_into(&mut c.next);
        if data_dir_denied && dir_in_doubt {
            c.next = data_dir_first(input) + &upper_first(SAME_PRINCIPAL_NEXT);
        }
        if input.config_unreadable.is_some() {
            if saw_config_file {
                c.next.push_str(". If this is already that user, then the file's own owner, group and mode refuse it, and the detail above names both sides");
            } else {
                c.next.push_str(". If this is already that user, then the refusal is on a directory on the way to the config file rather than on the file itself; read the permissions of each directory in its path");
            }
        }
    } else if (input.euid)() == 0 {
        c.set(status::UNKNOWN, reason::RUNNING_AS_ROOT);
        c.detail.push_str("; root bypasses file permissions, so this run cannot say whether the user the agent runs as can reach them");
        "run this command as the same user as the agent. For the packaged systemd unit, that is wgft: runuser -u wgft -- wgft agent doctor. If the agent itself runs as root, this result is expected".clone_into(&mut c.next);
    } else if any_undetermined {
        c.set(status::UNKNOWN, reason::PERMISSION_NOT_DETERMINED);
        "if the agent cannot start, read its log for the first write it fails; this command does not answer it".clone_into(&mut c.next);
    } else {
        c.status = status::OK;
    }
    c
}

/// 稼働中の agent の実行主体を、root で実行した所見に添える。ユーザー空間モードでは `CAP_NET_ADMIN` を
/// 述べない。
pub(crate) fn privileges_with_agent(c: &mut Check, live: &Live) {
    let Some(p) = live.resp.as_ref().and_then(|r| r.process.as_ref()) else {
        return;
    };
    if c.reason != reason::RUNNING_AS_ROOT {
        return;
    }
    let mut who = format!("uid {}", p.uid);
    if !p.user.is_empty() {
        who.push_str(", ");
        who.push_str(&p.user);
    }
    c.detail.push_str("; the running agent runs as ");
    c.detail.push_str(&who);
}

/// 既定のデータディレクトリを見て、登録済みの認証情報ファイルが見つからなかったか。
pub(crate) fn data_dir_in_doubt(input: &Input, cred: &CredFile) -> bool {
    if !input.data_dir_default {
        return false;
    }
    match cred.state {
        CredState::Missing | CredState::DirUnreadable => true,
        CredState::Ok => !cred.registered(),
        _ => false,
    }
}

/// [`data_dir_in_doubt`] の実行で、終了の 1 行へ添える句。
pub(crate) fn default_dir_exit_note(input: &Input, cred: &CredFile) -> String {
    if !data_dir_in_doubt(input, cred) {
        return String::new();
    }
    format!(
        "this run looked at the default data directory {}; if the agent runs with --data-dir or WGFT_DATA_DIR, run it again with the same --data-dir",
        input.data_dir
    )
}

/// 未登録、停止、権限の不足を断定する所見の前に置く句。
fn data_dir_first(input: &Input) -> String {
    if input.data_dir_default {
        return format!(
            "This run looked at the default data directory {}. If the agent runs with --data-dir or WGFT_DATA_DIR, run this command again with the same --data-dir first. ",
            input.data_dir
        );
    }
    format!(
        "This run looked at {}. If the agent runs with another data directory, run this command with that --data-dir first. ",
        input.data_dir
    )
}

/// 設定ファイルを読めずにデータディレクトリを既定値から取った実行に添える句。
fn assumed_data_dir_note(input: &Input) -> String {
    if !input.data_dir_assumed {
        return String::new();
    }
    format!(
        "this answers for {}, the default, because {} could not be read here and may name another data directory",
        input.data_dir,
        input.config_path.display()
    )
}

/// このホストのインタフェースとアドレスを示す。
pub(crate) fn interfaces(input: &Input) -> Check {
    let mut c = Check::new(CHECK_INTERFACES, GROUP_HOST, "interfaces");
    let ifs = match (input.interfaces)() {
        Ok(v) => v,
        Err(e) => {
            c.set(status::UNKNOWN, reason::INTERFACES_UNREADABLE);
            c.detail = format!("this host's network interfaces could not be read: {e}");
            "read them with ip addr on Linux, ifconfig on macOS, or ipconfig on Windows"
                .clone_into(&mut c.next);
            return c;
        }
    };
    let named: Vec<String> = ifs
        .iter()
        .filter(|i| i.up && !i.loopback)
        .filter_map(|i| i.addrs.first().map(|a| format!("{} {a}", i.name)))
        .take(6)
        .collect();
    c.status = status::OK;
    c.detail = format!("{} interface{}", ifs.len(), plural_s(ifs.len()));
    if !named.is_empty() {
        c.detail.push_str("; up and not loopback: ");
        c.detail.push_str(&named.join(", "));
    }
    c
}

/// エージェント用 API の宛先の名前を解決する。
pub(crate) fn endpoint_resolve(input: &Input, cred: &CredFile) -> Check {
    let mut c = Check::new(CHECK_HOST_RESOLVE, GROUP_HOST, "endpoint resolve");
    if skip_for_credentials(&mut c, cred, "the endpoint") {
        return c;
    }
    let ep = cred.creds.as_ref().map_or("", |f| f.endpoint.as_str());
    resolve_into(c, input, ep, "the agent API endpoint")
}

// --- Credentials 群 ---

/// 認証情報ファイルを見る。総合判定を動かす。
pub(crate) fn credentials(input: &Input, cred: &CredFile) -> Check {
    let mut c = Check::new(CHECK_CREDENTIALS, GROUP_CREDENTIALS, "credentials");
    c.verdict = true;
    let path = input.credentials_path.display();
    match cred.state {
        CredState::Missing => {
            c.set(status::FAILED, reason::CREDENTIALS_MISSING);
            c.detail = format!(
                "there is no credentials file at {path}, so no agent has registered from this data directory"
            );
            let note = assumed_data_dir_note(input);
            if !note.is_empty() {
                c.detail.push_str("; ");
                c.detail.push_str(&note);
            }
            c.next =
                data_dir_first(input) + "If no agent has registered on this host yet, " + JOIN_NEXT;
            return c;
        }
        CredState::DirUnreadable => {
            c.set(status::UNKNOWN, reason::DATA_DIR_UNREADABLE);
            c.evidence_unreachable = true;
            c.detail = format!(
                "whether a credentials file exists at {path} could not be determined: the data directory {} cannot be searched here: {}",
                input.data_dir,
                err_text(&cred.err)
            );
            c.next = data_dir_first(input) + &upper_first(SAME_PRINCIPAL_NEXT);
            return c;
        }
        CredState::Unreadable => {
            c.set(status::UNKNOWN, reason::CREDENTIALS_UNREADABLE);
            c.evidence_unreachable = true;
            c.detail = format!(
                "the credentials file at {path} exists but cannot be read here: {}",
                err_text(&cred.err)
            );
            SAME_PRINCIPAL_NEXT.clone_into(&mut c.next);
            return c;
        }
        CredState::Malformed => {
            c.set(status::FAILED, reason::CREDENTIALS_MALFORMED);
            c.detail = if cred.refused_before_parsing {
                format!(
                    "the credentials file at {path} is not one the agent reads: {}",
                    err_text(&cred.err)
                )
            } else {
                format!(
                    "the credentials file at {path} cannot be read as JSON: {}",
                    err_text(&cred.err)
                )
            };
            "the agent cannot start from this file. Keep a copy, remove it, and register again with a fresh join string; the server keeps the old registration until you revoke it".clone_into(&mut c.next);
            return c;
        }
        CredState::Ok => {}
    }
    let Some(f) = cred.creds.as_ref() else {
        return c;
    };
    if f.permanent_token.is_empty() {
        c.set(status::FAILED, reason::NOT_REGISTERED);
        "the credentials file holds no permanent token, so no agent has registered from this data directory yet".clone_into(&mut c.detail);
        c.next =
            data_dir_first(input) + "If no agent has registered on this host yet, " + JOIN_NEXT;
        return c;
    }
    c.status = status::OK;
    let mut parts = vec![format!(
        "last: registered as {} to {}",
        wgft_agent::config::gostd::quote(&f.name),
        or_dash(&f.endpoint)
    )];
    if !f.cert_sha256.is_empty() {
        parts.push(format!(
            "pinned to cert sha256:{}",
            short_hash(&f.cert_sha256)
        ));
    }
    if !f.used_join_token_sha256.is_empty() {
        parts.push(format!(
            "joined with token sha256:{}",
            short_hash(&f.used_join_token_sha256)
        ));
    }
    if let Some(m) = cred.mode {
        let mut note = format!("mode {m:04o}");
        if m & 0o077 != 0 {
            note.push_str(", which lets other local users read the permanent token; tighten it with chmod 0600");
        }
        parts.push(note);
    }
    c.detail = parts.join(", ");
    c
}

/// 稼働中かどうかを見る。総合判定を動かす。
pub(crate) fn process(input: &Input, run: &RunState, dir_in_doubt: bool) -> Check {
    let mut c = Check::new(CHECK_PROCESS, GROUP_CREDENTIALS, "process");
    c.verdict = true;
    let lock = credentials::lock_path(&input.credentials_path);
    let Some(state) = run.state else {
        c.set(status::UNKNOWN, reason::LOCK_UNREADABLE);
        c.evidence_unreachable = run.permission_denied;
        c.detail = format!(
            "whether an agent is running here could not be determined: {}",
            err_text(&run.err)
        );
        SAME_PRINCIPAL_NEXT.clone_into(&mut c.next);
        if run.permission_denied && dir_in_doubt {
            c.next = data_dir_first(input) + &upper_first(SAME_PRINCIPAL_NEXT);
        }
        if !run.permission_denied {
            c.next = format!(
                "read the lock file next to the credentials file, {}, and why it cannot be opened",
                lock.display()
            );
        }
        return c;
    };
    match state {
        LockState::Locked => {
            c.status = status::OK;
            "an agent process holds the lock next to the credentials file, so one is running for this data directory".clone_into(&mut c.detail);
            return c;
        }
        LockState::Absent => {
            c.set(status::FAILED, reason::NOT_RUNNING);
            c.detail = format!(
                "no agent is running for this data directory: there is no lock file at {}, so either no agent has ever started here or the file was removed",
                lock.display()
            );
        }
        LockState::Unlocked => {
            c.set(status::FAILED, reason::NOT_RUNNING);
            c.detail = format!(
                "no agent is running for this data directory: the lock file at {} is there, but no process holds it",
                lock.display()
            );
        }
    }
    let note = assumed_data_dir_note(input);
    if !note.is_empty() {
        c.detail.push_str("; ");
        c.detail.push_str(&note);
    }
    c.next = format!(
        "start it and read why it stopped: systemctl status wgft-agent and journalctl -u wgft-agent, or docker ps and docker logs for a container. This answers for {} alone; an agent running with another WGFT_DATA_DIR is not visible here",
        input.data_dir
    );
    if dir_in_doubt {
        c.next = data_dir_first(input)
            + "Otherwise start it and read why it stopped: systemctl status wgft-agent and journalctl -u wgft-agent, or docker ps and docker logs for a container";
    }
    c
}

/// 最後に処理した全体状態を示す。
pub(crate) fn last_state(cred: &CredFile) -> Check {
    let mut c = Check::new(CHECK_LAST_STATE, GROUP_CREDENTIALS, "last state");
    if skip_for_credentials(&mut c, cred, "the last full state") {
        return c;
    }
    let Some(ls) = cred.creds.as_ref().and_then(|f| f.last_state.as_ref()) else {
        c.set(status::UNKNOWN, reason::NO_LAST_STATE);
        "agent.json holds no full state, so this host holds no rules of its own yet"
            .clone_into(&mut c.detail);
        "start the agent and let it reach the server; the server sends the whole state on every connection".clone_into(&mut c.next);
        return c;
    };
    c.status = status::OK;
    c.detail = format!(
        "last: generation {}, {} rule{}",
        ls.generation,
        ls.rules.len(),
        plural_s(ls.rules.len())
    );
    if !ls.wg.address.is_empty() {
        c.detail.push_str(", tunnel address ");
        c.detail.push_str(&ls.wg.address);
    }
    if !ls.wg.endpoint.is_empty() {
        c.detail.push_str(", peer ");
        c.detail.push_str(&ls.wg.endpoint);
    }
    if ls.wg.mtu > 0 {
        let _ = write!(c.detail, ", mtu {}", ls.wg.mtu);
    }
    if ls.agent_disabled {
        c.detail.push_str("; the server has disabled this agent");
    }
    c
}

// --- Tunnel 群 ---

/// WireGuard のピアの宛先の名前を解決する。
pub(crate) fn wg_resolve(input: &Input, cred: &CredFile) -> Check {
    let mut c = Check::new(CHECK_WG_RESOLVE, GROUP_TUNNEL, "wg endpoint resolve");
    if skip_for_credentials(&mut c, cred, "the WireGuard peer's address") {
        return c;
    }
    let Some(ls) = cred.creds.as_ref().and_then(|f| f.last_state.as_ref()) else {
        c.set(status::UNKNOWN, reason::NO_LAST_STATE);
        "agent.json holds no full state, so this host does not know which WireGuard peer to resolve".clone_into(&mut c.detail);
        "start the agent and let it reach the server; the peer's address arrives with the full state".clone_into(&mut c.next);
        return c;
    };
    if ls.wg.endpoint.trim().is_empty() {
        c.set(status::UNKNOWN, reason::NO_WG_ENDPOINT);
        "the recorded full state carries no WireGuard peer address, so there is nothing to resolve"
            .clone_into(&mut c.detail);
        "read the server's WGFT_WG_ENDPOINT on the VPS; the agent takes the peer's address from the state the server sends".clone_into(&mut c.next);
        return c;
    }
    resolve_into(c, input, &ls.wg.endpoint, "the WireGuard peer")
}

// --- Dataplane 群 ---

/// カーネルモードの検査。このビルドが診断するのはユーザー空間モードだけなので、モードが分からない実行と
/// ユーザー空間モードの実行の 2 つだけを扱う。
pub(crate) fn kernel_checks(cred: &CredFile, mode: &str) -> Vec<Check> {
    [
        (CHECK_DP_INTERFACE, "interface"),
        (CHECK_DP_TABLE, "table"),
        (CHECK_FORWARDING, "forwarding"),
    ]
    .into_iter()
    .map(|(id, label)| {
        let mut c = Check::new(id, GROUP_DATAPLANE, label);
        c.verdict = true;
        if mode.is_empty() {
            // モードが分からない。手前の agent.credentials の符号を持つ
            skip_for_credentials(&mut c, cred, "which mode the agent runs in");
        } else {
            c.set(status::NOT_TESTED, reason::USERSPACE_MODE);
            "the agent runs in userspace mode and relays traffic itself, so there is no kernel dataplane to read; the Relay lines above answer for forwarding".clone_into(&mut c.detail);
        }
        c
    })
    .collect()
}

// --- 小さな部品 ---

/// 認証情報ファイルの中身に依る検査を、ファイルが無いか読めないか登録が済んでいなければ SKIPPED にする。
/// SKIPPED にしたら真を返す。
pub(crate) fn skip_for_credentials(c: &mut Check, cred: &CredFile, what: &str) -> bool {
    let (r, detail) = match cred.state {
        CredState::Missing => (
            reason::CREDENTIALS_MISSING,
            format!("not tested: there is no credentials file, so {what} is not recorded anywhere"),
        ),
        CredState::Unreadable => (
            reason::CREDENTIALS_UNREADABLE,
            format!(
                "not tested: the credentials file cannot be read here, so {what} could not be taken from it"
            ),
        ),
        CredState::DirUnreadable => (
            reason::DATA_DIR_UNREADABLE,
            format!(
                "not tested: the data directory cannot be searched here, so {what} could not be read from a credentials file"
            ),
        ),
        CredState::Malformed if cred.refused_before_parsing => (
            reason::CREDENTIALS_MALFORMED,
            format!(
                "not tested: the credentials file is not one the agent reads, so {what} could not be taken from it"
            ),
        ),
        CredState::Malformed => (
            reason::CREDENTIALS_MALFORMED,
            format!(
                "not tested: the credentials file cannot be read as JSON, so {what} could not be taken from it"
            ),
        ),
        CredState::Ok if !cred.registered() => (
            reason::NOT_REGISTERED,
            format!(
                "not tested: this host has not registered yet, so {what} is not recorded anywhere"
            ),
        ),
        CredState::Ok => return false,
    };
    c.set(status::SKIPPED, r);
    c.detail = detail;
    true
}

/// `host:port` の名前を解決し、結果を `c` に入れて返す。解決の失敗は FAILED でなく UNKNOWN である。
fn resolve_into(mut c: Check, input: &Input, endpoint: &str, what: &str) -> Check {
    let host = split_host(endpoint);
    if host.parse::<std::net::IpAddr>().is_ok() {
        c.status = status::OK;
        c.detail = format!("{what} is the literal address {host}, so there is no name to resolve");
        return c;
    }
    match (input.resolve)(host) {
        Ok(addrs) if !addrs.is_empty() => {
            c.status = status::OK;
            c.detail = format!(
                "{host}, the name of {what}, resolves to {}",
                trim_addrs(&addrs).join(", ")
            );
        }
        r => {
            c.set(status::UNKNOWN, reason::RESOLVE_FAILED);
            let e = r.err().unwrap_or_default();
            c.detail = format!(
                "this host cannot resolve {host}, the name of {what}: {}",
                err_text(&e)
            );
            "fix name resolution on this host. An address resolved earlier can still carry traffic, so this alone does not mean the agent has stopped forwarding".clone_into(&mut c.next);
        }
    }
    c
}

/// Go の `net.SplitHostPort` の host の側。読めなければ全体を返す。
fn split_host(endpoint: &str) -> &str {
    if let Some(rest) = endpoint.strip_prefix('[')
        && let Some((h, port)) = rest.split_once(']')
        && port.starts_with(':')
        && !port[1..].contains(':')
    {
        return h;
    }
    match endpoint.rsplit_once(':') {
        Some((h, _)) if !h.contains(':') && !h.contains('[') => h,
        _ => endpoint,
    }
}

/// 所見が長くなりすぎないよう、先頭のいくつかだけを返す。
fn trim_addrs(addrs: &[String]) -> Vec<String> {
    const MAX: usize = 4;
    if addrs.len() <= MAX {
        return addrs.to_vec();
    }
    let mut v = addrs[..MAX].to_vec();
    v.push(format!("and {} more", addrs.len() - MAX));
    v
}

pub(crate) fn err_text(e: &str) -> String {
    if e.is_empty() {
        "no reason reported".into()
    } else {
        e.to_owned()
    }
}

fn short_hash(h: &str) -> &str {
    h.get(..12).unwrap_or(h)
}

pub(crate) fn or_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_like_go() {
        assert_eq!(split_host("203.0.113.1:8443"), "203.0.113.1");
        assert_eq!(split_host("vps.example:8443"), "vps.example");
        assert_eq!(split_host("[2001:db8::1]:51820"), "2001:db8::1");
        assert_eq!(split_host("vps.example"), "vps.example");
        assert_eq!(split_host("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn trims_long_address_lists() {
        let v: Vec<String> = (0..6).map(|i| format!("192.0.2.{i}")).collect();
        assert_eq!(trim_addrs(&v).last().unwrap(), "and 2 more");
    }
}
