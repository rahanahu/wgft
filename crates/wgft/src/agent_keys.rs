//! `wgft agent pubkey`、`wgft agent rotate-key`、`wgft agent teardown`。仕様は
//! `docs/design/spec/cli-config.md` の各節、ファイルの扱いは `docs/design/spec/credentials.md` にある。
//!
//! 稼働中かどうかはロックファイルを作らない読みで決め、稼働中の agent の `agent.json` には書かない。
//! 稼働中の agent はファイルの中身をメモリに持ち、保存のたびに全体を書き直すためである。

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use wgft_agent::config::agent::validate_interface_name;
use wgft_agent::config::{self, Config, Defaults, Env, Spec};
use wgft_agent::controlapi::{self, CONTROL_PATH_LIMIT, ROTATE_KEY_REPLY_MAX_BYTES, control_path};
use wgft_agent::credentials::{self, Credentials, CredentialsError, WhileStopped};
use wgft_agent::platform::ctlsock;
use wgft_agent::{AgentError, Refusal, tunnel};
use wgft_proto::textsafe::sanitize_for_terminal;

use crate::cli::{AgentGlobal, TeardownArgs};

/// 稼働中の `rotate-key` が制御ソケットに繋ぐまでの期限。
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// 稼働中の `rotate-key` の要求と応答の全体の期限。
const REPLY_DEADLINE: Duration = Duration::from_secs(30);

/// 別のプロセスがロックを持ち、鍵がまだ無いときの誤り。
const KEY_NOT_SAVED_YET: &str = "the credentials file has no key yet and another process is using the data directory, such as an agent that is still starting; run this again in a moment";

/// `--data-dir` を `WGFT_DATA_DIR` の値として引ける対応表にする。
fn data_dir_flag(global: &AgentGlobal) -> Result<HashMap<&'static str, String>, AgentError> {
    let mut out = HashMap::new();
    if let Some(d) = &global.data_dir {
        let d = d
            .to_str()
            .ok_or_else(|| Refusal::config("WGFT_DATA_DIR", "is not valid UTF-8"))?;
        out.insert("WGFT_DATA_DIR", d.to_owned());
    }
    Ok(out)
}

fn data_dir_spec(d: &Defaults) -> Spec {
    Spec {
        env: "WGFT_DATA_DIR",
        flag: "data-dir",
        default: d.data_dir.clone(),
        secret: false,
    }
}

/// `specs` の設定を、フラグ、環境変数、dotenv、既定から読む。dotenv を読めなければ拒む。`hint` は権限で
/// 読めないときの直し方である。
fn load(
    global: &AgentGlobal,
    flags: &HashMap<&'static str, String>,
    specs: impl FnOnce(&Defaults) -> Vec<Spec>,
    env: &dyn Env,
    hint: bool,
) -> Result<Config, AgentError> {
    let defaults = Defaults::for_host(env);
    let path = config::config_path(global.config.as_deref(), env, &defaults.config_path);
    let file = config::dotenv::read(&path).map_err(|e| match e {
        config::dotenv::ReadError::Permission(r) if hint => {
            AgentError::from(r.hint(config::agent::unreadable_hint(&path)))
        }
        other => other.into_error(),
    })?;
    Ok(Config::resolve(specs(&defaults), flags, env, &file)?)
}

/// 認証情報ファイルの場所。Go の v1 と同じく、Unix では `<dir>/agent.json` を文字列でつなぐので、空の
/// データディレクトリは `/agent.json` になる。
fn credentials_path(dir: &str) -> PathBuf {
    if cfg!(all(unix, not(target_os = "macos"))) {
        PathBuf::from(format!("{dir}/{}", credentials::FILE_NAME))
    } else {
        Path::new(dir).join(credentials::FILE_NAME)
    }
}

fn other(e: impl std::fmt::Display) -> AgentError {
    AgentError::Other(e.to_string())
}

fn creds_error(e: CredentialsError, path: &Path) -> AgentError {
    match e {
        CredentialsError::NotFound => AgentError::Other(format!(
            "credentials file {} does not exist",
            path.display()
        )),
        e => other(e),
    }
}

/// `wgft agent pubkey`。
///
/// # Errors
///
/// 設定の拒否、読み書きの誤り、鍵がまだ無い稼働中のデータディレクトリを返す。
pub fn pubkey(global: &AgentGlobal, env: &dyn Env, out: &mut dyn Write) -> Result<(), AgentError> {
    let c = load(
        global,
        &data_dir_flag(global)?,
        |d| vec![data_dir_spec(d)],
        env,
        false,
    )
    .map_err(AgentError::one_shot)?;
    let path = credentials_path(c.get("WGFT_DATA_DIR"));
    let key = public_key(&path)?;
    writeln!(out, "{key}").map_err(other)
}

/// 認証情報ファイルの公開鍵。止まっていて鍵が無ければ作って保存する。
fn public_key(path: &Path) -> Result<String, AgentError> {
    let held = match credentials::lock_while_stopped(path).map_err(other)? {
        WhileStopped::Running => return locked_public_key(path),
        WhileStopped::Stopped(lock) => lock,
    };
    let mut f = Credentials::load_or_new(path).map_err(|e| creds_error(e, path))?;
    if f.wg_private_key.is_empty() {
        let k = tunnel::generate_private_key().map_err(other)?;
        f.wg_private_key.clone_from(&k);
        f.save(path).map_err(other)?;
    }
    let key = tunnel::public_key(&f.wg_private_key)
        .map_err(|e| AgentError::Other(format!("wg_private_key: {e}")))?;
    drop(held);
    Ok(key)
}

/// 別のプロセスがロックを持つ間に、公開鍵を読むだけで読む。鍵が無くても作らない。ファイルを書き換える
/// 読み (Windows の DACL の付け直し) を使わない。
fn locked_public_key(path: &Path) -> Result<String, AgentError> {
    let b = match credentials::read_file(path) {
        Ok((b, _)) => b,
        Err(credentials::ReadFileError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AgentError::Other(KEY_NOT_SAVED_YET.into()));
        }
        Err(e) => return Err(AgentError::Other(format!("credentials file: {e}"))),
    };
    let f: Credentials = serde_json::from_slice(&b)
        .map_err(|e| AgentError::Other(format!("credentials file {}: {e}", path.display())))?;
    if f.wg_private_key.is_empty() {
        return Err(AgentError::Other(KEY_NOT_SAVED_YET.into()));
    }
    tunnel::public_key(&f.wg_private_key)
        .map_err(|e| AgentError::Other(format!("wg_private_key: {e}")))
}

/// `wgft agent rotate-key`。
///
/// # Errors
///
/// 設定の拒否、読み書きの誤り、稼働中の agent の誤りの応答を返す。
pub fn rotate_key(
    global: &AgentGlobal,
    env: &dyn Env,
    out: &mut dyn Write,
) -> Result<(), AgentError> {
    let c = load(
        global,
        &data_dir_flag(global)?,
        |d| vec![data_dir_spec(d)],
        env,
        false,
    )
    .map_err(AgentError::one_shot)?;
    let path = credentials_path(c.get("WGFT_DATA_DIR"));
    let msg = rotate(&path)?;
    writeln!(out, "{msg}").map_err(other)
}

fn rotate(path: &Path) -> Result<String, AgentError> {
    let held = match credentials::lock_while_stopped(path).map_err(other)? {
        WhileStopped::Running => return rotate_running(path),
        WhileStopped::Stopped(lock) => lock,
    };
    let mut f = Credentials::load(path).map_err(|e| creds_error(e, path))?;
    // カーネルモードでは、消す鍵を 1 つ前の鍵として残す。カーネルの WireGuard のインタフェースはまだ
    // その鍵を持つので、次の起動はそれで自分のものと判定し、新しい鍵へ書き換える
    let kernel = f.recorded_mode() == "kernel";
    f.keep_previous_key();
    f.wg_private_key.clear();
    f.last_state = None;
    f.save(path).map_err(other)?;
    drop(held);
    let mut msg = "agent stopped: cleared the key and last_state in the credentials file, agent.json; the next start regenerates the key and receives full state over the stream".to_owned();
    if kernel {
        msg.push_str("; the old key is kept as the previous key, so the next start still recognises the kernel WireGuard interface that holds it and moves it to the new key");
    }
    Ok(msg)
}

/// 稼働中の agent に制御ソケットで鍵の作り直しを頼む。応答は信頼の境界の外から来るので、表示できない
/// 文字を逃がしてから使う。
fn rotate_running(path: &Path) -> Result<String, AgentError> {
    let sock = control_path(path);
    let mut c = ctlsock::connect(&sock, DIAL_TIMEOUT).map_err(|e| {
        AgentError::Other(format!(
            "agent is running but the control socket is unreachable: {}",
            explain_control_err(&sock, &e)
        ))
    })?;
    c.set_deadline(REPLY_DEADLINE);
    c.write_all(b"rotate-key\n").map_err(other)?;
    let line = controlapi::read_control_reply(&mut c, ROTATE_KEY_REPLY_MAX_BYTES).map_err(other)?;
    let line = sanitize_for_terminal(line.trim());
    match line.strip_prefix("ok ") {
        Some(key) => Ok(format!(
            "running agent regenerated its key; public key: {key}"
        )),
        None => Err(AgentError::Other(
            line.strip_prefix("error: ").unwrap_or(&line).to_owned(),
        )),
    }
}

/// パスが長すぎて繋げない場合に、原因と直し方を添える。
pub(crate) fn explain_control_err(path: &Path, e: &std::io::Error) -> String {
    let n = path.as_os_str().as_encoded_bytes().len();
    if e.kind() == std::io::ErrorKind::InvalidInput && n > CONTROL_PATH_LIMIT {
        format!(
            "the socket path is {n} bytes; Unix socket paths hold at most 107 bytes on Linux and Windows and 103 on macOS, so use a shorter data directory"
        )
    } else {
        e.to_string()
    }
}

/// `wgft agent teardown`。このビルドはカーネルモードを持たないので、Linux でも設定の検査の後に拒む。
///
/// # Errors
///
/// いつも拒否を返す。
pub fn teardown(
    global: &AgentGlobal,
    args: &TeardownArgs,
    env: &dyn Env,
    os: &str,
) -> Result<(), AgentError> {
    if os != "linux" {
        return Err(Refusal::prerequisite(
            "operating system",
            format!(
                "the agent's kernel mode, which agent teardown cleans up after, runs on Linux only, and this is {os}; a userspace-mode agent leaves nothing in the kernel"
            ),
        )
        .one_shot()
        .into());
    }
    let mut flags = data_dir_flag(global).map_err(AgentError::one_shot)?;
    if let Some(i) = &args.wg_interface {
        flags.insert("WGFT_WG_INTERFACE", i.clone());
    }
    let c = load(
        global,
        &flags,
        |d| {
            vec![
                data_dir_spec(d),
                Spec {
                    env: "WGFT_WG_INTERFACE",
                    flag: "wg-interface",
                    default: "wgft0".into(),
                    secret: false,
                },
            ]
        },
        env,
        true,
    )
    .map_err(AgentError::one_shot)?;
    if c.get("WGFT_DATA_DIR").trim().is_empty() {
        return Err(Refusal::config(
            "WGFT_DATA_DIR",
            "is empty; give the directory that holds agent.json",
        )
        .one_shot()
        .into());
    }
    validate_interface_name(c.get("WGFT_WG_INTERFACE")).map_err(Refusal::one_shot)?;
    Err(Refusal::prerequisite(
        "WGFT_MODE",
        "this build does not include the agent's kernel mode yet, so it cannot remove what a kernel-mode agent left; use a build that includes it",
    )
    .one_shot()
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn global(dir: &Path) -> AgentGlobal {
        AgentGlobal {
            config: Some(dir.join("none.env").into_os_string()),
            data_dir: Some(dir.as_os_str().to_owned()),
        }
    }

    fn no_env() -> HashMap<String, OsString> {
        HashMap::new()
    }

    #[test]
    fn pubkey_creates_a_key_once_while_stopped() {
        let d = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        pubkey(&global(d.path()), &no_env(), &mut out).unwrap();
        let first = String::from_utf8(out).unwrap();
        assert_eq!(first.trim().len(), 44, "{first}");
        // ロックファイルが無いデータディレクトリでは作らない
        assert!(!credentials::lock_path(&d.path().join("agent.json")).exists());
        let mut again = Vec::new();
        pubkey(&global(d.path()), &no_env(), &mut again).unwrap();
        assert_eq!(String::from_utf8(again).unwrap(), first);
    }

    #[test]
    fn pubkey_of_a_running_agent_reads_without_writing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("agent.json");
        let _held = credentials::acquire(&p).unwrap();
        let e = pubkey(&global(d.path()), &no_env(), &mut Vec::new()).unwrap_err();
        assert_eq!(e.to_string(), KEY_NOT_SAVED_YET);
        assert!(
            !p.exists(),
            "a running agent's data directory is not written"
        );
        let key = tunnel::generate_private_key().unwrap();
        let saved = Credentials {
            wg_private_key: key.to_string(),
            ..Credentials::default()
        };
        saved.save(&p).unwrap();
        let mut out = Vec::new();
        pubkey(&global(d.path()), &no_env(), &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap().trim(),
            tunnel::public_key(&key).unwrap()
        );
    }

    #[test]
    fn rotate_key_while_stopped_clears_the_key_and_the_state() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("agent.json");
        let e = rotate_key(&global(d.path()), &no_env(), &mut Vec::new()).unwrap_err();
        assert!(e.to_string().contains("does not exist"), "{e}");
        let f = Credentials {
            wg_private_key: tunnel::generate_private_key().unwrap().to_string(),
            last_state: Some(wgft_proto::State::default()),
            mode: "kernel".into(),
            ..Credentials::default()
        };
        f.save(&p).unwrap();
        // ロックファイルがあれば取ってから書く
        drop(credentials::acquire(&p).unwrap());
        let mut out = Vec::new();
        rotate_key(&global(d.path()), &no_env(), &mut out).unwrap();
        let msg = String::from_utf8(out).unwrap();
        assert!(msg.starts_with("agent stopped: cleared the key"), "{msg}");
        assert!(
            msg.contains("the old key is kept as the previous key"),
            "{msg}"
        );
        let after = Credentials::load(&p).unwrap();
        assert!(after.wg_private_key.is_empty() && after.last_state.is_none());
        assert_eq!(after.previous_wg_private_key, f.wg_private_key);
    }

    #[test]
    fn rotate_key_of_a_running_agent_without_a_socket_says_so() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("agent.json");
        let _held = credentials::acquire(&p).unwrap();
        let e = rotate_key(&global(d.path()), &no_env(), &mut Vec::new()).unwrap_err();
        assert!(
            e.to_string()
                .starts_with("agent is running but the control socket is unreachable: "),
            "{e}"
        );
        assert_eq!(e.exit_code(), 1);
    }

    /// 稼働中の agent の応答は信頼の境界の外から来るので、表示できない文字を逃がしてから書く。
    #[test]
    fn a_running_agents_reply_is_escaped_before_it_is_printed() {
        use std::io::{BufRead, BufReader};
        let d = std::env::temp_dir().join(format!("wgft-rk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("agent.json");
        let _held = credentials::acquire(&p).unwrap();
        let listener = ctlsock::Listener::bind(&control_path(&p)).unwrap();
        let answer = |reply: &'static [u8]| {
            let mut c = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&mut c).read_line(&mut line).unwrap();
            assert_eq!(line, "rotate-key\n");
            c.write_all(reply).unwrap();
        };
        std::thread::scope(|sc| {
            sc.spawn(|| answer(b"ok KEY\x1b[2J\n"));
            let mut out = Vec::new();
            rotate_key(&global(&d), &no_env(), &mut out).unwrap();
            let out = String::from_utf8(out).unwrap();
            assert_eq!(
                out,
                "running agent regenerated its key; public key: KEY\\x1b[2J\n"
            );
        });
        std::thread::scope(|sc| {
            sc.spawn(|| answer(b"error: no\x07pe\n"));
            let e = rotate_key(&global(&d), &no_env(), &mut Vec::new()).unwrap_err();
            assert_eq!(e.to_string(), "no\\ape");
        });
        drop(listener);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn teardown_refuses_after_checking_the_settings() {
        let d = tempfile::tempdir().unwrap();
        let args = TeardownArgs {
            wg_interface: None,
            dry_run: None,
        };
        let e = teardown(&global(d.path()), &args, &no_env(), "darwin").unwrap_err();
        assert_eq!(e.exit_code(), 3);
        assert!(
            e.to_string()
                .starts_with("cannot continue [prerequisite operating system]: "),
            "{e}"
        );
        let e = teardown(&global(d.path()), &args, &no_env(), "linux").unwrap_err();
        assert_eq!(
            e.to_string(),
            "cannot continue [prerequisite WGFT_MODE]: this build does not include the agent's kernel mode yet, so it cannot remove what a kernel-mode agent left; use a build that includes it"
        );
        let bad = TeardownArgs {
            wg_interface: Some("a/b".into()),
            dry_run: Some(true),
        };
        let e = teardown(&global(d.path()), &bad, &no_env(), "linux").unwrap_err();
        assert!(
            e.to_string()
                .starts_with("cannot continue [config WGFT_WG_INTERFACE]: "),
            "{e}"
        );
    }

    #[test]
    fn a_too_long_socket_path_is_explained() {
        let p = PathBuf::from(format!("/{}", "x".repeat(200)));
        let e = std::io::Error::new(std::io::ErrorKind::InvalidInput, "too long");
        assert!(explain_control_err(&p, &e).contains("use a shorter data directory"));
    }
}
