//! `agent run` の設定項目と、入口での検査 (仕様 `cli-config.md` の設定項目と入口での検査の順)。
//!
//! 入口は、認証情報ファイル、トンネル、待ち受けに触れる前に、値だけから判定できる誤りをすべて拒む。
//! 複数の誤りがあれば、仕様の順で最初の 1 つだけを示す。項目を足すときは、ここに検査を足し、
//! `testdata/spec/config/values.json` に壊れた値を 1 つ加える。

use super::allow_targets::{self, AllowList};
use super::gostd::{self, quote};
use super::{Config, Defaults, LogLine, Source, Spec};
use crate::error::Refusal;

/// フロー数の上限の下限と上限。
pub const FLOWS_MIN: i64 = 16;
/// フロー数の上限の上限。
pub const FLOWS_MAX: i64 = 65535;

/// 転送の方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// ユーザー空間モード。空の指定もここを指す。
    Userspace,
    /// カーネルモード。Linux だけ。
    Kernel,
}

/// `agent run` の設定項目。
#[must_use]
pub fn run_specs(d: &Defaults) -> Vec<Spec> {
    let s = |env, flag, default: &str, secret| Spec {
        env,
        flag,
        default: default.to_owned(),
        secret,
    };
    vec![
        s("WGFT_DATA_DIR", "data-dir", &d.data_dir, false),
        s("WGFT_JOIN", "join", "", true),
        s("WGFT_NAME", "name", "", false),
        s("WGFT_MODE", "mode", "", false),
        s("WGFT_WG_INTERFACE", "wg-interface", "wgft0", false),
        s("WGFT_AGENT_NETSTACK", "agent-netstack", "", false),
        s("WGFT_AGENT_BATCH_MIB", "agent-batch-mib", "", false),
        s(allow_targets::ENV, "agent-allow-targets", "", false),
        s("WGFT_MAX_UDP_FLOWS", "max-udp-flows", "8192", false),
        s("WGFT_MAX_TCP_FLOWS", "max-tcp-flows", "2048", false),
    ]
}

/// 入口を通った設定の値。
#[derive(Clone)]
pub struct Settings {
    /// 認証情報ファイルを置くディレクトリ。値をそのまま使う。
    pub data_dir: String,
    /// 接続文字列。構文は入口では見ない。
    pub join: String,
    /// 登録で送る名前。
    pub name: String,
    /// 転送の方式。
    pub mode: Mode,
    /// カーネルモードの WireGuard のインタフェースの名前。
    pub wg_interface: String,
    /// ユーザー空間モードの netstack の指定。`gvisor`、`wgstack`、または空。
    pub netstack: String,
    /// 送信の向きのバッチの予算 (MiB)。空は `None`。
    pub batch_mib: Option<i64>,
    /// 宛先の許可一覧。`None` は制限しない。
    pub allow_targets: Option<AllowList>,
    /// 同時 UDP フローの上限。
    pub max_udp_flows: u32,
    /// 同時 TCP フローの上限。
    pub max_tcp_flows: u32,
}

// 接続文字列は秘密なので Debug に出さない
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
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
            .field("mode", &self.mode)
            .field("wg_interface", &self.wg_interface)
            .field("netstack", &self.netstack)
            .field("batch_mib", &self.batch_mib)
            .field("allow_targets", &self.allow_targets)
            .field("max_udp_flows", &self.max_udp_flows)
            .field("max_tcp_flows", &self.max_tcp_flows)
            .finish()
    }
}

/// `Config` から入口の検査を通す。`os` は Go の `runtime.GOOS` の名前 (`linux`、`windows`、`darwin`)。
pub fn check_door(c: &Config, os: &str) -> Result<Settings, Refusal> {
    // 2. WGFT_DATA_DIR の空。パスには値をそのまま使う
    let data_dir = c.get("WGFT_DATA_DIR");
    if data_dir.trim().is_empty() {
        return Err(Refusal::config(
            "WGFT_DATA_DIR",
            "is empty; give the directory that holds agent.json",
        ));
    }
    // 3, 4. WGFT_MODE。値は大文字と小文字を区別し、前後の空白も値の一部である
    let mode = match c.get("WGFT_MODE") {
        "" | "userspace" => Mode::Userspace,
        "kernel" => Mode::Kernel,
        m => {
            return Err(Refusal::config(
                "WGFT_MODE",
                format!("must be kernel or userspace, not {}", quote(m)),
            ));
        }
    };
    if mode == Mode::Kernel && os != "linux" {
        return Err(Refusal::prerequisite(
            "WGFT_MODE",
            format!(
                "the agent's kernel mode needs Linux, and this is {os}; leave WGFT_MODE unset or set it to userspace"
            ),
        ));
    }
    // 5. インタフェースの名前はカーネルモードでだけ使うが、値だけで判定できるので、モードによらず弾く。
    //    後でカーネルモードへ切り替えたときに、起動の後半で初めて失敗しないためである
    validate_interface_name(c.get("WGFT_WG_INTERFACE"))?;
    // 6. netstack も、使わないモードで弾く理由は同じ
    let netstack = c.get("WGFT_AGENT_NETSTACK");
    if !matches!(netstack, "" | "gvisor" | "wgstack") {
        return Err(Refusal::config(
            "WGFT_AGENT_NETSTACK",
            format!("must be gvisor or wgstack, not {}", quote(netstack)),
        ));
    }
    // 7. 上限は UDP を先に検査する
    let max_udp_flows = flow_cap(c, "WGFT_MAX_UDP_FLOWS")?;
    let max_tcp_flows = flow_cap(c, "WGFT_MAX_TCP_FLOWS")?;
    // 8. バッチの予算
    let batch_mib = batch_mib(c.get("WGFT_AGENT_BATCH_MIB"))?;
    // 9. 宛先の許可一覧
    let allow_targets = allow_targets::parse(c.get(allow_targets::ENV))
        .map_err(|e| Refusal::config(allow_targets::ENV, e))?;
    Ok(Settings {
        data_dir: data_dir.to_owned(),
        join: c.get("WGFT_JOIN").to_owned(),
        name: c.get("WGFT_NAME").to_owned(),
        mode,
        wg_interface: c.get("WGFT_WG_INTERFACE").to_owned(),
        netstack: netstack.to_owned(),
        batch_mib,
        allow_targets,
        max_udp_flows,
        max_tcp_flows,
    })
}

/// 環境変数と dotenv の整数は `strconv.Atoi` で読む。フラグの値は 10 進に書き直してあるので同じ道を通る。
pub fn flow_cap(c: &Config, env: &str) -> Result<u32, Refusal> {
    let v = c.get(env);
    gostd::atoi(v)
        .filter(|n| (FLOWS_MIN..=FLOWS_MAX).contains(n))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| {
            Refusal::config(
                env,
                format!(
                    "{} is not an integer between {FLOWS_MIN} and {FLOWS_MAX}",
                    quote(v)
                ),
            )
        })
}

/// 0 以上の 10 進の整数。`int64` を超える正の値は誤りにせず、最大に丸める。
/// 解釈は Go の `strconv.ParseInt(v, 10, 64)` で、符号を外した後の走査の順も同じである。
fn batch_mib(v: &str) -> Result<Option<i64>, Refusal> {
    if v.is_empty() {
        return Ok(None);
    }
    match gostd::parse_int_base10(v) {
        Ok(n) if n >= 0 => Ok(Some(n)),
        Err(gostd::IntError::Range) if !v.starts_with('-') => Ok(Some(i64::MAX)),
        _ => Err(Refusal::config(
            "WGFT_AGENT_BATCH_MIB",
            format!(
                "{} is not a whole number of MiB of at least 0; 0 turns send batching off",
                quote(v)
            ),
        )),
    }
}

/// Linux のカーネルの `dev_valid_name` に合わせ、名前をバイト列として調べる。
/// 合わせて NUL と `%` も拒む。通すと、宣言した名前と実際に付く名前が食い違う。
pub fn validate_interface_name(name: &str) -> Result<(), Refusal> {
    const SUBJECT: &str = "WGFT_WG_INTERFACE";
    if name.is_empty() {
        return Err(Refusal::config(
            SUBJECT,
            "is empty; give the WireGuard interface name, for example wgft0",
        ));
    }
    if name.len() > 15 {
        return Err(Refusal::config(
            SUBJECT,
            format!(
                "{} is longer than the 15 bytes the kernel allows for an interface name",
                quote(name)
            ),
        ));
    }
    if name == "." || name == ".." {
        return Err(Refusal::config(
            SUBJECT,
            format!("{} is not a usable interface name", quote(name)),
        ));
    }
    // 0xA0 は UTF-8 の文字の 2 バイト目にも現れるので、`wgà` も拒む
    if let Some(b) = name
        .bytes()
        .find(|b| matches!(b, b'/' | b':' | b'%' | 0 | 0x09..=0x0D | b' ' | 0xA0))
    {
        return Err(Refusal::config(
            SUBJECT,
            format!(
                "{} contains byte 0x{b:02x}, which is not usable in an interface name; /, :, %, a NUL byte and whitespace including 0xa0 are not allowed",
                quote(name)
            ),
        ));
    }
    Ok(())
}

/// この版が持たない機能を要る設定を、認証情報とトンネルに触れる前に拒む。入口の検査のすぐ後に呼ぶ。
/// 今はカーネルモードだけである。
pub fn check_supported(s: &Settings) -> Result<(), Refusal> {
    if s.mode == Mode::Kernel {
        return Err(Refusal::prerequisite(
            "WGFT_MODE",
            "this build does not include the agent's kernel mode yet, so it cannot start in kernel mode; use a build that includes it",
        ));
    }
    Ok(())
}

/// 入口を通った後に標準エラーへ書く行。有効な設定、まだ効かせていない設定の知らせ、使わない設定の知らせ、
/// 宛先の許可一覧の行の順である。
#[must_use]
pub fn startup_lines(c: &Config, s: &Settings) -> Vec<LogLine> {
    let mut out = vec![LogLine::Plain("effective config:".to_owned())];
    out.extend(c.effective_lines().into_iter().map(LogLine::Plain));
    // 送信の向きのバッチは、値から導く量が wgstack の送信の経路で決まるまで効かせない
    if !c.get("WGFT_AGENT_BATCH_MIB").is_empty() {
        out.push(LogLine::Stamped(
            "WGFT_AGENT_BATCH_MIB: not applied yet, since this build has no send batching; the setting is kept so the same agent.env works later".to_owned(),
        ));
    }
    if c.source("WGFT_AGENT_NETSTACK") != Source::Default {
        out.push(LogLine::Stamped(format!(
            "WGFT_AGENT_NETSTACK={}: unused, since this build has no choice of network stack; the setting is kept so the same agent.env works",
            s.netstack
        )));
    }
    // Go の v1 と同じ文。一覧が無いことも書き、制限が無いことを運用者に見せる
    out.push(LogLine::Stamped(match &s.allow_targets {
        None => format!(
            "no target allowlist: {} is not set; the server can direct this agent to any address it can reach",
            allow_targets::ENV
        ),
        Some(l) => format!(
            "target allowlist {}={l}; the server can direct this agent only to these addresses",
            allow_targets::ENV
        ),
    }));
    out
}

/// 入口の警告。`WGFT_JOIN` が空でなく構文が誤っていれば 1 行を返す。拒否にしないのは、登録済みの agent が
/// compose に残った古い値を読まないからで、構文の判定は登録の直前に行う。
#[must_use]
pub fn join_warning(s: &Settings) -> Option<LogLine> {
    if s.join.is_empty() {
        return None;
    }
    let e = wgft_proto::Join::parse(&s.join).err()?;
    Some(LogLine::Stamped(format!(
        "warning: WGFT_JOIN is malformed: {e}; it is used only for a first registration or after a revocation, so this agent starts if it is already registered"
    )))
}

/// Go の `runtime.GOOS` に当たる OS の名前。
#[must_use]
pub fn host_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        os => os,
    }
}

/// agent が設定ファイルを読めないときの直し方。agent の設定は `WGFT_JOIN` を含みうるので、全員に読ませる
/// 権限は勧めず、agent の利用者のグループにだけ読ませる。勧める所有者とパーミッションが既に満たされて
/// いる配置もあるので、読んだのが agent を動かす利用者ではない場合を最後に書く。
#[must_use]
pub fn unreadable_hint(path: &std::path::Path) -> String {
    let p = path.display();
    format!(
        "It may hold WGFT_JOIN, so let the agent's group read it rather than every local user; with the provided agent.service, which runs the agent as the wgft user: chown root:wgft {p} && chmod 0640 {p}. If the file already has that owner, group and mode, the user that read it here is not the one the agent runs as"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::OsString;

    use super::*;
    use crate::config::dotenv::Map;

    fn settings(env: &[(&str, &str)], file: &[(&str, &str)]) -> (Config, Settings) {
        let d = Defaults {
            data_dir: "/d".into(),
            config_path: "/e".into(),
        };
        let env: HashMap<String, OsString> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        let file = Map {
            values: file
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..Map::default()
        };
        let c = Config::resolve(run_specs(&d), &HashMap::new(), &env, &file).unwrap();
        let s = check_door(&c, "linux").unwrap();
        (c, s)
    }

    fn stamped(lines: &[LogLine]) -> Vec<&str> {
        lines
            .iter()
            .filter_map(|l| match l {
                LogLine::Stamped(s) => Some(s.as_str()),
                LogLine::Plain(_) => None,
            })
            .collect()
    }

    #[test]
    fn defaults_write_the_block_and_the_allowlist_line() {
        let (c, s) = settings(&[], &[]);
        let lines = startup_lines(&c, &s);
        assert_eq!(lines[0], LogLine::Plain("effective config:".into()));
        let st = stamped(&lines);
        assert_eq!(
            st,
            vec![
                "no target allowlist: WGFT_AGENT_ALLOW_TARGETS is not set; the server can direct this agent to any address it can reach"
            ]
        );
    }

    #[test]
    fn a_set_allowlist_is_enforced_and_logged_in_its_normal_form() {
        let (c, s) = settings(
            &[("WGFT_AGENT_ALLOW_TARGETS", " 10.0.0.1/8 ,192.168.1.10:80")],
            &[],
        );
        assert_eq!(check_supported(&s), Ok(()));
        assert_eq!(
            stamped(&startup_lines(&c, &s)),
            vec![
                "target allowlist WGFT_AGENT_ALLOW_TARGETS=10.0.0.0/8,192.168.1.10/32:80; the server can direct this agent only to these addresses"
            ]
        );
    }

    #[test]
    fn a_set_batch_and_netstack_get_their_notice_and_flow_caps_none() {
        let (c, s) = settings(
            &[
                ("WGFT_AGENT_NETSTACK", "gvisor"),
                ("WGFT_MAX_UDP_FLOWS", "100"),
            ],
            &[("WGFT_AGENT_BATCH_MIB", "4")],
        );
        let st = stamped(&startup_lines(&c, &s)).join("\n");
        assert!(st.contains("WGFT_AGENT_BATCH_MIB: not applied yet"), "{st}");
        assert!(!st.contains("WGFT_MAX_UDP_FLOWS"), "{st}");
        assert!(
            st.contains("WGFT_AGENT_NETSTACK=gvisor: unused, since this build has no choice of network stack;"),
            "{st}"
        );
        // 空の値でも、出所が既定でなければ書く
        let (c, s) = settings(&[("WGFT_AGENT_NETSTACK", "")], &[]);
        assert!(
            stamped(&startup_lines(&c, &s))
                .iter()
                .any(|l| l.starts_with("WGFT_AGENT_NETSTACK=: unused"))
        );
        let (c, s) = settings(&[], &[]);
        assert!(
            !stamped(&startup_lines(&c, &s))
                .join("\n")
                .contains("NETSTACK")
        );
    }

    #[test]
    fn join_warning_only_for_a_non_empty_malformed_string() {
        let w = |j: &str| join_warning(&settings(&[("WGFT_JOIN", j)], &[]).1);
        assert_eq!(w(""), None);
        assert_eq!(
            w(
                "wgft://h:1/tok#sha256:0000000000000000000000000000000000000000000000000000000000000000"
            ),
            None
        );
        let Some(LogLine::Stamped(m)) = w("not-a-join-string") else {
            panic!("no warning");
        };
        assert!(
            m.starts_with("warning: WGFT_JOIN is malformed: join string must look like"),
            "{m}"
        );
        assert!(!m.contains("not-a-join-string"));
    }

    #[test]
    fn debug_hides_the_join_string() {
        let (c, s) = settings(&[("WGFT_JOIN", "wgft://h:1/secret#sha256:00")], &[]);
        assert!(!format!("{s:?}").contains("secret"));
        assert!(!format!("{c:?}").contains("secret"));
        assert!(format!("{c:?}").contains("****"));
    }
}
