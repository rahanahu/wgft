//! コマンドラインの構成と解釈 (仕様 `cli-config.md` の「Go の性質:コマンドラインの解釈」)。
//!
//! clap の derive でコマンドの構成とフラグの名前を書き、値の解釈と誤りの出力は wgft が持つ。
//! clap の `env` の機能は使わない。優先順位と出所は設定の層 (`wgft_agent::config`) が決める。
//! フラグの値はすべて文字列で受け、整数のフラグだけ Go の `strconv.ParseInt` の基数 0 の規則で読んで
//! 10 進に書き直す。

use std::ffi::OsString;

use clap::error::ErrorKind;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use wgft_agent::config::gostd;

use crate::failure::Failure;

/// `wgft` のルート。
#[derive(Debug, Parser)]
#[command(
    name = "wgft",
    about = "Forward TCP/UDP received at a VPS to home services over WireGuard",
    disable_version_flag = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Print the wgft version
    #[arg(short = 'v', long = "version")]
    pub version: bool,
    /// コマンド
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

/// ルートの下のコマンド。VPS の側のコマンドは server を移す段まで持たない。
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run or manage the home-side agent
    Agent(AgentArgs),
    /// Print the wgft version
    Version,
}

/// `wgft agent` と、その下の global のフラグ。`wgft agent --data-dir X pubkey` を受ける。
#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct AgentArgs {
    /// `--config` と `--data-dir`
    #[command(flatten)]
    pub global: AgentGlobal,
    /// コマンド
    #[command(subcommand)]
    pub cmd: AgentCmd,
}

/// `wgft agent` の下のどのコマンドも受けるフラグ。
///
/// 値を取るフラグは Go の pflag に合わせ、次の語が `-` で始まっても値にし、同じフラグを繰り返せば最後の値が勝つ。
#[derive(Debug, Args)]
pub struct AgentGlobal {
    /// dotenv config file
    #[arg(
        long,
        global = true,
        allow_hyphen_values = true,
        overrides_with = "config"
    )]
    pub config: Option<OsString>,
    /// data dir, env WGFT_DATA_DIR; holds agent.json
    #[arg(
        long = "data-dir",
        global = true,
        allow_hyphen_values = true,
        overrides_with = "data_dir"
    )]
    pub data_dir: Option<OsString>,
}

/// `wgft agent` の下のコマンド。
#[derive(Debug, Subcommand)]
pub enum AgentCmd {
    /// Run the agent
    Run(Box<RunArgs>),
    /// Print the wg public key
    Pubkey,
    /// Regenerate the wg key pair
    #[command(name = "rotate-key")]
    RotateKey,
    /// Diagnose the agent's own state and environment
    Doctor(DoctorArgs),
    /// Remove what a stopped kernel-mode agent left: its WireGuard interface, table inet wgft_agent and the kernel-mode records
    Teardown(TeardownArgs),
}

/// `wgft agent doctor` のフラグ。環境変数と dotenv からは `agent run` と同じ項目をすべて読む。
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// output as JSON; the stable diagnostic model of this command
    #[arg(
        long,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        value_parser = go_bool,
        overrides_with = "json"
    )]
    pub json: Option<bool>,
    /// process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS
    #[arg(
        long = "max-udp-flows",
        allow_hyphen_values = true,
        value_parser = go_int,
        overrides_with = "max_udp_flows"
    )]
    pub max_udp_flows: Option<i64>,
    /// process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS
    #[arg(
        long = "max-tcp-flows",
        allow_hyphen_values = true,
        value_parser = go_int,
        overrides_with = "max_tcp_flows"
    )]
    pub max_tcp_flows: Option<i64>,
}

/// `wgft agent teardown` のフラグ。
#[derive(Debug, Args)]
pub struct TeardownArgs {
    /// kernel-mode WireGuard interface name, env WGFT_WG_INTERFACE
    #[arg(
        long = "wg-interface",
        allow_hyphen_values = true,
        overrides_with = "wg_interface"
    )]
    pub wg_interface: Option<String>,
    /// only print what would be removed and the list to restore by hand
    #[arg(
        long = "dry-run",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        value_parser = go_bool,
        overrides_with = "dry_run"
    )]
    pub dry_run: Option<bool>,
}

/// `wgft agent run` のフラグ。`--config` と `--data-dir` は [`AgentGlobal`] にある。
#[derive(Args)]
pub struct RunArgs {
    /// join string wgft://host:port/token#sha256:..., env WGFT_JOIN
    #[arg(long, allow_hyphen_values = true, overrides_with = "join")]
    pub join: Option<String>,
    /// agent name, env WGFT_NAME; optional, the join string is already bound to a name
    #[arg(long, allow_hyphen_values = true, overrides_with = "name")]
    pub name: Option<String>,
    /// forwarding mode userspace or kernel, env WGFT_MODE; unset means userspace, and kernel is Linux only
    #[arg(long, allow_hyphen_values = true, overrides_with = "mode")]
    pub mode: Option<String>,
    /// kernel-mode WireGuard interface name, env WGFT_WG_INTERFACE; this build names its TUN device with it
    #[arg(
        long = "wg-interface",
        allow_hyphen_values = true,
        overrides_with = "wg_interface"
    )]
    pub wg_interface: Option<String>,
    /// userspace-mode network stack gvisor or wgstack, env WGFT_AGENT_NETSTACK; this build always runs wgstack
    #[arg(
        long = "agent-netstack",
        allow_hyphen_values = true,
        overrides_with = "agent_netstack"
    )]
    pub agent_netstack: Option<String>,
    /// send batch budget in MiB, env WGFT_AGENT_BATCH_MIB; 0 turns it off
    #[arg(
        long = "agent-batch-mib",
        allow_hyphen_values = true,
        overrides_with = "agent_batch_mib"
    )]
    pub agent_batch_mib: Option<String>,
    /// comma-separated targets the server may send traffic to, env WGFT_AGENT_ALLOW_TARGETS; entries are CIDR, CIDR:port or CIDR:lo-hi
    #[arg(
        long = "agent-allow-targets",
        allow_hyphen_values = true,
        overrides_with = "agent_allow_targets"
    )]
    pub agent_allow_targets: Option<String>,
    /// process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS
    #[arg(
        long = "max-udp-flows",
        allow_hyphen_values = true,
        value_parser = go_int,
        overrides_with = "max_udp_flows"
    )]
    pub max_udp_flows: Option<i64>,
    /// process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS
    #[arg(
        long = "max-tcp-flows",
        allow_hyphen_values = true,
        value_parser = go_int,
        overrides_with = "max_tcp_flows"
    )]
    pub max_tcp_flows: Option<i64>,
}

// 接続文字列は秘密なので Debug に出さない
impl std::fmt::Debug for RunArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunArgs")
            .field("join", &self.join.as_ref().map(|_| "<redacted>"))
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("wg_interface", &self.wg_interface)
            .finish_non_exhaustive()
    }
}

/// 整数のフラグの値の解釈。Go の `strconv.ParseInt(s, 0, 64)`。
fn go_int(s: &str) -> Result<i64, String> {
    gostd::parse_int(s).map_err(|e| e.go_text(s))
}

/// 真偽値のフラグの値の解釈。Go の `strconv.ParseBool`。
///
/// 真偽値のフラグ `--json` と `--dry-run` は次の属性で作る。値なしで真になり、値は `--json=false` の形でだけ
/// 渡せる。`--json false` の `false` は引数になる。
///
/// ```ignore
/// #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true",
///       value_parser = wgft::cli::go_bool, overrides_with = "json")]
/// json: bool,
/// ```
pub fn go_bool(s: &str) -> Result<bool, String> {
    gostd::parse_bool(s)
}

/// 既定の値を `--help` に出すコマンドの定義。既定はプロセスの起動の時に 1 回だけ決める。
fn command() -> clap::Command {
    use wgft_agent::config::{Defaults, ProcessEnv};
    command_with(&Defaults::for_host(&ProcessEnv))
}

/// 既定の値を呼び手が渡すコマンドの定義。`docs/cli.md` との照合の試験が環境に依らない既定で呼ぶ。
#[must_use]
pub fn command_with(defaults: &wgft_agent::config::Defaults) -> clap::Command {
    use wgft_agent::config::agent::run_specs;
    let with_default = |a: clap::Arg, d: &str| {
        let help = a.get_help().map(ToString::to_string).unwrap_or_default();
        a.help(format!("{help} [default: {d}]"))
    };
    let mut run_defaults = vec![];
    for sp in run_specs(defaults) {
        if !sp.default.is_empty() && sp.flag != "data-dir" {
            run_defaults.push((sp.flag.replace('-', "_"), sp.default));
        }
    }
    let data_dir = defaults.data_dir.clone();
    let config = defaults.config_path.display().to_string();
    Cli::command().mut_subcommand("agent", move |agent| {
        let agent = agent
            .mut_arg("config", |a| with_default(a, &config))
            .mut_arg("data_dir", |a| with_default(a, &data_dir));
        agent
            .mut_subcommand("teardown", |t| {
                t.mut_arg("wg_interface", |a| with_default(a, "wgft0"))
            })
            .mut_subcommand("doctor", |d| {
                d.mut_arg("max_udp_flows", |a| with_default(a, "8192"))
                    .mut_arg("max_tcp_flows", |a| with_default(a, "2048"))
            })
            .mut_subcommand("run", move |mut run| {
                for (id, d) in run_defaults {
                    run = run.mut_arg(id, |a| with_default(a, &d));
                }
                run
            })
    })
}

/// 解釈した結果。
#[derive(Debug)]
pub enum Parsed {
    /// 標準出力に書いて終了コード 0 で終わる。`--help` と `help` と、コマンドの足りない呼び出し。
    Print(String),
    /// `wgft version`
    Version,
    /// `wgft --version` と `wgft -v`
    VersionFlag,
    /// `wgft agent run`
    AgentRun {
        /// `--config` と `--data-dir`
        global: AgentGlobal,
        /// `agent run` のフラグ
        run: Box<RunArgs>,
    },
    /// `wgft agent pubkey`
    AgentPubkey {
        /// `--config` と `--data-dir`
        global: AgentGlobal,
    },
    /// `wgft agent rotate-key`
    AgentRotateKey {
        /// `--config` と `--data-dir`
        global: AgentGlobal,
    },
    /// `wgft agent doctor`
    AgentDoctor {
        /// `--config` と `--data-dir`
        global: AgentGlobal,
        /// `agent doctor` のフラグ
        args: DoctorArgs,
    },
    /// `wgft agent teardown`
    AgentTeardown {
        /// `--config` と `--data-dir`
        global: AgentGlobal,
        /// `agent teardown` のフラグ
        args: TeardownArgs,
    },
}

/// 引数を解釈する。誤りは `Error: <文>` の 1 行で、使い方は書かない。
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Parsed, Failure> {
    let args: Vec<OsString> = args.into_iter().collect();
    let cli = match command()
        .try_get_matches_from(&args)
        .and_then(|m| Cli::from_arg_matches(&m))
    {
        Ok(c) => c,
        Err(e) => return classify(&e, &args),
    };
    match (cli.version, cli.cmd) {
        (true, None) => Ok(Parsed::VersionFlag),
        // 版のフラグはルートだけにある。サブコマンドの後ろに書いた場合と同じ誤りにする
        (true, Some(_)) => Err(Failure::new("unknown flag: --version", 1)),
        (false, Some(Cmd::Version)) => Ok(Parsed::Version),
        (false, Some(Cmd::Agent(AgentArgs { global, cmd }))) => Ok(match cmd {
            AgentCmd::Run(run) => Parsed::AgentRun { global, run },
            AgentCmd::Pubkey => Parsed::AgentPubkey { global },
            AgentCmd::RotateKey => Parsed::AgentRotateKey { global },
            AgentCmd::Doctor(args) => Parsed::AgentDoctor { global, args },
            AgentCmd::Teardown(args) => Parsed::AgentTeardown { global, args },
        }),
        (false, None) => Ok(Parsed::Print(help_text(&command()))),
    }
}

fn help_text(cmd: &clap::Command) -> String {
    cmd.clone().render_help().to_string()
}

/// clap の失敗を、標準出力に書く説明か、`Error:` の 1 行にする。
fn classify(e: &clap::Error, args: &[OsString]) -> Result<Parsed, Failure> {
    match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            Ok(Parsed::Print(e.render().to_string()))
        }
        _ => Err(Failure::new(
            first_line(&e.to_string()),
            error_exit_code(args),
        )),
    }
}

/// clap の誤りの文の 1 行目から `error: ` を除く。使い方と案内の行は書かない。
fn first_line(rendered: &str) -> String {
    let line = rendered.lines().next().unwrap_or_default();
    line.strip_prefix("error: ").unwrap_or(line).to_owned()
}

/// フラグと引数の誤りの終了コード。1 だが、`agent doctor` だけは 2 である。どのコマンドの誤りかは、
/// 誤りを無視して解釈し直したコマンドの並びで決める。ルートの知らないフラグのように、解釈し直しても
/// コマンドが決まらないときは、`-` で始まらない語の並びで決める (cobra もフラグを除いてコマンドを探す)。
fn error_exit_code(args: &[OsString]) -> u8 {
    if let Ok(m) = command().ignore_errors(true).try_get_matches_from(args)
        && let Some(("agent", a)) = m.subcommand()
        && let Some((sub, _)) = a.subcommand()
    {
        return if sub == "doctor" { 2 } else { 1 };
    }
    let mut words = args
        .iter()
        .skip(1)
        .filter_map(|a| a.to_str())
        .filter(|a| !a.starts_with('-'));
    if words.next() == Some("agent") && words.next() == Some("doctor") {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<OsString> {
        std::iter::once("wgft")
            .chain(v.iter().copied())
            .map(OsString::from)
            .collect()
    }

    fn run_flags(v: &[&str]) -> (AgentGlobal, RunArgs) {
        let mut a = vec!["agent", "run"];
        a.extend_from_slice(v);
        match parse(args(&a)) {
            Ok(Parsed::AgentRun { global, run }) => (global, *run),
            other => panic!("not agent run: {other:?}"),
        }
    }

    fn error_of(v: &[&str]) -> Failure {
        parse(args(v)).expect_err("expected an error")
    }

    #[test]
    fn the_command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn int_flags_take_go_integer_forms() {
        let (_, r) = run_flags(&["--max-udp-flows", "0x400", "--max-tcp-flows=1_000"]);
        assert_eq!(r.max_udp_flows, Some(1024));
        assert_eq!(r.max_tcp_flows, Some(1000));
        let (_, r) = run_flags(&["--max-udp-flows", "016"]);
        assert_eq!(r.max_udp_flows, Some(14));
    }

    #[test]
    fn a_bad_integer_is_an_error_line_with_the_go_reason() {
        let f = error_of(&["agent", "run", "--max-udp-flows", "abc"]);
        assert_eq!(f.code, 1);
        assert!(
            f.message
                .contains("strconv.ParseInt: parsing \"abc\": invalid syntax"),
            "{}",
            f.message
        );
        assert!(!f.message.contains("Usage"), "{}", f.message);
        assert!(!f.message.contains('\n'), "{}", f.message);
    }

    #[test]
    fn a_value_may_start_with_a_hyphen_and_the_last_repeat_wins() {
        let (g, r) = run_flags(&[
            "--name",
            "--odd",
            "--name",
            "second",
            "--data-dir",
            "/a",
            "--data-dir=/b",
        ]);
        assert_eq!(r.name.as_deref(), Some("second"));
        assert_eq!(g.data_dir.as_deref(), Some(std::ffi::OsStr::new("/b")));
    }

    #[test]
    fn global_flags_go_before_or_after_the_command() {
        let p = parse(args(&["agent", "--data-dir", "/x", "run"])).unwrap();
        let Parsed::AgentRun { global: g, .. } = p else {
            panic!("not run")
        };
        assert_eq!(g.data_dir.as_deref(), Some(std::ffi::OsStr::new("/x")));
        let (g, _) = run_flags(&["--config", ""]);
        assert_eq!(g.config.as_deref(), Some(std::ffi::OsStr::new("")));
    }

    #[test]
    fn every_setting_has_a_flag_of_its_name() {
        let defaults = wgft_agent::config::Defaults::for_host(&wgft_agent::config::ProcessEnv);
        let root = Cli::command();
        let run = root
            .find_subcommand("agent")
            .and_then(|a| a.find_subcommand("run"))
            .expect("agent run");
        let agent = root.find_subcommand("agent").unwrap();
        for sp in wgft_agent::config::agent::run_specs(&defaults) {
            let has = |c: &clap::Command| c.get_arguments().any(|a| a.get_long() == Some(sp.flag));
            assert!(
                has(run) || has(agent),
                "no flag --{} for {}",
                sp.flag,
                sp.env
            );
        }
    }

    #[test]
    fn errors_are_one_line_without_usage() {
        for v in [
            &["--bogus"][..],
            &["agent", "run", "--bogus"],
            &["agent", "run", "--name"],
            &["agent", "run", "extra"],
            &["nosuch"],
            &["version", "extra"],
            &["-d"],
            &["agent", "run", "-config", "x"],
        ] {
            let f = error_of(v);
            assert_eq!(f.code, 1, "{v:?}");
            assert!(
                !f.message.is_empty() && !f.message.contains('\n'),
                "{v:?}: {}",
                f.message
            );
            assert!(!f.message.contains("Usage"), "{v:?}: {}", f.message);
        }
    }

    #[test]
    fn version_forms() {
        assert!(matches!(parse(args(&["version"])), Ok(Parsed::Version)));
        assert!(matches!(
            parse(args(&["--version"])),
            Ok(Parsed::VersionFlag)
        ));
        assert!(matches!(parse(args(&["-v"])), Ok(Parsed::VersionFlag)));
        assert_eq!(error_of(&["--version", "extra"]).code, 1);
        assert_eq!(error_of(&["--version", "version"]).code, 1);
    }

    #[test]
    fn help_shows_the_defaults() {
        let Ok(Parsed::Print(h)) = parse(args(&["agent", "run", "--help"])) else {
            panic!("no help");
        };
        assert!(h.contains("[default: wgft0]"), "{h}");
        assert!(h.contains("[default: 8192]"), "{h}");
        assert!(h.contains("[default: 2048]"), "{h}");
        assert!(h.contains("--data-dir"), "{h}");
        let Ok(Parsed::Print(h)) = parse(args(&["agent", "--help"])) else {
            panic!("no help");
        };
        assert!(h.contains("[default: ") && h.contains("agent.env"), "{h}");
    }

    #[test]
    fn help_goes_to_standard_output() {
        for v in [
            &["--help"][..],
            &["-h"],
            &["help", "agent"],
            &["agent"],
            &[],
        ] {
            assert!(matches!(parse(args(v)), Ok(Parsed::Print(_))), "{v:?}");
        }
    }

    #[test]
    fn only_doctor_errors_exit_with_two() {
        assert_eq!(error_exit_code(&args(&["agent", "doctor", "--bogus"])), 2);
        assert_eq!(error_exit_code(&args(&["--x", "agent", "doctor"])), 2);
        assert_eq!(error_exit_code(&args(&["agent", "run", "--bogus"])), 1);
        assert_eq!(error_exit_code(&args(&["doctor"])), 1);
        // 値を取るフラグの値が doctor という語でも、run の誤りである
        assert_eq!(
            error_exit_code(&args(&["agent", "--data-dir", "doctor", "run", "--bogus"])),
            1
        );
        assert_eq!(error_exit_code(&args(&["agent", "doctor", "extra"])), 2);
        assert_eq!(
            error_exit_code(&args(&["agent", "doctor", "--json=yes"])),
            2
        );
        assert_eq!(
            error_exit_code(&args(&["agent", "doctor", "--max-udp-flows", "x"])),
            2
        );
    }

    #[test]
    fn join_is_not_debug_printed() {
        let (_, r) = run_flags(&["--join", "wgft://h:1/secret#sha256:00"]);
        assert!(!format!("{r:?}").contains("secret"));
    }

    /// 真偽値のフラグの属性が、仕様の形だけを受けること。
    #[test]
    fn bool_flags_take_only_the_equals_form() {
        let cmd = || {
            clap::Command::new("t").arg(
                clap::Arg::new("json")
                    .long("json")
                    .num_args(0..=1)
                    .require_equals(true)
                    .default_missing_value("true")
                    .value_parser(go_bool)
                    .overrides_with("json"),
            )
        };
        let get = |v: &[&str]| {
            cmd()
                .try_get_matches_from(std::iter::once("t").chain(v.iter().copied()))
                .map(|m| m.get_one::<bool>("json").copied())
        };
        assert_eq!(get(&["--json"]).unwrap(), Some(true));
        assert_eq!(get(&["--json=false"]).unwrap(), Some(false));
        assert_eq!(get(&["--json=T"]).unwrap(), Some(true));
        assert_eq!(get(&["--json=0", "--json"]).unwrap(), Some(true));
        assert_eq!(get(&[]).unwrap(), None);
        assert!(get(&["--json=yes"]).is_err());
        // `--json false` の false は引数であり、値ではない
        assert!(get(&["--json", "false"]).is_err());
    }
}
