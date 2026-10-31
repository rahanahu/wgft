//! v2 移行中の wgft のコマンド。今は Rust の agent の試作の `agent run` と `version` だけを持つ。
//!
//! 設定は v1 と同じく `WGFT_*` の環境変数で受け、フラグはその別名である。試作が持たない v1 の設定は、
//! 黙って無視せずに設定の誤り (終了コード 3) で止める。作りは `docs/design/v2/agent-control.md` に書く。

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use wgft_agent::{AgentError, Options, Refusal};

#[derive(Parser, Debug)]
#[command(
    name = "wgft",
    about = "Forward VPS ports to a home network over WireGuard; v2 Rust prototype"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run or manage the home-side agent
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// Print the wgft version
    Version,
}

#[derive(Subcommand, Debug)]
enum AgentCmd {
    /// Run the agent in the foreground; userspace mode only in this prototype
    Run(Box<RunArgs>),
}

#[derive(Args, Debug)]
struct RunArgs {
    /// data dir, env WGFT_DATA_DIR; holds agent.json
    #[arg(long = "data-dir", env = "WGFT_DATA_DIR", default_value = default_data_dir())]
    data_dir: String,
    /// join string wgft://host:port/token#sha256:..., env WGFT_JOIN
    #[arg(long, env = "WGFT_JOIN", default_value = "", hide_env_values = true)]
    join: String,
    /// agent name, env WGFT_NAME; optional, the join string is already bound to a name
    #[arg(long, env = "WGFT_NAME", default_value = "")]
    name: String,
    /// forwarding mode, env WGFT_MODE; this prototype accepts only userspace
    #[arg(long, env = "WGFT_MODE", default_value = "")]
    mode: String,
    /// interface name, env WGFT_WG_INTERFACE; this prototype names its TUN device with it
    #[arg(
        long = "wg-interface",
        env = "WGFT_WG_INTERFACE",
        default_value = "wgft0"
    )]
    wg_interface: String,
    /// env WGFT_AGENT_NETSTACK; gvisor or wgstack, accepted so the same agent.env works, and unused here
    #[arg(
        long = "agent-netstack",
        env = "WGFT_AGENT_NETSTACK",
        default_value = ""
    )]
    agent_netstack: String,
    /// env WGFT_CONFIG; not supported by this prototype
    #[arg(long, env = "WGFT_CONFIG", default_value = "")]
    config: String,
    /// env WGFT_AGENT_ALLOW_TARGETS; not supported by this prototype
    #[arg(
        long = "agent-allow-targets",
        env = "WGFT_AGENT_ALLOW_TARGETS",
        default_value = ""
    )]
    agent_allow_targets: String,
    /// env WGFT_AGENT_BATCH_MIB; not supported by this prototype
    #[arg(
        long = "agent-batch-mib",
        env = "WGFT_AGENT_BATCH_MIB",
        default_value = ""
    )]
    agent_batch_mib: String,
    /// env WGFT_MAX_TCP_FLOWS; not supported by this prototype
    #[arg(long = "max-tcp-flows", env = "WGFT_MAX_TCP_FLOWS", default_value = "")]
    max_tcp_flows: String,
    /// env WGFT_MAX_UDP_FLOWS; not supported by this prototype
    #[arg(long = "max-udp-flows", env = "WGFT_MAX_UDP_FLOWS", default_value = "")]
    max_udp_flows: String,
}

fn default_data_dir() -> &'static str {
    if cfg!(windows) {
        "C:\\ProgramData\\wgft"
    } else {
        "/var/lib/wgft"
    }
}

/// v1 の既定の dotenv。試作は読まないので、あれば止める。
fn default_config_path() -> &'static str {
    if cfg!(windows) {
        "C:\\ProgramData\\wgft\\agent.env"
    } else {
        "/etc/wgft/agent.env"
    }
}

/// 値だけから判定できる誤りを、認証情報とトンネルに触れる前にすべて拒む。
fn agent_options(a: &RunArgs) -> Result<Options, Refusal> {
    let unsupported = [
        ("WGFT_CONFIG", &a.config),
        ("WGFT_AGENT_ALLOW_TARGETS", &a.agent_allow_targets),
        ("WGFT_AGENT_BATCH_MIB", &a.agent_batch_mib),
        ("WGFT_MAX_TCP_FLOWS", &a.max_tcp_flows),
        ("WGFT_MAX_UDP_FLOWS", &a.max_udp_flows),
    ];
    for (env, v) in unsupported {
        if !v.trim().is_empty() {
            return Err(Refusal::config(
                env,
                "is set, and this Rust agent prototype does not implement it yet; unset it, or run the Go agent",
            ));
        }
    }
    if std::path::Path::new(default_config_path()).exists() {
        return Err(Refusal::config(
            "WGFT_CONFIG",
            format!(
                "{} exists, and this Rust agent prototype does not read dotenv files yet; pass the settings as environment variables",
                default_config_path()
            ),
        ));
    }
    match a.mode.as_str() {
        "" | "userspace" => {}
        "kernel" => {
            return Err(Refusal::config(
                "WGFT_MODE",
                "this Rust agent prototype runs userspace mode only; leave WGFT_MODE unset or set it to userspace",
            ));
        }
        m => {
            return Err(Refusal::config(
                "WGFT_MODE",
                format!("must be kernel or userspace, not {m:?}"),
            ));
        }
    }
    match a.agent_netstack.as_str() {
        "" | "gvisor" | "wgstack" => {}
        n => {
            return Err(Refusal::config(
                "WGFT_AGENT_NETSTACK",
                format!("must be gvisor or wgstack, not {n:?}"),
            ));
        }
    }
    let tun = &a.wg_interface;
    if tun.is_empty()
        || tun.len() > 15
        || tun.contains(|c: char| c == '/' || c == '%' || c.is_whitespace())
    {
        return Err(Refusal::config(
            "WGFT_WG_INTERFACE",
            "must be an interface name of 1 to 15 bytes without slashes, percent signs or whitespace; this prototype names its TUN device with it",
        ));
    }
    if a.data_dir.trim().is_empty() {
        return Err(Refusal::config(
            "WGFT_DATA_DIR",
            "is empty; give the directory that holds agent.json",
        ));
    }
    Ok(Options {
        data_dir: PathBuf::from(&a.data_dir),
        join: a.join.clone(),
        name: a.name.clone(),
        version: version(),
        tun_name: a.wg_interface.clone(),
    })
}

fn run_agent(a: &RunArgs) -> Result<(), AgentError> {
    let opts = agent_options(a)?;
    if !a.agent_netstack.is_empty() {
        wgft_agent::logf!(
            "WGFT_AGENT_NETSTACK={}: unused; this Rust agent prototype carries the tunnel on a Linux TUN device and the kernel network stack",
            a.agent_netstack
        );
    }
    wgft_agent::run(opts)
}

fn main() -> ExitCode {
    // 時差はスレッドが 1 つのうちに読む
    wgft_agent::logging::init();
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    match cli.cmd {
        Cmd::Version => {
            println!("{}", version());
            println!(
                "protocol range: v{}-v{}",
                wgft_proto::SUPPORTED_PROTOCOL.min,
                wgft_proto::SUPPORTED_PROTOCOL.max
            );
            ExitCode::SUCCESS
        }
        Cmd::Agent {
            cmd: AgentCmd::Run(a),
        } => match run_agent(&a) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(1))
            }
        },
    }
}

fn version() -> String {
    format!("dev-rust-{}", wgft::VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> RunArgs {
        let mut v = vec!["wgft", "agent", "run"];
        v.extend_from_slice(args);
        match Cli::try_parse_from(v).unwrap().cmd {
            Cmd::Agent {
                cmd: AgentCmd::Run(a),
            } => *a,
            Cmd::Version => panic!("not agent run"),
        }
    }

    #[test]
    fn version_is_set() {
        assert!(version().ends_with(wgft::VERSION));
    }

    #[test]
    fn unsupported_settings_are_config_errors() {
        for args in [
            &["--agent-allow-targets", "10.0.0.0/8"][..],
            &["--max-tcp-flows", "10"],
            &["--mode", "kernel"],
            &["--mode", "bogus"],
            &["--agent-netstack", "bogus"],
            &["--data-dir", " "],
            &["--wg-interface", "a%b"],
        ] {
            let r = agent_options(&parse(args)).unwrap_err();
            assert_eq!(AgentError::from(r).exit_code(), 3, "{args:?}");
        }
    }

    #[test]
    fn supported_settings_pass() {
        let o = agent_options(&parse(&[
            "--data-dir",
            "/tmp/x",
            "--name",
            "home",
            "--agent-netstack",
            "gvisor",
        ]))
        .unwrap();
        assert_eq!(o.data_dir, PathBuf::from("/tmp/x"));
        assert_eq!(o.name, "home");
    }
}
