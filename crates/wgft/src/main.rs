//! v2 移行中の wgft のコマンド。今は Rust の agent の `agent run` と `version` を持つ。
//!
//! 設定は `WGFT_*` の環境変数で受け、dotenv はそのファイルでの書き方、フラグはその別名である。
//! 優先順位と値の検査は `wgft_agent::config` にある。作りは `docs/design/v2/agent-parity.md` に書く。

use std::process::ExitCode;

use wgft::cli::{self, Parsed};
use wgft::failure::Failure;
use wgft::{agent_keys, agent_run};
use wgft_agent::config::{LogLine, ProcessEnv, agent::host_os};
use wgft_agent::credentials;

fn main() -> ExitCode {
    // 時差はスレッドが 1 つのうちに読む
    wgft_agent::logging::init();
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            eprintln!("{}", f.line());
            ExitCode::from(f.code)
        }
    }
}

fn execute() -> Result<(), Failure> {
    match cli::parse(std::env::args_os())? {
        Parsed::Print(text) => {
            print!("{text}");
            Ok(())
        }
        Parsed::Version => {
            print!("{}", wgft::version_text());
            Ok(())
        }
        Parsed::VersionFlag => {
            println!("{}", wgft::version());
            Ok(())
        }
        Parsed::AgentRun { global, run } => run_agent(&global, &run),
        Parsed::AgentPubkey { global } => Ok(agent_keys::pubkey(
            &global,
            &ProcessEnv,
            &mut std::io::stdout(),
        )?),
        Parsed::AgentRotateKey { global } => Ok(agent_keys::rotate_key(
            &global,
            &ProcessEnv,
            &mut std::io::stdout(),
        )?),
        Parsed::AgentDoctor { global, args } => {
            wgft::doctor::command::run(&global, &args, &ProcessEnv, &mut std::io::stdout())
        }
        Parsed::AgentTeardown { global, args } => Ok(agent_keys::teardown(
            &global,
            &args,
            &ProcessEnv,
            host_os(),
        )?),
    }
}

fn run_agent(global: &cli::AgentGlobal, run: &cli::RunArgs) -> Result<(), Failure> {
    let mut early = Vec::new();
    let prepared = agent_run::prepare(global, run, &ProcessEnv, host_os(), &mut early);
    // 拒否のときも、それまでに積んだ警告を先に書く
    emit(&early);
    let prepared = prepared?;
    // Go の実行環境が v1 で行っていたとおり、soft の open file の上限を hard の値まで上げる。
    // agent run だけで行い、他のコマンドは何も出さない
    if let Err(e) = wgft_agent::platform::fdlimit::raise_nofile() {
        wgft_agent::logf!("cannot raise the open file limit, continuing with the current one: {e}");
    }
    credentials::ensure_data_dir(&prepared.options.data_dir)
        .map_err(|e| Failure::new(format!("data dir: {e}"), 1))?;
    emit(&prepared.startup_lines());
    wgft_agent::run(prepared.options)?;
    Ok(())
}

fn emit(lines: &[LogLine]) {
    for l in lines {
        l.emit();
    }
}
