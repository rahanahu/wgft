//! `wgft agent doctor` の入口。設定から証拠の出どころを決め、診断し、報告を書き、終了コードを決める。

use std::collections::HashMap;
use std::io::Write;

use wgft_agent::config::agent::{flow_cap, run_specs};
use wgft_agent::config::dotenv::ReadError;
use wgft_agent::config::{self, Config, Defaults, Env, Source};
use wgft_agent::{AgentError, Refusal};

use super::Input;
use crate::cli::{AgentGlobal, DoctorArgs};
use crate::failure::Failure;

/// 設定から証拠の出どころを決める。dotenv を権限で読めなければ拒まずに所見にし、設定はフラグ、環境変数、
/// 既定から決める。構文の誤りは終了コード 3 の拒否、それ以外の読みの誤りは 1 である。
///
/// # Errors
///
/// 設定の拒否と、dotenv の権限以外の読みの誤りを返す。
pub fn input_from(
    global: &AgentGlobal,
    args: &DoctorArgs,
    env: &dyn Env,
) -> Result<Input, AgentError> {
    let defaults = Defaults::for_host(env);
    let config_path = config::config_path(global.config.as_deref(), env, &defaults.config_path);
    let (file, unreadable) = match config::dotenv::read(&config_path) {
        Ok(m) => (m, None),
        Err(ReadError::Permission(r)) => {
            // 拒否の文面は所見には長すぎる。もとの誤りの句だけを持つ
            let first = r
                .reason
                .split_once("; ")
                .map_or(r.reason.as_str(), |(a, _)| a)
                .to_owned();
            (config::dotenv::Map::default(), Some(first))
        }
        Err(e) => return Err(e.into_error().one_shot()),
    };
    let mut flags: HashMap<&'static str, String> = HashMap::new();
    if let Some(d) = &global.data_dir {
        let d = d.to_str().ok_or_else(|| {
            AgentError::from(Refusal::config("WGFT_DATA_DIR", "is not valid UTF-8").one_shot())
        })?;
        flags.insert("WGFT_DATA_DIR", d.to_owned());
    }
    for (k, v) in [
        ("WGFT_MAX_UDP_FLOWS", args.max_udp_flows),
        ("WGFT_MAX_TCP_FLOWS", args.max_tcp_flows),
    ] {
        if let Some(n) = v {
            flags.insert(k, n.to_string());
        }
    }
    let c = Config::resolve(run_specs(&defaults), &flags, env, &file).map_err(Refusal::one_shot)?;
    let dir = c.get("WGFT_DATA_DIR").trim().to_owned();
    if dir.is_empty() {
        return Err(Refusal::config(
            "WGFT_DATA_DIR",
            "is empty; give the directory that holds agent.json",
        )
        .one_shot()
        .into());
    }
    let udp = flow_cap(&c, "WGFT_MAX_UDP_FLOWS").map_err(Refusal::one_shot)?;
    let tcp = flow_cap(&c, "WGFT_MAX_TCP_FLOWS").map_err(Refusal::one_shot)?;
    let from_default = c.source("WGFT_DATA_DIR") == Source::Default;
    let mut input = Input::for_host(dir);
    input.max_udp_flows = udp;
    input.max_tcp_flows = tcp;
    input.data_dir_assumed = unreadable.is_some() && from_default;
    input.data_dir_default = from_default;
    input.config_unreadable = unreadable;
    input.config_path = config_path;
    Ok(input)
}

/// `wgft agent doctor` を実行する。報告を書いてから、総合判定に従う終了の誤りを返す。
///
/// # Errors
///
/// 設定の拒否 (3)、報告を書けなかった失敗 (2)、総合判定の `unknown` (2) と `failed` (1) を返す。
pub fn run(
    global: &AgentGlobal,
    args: &DoctorArgs,
    env: &dyn Env,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    let input = input_from(global, args, env)?;
    let rep = super::diagnose(&input)?;
    if args.json == Some(true) {
        super::write_json(out, &rep).map_err(|e| Failure::unavailable(e.to_string()))?;
    } else {
        super::write_report(out, &rep).map_err(|e| Failure::unavailable(e.to_string()))?;
    }
    super::exit(&rep).map_or(Ok(()), Err)
}
