//! `wgft agent run` の入口。設定を読んで入口の検査を通し、`wgft_agent::run` に渡す値を作る。
//!
//! 順序は仕様の起動ログの節に従う。この版が持たない機能を要る設定 (カーネルモード、宛先の許可一覧) は、
//! 認証情報とトンネルに触れる前に拒む。

use wgft_agent::config::agent::{self, Settings};
use wgft_agent::config::{self, Config, Defaults, Env, LogLine};
use wgft_agent::{AgentError, Options};

use crate::cli::{AgentGlobal, RunArgs};

/// 入口を通った設定。
#[derive(Debug)]
pub struct Prepared {
    /// `wgft_agent::run` に渡す値。
    pub options: Options,
    /// 解決した設定。
    pub config: Config,
    /// 入口を通った値。
    pub settings: Settings,
}

impl Prepared {
    /// データディレクトリを作った後に標準エラーへ書く行。
    #[must_use]
    pub fn startup_lines(&self) -> Vec<LogLine> {
        agent::startup_lines(&self.config, &self.settings)
    }
}

/// 書かれたフラグを、環境変数の名前で引く対応表にする。整数は 10 進に書き直す。
fn flag_values(
    global: &AgentGlobal,
    run: &RunArgs,
) -> std::collections::HashMap<&'static str, String> {
    let strings = [
        ("WGFT_DATA_DIR", &global.data_dir),
        ("WGFT_JOIN", &run.join),
        ("WGFT_NAME", &run.name),
        ("WGFT_MODE", &run.mode),
        ("WGFT_WG_INTERFACE", &run.wg_interface),
        ("WGFT_AGENT_NETSTACK", &run.agent_netstack),
        ("WGFT_AGENT_BATCH_MIB", &run.agent_batch_mib),
        (config::allow_targets::ENV, &run.agent_allow_targets),
    ];
    let mut out: std::collections::HashMap<_, _> = strings
        .into_iter()
        .filter_map(|(k, v)| v.clone().map(|v| (k, v)))
        .collect();
    for (k, v) in [
        ("WGFT_MAX_UDP_FLOWS", run.max_udp_flows),
        ("WGFT_MAX_TCP_FLOWS", run.max_tcp_flows),
    ] {
        if let Some(n) = v {
            out.insert(k, n.to_string());
        }
    }
    out
}

/// 設定を読み、入口の検査を通す。この版が持たない機能の拒否 (`prepare`) より前の段である。
/// 標準エラーに書く行は、失敗しても書けるよう `early` に積む。
///
/// # Errors
///
/// dotenv の読み取りと構文の誤り、入口の検査の拒否を返す。
pub fn prepare_door(
    global: &AgentGlobal,
    run: &RunArgs,
    env: &dyn Env,
    os: &str,
    early: &mut Vec<LogLine>,
) -> Result<Prepared, AgentError> {
    let defaults = Defaults::for_host(env);
    let path = config::config_path(global.config.as_deref(), env, &defaults.config_path);
    let file = config::dotenv::read(&path).map_err(|e| match e {
        config::dotenv::ReadError::Permission(r) => {
            AgentError::from(r.hint(agent::unreadable_hint(&path)))
        }
        other => other.into_error(),
    })?;
    let cfg = Config::resolve(
        agent::run_specs(&defaults),
        &flag_values(global, run),
        env,
        &file,
    )?;
    if cfg.has_secret_from_file() && config::readable_by_other(&path) {
        early.push(LogLine::Plain(config::insecure_file_warning(&path)));
    }
    let settings = agent::check_door(&cfg, os)?;
    early.extend(agent::join_warning(&settings));
    let options = Options {
        data_dir: settings.data_dir.clone().into(),
        join: settings.join.clone(),
        name: settings.name.clone(),
        version: crate::version(),
        tun_name: settings.wg_interface.clone(),
    };
    Ok(Prepared {
        options,
        config: cfg,
        settings,
    })
}

/// 入口の検査に加えて、この版が持たない機能を要る設定を、認証情報とトンネルに触れる前に拒む。
///
/// # Errors
///
/// 入口の検査の拒否と、カーネルモードと宛先の許可一覧の拒否を返す。
pub fn prepare(
    global: &AgentGlobal,
    run: &RunArgs,
    env: &dyn Env,
    os: &str,
    early: &mut Vec<LogLine>,
) -> Result<Prepared, AgentError> {
    let p = prepare_door(global, run, env, os, early)?;
    agent::check_supported(&p.settings)?;
    Ok(p)
}
