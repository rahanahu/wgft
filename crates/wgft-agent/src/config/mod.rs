//! agent の設定の層 (仕様 `docs/design/spec/cli-config.md`、作りは `docs/design/v2/agent-parity.md`)。
//!
//! コマンドの入口で 1 回だけ設定を読み、各項目の値と出所 (`flag`、`env`、`file`、`default`) を持つ。
//! 優先順位はフラグ、環境変数、dotenv、既定の順で、clap の `env` の機能は使わない。値の検査と起動ログの
//! 行も、ここが決める。clap への接続と標準エラーへの書き出しは `wgft` の crate が持つ。

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::Refusal;

pub mod agent;
pub mod allow_targets;
pub mod dotenv;
pub mod gostd;
mod perms;

pub use perms::{
    config_file_perm_facts, go_style_path_error, insecure_file_warning, readable_by_other,
};

/// 値の出所。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// コマンドラインのフラグ。値が既定と同じでも出所はフラグである。
    Flag,
    /// プロセスの環境変数。値が空でも、あれば dotenv と既定に優先する。
    Env,
    /// dotenv のファイル。値が空でも、あれば既定に優先する。
    File,
    /// どこにも無いときの既定。
    Default,
}

impl Source {
    /// 有効な設定の行に書く語。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Env => "env",
            Source::File => "file",
            Source::Default => "default",
        }
    }
}

/// 設定項目の定義。
#[derive(Clone, Debug)]
pub struct Spec {
    /// `WGFT_*` の環境変数の名前。dotenv のキーも同じ。
    pub env: &'static str,
    /// フラグの別名 (`--` を除く)。
    pub flag: &'static str,
    /// 既定の値。
    pub default: String,
    /// 秘密か。有効な設定の行で値を伏せる。
    pub secret: bool,
}

/// 環境変数の引き元。試験は対応表を渡す。
pub trait Env {
    /// 名前の変数。無ければ `None`。
    fn var(&self, name: &str) -> Option<OsString>;
}

/// このプロセスの環境。
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

impl<S: std::hash::BuildHasher> Env for HashMap<String, OsString, S> {
    fn var(&self, name: &str) -> Option<OsString> {
        self.get(name).cloned()
    }
}

/// 1 項目の解決結果。
#[derive(Clone)]
struct Resolved {
    value: String,
    source: Source,
}

/// 解決済みの設定。
#[derive(Clone)]
pub struct Config {
    specs: Vec<Spec>,
    vals: HashMap<&'static str, Resolved>,
}

// 秘密の項目の値は Debug に出さない
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut m = f.debug_map();
        for sp in &self.specs {
            let r = self.resolved(sp.env);
            let shown = if sp.secret && !r.value.is_empty() {
                "****"
            } else {
                r.value.as_str()
            };
            m.entry(
                &sp.env,
                &format_args!("{shown:?} from {}", r.source.as_str()),
            );
        }
        m.finish()
    }
}

impl Config {
    /// 優先順位に従って解決する。`flags` は書かれたフラグの値で、環境変数の名前で引く。整数のフラグは
    /// 10 進に書き直した文字列で渡す。知らない `WGFT_*` や、他のプロセス向けの `WGFT_*` は読まないので
    /// 黙って無視される。UTF-8 でない環境変数は、別の値に化かさず拒む。
    pub fn resolve(
        specs: Vec<Spec>,
        flags: &HashMap<&'static str, String>,
        env: &dyn Env,
        file: &dotenv::Map,
    ) -> Result<Config, Refusal> {
        let mut vals = HashMap::new();
        for sp in &specs {
            let mut r = Resolved {
                value: sp.default.clone(),
                source: Source::Default,
            };
            if file.invalid.contains(sp.env) {
                return Err(Refusal::config(
                    sp.env,
                    "is not valid UTF-8 in the dotenv file",
                ));
            }
            if let Some(v) = file.values.get(sp.env) {
                r = Resolved {
                    value: v.clone(),
                    source: Source::File,
                };
            }
            if let Some(v) = env.var(sp.env) {
                let value = v
                    .into_string()
                    .map_err(|_| Refusal::config(sp.env, "is not valid UTF-8"))?;
                r = Resolved {
                    value,
                    source: Source::Env,
                };
            }
            if let Some(v) = flags.get(sp.env) {
                r = Resolved {
                    value: v.clone(),
                    source: Source::Flag,
                };
            }
            vals.insert(sp.env, r);
        }
        Ok(Config { specs, vals })
    }

    /// 項目の値。定義に無い名前は誤りなので、空を返さず止める。
    #[must_use]
    pub fn get(&self, env: &str) -> &str {
        &self.resolved(env).value
    }

    /// 項目の出所。
    #[must_use]
    pub fn source(&self, env: &str) -> Source {
        self.resolved(env).source
    }

    fn resolved(&self, env: &str) -> &Resolved {
        self.vals
            .get(env)
            .unwrap_or_else(|| panic!("{env} is not a setting of this command"))
    }

    /// 秘密の項目の空でない値を、dotenv から読んだか。
    #[must_use]
    pub fn has_secret_from_file(&self) -> bool {
        self.specs.iter().any(|sp| {
            let r = self.resolved(sp.env);
            sp.secret && r.source == Source::File && !r.value.is_empty()
        })
    }

    /// 有効な設定の行。名前の昇順で、秘密は空でなければ `****` に置き換える。幅は Unicode のコード
    /// ポイントで数える (Rust の書式の幅と同じ)。
    #[must_use]
    pub fn effective_lines(&self) -> Vec<String> {
        let mut specs: Vec<&Spec> = self.specs.iter().collect();
        specs.sort_by_key(|sp| sp.env);
        specs
            .into_iter()
            .map(|sp| {
                let r = self.resolved(sp.env);
                let shown = if sp.secret && !r.value.is_empty() {
                    "****"
                } else {
                    r.value.as_str()
                };
                format!("  {:<22} = {shown:<28} from {}", sp.env, r.source.as_str())
            })
            .collect()
    }
}

/// OS ごとの既定のパス。
#[derive(Clone, Debug)]
pub struct Defaults {
    /// `WGFT_DATA_DIR` の既定。
    pub data_dir: String,
    /// agent の dotenv の既定。
    pub config_path: PathBuf,
}

impl Defaults {
    /// プロセスの起動の時に 1 回だけ決める。表は `platform::paths` が持つ。
    #[must_use]
    pub fn for_host(env: &dyn Env) -> Defaults {
        use crate::platform::paths::{Os, default_config_path_for, default_data_dir_for};
        let dir = default_data_dir_for(Os::HOST, |k| env.var(k));
        Defaults {
            config_path: default_config_path_for(Os::HOST, &dir),
            data_dir: dir.to_string_lossy().into_owned(),
        }
    }
}

/// dotenv のパスを決める。`--config`、`WGFT_CONFIG`、既定の順で、`WGFT_CONFIG` は環境変数でだけ受ける。
/// 空のパスは存在しないファイルと同じに扱う。
#[must_use]
pub fn config_path(flag: Option<&std::ffi::OsStr>, env: &dyn Env, default: &Path) -> PathBuf {
    if let Some(f) = flag {
        return PathBuf::from(f);
    }
    env.var("WGFT_CONFIG")
        .map_or_else(|| default.to_path_buf(), PathBuf::from)
}

/// 起動の時に標準エラーへ書く 1 行。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogLine {
    /// 時刻を付けずに書く。
    Plain(String),
    /// Go の `log` の既定の形の時刻を付けて書く。
    Stamped(String),
}

impl LogLine {
    /// 標準エラーに書く。
    pub fn emit(&self) {
        match self {
            LogLine::Plain(s) => eprintln!("{}", crate::logging::terminal_safe(s)),
            LogLine::Stamped(s) => crate::logging::line(s),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    #[test]
    fn a_non_utf8_environment_value_of_a_setting_is_refused_and_others_are_ignored() {
        let spec = Spec {
            env: "WGFT_NAME",
            flag: "name",
            default: String::new(),
            secret: false,
        };
        let mut env: HashMap<String, OsString> = HashMap::new();
        env.insert("WGFT_OTHER".into(), OsString::from_vec(vec![0xff]));
        let ok = Config::resolve(
            vec![spec.clone()],
            &HashMap::new(),
            &env,
            &dotenv::Map::default(),
        );
        assert!(ok.is_ok());
        env.insert("WGFT_NAME".into(), OsString::from_vec(vec![0xff]));
        let e = Config::resolve(
            vec![spec.clone()],
            &HashMap::new(),
            &env,
            &dotenv::Map::default(),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "refusing to start [config WGFT_NAME]: is not valid UTF-8"
        );
        // dotenv の値も、コマンドが読む名前のときだけ拒む
        let mut file = dotenv::Map::default();
        file.invalid.insert("WGFT_NAME".into());
        let e = Config::resolve(vec![spec], &HashMap::new(), &HashMap::new(), &file).unwrap_err();
        assert!(e.to_string().contains("WGFT_NAME"));
        file.invalid.clear();
        file.invalid.insert("WGFT_UNREAD".into());
        let spec2 = Spec {
            env: "WGFT_NAME",
            flag: "name",
            default: String::new(),
            secret: false,
        };
        assert!(Config::resolve(vec![spec2], &HashMap::new(), &HashMap::new(), &file).is_ok());
    }
}
