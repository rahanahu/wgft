//! `WGFT_DATA_DIR` と dotenv の既定のパス。規範は `docs/design/spec/credentials.md` の「置き場所」と
//! `docs/design/spec/cli-config.md` にある。OS の違いは [`Os`] と環境の引数で受けるので、3 つの OS の
//! 表をどの OS の試験でも確かめられる。

use std::ffi::OsString;
use std::path::PathBuf;

/// 既定のパスを決める OS の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux とその他の Unix。
    Unix,
    /// macOS。
    MacOs,
    /// Windows。
    Windows,
}

impl Os {
    /// このビルドの OS。
    pub const HOST: Os = if cfg!(windows) {
        Os::Windows
    } else if cfg!(target_os = "macos") {
        Os::MacOs
    } else {
        Os::Unix
    };
}

/// データディレクトリの既定。`env` は環境変数の引き方で、引けなければ `None`。空の値は無いものとして
/// 扱う。
///
/// - Unix:`/var/lib/wgft`
/// - macOS:`$HOME/Library/Application Support/wgft`。`HOME` が空なら作業ディレクトリの `wgft`
///   (Go の `os.UserConfigDir` が失敗したときの v1 の代わりと同じ)
/// - Windows:`%ProgramData%\wgft`。`ProgramData` が空なら `C:\ProgramData\wgft`
pub fn default_data_dir_for(os: Os, env: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    let nonempty = |k: &str| env(k).filter(|v| !v.is_empty());
    match os {
        Os::Unix => PathBuf::from("/var/lib/wgft"),
        Os::MacOs => match nonempty("HOME") {
            Some(home) => PathBuf::from(home).join("Library/Application Support/wgft"),
            None => PathBuf::from("wgft"),
        },
        Os::Windows => match nonempty("ProgramData") {
            Some(pd) => PathBuf::from(pd).join("wgft"),
            None => PathBuf::from(r"C:\ProgramData\wgft"),
        },
    }
}

/// dotenv の既定。Unix は `/etc/wgft/agent.env` で、macOS と Windows はデータディレクトリの
/// `agent.env`。
pub fn default_config_path_for(os: Os, data_dir: &std::path::Path) -> PathBuf {
    match os {
        Os::Unix => PathBuf::from("/etc/wgft/agent.env"),
        Os::MacOs | Os::Windows => data_dir.join("agent.env"),
    }
}

/// このホストのデータディレクトリの既定。起動の時に 1 回だけ読む。
pub fn default_data_dir() -> PathBuf {
    default_data_dir_for(Os::HOST, |k| std::env::var_os(k))
}

/// このホストの dotenv の既定。
pub fn default_config_path() -> PathBuf {
    default_config_path_for(Os::HOST, &default_data_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn unix_ignores_the_environment() {
        let d = default_data_dir_for(Os::Unix, env(&[("HOME", "/root")]));
        assert_eq!(d, Path::new("/var/lib/wgft"));
        assert_eq!(
            default_config_path_for(Os::Unix, &d),
            Path::new("/etc/wgft/agent.env")
        );
    }

    #[test]
    fn macos_uses_home_or_a_relative_directory() {
        let d = default_data_dir_for(Os::MacOs, env(&[("HOME", "/Users/a")]));
        assert_eq!(d, Path::new("/Users/a/Library/Application Support/wgft"));
        assert_eq!(
            default_config_path_for(Os::MacOs, &d),
            Path::new("/Users/a/Library/Application Support/wgft/agent.env")
        );
        for e in [&[][..], &[("HOME", "")][..]] {
            assert_eq!(default_data_dir_for(Os::MacOs, env(e)), Path::new("wgft"));
        }
    }

    #[test]
    fn windows_uses_program_data_or_the_system_drive_fallback() {
        let d = default_data_dir_for(Os::Windows, env(&[("ProgramData", "D:\\PD")]));
        assert_eq!(d, PathBuf::from("D:\\PD").join("wgft"));
        assert_eq!(
            default_config_path_for(Os::Windows, &d),
            d.join("agent.env")
        );
        for e in [&[][..], &[("ProgramData", "")][..]] {
            assert_eq!(
                default_data_dir_for(Os::Windows, env(e)),
                Path::new(r"C:\ProgramData\wgft")
            );
        }
    }

    #[test]
    fn host_default_is_absolute_except_the_macos_fallback() {
        let d = default_data_dir();
        assert!(d.is_absolute() || Os::HOST == Os::MacOs, "{d:?}");
    }

    // Windows の環境変数の名前は大文字と小文字を区別しない。std が Windows の API を使うので同じ扱いに
    // なる見込みを、Windows の CI で確かめる。
    #[cfg(windows)]
    #[test]
    fn windows_environment_names_are_case_insensitive() {
        let upper = std::env::var_os("PROGRAMDATA");
        let mixed = std::env::var_os("ProgramData");
        assert!(upper.is_some());
        assert_eq!(upper, mixed);
    }
}
