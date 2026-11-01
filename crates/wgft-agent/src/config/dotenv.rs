//! dotenv の読み取り (仕様 `cli-config.md` の dotenv の構文)。
//!
//! systemd、Docker の `--env-file`、compose の `env_file` の解釈が一致する範囲だけを受ける。誤りの文面は
//! 行の中身も値も出さない。行が `WGFT_JOIN` の接続文字列のような秘密を含みうるためである。

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::error::Refusal;

/// 読み取った内容。同じキーが複数あれば最後の行が勝つ。
///
/// 仕様はバイト列を UTF-8 として扱う。Rust は値を `String` で持つので、UTF-8 でない値は別の値に化かさず、
/// キーだけを覚える。そのキーをコマンドが読むなら、`Config::resolve` が拒否にする。
/// コメントと空行は UTF-8 でなくてもよく、読まない名前の値も同じである。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Map {
    /// UTF-8 の値。
    pub values: HashMap<String, String>,
    /// 値が UTF-8 でないキー。
    pub invalid: HashSet<String>,
}

// 値は秘密でありうるので、Debug にはキーだけを出す
impl std::fmt::Debug for Map {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Map")
            .field("keys", &self.values.keys().collect::<Vec<_>>())
            .field("invalid", &self.invalid)
            .finish()
    }
}

/// 構文の誤り。最初に誤った行で止まる。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    /// 1 から数えた行番号。CRLF の行も 1 行と数える。
    pub line: usize,
    /// 理由の文面。行の中身も値も含まない。
    pub reason: String,
}

/// 本文を読む。
pub fn parse(text: &[u8]) -> Result<Map, SyntaxError> {
    let mut out = Map::default();
    for (i, raw) in text.split(|&b| b == b'\n').enumerate() {
        let mut line = raw;
        while let [rest @ .., b'\r'] = line {
            line = rest;
        }
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let at = |reason: String| SyntaxError {
            line: i + 1,
            reason,
        };
        let Some(eq) = line.iter().position(|&b| b == b'=').filter(|&p| p > 0) else {
            return Err(at(
                "not in KEY=value form; the line is not shown, since it may hold a secret".into(),
            ));
        };
        let (key, val) = (&line[..eq], &line[eq + 1..]);
        // 前後の Unicode の空白と、キーの中の空白とタブ。垂直タブなどが中にあるキーは通す。
        // UTF-8 でないバイトは空白でないので、置き換えた文字で判定してよい
        let key_text = String::from_utf8_lossy(key);
        if key_text.trim() != key_text || key.iter().any(|&b| b == b' ' || b == b'\t') {
            return Err(at("key name may not contain whitespace; the line is not shown, since it may hold a secret".into()));
        }
        if val.starts_with(b"\"") || val.starts_with(b"'") {
            return Err(at(format!(
                "do not quote the value of {}; Docker keeps quotes as part of the value",
                key_label(&key_text)
            )));
        }
        if val.iter().any(|&b| b == b' ' || b == b'\t') {
            return Err(at(format!(
                "the value of {} may not contain whitespace",
                key_label(&key_text)
            )));
        }
        // 読めないキーはどの設定にも当たらない
        let Ok(key) = std::str::from_utf8(key) else {
            continue;
        };
        if let Ok(v) = std::str::from_utf8(val) {
            out.invalid.remove(key);
            out.values.insert(key.to_owned(), v.to_owned());
        } else {
            out.values.remove(key);
            out.invalid.insert(key.to_owned());
        }
    }
    Ok(out)
}

/// 構文の誤りの文面に出すキー。ASCII の英数字と `_` だけならそのまま、それ以外は出さない。
/// 行が壊れていると、`=` より前に値の一部が入りうるためである。
fn key_label(key: &str) -> &str {
    if !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        key
    } else {
        "this key"
    }
}

/// 読み取りの失敗。
#[derive(Debug)]
pub enum ReadError {
    /// 構文の誤り。種別 `config`、対象 `パス:行` の拒否で、終了コード 3。
    Syntax(Refusal),
    /// 権限で読めない。種別 `config`、対象パスの拒否。呼び手が直し方を足す。`agent doctor` は拒否にせず所見にする。
    Permission(Refusal),
    /// その他。パスがディレクトリの場合など。終了コード 1。
    Other(String),
}

impl ReadError {
    /// 拒否か普通の誤りにする。
    #[must_use]
    pub fn into_error(self) -> crate::AgentError {
        match self {
            ReadError::Syntax(r) | ReadError::Permission(r) => r.into(),
            ReadError::Other(s) => crate::AgentError::Other(s),
        }
    }
}

/// ファイルを読む。無ければ空の対応表である。ENOENT だけが無いことを表し、ENOTDIR は普通の誤りになる。
pub fn read(path: &Path) -> Result<Map, ReadError> {
    let shown = path.display().to_string();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::default()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let os = os_error_text(&e);
            return Err(ReadError::Permission(Refusal::config(
                &shown,
                format!("open {shown}: {os}; {}", super::perms::read_facts(path)),
            )));
        }
        Err(e) => {
            return Err(ReadError::Other(super::perms::go_style_path_error(
                "read", path, &e,
            )));
        }
    };
    parse(&bytes)
        .map_err(|e| ReadError::Syntax(Refusal::config(&format!("{shown}:{}", e.line), e.reason)))
}

/// Go の `*os.PathError` の末尾の文。権限の誤りは Unix では `permission denied` で、
/// Windows では OS の文 (末尾の句点と空白は除く)。
fn os_error_text(e: &std::io::Error) -> String {
    if cfg!(unix) {
        "permission denied".to_owned()
    } else {
        strip_os_suffix(&e.to_string())
            .trim_end_matches(['.', ' '])
            .to_owned()
    }
}

/// `std::io::Error` の文から `(os error N)` の接尾辞を除く。
pub(super) fn strip_os_error(e: &std::io::Error) -> String {
    strip_os_suffix(&e.to_string())
}

fn strip_os_suffix(s: &str) -> String {
    match s.rfind(" (os error ") {
        Some(i) if s.ends_with(')') => s[..i].to_owned(),
        _ => s.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_duplicate_wins_and_inner_equals_is_kept() {
        let m = parse(b"A=1\nA=2\nB=x=y\n").unwrap();
        assert_eq!(m.values["A"], "2");
        assert_eq!(m.values["B"], "x=y");
    }

    #[test]
    fn unicode_whitespace_around_a_key_is_refused() {
        // 前後の Unicode の空白は拒む。中の垂直タブは通す (Go の TrimSpace と ContainsAny の差)
        assert!(parse("\u{3000}A=1\n".as_bytes()).is_err());
        assert!(parse("A\u{b}=1\n".as_bytes()).is_err());
        assert!(parse("A\u{b}B=1\n".as_bytes()).is_ok());
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(&dir.path().join("none.env")).unwrap(), Map::default());
    }

    // Windows は、ディレクトリを開くことも、ファイルを通り抜けることも、別の OS の誤りで返す
    #[cfg(unix)]
    #[test]
    fn a_directory_is_an_ordinary_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(read(dir.path()), Err(ReadError::Other(_))));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_through_a_file_is_an_ordinary_error() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, "A=1\n").unwrap();
        assert!(matches!(read(&f.join("x")), Err(ReadError::Other(_))));
    }

    #[test]
    fn invalid_utf8_is_kept_per_key_and_comments_may_hold_it() {
        let m = parse(b"# \xff\xfe comment\nA=1\nWGFT_JOIN=\xff\nB=\xfe\nB=2\n\xff=3\n").unwrap();
        assert_eq!(m.values["A"], "1");
        assert_eq!(m.values["B"], "2");
        assert!(!m.invalid.contains("B"));
        assert!(m.invalid.contains("WGFT_JOIN"));
        // 読めないキーは覚えない
        assert_eq!(m.values.len(), 2);
        // 構文の誤りは UTF-8 でない値でも同じ文面で、値を出さない
        let e = parse(b"A=\xff \xfe\n").unwrap_err();
        assert_eq!(e.reason, "the value of A may not contain whitespace");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_gives_the_facts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.env");
        std::fs::write(&f, "A=1\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        // root は権限に関係なく読めるので、読めた場合は確かめない
        if let Err(ReadError::Permission(r)) = read(&f) {
            let s = r.to_string();
            assert!(
                s.starts_with(&format!(
                    "refusing to start [config {p}]: open {p}: permission denied; this process runs as uid ",
                    p = f.display()
                )),
                "{s}"
            );
            assert!(
                s.contains("and the file is mode 0000 with owner uid "),
                "{s}"
            );
        }
    }
}
