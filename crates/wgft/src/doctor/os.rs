//! `agent doctor` が OS を読む既定の入口。

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use super::Access;

/// 名前の解決を待つ長さ。応答しない resolver で黙って止まらない。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Go の `runtime.GOOS + "/" + runtime.GOARCH` に当たる名前。
pub(crate) fn platform() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        a => a,
    };
    format!("{}/{arch}", wgft_agent::config::agent::host_os())
}

/// 実行している利用者を表す 1 句。
pub(crate) fn running_user_text() -> String {
    use wgft_agent::platform::procinfo;
    let name = procinfo::current_user_name().unwrap_or_default();
    let id = procinfo::euid();
    match (name.is_empty(), id >= 0) {
        (false, true) => format!("running as {name}, uid {id}"),
        (false, false) => format!("running as {name}"),
        (true, true) => format!("running as uid {id}"),
        (true, false) => "running as an unnamed user".into(),
    }
}

/// 名前を agent の宛先と同じ上限のある resolver で引く。期限を過ぎたら結果を待たない。
pub(crate) fn resolve(host: &str) -> Result<Vec<String>, String> {
    let addrs = wgft_agent::targets::resolve::lookup_host_blocking(host, RESOLVE_TIMEOUT)?;
    Ok(addrs.iter().map(ToString::to_string).collect())
}

/// そのパスを読めるかを、実際に開いて判定する。ディレクトリは中身を 1 件読めることまで見る。ファイルは
/// symlink を辿らず、通常のファイルでなければ判定できないものとする。
pub(crate) fn readable(path: &Path, dir: bool) -> (Access, String) {
    let classify = |e: std::io::Error| {
        let text = super::checks::go_err("open", path, &e);
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            (Access::Denied, text)
        } else {
            (Access::NotDetermined, text)
        }
    };
    if dir {
        match std::fs::read_dir(path) {
            Ok(mut it) => match it.next() {
                Some(Err(e)) => classify(e),
                _ => (Access::Allowed, String::new()),
            },
            Err(e) => classify(e),
        }
    } else {
        match wgft_agent::credentials::open_regular_read(path) {
            Ok(_) => (Access::Allowed, String::new()),
            Err(e) if e.kind() == std::io::ErrorKind::Other => {
                (Access::NotDetermined, e.to_string())
            }
            Err(e) => classify(e),
        }
    }
}

/// そのディレクトリに新しいファイルを作れるかを、何も作らずに判定する。Windows では判定しない。
pub(crate) fn dir_create_access(dir: &Path) -> (Access, String) {
    match wgft_agent::platform::procinfo::can_create_in(dir) {
        Some(Ok(())) => (Access::Allowed, String::new()),
        Some(Err(e)) => {
            let text = super::checks::go_err("access", dir, &e);
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                (Access::Denied, text)
            } else {
                (Access::NotDetermined, text)
            }
        }
        None => (
            Access::NotDetermined,
            "this host offers no way to test it without creating a file, and ACLs are not evaluated here".into(),
        ),
    }
}

/// `path` から親をたどって最初に見つかる既存のディレクトリ。
pub(crate) fn nearest_existing_dir(path: &Path, is_dir: &dyn Fn(&Path) -> bool) -> PathBuf {
    let mut p = clean(path);
    loop {
        let Some(parent) = p.parent().map(Path::to_path_buf) else {
            return p;
        };
        let parent = if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent
        };
        if parent == p {
            return p;
        }
        if is_dir(&parent) {
            return parent;
        }
        p = parent;
    }
}

/// 報告が答えるデータディレクトリを、絶対パスの正規形にする (Go の `filepath.Abs`)。
pub(crate) fn abs_data_dir(dir: &str) -> String {
    let p = Path::new(dir);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p),
            Err(_) => p.to_path_buf(),
        }
    };
    clean(&abs).display().to_string()
}

/// 字面だけで `.` と `..` を畳む (Go の `filepath.Clean`)。
fn clean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if depth > 0 {
                    out.pop();
                    depth -= 1;
                } else if !out.has_root() {
                    out.push("..");
                }
            }
            Component::Normal(n) => {
                out.push(n);
                depth += 1;
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn cleans_like_go() {
        assert_eq!(clean(Path::new("/a/./b/../c/")), Path::new("/a/c"));
        assert_eq!(clean(Path::new("/../a")), Path::new("/a"));
        assert_eq!(clean(Path::new("a/../../b")), Path::new("../b"));
        assert_eq!(clean(Path::new("")), Path::new("."));
    }

    #[cfg(unix)]
    #[test]
    fn finds_the_nearest_existing_parent() {
        let is_dir = |p: &Path| p == Path::new("/var") || p == Path::new("/");
        assert_eq!(
            nearest_existing_dir(Path::new("/var/lib/wgft"), &is_dir),
            Path::new("/var")
        );
        assert_eq!(
            nearest_existing_dir(Path::new("/x/y"), &is_dir),
            Path::new("/")
        );
    }

    #[test]
    fn literal_names_resolve() {
        assert_eq!(resolve("127.0.0.1").unwrap(), vec!["127.0.0.1".to_owned()]);
    }
}
