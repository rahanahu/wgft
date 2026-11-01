//! このプロセスの実行主体。`agent doctor` の材料で、制御ソケットの応答 (`process`) と CLI の
//! `host.privileges` が使う。

/// 実 uid。Windows では Go の `os.Getuid` と同じく -1。
#[must_use]
pub fn uid() -> i64 {
    #[cfg(unix)]
    {
        // SAFETY: getuid は引数を取らず、失敗しない
        i64::from(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        -1
    }
}

/// 実効 uid。Windows では Go の `os.Geteuid` と同じく -1。
#[must_use]
pub fn euid() -> i64 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid は引数を取らず、失敗しない
        i64::from(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        -1
    }
}

/// uid の利用者名。引けなければ `None`。systemd の DynamicUser の利用者は `/etc/passwd` に無いので、
/// 静的なビルドでは引けないことがある。
#[cfg(unix)]
#[must_use]
pub fn user_name(uid: i64) -> Option<String> {
    let uid = libc::uid_t::try_from(uid).ok()?;
    let mut pw: libc::passwd = unsafe_zeroed_passwd();
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    for _ in 0..6 {
        // SAFETY: pw、buf、out は呼び出しの間は有効で、buf の長さを渡す
        let rc = unsafe {
            libc::getpwuid_r(uid, &raw mut pw, buf.as_mut_ptr(), buf.len(), &raw mut out)
        };
        if rc == libc::ERANGE {
            let n = buf.len() * 2;
            buf.resize(n, 0);
            continue;
        }
        if rc != 0 || out.is_null() || pw.pw_name.is_null() {
            return None;
        }
        // SAFETY: 成功したので pw_name は buf の中の NUL で終わる文字列を指す
        let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
        return Some(name.to_string_lossy().into_owned()).filter(|s| !s.is_empty());
    }
    None
}

#[cfg(unix)]
fn unsafe_zeroed_passwd() -> libc::passwd {
    // SAFETY: passwd はポインタと整数だけの C の構造体で、全ビット 0 は有効な値である
    unsafe { std::mem::zeroed() }
}

/// Windows では uid が無いので引かない。
#[cfg(not(unix))]
#[must_use]
pub fn user_name(_uid: i64) -> Option<String> {
    None
}

/// 実行している利用者の名前 (Go の `user.Current().Username`)。Windows では `DOMAIN\user` の形にする。
#[must_use]
pub fn current_user_name() -> Option<String> {
    #[cfg(unix)]
    {
        // Go の `user.Current` は実 uid で引く
        user_name(uid())
    }
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").ok().filter(|s| !s.is_empty())?;
        Some(match std::env::var("USERDOMAIN") {
            Ok(d) if !d.is_empty() => format!("{d}\\{user}"),
            _ => user,
        })
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        None
    }
}

/// このプロセスが実効の `CAP_NET_ADMIN` を持つか。Linux だけで `/proc/self/status` の `CapEff` から読み、
/// 他の OS と読めなかった場合は `None`。
#[must_use]
pub fn net_admin() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        cap_eff_has_net_admin(&s)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// `/proc/<pid>/status` の `CapEff` の行から `CAP_NET_ADMIN` (12) のビットを読む。
#[cfg(any(target_os = "linux", test))]
fn cap_eff_has_net_admin(status: &str) -> Option<bool> {
    const CAP_NET_ADMIN: u32 = 12;
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))?
        .trim();
    let v = u64::from_str_radix(hex, 16).ok()?;
    Some(v & (1 << CAP_NET_ADMIN) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_net_admin_bit() {
        assert_eq!(
            cap_eff_has_net_admin("Name:\tx\nCapEff:\t000001ffffffffff\n"),
            Some(true)
        );
        assert_eq!(
            cap_eff_has_net_admin("CapEff:\t0000000000000000\n"),
            Some(false)
        );
        assert_eq!(cap_eff_has_net_admin("CapInh:\t0\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn this_process_has_a_uid_and_root_is_named() {
        assert!(uid() >= 0);
        assert_eq!(user_name(0).as_deref(), Some("root"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_has_no_uid() {
        assert_eq!(uid(), -1);
        assert_eq!(euid(), -1);
    }
}
