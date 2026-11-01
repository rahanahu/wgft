//! 起動の時に soft の `RLIMIT_NOFILE` を hard の値まで上げる。Go の実行環境が v1 で行っていたことで、
//! 同梱の unit と plist は `LimitNOFILE` を書かずにこれに頼る。macOS では hard が無制限でも
//! `kern.maxfilesperproc` を超える値を設定できないので、その値で頭を打つ。
//!
//! 上げた上限は子のプロセスへ引き継がれる。Go は 1.21 から exec の前に元の値へ戻す。Rust の agent が子の
//! プロセスを起こす段 (カーネルモードの helper など) は、[`original_soft`] の値を `pre_exec` で戻すこと。
//! hard が無制限の Linux では、soft を `fs.nr_open` まで上げる (Go は上げない)。

/// 上げた結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Raised {
    /// 上げる前の soft の値。
    pub from: u64,
    /// 上げた後の soft の値。
    pub to: u64,
}

/// soft の上限を上げる。Unix でないホストには上限の概念が無いので何もせず `None` を返す。
/// 既に上げ切っていれば `from == to` を返す。
///
/// # Errors
///
/// 上限を読めないか設定できなければ誤りを返す。呼び出し側は英語の 1 行を出して起動を続ける。
pub fn raise_nofile() -> std::io::Result<Option<Raised>> {
    let r = imp::raise()?;
    if let Some(r) = r {
        // 最初の呼び出しの前の値だけを覚える
        let _ = ORIGINAL.set(r.from);
    }
    Ok(r)
}

static ORIGINAL: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// 上げる前の soft の値。上げていなければ `None`。子のプロセスを起こすときに戻すための値。
#[must_use]
pub fn original_soft() -> Option<u64> {
    ORIGINAL.get().copied()
}

/// 上げる先。`hard` が無制限 (`u64::MAX`) のときは `cap` で頭を打つ。`cap` が無ければ `hard` のまま。
#[cfg(any(unix, test))]
fn target(hard: u64, cap: Option<u64>) -> u64 {
    match cap {
        Some(c) => hard.min(c),
        None => hard,
    }
}

#[cfg(unix)]
mod imp {
    use super::{Raised, target};

    // macOS の rlim_t は u64、Linux は u64 (glibc, musl とも)。他の Unix でも変換で受ける
    #[expect(
        clippy::unnecessary_cast,
        reason = "rlim_t is a different integer type on some Unix targets"
    )]
    pub(super) fn get() -> std::io::Result<(u64, u64)> {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: lim は書き込める rlimit を指す
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((lim.rlim_cur as u64, lim.rlim_max as u64))
    }

    #[expect(
        clippy::useless_conversion,
        reason = "rlim_t is a different integer type on some Unix targets"
    )]
    fn set(cur: u64, max: u64) -> std::io::Result<()> {
        let lim = libc::rlimit {
            rlim_cur: cur.try_into().unwrap_or(libc::RLIM_INFINITY),
            rlim_max: max.try_into().unwrap_or(libc::RLIM_INFINITY),
        };
        // SAFETY: lim は読める rlimit を指す
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// OS が許す上限。macOS は `kern.maxfilesperproc`。Linux は hard が無制限のときに限り
    /// `fs.nr_open` を見る (soft をそれより大きくできないため)。
    pub(super) fn os_cap(hard: u64) -> Option<u64> {
        #[cfg(target_os = "macos")]
        {
            let _ = hard;
            let mut v: libc::c_int = 0;
            let mut len = size_of::<libc::c_int>();
            // SAFETY: 名前は NUL で終わり、v と len は書き込める場所を指す
            let rc = unsafe {
                libc::sysctlbyname(
                    c"kern.maxfilesperproc".as_ptr(),
                    (&raw mut v).cast(),
                    &raw mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            (rc == 0 && v > 0).then(|| u64::from(v.unsigned_abs()))
        }
        #[cfg(not(target_os = "macos"))]
        {
            if hard != u64::MAX && hard != libc::RLIM_INFINITY {
                return None;
            }
            std::fs::read_to_string("/proc/sys/fs/nr_open")
                .ok()
                .and_then(|s| s.trim().parse().ok())
        }
    }

    pub(super) fn raise() -> std::io::Result<Option<Raised>> {
        let (cur, raw_hard) = get()?;
        // RLIM_INFINITY は u64::MAX に揃えて比べる
        let hard = if raw_hard == libc::RLIM_INFINITY {
            u64::MAX
        } else {
            raw_hard
        };
        let to = target(hard, os_cap(hard));
        // soft が無制限か、既に目標以上なら触らない
        if cur >= to {
            return Ok(Some(Raised { from: cur, to: cur }));
        }
        // hard は読んだ値のまま渡す (macOS の RLIM_INFINITY は u64::MAX でない)
        set(to, raw_hard)?;
        Ok(Some(Raised { from: cur, to }))
    }
}

#[cfg(not(unix))]
mod imp {
    use super::Raised;

    #[expect(
        clippy::unnecessary_wraps,
        reason = "the same signature as the Unix version"
    )]
    pub(super) fn raise() -> std::io::Result<Option<Raised>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_is_capped_only_when_a_cap_exists() {
        assert_eq!(target(4096, None), 4096);
        assert_eq!(target(u64::MAX, None), u64::MAX);
        assert_eq!(target(u64::MAX, Some(10_240)), 10_240);
        assert_eq!(target(1024, Some(10_240)), 1024);
    }

    #[cfg(not(unix))]
    #[test]
    fn nothing_to_raise_on_windows() {
        assert_eq!(raise_nofile().unwrap(), None);
    }

    #[cfg(unix)]
    mod unix {
        use super::super::imp;
        use super::*;

        const CHILD_ENV: &str = "WGFT_FDLIMIT_CHILD";

        /// 子のプロセスの中身。soft の値を下げてから起動の処理を呼ぶ。親の試験が環境変数を付けて起動する
        /// ときだけ動く。プロセスの上限を変えるので、試験の本体のプロセスでは実行しない。
        #[test]
        fn child_body() {
            if std::env::var_os(CHILD_ENV).is_none() {
                return;
            }
            let (_, hard) = imp::get().unwrap();
            let low = 256.min(hard);
            // soft だけを下げる
            let lim = libc::rlimit {
                rlim_cur: low as libc::rlim_t,
                rlim_max: hard as libc::rlim_t,
            };
            // SAFETY: lim は読める rlimit を指す
            let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim) };
            assert_eq!(rc, 0);
            let r = raise_nofile().unwrap().unwrap();
            let (cur, hard_after) = imp::get().unwrap();
            assert_eq!(r.from, low);
            assert_eq!(cur, r.to);
            assert_eq!(hard_after, hard, "the hard limit must stay");
            let want = target(hard, imp::os_cap(hard));
            assert_eq!(cur, want.max(low));
            if want > low {
                assert!(cur > low, "soft limit was not raised: {cur}");
            }
            println!("raised {low} -> {cur}");
        }

        #[test]
        fn raises_the_soft_limit_in_a_child_process() {
            let exe = std::env::current_exe().unwrap();
            let out = std::process::Command::new(exe)
                .args([
                    "--exact",
                    "platform::fdlimit::tests::unix::child_body",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && stdout.contains("raised "),
                "child failed: {:?}\n{stdout}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
