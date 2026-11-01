//! Windows の DACL。規範は `docs/design/spec/credentials.md` の「Windows の DACL」にある。
//!
//! 継承を切った DACL で、SYSTEM、BUILTIN\Administrators、実行中の利用者の 3 者にフルアクセスを許す。
//! SDDL では `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<利用者の SID>)` である。ディレクトリには、子へ継承する
//! `OICI` を添える。

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SID_SYSTEM: &str = "S-1-5-18";
const SID_ADMINS: &str = "S-1-5-32-544";

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// `LocalFree` で解放する Windows の確保。
struct LocalMem<T>(*mut T);

impl<T> Drop for LocalMem<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: 0 でない値は Windows が LocalAlloc で確保したもので、ここで 1 回だけ解放する
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

fn wide_ptr_to_string(p: *const u16) -> String {
    let mut n = 0;
    // SAFETY: p は NUL で終わる UTF-16 の文字列を指す
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: 上で数えた n 個の要素は読める
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
}

/// 実行中の利用者の SID の文字列 (`S-1-5-21-...`)。
pub fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: token は書き込める場所を指す
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken が成功して返した handle で、drop で閉じる
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut len = 0u32;
    // 1 回目は必要な長さを知るためで、失敗が正しい
    // SAFETY: 長さの問い合わせでは buffer を null にできる
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &raw mut len,
        )
    };
    // TOKEN_USER が要る境界に揃える
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: buf は len byte 以上の書き込める領域
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            len,
            &raw mut len,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 成功したので buf の先頭は TOKEN_USER で、境界は u64 に揃っている
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut s: *mut u16 = ptr::null_mut();
    // SAFETY: sid は有効な SID で、s は書き込める場所を指す
    if unsafe { ConvertSidToStringSidW(sid, &raw mut s) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    let s = LocalMem(s);
    Ok(wide_ptr_to_string(s.0))
}

/// 3 者の SDDL。`inherit` が真なら子へ継承する `OICI` を添える。利用者が SYSTEM か Administrators
/// なら、同じ ACE を重ねない。
pub fn sddl_for(user_sid: &str, inherit: bool) -> String {
    let flags = if inherit { "OICI" } else { "" };
    let mut s = format!("D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)");
    if user_sid != SID_SYSTEM && user_sid != SID_ADMINS {
        let _ = write!(s, "(A;{flags};FA;;;{user_sid})");
    }
    s
}

/// 解放が要る security descriptor と、その DACL。
struct Descriptor {
    sd: LocalMem<core::ffi::c_void>,
}

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Descriptor> {
        let w = wide(OsStr::new(sddl));
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: w は NUL で終わり、sd は書き込める場所を指す
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd,
                ptr::null_mut(),
            )
        } == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor { sd: LocalMem(sd) })
    }

    fn dacl(&self) -> io::Result<*const ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl: *mut ACL = ptr::null_mut();
        // SAFETY: sd は有効な descriptor で、出力先は書き込める
        if unsafe {
            GetSecurityDescriptorDacl(
                self.sd.0,
                &raw mut present,
                &raw mut acl,
                &raw mut defaulted,
            )
        } == FALSE
            || present == 0
        {
            return Err(io::Error::other("the security descriptor has no DACL"));
        }
        Ok(acl)
    }
}

/// 属性に descriptor を持たせて `f` を呼ぶ。`f` の間だけ有効な属性を渡す。
fn with_attributes<R>(
    sddl: &str,
    f: impl FnOnce(&SECURITY_ATTRIBUTES) -> io::Result<R>,
) -> io::Result<R> {
    let d = Descriptor::from_sddl(sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: d.sd.0,
        bInheritHandle: FALSE,
    };
    f(&sa)
}

/// 3 者だけの DACL を持つファイルを作る。`create_new` が真なら既にあれば失敗し、偽なら開く (無ければ
/// 作る)。作成の時点から DACL を持つので、作ってから締めるまでの間に他の利用者が開けない。開いた
/// 既存のファイルには付かないので、続けて [`restrict_file`] を呼ぶ。
pub fn create_private_file(path: &Path, create_new: bool) -> io::Result<File> {
    let sddl = sddl_for(&current_user_sid()?, false);
    let w = wide(path.as_os_str());
    with_attributes(&sddl, |sa| {
        // SAFETY: w は NUL で終わり、sa は呼び出しの間有効である
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                sa,
                if create_new { CREATE_NEW } else { OPEN_ALWAYS },
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW が返した所有する handle
        Ok(unsafe { File::from_raw_handle(h) })
    })
}

/// 3 者だけの DACL を持つディレクトリを 1 つ作る。親は有る前提。`OICI` で子へ継承する。既に有れば
/// `AlreadyExists` を返し、何も変えない。
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let sddl = sddl_for(&current_user_sid()?, true);
    let w = wide(path.as_os_str());
    with_attributes(&sddl, |sa| {
        // SAFETY: w は NUL で終わり、sa は呼び出しの間有効である
        if unsafe { CreateDirectoryW(w.as_ptr(), sa) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
}

/// 開いた handle の DACL を 3 者だけの継承なしの形にする。
fn restrict_handle(h: HANDLE) -> io::Result<()> {
    let d = Descriptor::from_sddl(&sddl_for(&current_user_sid()?, false))?;
    let acl = d.dacl()?;
    // SAFETY: h は WRITE_DAC つきで開いた handle で、acl は d が持つ DACL
    let rc = unsafe {
        SetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc.cast_signed()))
    }
}

/// 既存のファイル `path` に 3 者だけの DACL を付け直す。名前を辿らず、開いた handle に付ける。
/// `regular` が真なら通常のファイルだけを受け、symlink などは拒む。制御ソケットのファイルは通常の
/// ファイルでないので偽で呼ぶ。
pub fn restrict_file(path: &Path, regular: bool) -> io::Result<()> {
    let f = OpenOptions::new()
        .access_mode(WRITE_DAC | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if regular && !f.metadata()?.file_type().is_file() {
        return Err(io::Error::other("is not a regular file"));
    }
    restrict_handle(f.as_raw_handle())
}

/// `path` の DACL を SDDL の文字列で読む。
pub fn read_dacl_sddl(path: &Path) -> io::Result<String> {
    let w = wide(path.as_os_str());
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: w は NUL で終わり、sd は書き込める場所を指す
    let rc = unsafe {
        GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let sd = LocalMem(sd);
    let mut s: *mut u16 = ptr::null_mut();
    // SAFETY: sd は有効な descriptor で、s は書き込める場所を指す
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &raw mut s,
            ptr::null_mut(),
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    let s = LocalMem(s);
    Ok(wide_ptr_to_string(s.0))
}

/// `path` の DACL が 3 者だけの継承なしの形かを確かめる。ACE の並びの違いや、継承の印の書き方の差は
/// 許し、保護 (`P`) と ACE の集合を見る。
pub fn dacl_is_private(path: &Path, inherit: bool) -> io::Result<bool> {
    let got = read_dacl_sddl(path)?;
    let want = sddl_for(&current_user_sid()?, inherit);
    Ok(same_dacl(&got, &want))
}

/// 試験用。3 者だけの DACL でなければ、読み返した SDDL と期待を添えて panic する。
#[cfg(test)]
pub(crate) fn assert_private(path: &Path, inherit: bool) {
    let got = read_dacl_sddl(path).unwrap();
    let want = sddl_for(&current_user_sid().unwrap(), inherit);
    assert!(same_dacl(&got, &want), "{path:?}: got {got} want {want}");
}

fn split_dacl(s: &str) -> Option<(bool, Vec<String>)> {
    let body = s.strip_prefix("D:")?;
    let (flags, aces) = body.split_at(body.find('(').unwrap_or(body.len()));
    let mut v: Vec<String> = aces
        .split('(')
        .filter(|a| !a.is_empty())
        .map(|a| canonical_ace(a.trim_end_matches(')')))
        .collect();
    v.sort();
    Some((flags.contains('P'), v))
}

/// ACE の trustee を SID の文字列に揃える。読み返しの SDDL は、既知の SID を別名 (`LA` は組み込みの
/// Administrator など) で書くので、別名と SID の違いで落とさない。読めなければ大文字にして返す。
fn canonical_ace(ace: &str) -> String {
    let ace = ace.to_ascii_uppercase();
    let Some((head, trustee)) = ace.rsplit_once(';') else {
        return ace;
    };
    let w = wide(OsStr::new(trustee));
    let mut sid: *mut core::ffi::c_void = ptr::null_mut();
    // SAFETY: w は NUL で終わり、sid は書き込める場所を指す
    if unsafe { ConvertStringSidToSidW(w.as_ptr(), &raw mut sid) } == FALSE {
        return ace;
    }
    let sid = LocalMem(sid);
    let mut out: *mut u16 = ptr::null_mut();
    // SAFETY: sid は有効な SID で、out は書き込める場所を指す
    if unsafe { ConvertSidToStringSidW(sid.0, &raw mut out) } == FALSE {
        return ace;
    }
    let out = LocalMem(out);
    format!("{head};{}", wide_ptr_to_string(out.0))
}

fn same_dacl(got: &str, want: &str) -> bool {
    match (split_dacl(got), split_dacl(want)) {
        (Some((gp, ga)), Some((wp, wa))) => gp == wp && ga == wa,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wgft-winsec-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sddl_has_three_parties_and_skips_a_duplicate_user() {
        assert_eq!(
            sddl_for("S-1-5-21-1-2-3-1001", false),
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            sddl_for("S-1-5-21-1-2-3-1001", true),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(sddl_for(SID_SYSTEM, false), "D:P(A;;FA;;;SY)(A;;FA;;;BA)");
    }

    #[test]
    fn dacl_comparison_ignores_order_and_inheritance_marks() {
        assert!(same_dacl(
            "D:PAI(A;;FA;;;BA)(A;;FA;;;SY)",
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
        assert!(!same_dacl("D:(A;;FA;;;SY)", "D:P(A;;FA;;;SY)"));
        assert!(!same_dacl("D:P(A;;FA;;;SY)", "D:P(A;;FA;;;SY)(A;;FA;;;BA)"));
    }

    #[test]
    fn created_file_carries_the_dacl_from_the_start() {
        let d = tmpdir("file");
        let p = d.join("agent.json");
        let _f = create_private_file(&p, true).unwrap();
        assert_private(&p, false);
        // 既にあれば create_new は失敗する
        assert!(create_private_file(&p, true).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn restrict_file_tightens_an_existing_file() {
        let d = tmpdir("restrict");
        let p = d.join("old.json");
        std::fs::write(&p, b"{}").unwrap();
        restrict_file(&p, true).unwrap();
        assert_private(&p, false);
        // 内容は変わらない
        assert_eq!(std::fs::read(&p).unwrap(), b"{}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn created_dir_inherits_to_children() {
        let d = tmpdir("dir");
        let sub = d.join("data");
        create_private_dir(&sub).unwrap();
        assert_private(&sub, true);
        assert_eq!(
            create_private_dir(&sub).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        // 子は継承で 3 者だけになる (継承した ACE の印で読み返しの文字列は変わるので、ACE の集合で見る)
        let child = sub.join("child.txt");
        std::fs::write(&child, b"x").unwrap();
        let got = read_dacl_sddl(&child).unwrap();
        assert!(!got.contains("WD") && !got.contains("BU"), "{got}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
