//! handshake の時刻の印 (TAI64N) の高い水位。
//!
//! device は handshake の初めの送信に時刻の印を付け、相手の WireGuard (Linux と wireguard-go) は前に
//! 受けた印より古い印の handshake を捨てる。壁時計が前の device より戻っていると (RTC の無いホストの
//! NTP の前、時計の巻き戻し)、handshake が通らなくなる。device は作るときに渡した下限より 1 秒新しい
//! 値と壁時計の大きい方から印を作り、使った印の高い水位を返す。この module は、プロセスの中で見た
//! 最も高い水位と、データディレクトリのファイルに残した水位の大きい方を下限として渡す。ファイルは
//! agent.json と分ける。Go の agent が agent.json を書き直すと、知らないキーを捨てるためである。
//!
//! ファイルは 1 行の秒の値を、前の版の単位で持つ。前の版は sanstun の基準 (2^62 + 37) のまま印を
//! 付けたので、同じ値の下限でも印が今の版より 27 秒進む。今の版は [`FILE_BEHIND`] を引いて書き、足して
//! 読む。こうすると、前の版と今の版のどちらが書いたファイルを、どちらが読んでも、次の印は相手が前に
//! 受けた印を下回らない。前の版が読むと印は 27 秒進むだけで、戻らない。

use std::io::Read;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use crate::credentials;

/// 定期に残す値に足す余裕。水位は 30 秒ごとに残すので、それより長くする。前に残してから落ちる
/// までに使った印も、次の下限が超えるようにするためである。
pub(super) const SAVE_MARGIN: Duration = Duration::from_mins(1);

/// device が受ける下限の上限。これ以上の値は壊れた記録として捨てる。
const FLOOR_LIMIT: u64 = 1 << 40;

/// ファイルの大きさの上限。`<秒>\n` の 1 行で足りる。
const FILE_LIMIT: u64 = 64;

/// ファイルの値と、今の版の下限 (本当の Unix 時刻) の差。前の版の印が標準の印より進んでいた秒で、
/// ファイルの値は今の版の下限よりこれだけ小さい。
const FILE_BEHIND: u64 = 27;

/// プロセスの中で見た最も高い水位。
static HIGH: Mutex<Duration> = Mutex::new(Duration::ZERO);

/// ファイルへの書き込みを 1 つずつにする。書く値は書く時点の [`HIGH`] から決めるので、後に始めた
/// 書き込みが先に始めた書き込みより低い値を残さない。
static WRITING: Mutex<()> = Mutex::new(());

fn high() -> Duration {
    *HIGH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 残した値。無ければ `Ok(None)`。symlink を辿らず、通常のファイルでないもの (FIFO を含む) と
/// 大きすぎるものは開いた記述子で拒む (認証情報ファイルと同じ読み)。
fn read(file: &Path) -> Result<Option<Duration>, String> {
    let (f, meta) = match credentials::open_regular_read(file) {
        Ok(x) => x,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if meta.len() > FILE_LIMIT {
        return Err(format!("{} bytes is too long", meta.len()));
    }
    let mut text = String::new();
    f.take(FILE_LIMIT)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    let secs = text
        .trim()
        .parse::<u64>()
        .map_err(|_| "not a number of seconds".to_owned())?;
    secs.checked_add(FILE_BEHIND)
        .map(|s| Some(Duration::from_secs(s)))
        .ok_or_else(|| "out of range".into())
}

/// 新しい device に渡す下限。プロセスの中の水位と、残した値の大きい方である。残した値が読めないか
/// 大きすぎれば、1 行を出して壁時計から始める。ファイルは消さず、次の記録が置き換える。通常の
/// ファイルでなければ、記録は置き換えずに書けない旨を出す。ファイルの読みは blocking の
/// スレッドで行う。
pub(super) async fn floor(file: Option<&Path>) -> Duration {
    let high = high();
    let Some(file) = file.map(Path::to_path_buf) else {
        return high;
    };
    let saved = tokio::task::spawn_blocking(move || match read(&file) {
        Ok(Some(s)) if s.as_secs() < FLOOR_LIMIT => s,
        Ok(None) => Duration::ZERO,
        r => {
            let why = match r {
                Err(e) => e,
                _ => "out of range".into(),
            };
            // 開けないファイルの誤りの文はパスを含むので、行にパスを重ねない
            let path = file.display().to_string();
            if why.contains(&path) {
                crate::logf!(
                    "the handshake clock is unreadable: {why}; starting from the wall clock"
                );
            } else {
                crate::logf!(
                    "the handshake clock in {path} is unreadable: {why}; starting from the wall clock"
                );
            }
            Duration::ZERO
        }
    })
    .await
    .unwrap_or_default();
    high.max(saved)
}

/// device が返した高い水位を覚え、ファイルに残す。`margin` が真なら [`SAVE_MARGIN`] を足す (定期の
/// 保存とプロセスの中のトンネルの作り直し)。偽なら水位そのものを残す (プロセスの終わり)。偽は、
/// その後にこのプロセスが印を使わないときだけ渡す。作り直しの後の device はファイルを読み直さずに
/// 印を使い、次の定期の保存の前に落ちると、余裕の無い値が使った印より低い下限になるためである。
/// ファイルの書き込みは blocking のスレッドで行い、書けなくても動作は続ける。
pub(super) async fn record(file: Option<&Path>, high_water: Duration, margin: bool) {
    {
        let mut h = HIGH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *h = (*h).max(high_water);
    }
    let Some(file) = file.map(Path::to_path_buf) else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || write(&file, margin)).await;
}

fn write(file: &Path, margin: bool) {
    let _one = WRITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let high = high();
    // 秒を切り上げ、下限が使った印より古くならないようにする
    let mut secs = high.as_secs() + u64::from(high.subsec_nanos() > 0);
    if margin {
        secs += SAVE_MARGIN.as_secs();
    }
    // ファイルは前の版の単位で持つので、読み返した値は 27 秒を足した値になる
    let r = if read(file)
        .is_ok_and(|saved| saved.is_some_and(|s| s.as_secs() == secs.max(FILE_BEHIND)))
    {
        Ok(())
    } else {
        let text = encode(secs);
        credentials::replace_private_file(file, "handshake clock", FILE_LIMIT, |w| {
            w.write_all(text.as_bytes())
        })
    };
    let mut failing = FAILING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(line) = record_line(&mut failing, file, r) {
        crate::logf!("{line}");
    }
}

/// ファイルの中身。`secs` は今の版の下限 (切り上げた秒)。
fn encode(secs: u64) -> String {
    format!("{}\n", secs.saturating_sub(FILE_BEHIND))
}

/// 記録の失敗の文。定期の保存は 30 秒ごとに書くので、同じ失敗を毎回出さない。
static FAILING: Mutex<Option<String>> = Mutex::new(None);

/// 記録の結果 `r` のうち、ログに出す行。失敗が始まったときと失敗の文が変わったとき、失敗から戻った
/// ときだけ返す。`last` は前の失敗の文で、ここで更新する。
fn record_line(last: &mut Option<String>, file: &Path, r: Result<(), String>) -> Option<String> {
    match r {
        Ok(()) => last.take().map(|_| {
            format!(
                "the handshake clock in {} is recorded again",
                file.display()
            )
        }),
        Err(e) if last.as_deref() == Some(e.as_str()) => None,
        Err(e) => {
            let line = format!(
                "cannot record the handshake clock in {}: {e}",
                file.display()
            );
            *last = Some(e);
            Some(line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_floor_never_goes_back() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("agent.json.clock");
        let future = Duration::from_secs(4_000_000_000);
        record(Some(&f), future + Duration::from_millis(500), true).await;
        let saved = future + Duration::from_secs(1) + SAVE_MARGIN;
        assert_eq!(read(&f), Ok(Some(saved)));
        assert!(floor(Some(&f)).await >= saved);
        // 一時ファイルは残らない
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        // プロセスの終わりは余裕を足さない。プロセスの中の水位は下がらない
        record(Some(&f), Duration::from_secs(10), false).await;
        assert_eq!(read(&f), Ok(Some(future + Duration::from_secs(1))));
        assert!(floor(Some(&f)).await >= future);
        // 壊れた記録は使わず、次の記録が置き換える
        std::fs::write(&f, format!("{}\n", 1u64 << 41)).unwrap();
        assert!(floor(Some(&f)).await < Duration::from_secs(1 << 40));
        record(Some(&f), Duration::from_secs(10), true).await;
        assert!(read(&f).unwrap().unwrap() < Duration::from_secs(1 << 40));
        std::fs::write(&f, "100 other-format\n").unwrap();
        assert!(read(&f).is_err());
        // ファイルの値は前の版の単位
        record(Some(&f), future + Duration::from_secs(5), false).await;
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            format!("{}\n", future.as_secs() + 5 - 27)
        );
    }

    #[test]
    fn the_file_keeps_the_earlier_builds_units() {
        // 前の版は値 N の下限から 2^62 + 37 + N + 1 秒以上の印を付けた。今の版は 27 秒足して読み、
        // 2^62 + 10 + (N + 27) + 1 秒以上の印を付けるので、同じ値から同じ印の下限になる
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("agent.json.clock");
        std::fs::write(&f, "4100000000\n").unwrap();
        let floor = read(&f).unwrap().unwrap();
        assert_eq!(floor, Duration::from_secs(4_100_000_027));
        // 今の版が書いた値を前の版が読めば、印は 27 秒進むだけで戻らない
        assert_eq!(encode(4_100_000_027), "4100000000\n");
        std::fs::write(&f, encode(4_100_000_027)).unwrap();
        assert_eq!(read(&f), Ok(Some(floor)));
    }

    /// 記録の失敗の行は、失敗が始まったときと文が変わったとき、戻ったときだけ出す。
    #[test]
    fn a_failing_record_is_logged_once_per_change() {
        let f = Path::new("/data/agent.json.clock");
        let mut last = None;
        let fail = |e: &str| Err(e.to_owned());
        assert_eq!(record_line(&mut last, f, Ok(())), None);
        assert_eq!(
            record_line(&mut last, f, fail("disk full")).as_deref(),
            Some("cannot record the handshake clock in /data/agent.json.clock: disk full")
        );
        assert_eq!(record_line(&mut last, f, fail("disk full")), None);
        assert!(record_line(&mut last, f, fail("read-only")).is_some());
        assert_eq!(
            record_line(&mut last, f, Ok(())).as_deref(),
            Some("the handshake clock in /data/agent.json.clock is recorded again")
        );
        assert_eq!(record_line(&mut last, f, Ok(())), None);
    }

    /// 記録のファイルの場所にある通常のファイルでないものは、読まずに使わず、置き換えもしない。FIFO
    /// を開いて止まらない。
    #[cfg(unix)]
    #[tokio::test]
    async fn irregular_files_are_neither_read_nor_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "5000000000\n").unwrap();
        let link = dir.path().join("link.clock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let fifo = dir.path().join("fifo.clock");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: 有効な NUL 終端のパスを渡すだけである
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let big = dir.path().join("big.clock");
        std::fs::write(&big, "1".repeat(100)).unwrap();
        for f in [&link, &fifo, &big] {
            let got = tokio::time::timeout(Duration::from_secs(2), floor(Some(f)))
                .await
                .expect("reading the clock does not block");
            assert!(got < Duration::from_secs(5_000_000_000), "{}", f.display());
        }
        record(Some(&link), Duration::from_secs(10), true).await;
        record(Some(&fifo), Duration::from_secs(10), true).await;
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "5000000000\n");
    }
}
