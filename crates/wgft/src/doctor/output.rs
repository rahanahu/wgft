//! `agent doctor` の人向けの出力と `--json` の模型 (Go の `agentdoctorjson.go` と `doctor.go` の出力の部分)。
//!
//! 文字列は稼働中の agent の応答や `agent.json` に由来しうるので、表示できない文字は出力の側で逃がす。
//! ID、状態の語、理由の符号は固定の定数なので対象にしない。

use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::macros::format_description;
use wgft_proto::textsafe::sanitize_for_terminal;

use super::checks::SAME_PRINCIPAL_NEXT;
use super::{Check, NotTested, Report, status, verdict};

/// 人向けの出力の桁。表そのものは保証の外である。
const LABEL_WIDTH: usize = 18;
const STATUS_WIDTH: usize = 11;
const INLINE_DETAIL: usize = 46;
const INDENT: usize = 2 + LABEL_WIDTH + 1;

/// `--json` の報告全体。キーの順は仕様の表の順である。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonReport {
    /// 総合判定。
    pub status: String,
    /// 診断した時刻。RFC 3339 の UTC で、秒の小数部を持たない。
    pub checked_at: String,
    /// 報告が答えるデータディレクトリ。
    pub data_dir: String,
    /// 検査。
    pub checks: Vec<JsonCheck>,
    /// 履歴。
    pub history: JsonHistory,
    /// 試していない範囲。
    pub not_tested: Vec<JsonNotTested>,
}

/// 1 つの検査。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonCheck {
    /// 検査の ID。
    pub id: String,
    /// 状態の語。
    pub status: String,
    /// 理由の符号。`ok` では省く。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// 終了コード 2 に倒した検査だけが真。
    #[serde(default, skip_serializing_if = "is_false")]
    pub evidence_unreachable: bool,
    /// 群。
    pub group: String,
    /// 名前。
    pub label: String,
    /// 所見。
    pub detail: String,
    /// 次の手。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next: String,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_false(v: &bool) -> bool {
    !*v
}

/// 履歴の有無。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonHistory {
    /// 履歴を持つか。v1 は持たない。
    pub available: bool,
    /// 説明。
    pub detail: String,
}

/// 試していない範囲 1 件。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonNotTested {
    /// 名前。
    pub id: String,
    /// 説明。
    pub detail: String,
}

/// RFC 3339 の UTC で、秒の小数部を持たない形。
pub(crate) fn rfc3339(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .unwrap_or_default()
}

/// 報告を `--json` の模型に写す。
#[must_use]
pub fn json_report(rep: &Report) -> JsonReport {
    JsonReport {
        status: verdict(rep).to_owned(),
        checked_at: rfc3339(rep.checked_at),
        data_dir: rep.data_dir.clone(),
        checks: rep
            .checks
            .iter()
            .map(|c| JsonCheck {
                id: c.id.to_owned(),
                status: c.status.to_owned(),
                reason: c.reason.to_owned(),
                evidence_unreachable: c.evidence_unreachable,
                group: c.group.to_owned(),
                label: c.label.to_owned(),
                detail: sanitize_for_terminal(&c.detail),
                next: sanitize_for_terminal(&c.next),
            })
            .collect(),
        history: JsonHistory {
            available: false,
            detail: sanitize_for_terminal(&rep.history),
        },
        not_tested: rep
            .not_tested
            .iter()
            .map(|n| JsonNotTested {
                id: n.id.to_owned(),
                detail: sanitize_for_terminal(&n.detail),
            })
            .collect(),
    }
}

/// `--json` の報告を、2 つの空白で字下げした JSON と改行で書く (Go の `json.Encoder` と同じ byte 列)。
///
/// # Errors
///
/// 書けなければ誤りを返す。
pub fn write_json(w: &mut dyn Write, rep: &Report) -> io::Result<()> {
    let mut b = wgft_proto::gojson::to_vec_indent(&json_report(rep)).map_err(io::Error::other)?;
    b.push(b'\n');
    w.write_all(&b)
}

/// 状態の語の人向けの表記。
fn status_word(s: &str) -> &str {
    match s {
        status::OK => "OK",
        status::FAILED => "FAILED",
        status::UNKNOWN => "UNKNOWN",
        status::NOT_TESTED => "NOT TESTED",
        status::SKIPPED => "SKIPPED",
        other => other,
    }
}

/// 検査を群ごとに出す。値だけを示す検査は群から抜き、判定済みの検査の後に別の節として出す。
///
/// # Errors
///
/// 書けなければ誤りを返す。
pub fn write_report(w: &mut dyn Write, rep: &Report) -> io::Result<()> {
    let mut group = "";
    let mut unreachable = false;
    let mut observed: Vec<&Check> = Vec::new();
    for c in &rep.checks {
        unreachable |= c.evidence_unreachable;
        if c.value_only {
            observed.push(c);
            continue;
        }
        if c.group != group {
            writeln!(w, "{}", c.group)?;
            group = c.group;
        }
        write_line(w, c.label, status_word(c.status), &c.detail)?;
        if !c.next.is_empty() && c.status != status::OK {
            write_next(w, &c.next)?;
        }
    }
    if !observed.is_empty() {
        writeln!(w, "\nObserved values")?;
        for c in observed {
            if c.status == status::UNKNOWN {
                writeln!(
                    w,
                    "  {:<LABEL_WIDTH$} {}",
                    c.label,
                    wrap_at(&sanitize_for_terminal(&c.detail), INDENT)
                )?;
                continue;
            }
            write_line(w, c.label, status_word(c.status), &c.detail)?;
            if !c.next.is_empty() && c.status != status::OK {
                write_next(w, &c.next)?;
            }
        }
    }
    if unreachable {
        writeln!(w, "\nIncomplete")?;
        writeln!(
            w,
            "  {}",
            wrap_at(
                &format!(
                    "Some evidence could not be read with this command's permissions, so the lines above do not settle whether this agent can forward. {}.",
                    upper_first(SAME_PRINCIPAL_NEXT)
                ),
                2
            )
        )?;
    }
    writeln!(w, "\nHistory")?;
    write_line(w, "when it broke", "NOT AVAILABLE", "")?;
    writeln!(
        w,
        "{}{}",
        " ".repeat(INDENT),
        wrap_at(&sanitize_for_terminal(&rep.history), INDENT)
    )?;
    write_not_tested(w, &rep.not_tested)
}

fn write_not_tested(w: &mut dyn Write, items: &[NotTested]) -> io::Result<()> {
    writeln!(w, "\nNot tested by this command")?;
    for n in items {
        writeln!(
            w,
            "  {:<16} {}",
            n.id,
            wrap_at(&sanitize_for_terminal(&n.detail), 19)
        )?;
    }
    Ok(())
}

/// 1 つの検査を出す。短い所見は状態の右に、長い所見は次の行に出す。
fn write_line(w: &mut dyn Write, label: &str, status: &str, detail: &str) -> io::Result<()> {
    let detail = sanitize_for_terminal(detail);
    if !detail.is_empty() && detail.len() <= INLINE_DETAIL {
        return writeln!(w, "  {label:<LABEL_WIDTH$} {status:<STATUS_WIDTH$}{detail}");
    }
    writeln!(w, "  {label:<LABEL_WIDTH$} {status}")?;
    if !detail.is_empty() {
        writeln!(w, "{}{}", " ".repeat(INDENT), wrap_at(&detail, INDENT))?;
    }
    Ok(())
}

fn write_next(w: &mut dyn Write, next: &str) -> io::Result<()> {
    writeln!(
        w,
        "{}Check: {}",
        " ".repeat(INDENT),
        wrap_at(&sanitize_for_terminal(next), INDENT + 7)
    )
}

/// `indent` 文字ぶん字下げした桁に折り返す。1 行目の字下げは呼び出し元が出す。幅は byte で数える
/// (Go の `len` と同じ)。
fn wrap_at(s: &str, indent: usize) -> String {
    const WIDTH: usize = 96;
    let limit = WIDTH.saturating_sub(indent).max(20);
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if line.is_empty() {
            word.clone_into(&mut line);
        } else if line.len() + 1 + word.len() <= limit {
            line.push(' ');
            line.push_str(word);
        } else {
            out.push(std::mem::replace(&mut line, word.to_owned()));
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    out.join(&format!("\n{}", " ".repeat(indent)))
}

/// 1 でなければ `s`。
pub(crate) fn plural_s(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// 先頭の 1 文字を大文字にする。
pub(crate) fn upper_first(s: &str) -> String {
    let mut cs = s.chars();
    cs.next()
        .map(|c| c.to_uppercase().chain(cs).collect())
        .unwrap_or_default()
}

/// Go の `time.Duration.String` と同じ書き方。
pub(crate) fn go_duration(d: i64) -> String {
    fn frac(buf: &mut Vec<u8>, mut v: u64, prec: usize) -> u64 {
        let mut print = false;
        for _ in 0..prec {
            let digit = v % 10;
            print = print || digit != 0;
            if print {
                buf.push(b'0' + u8::try_from(digit).unwrap_or(0));
            }
            v /= 10;
        }
        if print {
            buf.push(b'.');
        }
        v
    }
    fn int(buf: &mut Vec<u8>, mut v: u64) {
        if v == 0 {
            buf.push(b'0');
            return;
        }
        while v > 0 {
            buf.push(b'0' + u8::try_from(v % 10).unwrap_or(0));
            v /= 10;
        }
    }
    if d == 0 {
        return "0s".into();
    }
    let neg = d < 0;
    let mut u = d.unsigned_abs();
    // 後ろから組み、最後に逆にする
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    if u < 1_000_000_000 {
        let prec;
        buf.push(b's');
        if u < 1_000 {
            prec = 0;
            buf.push(b'n');
        } else if u < 1_000_000 {
            prec = 3;
            // "µ" (U+00B5) の UTF-8 を逆順に積む
            buf.extend_from_slice(&[0xb5, 0xc2]);
        } else {
            prec = 6;
            buf.push(b'm');
        }
        u = frac(&mut buf, u, prec);
        int(&mut buf, u);
    } else {
        buf.push(b's');
        u = frac(&mut buf, u, 9);
        int(&mut buf, u % 60);
        u /= 60;
        if u > 0 {
            buf.push(b'm');
            int(&mut buf, u % 60);
            u /= 60;
            if u > 0 {
                buf.push(b'h');
                int(&mut buf, u);
            }
        }
    }
    if neg {
        buf.push(b'-');
    }
    buf.reverse();
    String::from_utf8(buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_like_go() {
        for (d, want) in [
            (0, "0s"),
            (1, "1ns"),
            (1_100, "1.1µs"),
            (2_200_000, "2.2ms"),
            (2_000_000_000, "2s"),
            (35_000_000_000, "35s"),
            (300_000_000_000, "5m0s"),
            (3_723_000_000_000, "1h2m3s"),
            (1_500_000_000, "1.5s"),
            (-61_000_000_000, "-1m1s"),
        ] {
            assert_eq!(go_duration(d), want, "{d}");
        }
    }

    #[test]
    fn wraps_at_the_column() {
        let s = "word ".repeat(40);
        let w = wrap_at(s.trim(), INDENT);
        for l in w.lines() {
            assert!(l.len() <= 96, "{l}");
        }
    }
}
