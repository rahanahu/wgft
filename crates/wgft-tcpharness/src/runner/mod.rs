//! 台本を手で進める時計の DUT に流す Rust の runner です (`docs/design/v2/test-tooling.md` の 2 節)。
//!
//! Go の runner (`internal/tcpharness/script*.go`) と harness の写しで、同じ台本を同じ種で流すと、DUT への
//! 呼び出しの列が Go の runner と同じになります。確かめの結果は Go と同じ形の行 (`PASS`、`FAIL`、
//! `KNOWN DIFFERENCE`、`CHANGED DIFFERENCE`、`UNEXPECTED PASS`、`MEASURE`) で、log の行は DUT の時刻を頭に
//! 付けます。
//!
//! 偽の時計の規則は Go の harness と同じです。待つ文は `poll` で packet を引き取り、無ければ時計を 1 ms
//! 進めます。読み書きと受け入れが待つ必要を返した時は、待たずに締め切りが来たものとして扱います。Rust の
//! runner は 1 つの流れで動き、待つ間に DUT の状態を変える者がいないためです。

mod gofmt;
mod goprint;
mod harness;
mod interp;
mod value;

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;

pub use gofmt::{duration as go_duration, float_f as go_float_f, quote as go_quote};
/// `go_quote` が持つ Go の `strconv.IsPrint` の表の Unicode の版です。
pub use goprint::UNICODE_VERSION as GO_UNICODE_VERSION;

use crate::dut::ClockedDut;
use crate::gojson::{self, Json};
use crate::script::Script;

use harness::{Cleanup, H, Stop};

/// 試験台の相手のアドレスです。
pub const PEER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
/// DUT のアドレスです。
pub const DUT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
/// DUT の MTU です。wgft の既定のトンネルの MTU です。
pub const MTU: usize = 1420;

/// Rust の wgstack の期待した差の一覧の、リポジトリの根からのパスです。Go の `rustdut` と同じファイルを読みます。
pub const KNOWN_WGSTACK_RS: &str = "internal/tcpharness/rustdut/known-wgstack-rs.json";

/// 確かめの結果です。
pub const OUTCOME_PASS: &str = "pass";
pub const OUTCOME_FAIL: &str = "fail";
pub const OUTCOME_KNOWN: &str = "known";
pub const OUTCOME_UNEXPECTED: &str = "unexpected-pass";
pub const OUTCOME_CHANGED: &str = "changed-difference";

/// 期待した差の一覧の 1 項目です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    /// 落ちた確かめの観察の文字列と一致しなければならない値
    pub observed: String,
    /// 受け入れる理由
    pub reason: String,
    /// 実時間の engine で時々だけ出る差。手で進める時計の DUT では、この印を持つ項目そのものが誤りです
    pub sometimes: bool,
}

/// `scenario/check` の鍵から期待した差への一覧です。
pub type KnownList = HashMap<String, Known>;

/// 期待した差の一覧の JSON を読みます。形は `{"scenario/check": {"observed": "...", "reason": "...",
/// "sometimes": false}}` で、`sometimes` は省けます。
pub fn parse_known(src: &[u8]) -> Result<KnownList, String> {
    let Json::Obj(m) = gojson::parse(src)? else {
        return Err("the list is not a JSON object".to_owned());
    };
    let mut out = KnownList::new();
    for (k, v) in m {
        let field = |name: &str| {
            v.get(name)
                .and_then(Json::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("{k}: no string {name}"))
        };
        let sometimes = match v.get("sometimes") {
            None => false,
            Some(s) => s
                .as_bool()
                .ok_or_else(|| format!("{k}: sometimes is not a bool"))?,
        };
        let known = Known {
            observed: field("observed")?,
            reason: field("reason")?,
            sometimes,
        };
        out.insert(k, known);
    }
    Ok(out)
}

/// 1 つの確かめか測った値です。Go の `CheckRecord` です。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRecord {
    /// `scenario/check` の鍵
    pub key: String,
    /// 結果 (`OUTCOME_*`) か `measure`
    pub outcome: String,
    /// 観察の文字列か測った値
    pub got: String,
}

/// 1 回の実行の結果です。Go の `CheckTrace` と同じ中身を持ちます。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// 確かめと測った値、順に
    pub checks: Vec<CheckRecord>,
    /// 記録した失敗の文、順に
    pub failures: Vec<String>,
    pub failed: bool,
    pub skipped: bool,
    /// log の行。DUT の時刻 (Go の `time.Duration` の書式) を頭に付けます
    pub lines: Vec<String>,
    /// 鍵ごとの結果。確かめを流した回数だけ並びます
    pub outcomes: BTreeMap<String, Vec<&'static str>>,
}

impl Outcome {
    /// `known` のうち、この台本の鍵で、どの確かめも届かなかった項目です。
    pub fn unreached(&self, known: &KnownList, scenario: &str) -> Vec<String> {
        let prefix = format!("{scenario}/");
        let mut out: Vec<String> = known
            .keys()
            .filter(|k| k.starts_with(&prefix) && !self.outcomes.contains_key(*k))
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Go の `CheckTrace` を `json.Marshal` で書いた bytes です。Go の試験が書いた trace と比べます。
    pub fn trace_json(&self) -> Vec<u8> {
        let strs = |v: &[String]| {
            if v.is_empty() {
                Json::Null
            } else {
                Json::Arr(v.iter().map(|s| Json::Str(s.clone())).collect())
            }
        };
        let checks = if self.checks.is_empty() {
            Json::Null
        } else {
            Json::Arr(
                self.checks
                    .iter()
                    .map(|c| {
                        Json::fields([
                            ("Key", Json::Str(c.key.clone())),
                            ("Outcome", Json::Str(c.outcome.clone())),
                            ("Got", Json::Str(c.got.clone())),
                        ])
                    })
                    .collect(),
            )
        };
        Json::fields([
            ("Checks", checks),
            ("Failures", strs(&self.failures)),
            ("Failed", Json::Bool(self.failed)),
            ("Skipped", Json::Bool(self.skipped)),
            ("Lines", strs(&self.lines)),
        ])
        .to_bytes()
    }
}

/// 1 回の実行の設定です。
#[derive(Debug, Clone, Copy)]
pub struct RunConfig<'a> {
    /// 結果の行と期待した差の鍵に使う engine の名前
    pub engine: &'a str,
    /// 期待した差の一覧
    pub known: &'a KnownList,
    /// DUT のアドレス (`DUT_ADDR`)
    pub dut_addr: Ipv4Addr,
    /// DUT の MTU (`DUT_MTU`)
    pub mtu: usize,
    /// 台本の種 ([`crate::rng::scenario_seed`])
    pub seed: u64,
}

/// 台本 `script` を `dut` に流します。`file` は台本の誤りの文に出す名前で、Go と同じ文にするには
/// `scripts/<名前>.scn` を渡します。台本の終わりに、Go と同じく逆の順で後始末 (受け入れた接続の abort、
/// 待ち受けと UDP の socket の close) をします。DUT そのものは閉じません。
pub fn run_script(
    dut: &mut dyn ClockedDut,
    file: &str,
    script: &Script,
    cfg: &RunConfig<'_>,
) -> Outcome {
    let mut h = H::new(
        dut,
        cfg.engine,
        &script.name,
        cfg.known,
        cfg.dut_addr,
        cfg.mtu,
        cfg.seed,
    );
    let r = interp::Interp::new(&mut h, file).run(script);
    match r {
        Ok(()) => {}
        Err(Stop::Fail) => h.failed = true,
        Err(Stop::Skip) => h.skipped = true,
    }
    let cleanups: Vec<Cleanup> = h.cleanups.drain(..).rev().collect();
    for c in cleanups {
        let d = h.dut();
        let _ = match c {
            Cleanup::CloseListener(l) => {
                let l = l.borrow();
                if l.closed { Ok(()) } else { d.close(l.h) }
            }
            Cleanup::AbortConn(c) => d.abort(c),
            Cleanup::CloseUdp(u) => {
                let mut u = u.borrow_mut();
                if u.closed {
                    Ok(())
                } else {
                    u.closed = true;
                    d.close(u.h)
                }
            }
        };
    }
    Outcome {
        checks: h.checks,
        failures: h.failures,
        failed: h.failed,
        skipped: h.skipped,
        lines: h.lines,
        outcomes: h.outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_known_list() {
        let k = parse_known(
            br#"{"icmp-echo/oversized": {"observed": "no reply", "reason": "r"},
                 "x/y": {"observed": "o", "reason": "r", "sometimes": true}}"#,
        )
        .unwrap();
        assert_eq!(k["icmp-echo/oversized"].observed, "no reply");
        assert!(k["x/y"].sometimes);
        assert!(parse_known(br#"{"a/b": {"reason": "r"}}"#).is_err());
    }

    const KNOWN_SCRIPT: &str = "\
scenario k
refs: the known-list paths of H.Check and H.Require

check pass true
  what: w
  got: fine
check unexpected true
  what: w
  got: fine
check known false
  what: w
  got: no reply
check changed false
  what: w
  got: no reply
check sometimes false
  what: w
  got: no reply
check sometimes-pass true
  what: w
  got: fine
check plain false
  what: w
  got: no reply
require req false
  what: w
  got: gone
check after true
  what: w
  got: never
";

    fn known(entries: &[(&str, &str, bool)]) -> KnownList {
        entries
            .iter()
            .map(|&(k, observed, sometimes)| {
                let v = Known {
                    observed: observed.to_owned(),
                    reason: format!("reason {k}"),
                    sometimes,
                };
                (k.to_owned(), v)
            })
            .collect()
    }

    fn run(src: &str, known: &KnownList) -> Outcome {
        let script = crate::script::parse_script("k.scn", src.as_bytes()).unwrap();
        let mut dut = crate::dut::stub::Stub::new(crate::dut::stub::idle);
        let cfg = RunConfig {
            engine: "e",
            known,
            dut_addr: DUT_ADDR,
            mtu: MTU,
            seed: 1,
        };
        run_script(&mut dut, "k.scn", &script, &cfg)
    }

    /// Go の `H.Check` と `H.Require` の期待した差の扱いです。手で進める時計の DUT なので、`sometimes` の項目は
    /// 落ちた確かめでも通った確かめでも誤りです。
    #[test]
    fn check_and_require_follow_the_known_list() {
        let list = known(&[
            ("k/unexpected", "x", false),
            ("k/known", "no reply", false),
            ("k/changed", "other", false),
            ("k/sometimes", "no reply", true),
            ("k/sometimes-pass", "no reply", true),
            ("k/req", "gone", false),
            ("k/never-reached", "n", false),
            ("other/x", "n", false),
        ]);
        let out = run(KNOWN_SCRIPT, &list);
        let got: Vec<(&str, &str)> = out
            .checks
            .iter()
            .map(|c| (c.key.as_str(), c.outcome.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("k/pass", OUTCOME_PASS),
                ("k/unexpected", OUTCOME_UNEXPECTED),
                ("k/known", OUTCOME_KNOWN),
                ("k/changed", OUTCOME_CHANGED),
                ("k/sometimes", OUTCOME_CHANGED),
                ("k/sometimes-pass", OUTCOME_UNEXPECTED),
                ("k/plain", OUTCOME_FAIL),
                ("k/req", OUTCOME_KNOWN),
            ]
        );
        // 期待した差の require は skip で止まり、後の確かめは流れません。誤りは記録したまま失敗です
        assert!(out.skipped);
        assert!(out.failed);
        assert_eq!(
            out.failures,
            [
                "UNEXPECTED PASS  k/unexpected on e: w; got: fine; the list says: x; remove the entry",
                "CHANGED DIFFERENCE  k/changed on e: w; got: no reply; the list says: other",
                "CHANGED DIFFERENCE  k/sometimes on e: w; got: no reply; the list marks it as shown only on some runs, which a DUT on the harness's clock cannot be",
                "UNEXPECTED PASS  k/sometimes-pass on e: w; got: fine; the list says: no reply; remove the entry",
                "FAIL  k/plain on e: w; got: no reply",
            ]
        );
        assert!(out.lines.iter().any(|l| l.ends_with(
            "KNOWN DIFFERENCE  k/known on e: w; got: no reply; reason: reason k/known"
        )));
        assert!(
            out.lines
                .iter()
                .any(|l| l.ends_with("PASS  k/pass: w; got: fine"))
        );
        assert_eq!(out.unreached(&list, "k"), ["k/never-reached"]);
    }

    #[test]
    fn a_failed_require_off_the_list_fails() {
        let src = "scenario k\nrefs: r\n\nrequire req false\n  what: w\n  got: gone\ncheck after true\n  what: w\n  got: never\n";
        for list in [
            KnownList::new(),
            known(&[("k/req", "other", false)]),
            known(&[("k/req", "gone", true)]),
        ] {
            let out = run(src, &list);
            assert!(out.failed && !out.skipped, "{list:?}");
            assert_eq!(out.checks.len(), 1, "{list:?}");
        }
        let out = run(src, &known(&[("k/req", "gone", false)]));
        assert!(out.skipped && !out.failed);
        assert_eq!(
            out.unreached(&known(&[("k/after", "n", false)]), "k"),
            ["k/after"]
        );
    }
}
