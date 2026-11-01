//! 凍結した Go の wgstack の記録の読み込みと照合です (`docs/design/v2/test-tooling.md` の 4 節)。
//!
//! 記録は gzip で圧縮した magic (`WGFTREC1`)、meta の長さ (u32、little endian)、meta (JSON)、要求と応答の
//! frame の組の列です。Go の符号は `internal/dutproto` の `ReadRecord` と `SplitFrames` です。
//!
//! 照合は、`HELLO` から Rust の wgstack を作り、要求を 1 つずつ同じプロセスの server の処理 ([`answer_frame`])
//! に渡し、応答の frame を記録の応答と byte の単位で比べ、最初に食い違った所で止めます。`HELLO_OK` は種類と
//! 口の版だけを、`STATS`、`BOUND`、`HELD` の応答は種類だけを比べます。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use serde::Deserialize;
use wgft_tcpharness::dut::{ClockedDut, answer_frame};
use wgft_tcpharness::frame::{Kind, Msg, VERSION};

use crate::dut::WgstackDut;

/// 記録の始まりの magic です。
pub const MAGIC: &[u8; 8] = b"WGFTREC1";

/// 台本の記録の元の名前です。この元の記録は `dutserve` が作り、`dutserve` は `WRITE` の bytes を書ける量で切ります。
pub const SOURCE_SCENARIOS: &str = "scenarios";

/// 台本の確かめの 1 つです。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub key: String,
    pub outcome: String,
}

/// 記録の meta です。欄は Go の `dutproto.RecMeta` と同じで、知らない欄は断ります。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub source: String,
    pub name: String,
    pub test: String,
    #[serde(default)]
    pub scenario: String,
    #[serde(default)]
    pub run_seed: u64,
    #[serde(default)]
    pub scenario_seed: u64,
    #[serde(default)]
    pub seed: u64,
    #[serde(default)]
    pub variant: String,
    pub go_commit: String,
    pub go_version: String,
    pub goarch: String,
    pub goamd64: String,
    pub tags: Vec<String>,
    #[serde(default)]
    pub truncated: String,
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub concurrent: bool,
}

/// 1 つの frame です。
#[derive(Debug, Clone, Copy)]
pub struct RawFrame<'a> {
    pub kind: u8,
    pub body: &'a [u8],
    /// 長さ、種類、本体を含む frame の全体
    pub bytes: &'a [u8],
}

/// 読んだ記録です。
#[derive(Debug, Clone)]
pub struct Recording {
    pub meta: Meta,
    /// frame の列の bytes
    pub frames: Vec<u8>,
}

impl Recording {
    /// `<元>/<名前>` の形の記録の名前です。意図した違いの一覧の `record` の欄はこの形です。
    pub fn id(&self) -> String {
        format!("{}/{}", self.meta.source, self.meta.name)
    }

    /// frame を要求と応答の組に分けます。
    pub fn pairs(&self) -> Result<Vec<(RawFrame<'_>, RawFrame<'_>)>, String> {
        let fs = split_frames(&self.frames)?;
        Ok(fs.as_chunks::<2>().0.iter().map(|&[q, a]| (q, a)).collect())
    }
}

/// 記録のファイルを読みます。
pub fn read_file(path: &Path) -> Result<Recording, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    read(f).map_err(|e| format!("{}: {e}", path.display()))
}

/// 記録の meta だけを読みます。圧縮を meta の終わりまでだけ解くので、試験の一覧を作る時に使います。
pub fn read_meta(path: &Path) -> Result<Meta, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut z = GzDecoder::new(f);
    let mut hdr = [0u8; 12];
    z.read_exact(&mut hdr)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if &hdr[..8] != MAGIC.as_slice() {
        return Err(format!(
            "{}: not a recording: no WGFTREC1 magic",
            path.display()
        ));
    }
    let n = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let mut js = Vec::new();
    z.take(u64::from(n))
        .read_to_end(&mut js)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&js).map_err(|e| format!("{}: recording meta: {e}", path.display()))
}

/// 記録を読みます。
pub fn read(r: impl Read) -> Result<Recording, String> {
    let mut all = Vec::new();
    GzDecoder::new(r)
        .read_to_end(&mut all)
        .map_err(|e| format!("gzip: {e}"))?;
    let Some(rest) = all.strip_prefix(MAGIC.as_slice()) else {
        return Err("not a recording: no WGFTREC1 magic".to_owned());
    };
    let Some((len, rest)) = rest.split_first_chunk::<4>() else {
        return Err("not a recording: no meta length".to_owned());
    };
    let n = usize::try_from(u32::from_le_bytes(*len)).unwrap_or(usize::MAX);
    if n > rest.len() {
        return Err(format!("meta of {n} bytes in {}", rest.len()));
    }
    let (js, frames) = rest.split_at(n);
    let meta: Meta = serde_json::from_slice(js).map_err(|e| format!("recording meta: {e}"))?;
    Ok(Recording {
        meta,
        frames: frames.to_vec(),
    })
}

/// frame の列を切り分けます。要求と応答が交互に並び、最後の要求は応答を持ちます。
pub fn split_frames(mut b: &[u8]) -> Result<Vec<RawFrame<'_>>, String> {
    let mut out: Vec<RawFrame<'_>> = Vec::new();
    while !b.is_empty() {
        let Some(len) = b.first_chunk::<4>() else {
            return Err(format!("{} bytes after the last frame", b.len()));
        };
        let n = usize::try_from(u32::from_le_bytes(*len)).unwrap_or(usize::MAX);
        if n == 0 || n.saturating_add(4) > b.len() {
            return Err(format!("frame length {n} with {} bytes left", b.len()));
        }
        let (bytes, rest) = b.split_at(4 + n);
        let f = RawFrame {
            kind: bytes[4],
            body: &bytes[5..],
            bytes,
        };
        let want_request = out.len().is_multiple_of(2);
        let is_request = Kind::from_byte(f.kind).is_some_and(Kind::is_request);
        if is_request != want_request {
            return Err(format!(
                "frame {} has kind {:#04x}; requests and responses alternate",
                out.len(),
                f.kind
            ));
        }
        out.push(f);
        b = rest;
    }
    if !out.len().is_multiple_of(2) {
        return Err("the last request has no response".to_owned());
    }
    Ok(out)
}

/// Rust の wgstack が入れた段と、段ごとの記録の印です (`stages.json`)。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stages {
    /// 核に入った段。段を入れる PR がここに足します
    pub landed: Vec<String>,
    /// 段ごとに、その段で照らせるようになる記録の印
    pub stages: BTreeMap<String, Vec<String>>,
}

impl Stages {
    /// `stages.json` を読みます。
    pub fn parse(b: &[u8]) -> Result<Self, String> {
        let s: Self = serde_json::from_slice(b).map_err(|e| format!("stages: {e}"))?;
        for l in &s.landed {
            if !s.stages.contains_key(l) {
                return Err(format!("stages: landed stage {l:?} has no tags"));
            }
        }
        Ok(s)
    }

    /// どれかの段にある印の集まりです。
    pub fn all_tags(&self) -> BTreeSet<String> {
        self.stages.values().flatten().cloned().collect()
    }

    /// 入れた段の印の集まりです。
    pub fn tags(&self) -> BTreeSet<String> {
        self.landed
            .iter()
            .filter_map(|l| self.stages.get(l))
            .flatten()
            .cloned()
            .collect()
    }
}

/// 照らせる印の集まりです。
#[derive(Debug, Clone)]
pub enum TagFilter {
    /// すべての記録を照らします
    All,
    /// 印がすべてこの中にある記録だけを照らします
    Only(BTreeSet<String>),
}

impl TagFilter {
    /// `tags` のうち照らせない印です。空なら記録を照らせます。
    pub fn missing<'a>(&self, tags: &'a [String]) -> Vec<&'a str> {
        match self {
            Self::All => Vec::new(),
            Self::Only(set) => tags
                .iter()
                .filter(|t| !set.contains(*t))
                .map(String::as_str)
                .collect(),
        }
    }
}

/// 意図した違いの一覧の 1 行です (`testdata/wgstack-rec/divergences.json`)。
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Divergence {
    /// `<元>/<名前>`
    pub record: String,
    /// 最初に食い違う応答の要求の番号。0 は `HELLO`
    pub request: usize,
    /// Rust の応答の frame の 16 進
    pub response: String,
    /// 理由
    pub reason: String,
}

/// 意図した違いの一覧を読みます。どの行も理由を持ち、`HELLO` (要求 0) でない要求と空でない応答を指し、
/// 同じ記録の行は 1 つだけです。
pub fn parse_divergences(b: &[u8]) -> Result<Vec<Divergence>, String> {
    let v: Vec<Divergence> = serde_json::from_slice(b).map_err(|e| format!("divergences: {e}"))?;
    let mut seen = BTreeSet::new();
    for d in &v {
        if d.reason.trim().is_empty() {
            return Err(format!("divergences: {} has no reason", d.record));
        }
        if d.request == 0 {
            return Err(format!(
                "divergences: {} names request 0; a HELLO that fails is no intended divergence",
                d.record
            ));
        }
        if d.response.is_empty() {
            return Err(format!(
                "divergences: {} has an empty response; a DUT that broke is no intended divergence",
                d.record
            ));
        }
        if !seen.insert(d.record.as_str()) {
            return Err(format!("divergences: {} has more than one row", d.record));
        }
    }
    Ok(v)
}

/// `testNet` の記録の `WRITE` が、Go の答えた byte 数と同じ長さの bytes を渡していることを確かめます。
fn check_testnet_writes(pairs: &[(RawFrame<'_>, RawFrame<'_>)]) -> Result<(), String> {
    for (i, (q, a)) in pairs.iter().enumerate() {
        if q.kind != Kind::Write as u8 {
            continue;
        }
        if let (Ok(Msg::Write { data, .. }), Ok(Msg::Wrote(n))) =
            (Msg::decode(q.kind, q.body), Msg::decode(a.kind, a.body))
            && usize::try_from(n).ok() != Some(data.len())
        {
            return Err(format!(
                "request {i}: a testNet WRITE of {} bytes answered WROTE {n}; testNet passes at most the room, so Go writes it all",
                data.len()
            ));
        }
    }
    Ok(())
}

/// 小文字の 16 進です。
pub fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// 最初の食い違いです。
#[derive(Debug, Clone)]
pub struct Mismatch {
    /// 要求の番号。0 は `HELLO`
    pub request: usize,
    /// Rust の応答の frame の bytes。DUT が壊れた時は空です
    pub got: Vec<u8>,
    /// 人が読む説明。要求、期待した応答、得た応答と、その前の要求と応答です
    pub detail: String,
}

/// 照合の結果です。
#[derive(Debug, Clone)]
pub enum Outcome {
    /// すべての応答が一致しました
    Match {
        /// 照らした要求の数 (`HELLO` を含む)
        requests: usize,
    },
    /// 食い違いました
    Diverged(Mismatch),
}

fn show(kind: u8, body: &[u8]) -> String {
    match Msg::decode(kind, body) {
        Ok(m) => m.to_string(),
        Err(e) => format!("undecodable frame of kind {kind:#04x}: {e}"),
    }
}

fn show_frame(f: &[u8]) -> String {
    if f.len() < 5 {
        return format!("short frame {}", hex(f));
    }
    show(f[4], &f[5..])
}

/// 応答を比べます。`STATS`、`BOUND`、`HELD` は応答の種類だけを比べます。
fn same(req: Kind, want: &RawFrame<'_>, got: &[u8]) -> bool {
    match req {
        Kind::Stats | Kind::Bound | Kind::Held => got.get(4) == Some(&want.kind),
        _ => got == want.bytes,
    }
}

/// 照らす前の文脈として出す前の要求の数です。
const CONTEXT: usize = 4;

/// 記録を Rust の wgstack で照らします。記録が読めない時と要求が復号できない時は誤りです。
///
/// 核の不変条件も確かめ、破れたらそこで食い違いとして止めます。`HELLO` が上限の組を持つ記録 (`testNet` の
/// 小さな表) は要求ごとに、既定の表の記録は最後に確かめます。既定の表は大きく、要求ごとに確かめると
/// debug の build で 1 要求に 20 ms ほどかかるためです。
pub fn replay(rec: &Recording) -> Result<Outcome, String> {
    let pairs = rec.pairs()?;
    let Some(((hreq, hresp), rest)) = pairs.split_first() else {
        return Err("the recording has no frames".to_owned());
    };
    let Ok(Msg::Hello(hello)) = Msg::decode(hreq.kind, hreq.body) else {
        return Err("the first request is not a HELLO".to_owned());
    };
    let mut dut = match WgstackDut::for_replay(&hello) {
        Ok(d) => d,
        Err(e) => {
            return Ok(Outcome::Diverged(Mismatch {
                request: 0,
                got: Vec::new(),
                detail: format!(
                    "request 0: {}\n  Go    {}\n  Rust  HELLO failed: {e}",
                    show(hreq.kind, hreq.body),
                    show(hresp.kind, hresp.body)
                ),
            }));
        }
    };
    match Msg::decode(hresp.kind, hresp.body) {
        Ok(Msg::HelloOk { version, .. }) if version == VERSION => {}
        other => {
            return Err(format!(
                "the recorded HELLO answer is {other:?}, not HELLO_OK version {VERSION}"
            ));
        }
    }
    // testNet の記録は WRITE に書ける量 (room) までしか渡さず、Go の Write は渡した bytes をすべて書いた。
    // そうでない記録は、adapter が write を 1 回だけ呼ぶ前提を崩すので、照らす前に断る
    if rec.meta.source != SOURCE_SCENARIOS {
        check_testnet_writes(&pairs)?;
    }
    let each = !hello.limits.is_empty();
    for (i, (req, want)) in rest.iter().enumerate() {
        let n = i + 1;
        let msg = Msg::decode(req.kind, req.body)
            .map_err(|e| format!("request {n} does not decode: {e}"))?;
        if matches!(msg, Msg::Hello(_)) {
            return Err(format!("request {n} is a second HELLO"));
        }
        let kind = msg.kind();
        let (got, got_text) = match answer_frame(&mut dut, &msg) {
            Ok(a) => {
                let t = show_frame(&a.frame);
                (a.frame, t)
            }
            Err(e) => (Vec::new(), format!("the DUT broke: {e}")),
        };
        let broken = if each || n == rest.len() {
            dut.check_invariants().err()
        } else {
            None
        };
        if same(kind, want, &got) && broken.is_none() {
            continue;
        }
        let mut detail = String::new();
        let now = dut.now().map_or(0, |d| d.as_nanos());
        let _ = writeln!(
            detail,
            "first difference at request {n} of {} (DUT time {now} ns)",
            pairs.len() - 1
        );
        for (j, (r, w)) in pairs
            .iter()
            .enumerate()
            .take(n)
            .skip(n.saturating_sub(CONTEXT))
        {
            let _ = writeln!(detail, "  request {j}: {}", show(r.kind, r.body));
            let _ = writeln!(detail, "    both  {}", show(w.kind, w.body));
        }
        let _ = writeln!(detail, "  request {n}: {msg}");
        let _ = writeln!(detail, "    Go    {}", show(want.kind, want.body));
        let _ = writeln!(detail, "    Rust  {got_text}");
        if let Some(e) = broken {
            let _ = writeln!(detail, "    invariant: {e}");
        }
        let _ = writeln!(detail, "    Rust frame {}", hex(&got));
        return Ok(Outcome::Diverged(Mismatch {
            request: n,
            got,
            detail,
        }));
    }
    Ok(Outcome::Match {
        requests: pairs.len(),
    })
}

/// 照合の結果を意図した違いの一覧と照らします。通るなら 1 行の説明を、落ちるなら理由を返します。
///
/// 一覧に行の無い記録は、すべての応答が一致すれば通ります。行を持つ記録は、行と同じ要求で同じ応答の frame に
/// 食い違えば既知の違いとして通り、位置か応答が違うか、最後まで一致すれば落ちます。
pub fn judge(rec: &Recording, out: &Outcome, divs: &[Divergence]) -> Result<String, String> {
    let id = rec.id();
    let row = divs.iter().find(|d| d.record == id);
    if let Some(d) = row {
        let pairs = rec.pairs()?;
        let Some((_, want)) = pairs.get(d.request) else {
            return Err(format!(
                "{id}: the intended-divergence row names request {} of {}",
                d.request,
                pairs.len()
            ));
        };
        if d.response == hex(want.bytes) {
            return Err(format!(
                "{id}: the intended-divergence row at request {} names Go's own answer; it is no divergence",
                d.request
            ));
        }
    }
    match (out, row) {
        (Outcome::Match { requests }, None) => Ok(format!("{id}: {requests} requests match")),
        (Outcome::Match { requests }, Some(d)) => Err(format!(
            "{id}: the intended-divergence list expects a difference at request {}, but all {requests} requests match; remove the row",
            d.request
        )),
        (Outcome::Diverged(m), Some(d)) if d.request == m.request && d.response == hex(&m.got) => {
            Ok(format!(
                "{id}: intended divergence at request {}: {}",
                d.request, d.reason
            ))
        }
        (Outcome::Diverged(m), row) => {
            let mut msg = format!("{id}: {}", m.detail);
            if let Some(d) = row {
                let _ = writeln!(
                    msg,
                    "the intended-divergence list expects request {} answered {}",
                    d.request, d.response
                );
            }
            if !rec.meta.truncated.is_empty() {
                let _ = writeln!(msg, "the recording is truncated: {}", rec.meta.truncated);
            }
            Err(msg)
        }
    }
}
