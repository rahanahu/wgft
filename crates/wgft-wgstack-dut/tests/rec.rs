//! 記録の読み込みと照合そのものの試験です (`docs/design/v2/test-tooling.md` の 4 節)。
//!
//! - 照合が 1 byte の違いを捉えてその要求で止まることと、意図した違いの一覧の照らし方
//! - バイナリ `wgstack-dut` が記録の応答と同じ bytes を返すこと

use std::path::{Path, PathBuf};

use wgft_tcpharness::dut::{ClockedDut, ProcessDut};
use wgft_tcpharness::frame::{self, Msg};
use wgft_wgstack_dut::dut::ENGINE;
use wgft_wgstack_dut::rec;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wgstack-dut"))
}

/// 記録の要求を別のプロセスの `wgstack-dut` に送り、応答が記録と同じ bytes であることを確かめます。
fn replay_through_process(path: &Path) {
    let r = rec::read_file(path).expect("read");
    let pairs = r.pairs().expect("frames");
    let Ok(Msg::Hello(h)) = Msg::decode(pairs[0].0.kind, pairs[0].0.body) else {
        panic!("no HELLO");
    };
    let mut d = ProcessDut::spawn(&bin(), h, |l| eprintln!("{l}")).expect("spawn");
    assert_eq!(d.engine(), ENGINE);
    for (i, (req, want)) in pairs.iter().enumerate().skip(1) {
        let m = Msg::decode(req.kind, req.body).expect("request");
        let got = d.exchange_frame(&m).expect("exchange");
        assert_eq!(got.frame, want.bytes, "{}: request {i} {m}", path.display());
    }
    d.close().expect("close");
}

#[test]
fn binary_answers_as_the_recordings() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wgstack-rec/scenarios");
    replay_through_process(&dir.join("handshake-bare.seed-1.4b.rec.gz"));
    replay_through_process(&dir.join("handshake-mss-floor.seed-1.4b.rec.gz"));
}

/// 照合が 1 byte の違いを捉え、その要求で止まることの確かめです。
#[test]
fn replay_stops_at_a_changed_byte() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wgstack-rec/stream-tx");
    let r = rec::read_file(&dir.join("seed-1.4b.rec.gz")).expect("read");
    assert!(matches!(rec::replay(&r), Ok(rec::Outcome::Match { .. })));
    // 最初に packet を返した POLL の応答の最後の byte (TCP の payload か checksum) を変える
    let (at, end) = {
        let pairs = r.pairs().expect("frames");
        let (i, (_, resp)) = pairs
            .iter()
            .enumerate()
            .find(|(_, (q, a))| q.kind == frame::Kind::Poll as u8 && a.bytes.len() > 9 + 20)
            .expect("a POLL that returned a packet");
        let off = resp.bytes.as_ptr() as usize - r.frames.as_ptr() as usize;
        (i, off + resp.bytes.len() - 1)
    };
    let mut bad = r.clone();
    bad.frames[end] ^= 0x01;
    let out = rec::replay(&bad).expect("replay");
    let rec::Outcome::Diverged(m) = &out else {
        panic!("a changed byte replays as {out:?}");
    };
    assert_eq!(m.request, at, "{}", m.detail);

    // 意図した違いの一覧:同じ位置で同じ応答なら通り、位置か応答が違うか、最後まで一致すれば落ちる
    let row = |request, response: String| rec::Divergence {
        record: bad.id(),
        request,
        response,
        reason: "test".to_owned(),
    };
    let got = rec::hex(&m.got);
    assert!(rec::judge(&bad, &out, &[]).is_err());
    assert!(rec::judge(&bad, &out, &[row(at, got.clone())]).is_ok());
    assert!(rec::judge(&bad, &out, &[row(at + 1, got.clone())]).is_err());
    assert!(rec::judge(&bad, &out, &[row(at, "00".to_owned())]).is_err());
    let good = rec::replay(&r).expect("replay");
    assert!(rec::judge(&r, &good, &[]).is_ok());
    assert!(rec::judge(&r, &good, &[row(at, got)]).is_err());
    // Go の記録の応答そのものを指す行は違いではない
    let pairs = bad.pairs().expect("frames");
    let own = rec::hex(pairs[at].1.bytes);
    assert!(rec::judge(&bad, &out, &[row(at, own)]).is_err());
}

/// `stages.json` の 4b の段の印が、Go の `dutproto.Stage4bTags` (4b の変種の記録が持ちうる印) と同じことの
/// 確かめです。Go の定義の行を読みます。
#[test]
fn stage_4b_tags_match_go() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let go =
        std::fs::read_to_string(root.join("../../internal/dutproto/rec.go")).expect("read rec.go");
    let line = go
        .lines()
        .find(|l| l.starts_with("var Stage4bTags = []string{"))
        .expect("the Stage4bTags line in internal/dutproto/rec.go");
    let mut want: Vec<String> = line
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    want.sort();
    let stages =
        rec::Stages::parse(&std::fs::read(root.join("stages.json")).expect("read stages.json"))
            .expect("stages.json");
    let mut got = stages.stages["4b"].clone();
    got.sort();
    assert_eq!(want.len(), 3, "{line}");
    assert_eq!(got, want);
}

/// 意図した違いの一覧の形の誤りを断ることの確かめです。
#[test]
fn divergence_rows_are_checked() {
    let row = |record: &str, request: usize, response: &str| {
        format!(
            r#"{{"record": "{record}", "request": {request}, "response": "{response}", "reason": "r"}}"#
        )
    };
    let list = |rows: &[String]| format!("[{}]", rows.join(","));
    assert!(rec::parse_divergences(list(&[row("a/b", 3, "0500000081")]).as_bytes()).is_ok());
    assert!(rec::parse_divergences(list(&[row("a/b", 0, "0500000081")]).as_bytes()).is_err());
    assert!(rec::parse_divergences(list(&[row("a/b", 3, "")]).as_bytes()).is_err());
    assert!(
        rec::parse_divergences(
            list(&[row("a/b", 3, "0500000081"), row("a/b", 4, "0500000081")]).as_bytes()
        )
        .is_err()
    );
}
