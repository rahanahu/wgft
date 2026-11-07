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

/// PACKETS の応答の frame で、IPv4 の ID と header の checksum を 0 にした写しを返します。製品の核は DF を立てた
/// packet の ID を 0 にし (RFC 6864 4.1)、凍結した Go の記録は数えの値を持つので、ID だけが違います。
/// 照合用の切り替えは `for_replay` の核だけが持つため、別のプロセスの製品の核では ID を比べません。
fn mask_ipv4_id(frame: &[u8]) -> Vec<u8> {
    let mut f = frame.to_vec();
    // frame は長さ (4 byte)、種類 (1 byte)、本体で、PACKETS の本体は個数 (4 byte) と (長さ (4 byte)、packet) の列です。
    if f.get(4) != Some(&(frame::Kind::Packets as u8)) {
        return f;
    }
    let count = u32::from_le_bytes(f[5..9].try_into().expect("count")) as usize;
    let mut at = 9;
    for _ in 0..count {
        let len = u32::from_le_bytes(f[at..at + 4].try_into().expect("length")) as usize;
        at += 4;
        let ihl = usize::from(f[at] & 15) * 4;
        let sum = f[at..at + ihl]
            .chunks(2)
            .fold(0u32, |a, c| a + u32::from(u16::from_be_bytes([c[0], c[1]])));
        let sum = (sum & 0xffff) + (sum >> 16);
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xffff, "IPv4 header checksum");
        f[at + 4..at + 6].fill(0);
        f[at + 10..at + 12].fill(0);
        at += len;
    }
    f
}

/// 記録の要求を別のプロセスの `wgstack-dut` に送り、応答が記録と同じ bytes (IPv4 の ID と header の checksum を除く。checksum は値が正しいことを確かめてから除く)
/// であることを確かめます。
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
        assert_eq!(
            mask_ipv4_id(&got.frame),
            mask_ipv4_id(want.bytes),
            "{}: request {i} {m}",
            path.display()
        );
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

/// 完全な集まりの意図した違いの一覧の形の誤りを断ることの確かめです。種で名前が決まる記録は名前だけで、Go の
/// fuzz の cache の記録 (`fuzzcore/cache-*`) は frame の列の SHA-256 で指します。
#[test]
fn full_divergence_rows_are_checked() {
    let h = "0".repeat(64);
    let row = |record: &str, sha: Option<&str>, request: usize, resp: &str| {
        let sha = sha.map_or_else(String::new, |s| format!(r#""sha256": "{s}", "#));
        format!(
            r#"{{"record": "{record}", {sha}"request": {request}, "response_sha256": "{resp}", "reason": "r"}}"#
        )
    };
    let parse =
        |rows: &[String]| rec::FullDivergences::parse(format!("[{}]", rows.join(",")).as_bytes());
    assert!(parse(&[row("adversarial/seed-1", None, 3, &h)]).is_ok());
    assert!(parse(&[row("fuzzcore/cache-ab", Some(&h), 3, &h)]).is_ok());
    // cache の記録は hash が要り、種の記録は hash を持てません
    assert!(parse(&[row("fuzzcore/cache-ab", None, 3, &h)]).is_err());
    assert!(parse(&[row("adversarial/seed-1", Some(&h), 3, &h)]).is_err());
    // hash の形、要求 0、空の理由と同じ記録の 2 つ目の行を断ります
    assert!(parse(&[row("fuzzcore/cache-ab", Some("00"), 3, &h)]).is_err());
    assert!(parse(&[row("adversarial/seed-1", None, 3, "00")]).is_err());
    assert!(parse(&[row("adversarial/seed-1", None, 0, &h)]).is_err());
    assert!(
        parse(&[
            row("adversarial/seed-1", None, 3, &h),
            row("adversarial/seed-1", None, 4, &h)
        ])
        .is_err()
    );
    assert!(
        parse(&[
            row("fuzzcore/cache-ab", Some(&h), 3, &h),
            row("fuzzcore/cache-cd", Some(&h), 4, &h)
        ])
        .is_err()
    );
    // git の一覧は応答を 16 進で持ち、hash を持てません
    assert!(
        rec::parse_divergences(
            br#"[{"record": "a/b", "request": 3, "response": "sha256:00", "reason": "r"}]"#
        )
        .is_err()
    );
}

/// 完全な集まりの一覧の行で、記録を名前か frame の列の SHA-256 で引き、応答の SHA-256 で照らすことの確かめです。
#[test]
fn full_divergence_rows_match_by_name_or_content() {
    use sha2::{Digest, Sha256};
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wgstack-rec/stream-tx");
    let r = rec::read_file(&dir.join("seed-1.4b.rec.gz")).expect("read");
    // 最初に packet を返した POLL の応答の最後の byte を変えて、Rust と食い違う記録を作ります。
    let end = {
        let pairs = r.pairs().expect("frames");
        let (_, resp) = pairs
            .iter()
            .find(|(q, a)| q.kind == frame::Kind::Poll as u8 && a.bytes.len() > 9 + 20)
            .expect("a POLL that returned a packet");
        resp.bytes.as_ptr() as usize - r.frames.as_ptr() as usize + resp.bytes.len() - 1
    };
    let mut bad = r.clone();
    bad.frames[end] ^= 0x01;
    let out = rec::replay(&bad).expect("replay");
    let rec::Outcome::Diverged(m) = &out else {
        panic!("a changed byte replays as {out:?}");
    };
    let resp = rec::hex(&Sha256::digest(&m.got));
    let list = |record: &str, sha: Option<String>, request: usize, resp: &str| {
        let sha = sha.map_or_else(String::new, |s| format!(r#""sha256": "{s}", "#));
        rec::FullDivergences::parse(
            format!(
                r#"[{{"record": "{record}", {sha}"request": {request}, "response_sha256": "{resp}", "reason": "r"}}]"#
            )
            .as_bytes(),
        )
        .expect("list")
    };
    let judge = |rec: &rec::Recording, full: &rec::FullDivergences| {
        let row = full.for_recording(rec);
        rec::judge(rec, &out, row.as_slice())
    };
    // 名前で引く行
    let id = bad.id();
    assert!(judge(&bad, &list(&id, None, m.request, &resp)).is_ok());
    assert!(judge(&bad, &list(&id, None, m.request + 1, &resp)).is_err());
    assert!(judge(&bad, &list(&id, None, m.request, &"1".repeat(64))).is_err());
    assert!(judge(&bad, &list("stream-tx/seed-2", None, m.request, &resp)).is_err());
    // cache の記録は名前によらず、frame の列の SHA-256 で引きます
    let mut cached = bad.clone();
    cached.meta.source = "fuzzcore".to_owned();
    cached.meta.name = "cache-0123".to_owned();
    // hash は meta と圧縮を含まない frame の列だけの値です。git の記録の値を固定し、meta (go_version を含みます)
    // を変えても同じ値になることを確かめます。値は記録のファイルの形から別に計算しました。frame の列が変わるように
    // 記録を作り直したら、値を直します。
    let mut other_go = r.clone();
    other_go.meta.go_version = "go0.0".to_owned();
    for x in [&r, &other_go] {
        assert_eq!(
            rec::frames_sha256(x),
            "f0e70d5891066c9f748b75d45d852b1dc6fddeb01fa0423394321f1306987730"
        );
    }
    let sha = rec::frames_sha256(&cached);
    let row = list("fuzzcore/cache-other", Some(sha.clone()), m.request, &resp);
    assert!(judge(&cached, &row).is_ok());
    assert!(
        judge(
            &cached,
            &list(
                "fuzzcore/cache-0123",
                Some("2".repeat(64)),
                m.request,
                &resp
            )
        )
        .is_err()
    );
    assert!(
        judge(
            &cached,
            &list("fuzzcore/cache-0123", Some(sha), m.request, &"1".repeat(64))
        )
        .is_err()
    );
    // 一致する記録に行があれば落ちます
    let good = rec::replay(&r).expect("replay");
    let row = list(&r.id(), None, m.request, &resp).for_recording(&r);
    assert!(rec::judge(&r, &good, row.as_slice()).is_err());
}

/// 核の不変条件が破れた食い違いは、意図した違いの一覧の行が位置と応答に当たっても落ちることの確かめです。
#[test]
fn a_declared_row_does_not_hide_an_invariant_break() {
    use sha2::{Digest, Sha256};
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/wgstack-rec/stream-tx");
    let r = rec::read_file(&dir.join("seed-1.4b.rec.gz")).expect("read");
    let end = {
        let pairs = r.pairs().expect("frames");
        let (_, resp) = pairs
            .iter()
            .find(|(q, a)| q.kind == frame::Kind::Poll as u8 && a.bytes.len() > 9 + 20)
            .expect("a POLL that returned a packet");
        resp.bytes.as_ptr() as usize - r.frames.as_ptr() as usize + resp.bytes.len() - 1
    };
    let mut bad = r.clone();
    bad.frames[end] ^= 0x01;
    let out = rec::replay(&bad).expect("replay");
    let rec::Outcome::Diverged(m) = &out else {
        panic!("a changed byte replays as {out:?}");
    };
    // 変えたのは記録の応答だけなので、核の不変条件は保たれています。
    assert_eq!(m.invariant, None, "{}", m.detail);
    let git_row = rec::Divergence {
        record: bad.id(),
        request: m.request,
        response: rec::hex(&m.got),
        reason: "test".to_owned(),
    };
    let full = rec::FullDivergences::parse(
        format!(
            r#"[{{"record": "{}", "request": {}, "response_sha256": "{}", "reason": "test"}}]"#,
            bad.id(),
            m.request,
            rec::hex(&Sha256::digest(&m.got))
        )
        .as_bytes(),
    )
    .expect("list");
    let full_row = full.for_recording(&bad).expect("row");
    for row in [&git_row, &full_row] {
        assert!(rec::judge(&bad, &out, std::slice::from_ref(row)).is_ok());
        let mut broken = m.clone();
        broken.invariant = Some("the send window is not the one of the ACK at SND.UNA".to_owned());
        let err = rec::judge(
            &bad,
            &rec::Outcome::Diverged(broken),
            std::slice::from_ref(row),
        )
        .expect_err("a declared row hid an invariant break");
        assert!(err.contains("expects request"), "{err}");
    }
}
