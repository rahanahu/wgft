//! stream の 1 通を読む間の確保の最大値と、読んだ全体状態の保持を、入力の長さと比べる
//! (`docs/design/v2/agent-control.md` の「全体状態の保持」)。
//!
//! 数えはプロセスで 1 つなので、測る試験はこの試験のバイナリに 1 つだけ置く。

use wgft_alloc_count::{CountingAlloc, live_bytes, peak_bytes, reset_peak};
use wgft_proto::{Message, STATE_HELD_FACTOR, STREAM_READ_LIMIT};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// `body` を上限の長さまで並べた配列にする。
fn fill(head: &str, item: &str, tail: &str) -> String {
    let mut s = String::with_capacity(STREAM_READ_LIMIT);
    s.push_str(head);
    let n = (STREAM_READ_LIMIT - head.len() - tail.len()) / (item.len() + 1);
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        s.push_str(item);
    }
    s.push_str(tail);
    assert!(s.len() <= STREAM_READ_LIMIT);
    s
}

/// 読む間の確保の最大値 (入力を除く) と、読んだ値の保持を返す。
fn measure(text: &str) -> (usize, usize, Option<Message>) {
    let before = live_bytes();
    reset_peak();
    let m = Message::decode(text).ok();
    let peak = peak_bytes() - before;
    let held = live_bytes() - before;
    (peak, held, m)
}

#[test]
fn decoding_holds_a_bounded_multiple_of_the_input() {
    // 知らないキーの下の小さな値の列。型の値は何も持たないので、読む間の確保も小さい
    let ignored = fill(r#"{"type":"state","x":["#, "0", "]}");
    let (peak, _, m) = measure(&ignored);
    assert!(m.is_some());
    assert!(
        peak < 64 << 10,
        "an ignored array of {} bytes peaked at {peak} bytes",
        ignored.len()
    );
    drop(m);

    // 中身の最も小さいルールの列と、長い文字列を持つルール。読んだ全体状態の保持と読む間の最大値が、
    // 入力の長さの STATE_HELD_FACTOR 倍に収まる
    let cases = [
        fill(
            r#"{"type":"state","state":{"generation":1,"wg":{},"rules":["#,
            r#"{"id":"","proto":"tcp","listen_port":"1","target":""}"#,
            "]}}",
        ),
        fill(
            r#"{"type":"state","state":{"generation":1,"wg":{},"rules":["#,
            r#"{"id":"a","proto":"x","listen_port":"1","target":"b"}"#,
            "]}}",
        ),
        fill(
            r#"{"type":"state","state":{"generation":1,"wg":{},"rules":["#,
            &format!(
                r#"{{"id":"{}","proto":"tcp","listen_port":"1-65535","target":"{}:1"}}"#,
                "i".repeat(4000),
                "h".repeat(4000)
            ),
            "]}}",
        ),
        fill(
            r#"{"type":"state","state":{"generation":1,"wg":{},"server_capabilities":["#,
            r#""""#,
            "]}}",
        ),
        fill(
            r#"{"type":"state","capabilities":["#,
            r#""""#,
            "],\"state\":{}}",
        ),
        fill(
            r#"{"type":"state","state":{"generation":1,"wg":{},"server_capabilities":["#,
            r#""a""#,
            "]}}",
        ),
    ];
    for text in &cases {
        let (peak, held, m) = measure(text);
        assert!(m.is_some_and(|m| m.state.is_some()), "{}", &text[..80]);
        println!(
            "{}... in {} bytes: held {held} bytes ({}% of the input), peak {peak} bytes ({}%)",
            &text[..80],
            text.len(),
            held * 100 / text.len(),
            peak * 100 / text.len()
        );
        assert!(
            held <= STATE_HELD_FACTOR * text.len(),
            "held {held} bytes for {} bytes",
            text.len()
        );
        assert!(
            peak <= STATE_HELD_FACTOR * text.len(),
            "peaked at {peak} bytes for {} bytes",
            text.len()
        );
    }
}
