use super::parse::trim_space;
use super::*;

#[test]
fn trim_space_like_go() {
    assert_eq!(trim_space(b" \t\x0b\x0cx y\r\n"), b"x y");
    // U+00A0、U+3000 は Go の unicode.IsSpace で空白
    assert_eq!(trim_space("\u{a0}x\u{3000}".as_bytes()), b"x");
    // 読めない byte と U+FFFD は空白でない
    assert_eq!(trim_space(b"\xff "), b"\xff");
    assert_eq!(trim_space(b"\xe2\x80"), b"\xe2\x80");
}

#[test]
fn display_names_file_and_line() {
    let e = parse_script("x.scn", b"scenario x\nrefs: r\nbogus 1\n").unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnknownStatement);
    assert_eq!(e.line, 3);
    assert!(e.to_string().starts_with("x.scn:3: "), "{e}");
}

#[test]
fn stop_branch_binds_everything() {
    let src = b"scenario x\nrefs: r\nif true\n  let a = 1\nelse\n  stop\nend\nlet b = a\n";
    parse_script("x.scn", src).unwrap();
}

#[test]
fn escaped_bytes_that_are_not_utf8_are_hex() {
    let s = parse_script("x.scn", b"scenario x\nrefs: <r>\nlet a = \"\\xfe\"\n").unwrap();
    let json = String::from_utf8(s.ast().to_bytes()).unwrap();
    assert!(json.contains("{\"hex\":\"fe\"}"), "{json}");
    assert!(json.contains("\"refs\":\"\\u003cr\\u003e\""), "{json}");
}

#[test]
fn line_not_utf8_is_layout() {
    let e = parse_script("x.scn", b"scenario x\nrefs: r\n# \xff\n").unwrap_err();
    assert_eq!((e.line, e.kind), (3, ErrorKind::Layout));
}
