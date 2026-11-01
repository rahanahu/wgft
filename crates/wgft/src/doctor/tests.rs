//! `agent doctor` の試験。仕様の fixture (Go の v1 がラボで書いた出力) を Rust の診断で作り直して照らし、
//! 設計の表と検査の ID と理由の符号を照らし、場面ごとの状態と終了コードを確かめる。

use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use wgft_agent::credentials::{Credentials, LockState};
use wgft_agent::hostaddr::Interface;

use super::output::JsonReport;
use super::*;

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
        .replace("\r\n", "\n")
}

/// 制御ソケットの代わり。書かれたものを捨て、決めた応答を返す。
struct FakeConn(Cursor<Vec<u8>>);

impl Read for FakeConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for FakeConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn iface(name: &str, addr: &str) -> Interface {
    Interface {
        name: name.into(),
        up: true,
        loopback: false,
        addrs: vec![addr.into()],
    }
}

fn lo() -> Interface {
    Interface {
        name: "lo".into(),
        up: true,
        loopback: true,
        addrs: vec!["127.0.0.1/8".into()],
    }
}

/// OS を読まない入口で作る。権限はすべて通り、利用者は root でない。
fn input(dir: &Path) -> Input {
    let mut i = Input::for_host(dir.display().to_string());
    i.now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    i.version = "test".into();
    i.platform = "linux/amd64".into();
    i.user = "running as wgft, uid 999".into();
    i.config_path = dir.join("agent.env");
    i.inspect = Box::new(|_| Ok(LockState::Absent));
    i.resolve = Box::new(|h| Err(format!("lookup {h}: no such host")));
    i.interfaces = Box::new(|| Ok(vec![lo(), iface("eth0", "192.168.50.2/24")]));
    i.readable = Box::new(|_, _| (Access::Allowed, String::new()));
    i.dir_create_access = Box::new(|_| (Access::Allowed, String::new()));
    i.dial = Box::new(|_| Err(io::Error::from(io::ErrorKind::ConnectionRefused)));
    i.euid = Box::new(|| 999);
    i.is_dir = Box::new(|_| true);
    i
}

fn reply(line: &str) -> DialFn {
    let line = line.to_owned();
    Box::new(move |_| {
        let c: Box<dyn Conn> = Box::new(FakeConn(Cursor::new(line.clone().into_bytes())));
        Ok(c)
    })
}

fn registered(generation: u64) -> Credentials {
    let rules: Vec<serde_json::Value> = (0..4)
        .map(|i| {
            serde_json::json!({"id": format!("r_{i}"), "proto": "tcp", "listen_port": format!("{}", 39971 + i),
                "target": "192.168.50.3:25565", "enabled": true})
        })
        .collect();
    let state = serde_json::json!({
        "generation": generation,
        "wg": {"server_pubkey": "S", "endpoint": "203.0.113.1:51820", "address": "10.200.0.2/24",
               "mtu": 1420, "keepalive": 25, "udp_timeout": 30, "udp_timeout_stream": 120},
        "rules": rules, "server_protocol_version": 1, "server_capabilities": []
    });
    Credentials {
        name: "home".into(),
        endpoint: "203.0.113.1:8443".into(),
        cert_sha256: "3f1c9a5e7b2d0123456789abcdef0123456789abcdef0123456789abcdef0123".into(),
        permanent_token: "secret".into(),
        used_join_token_sha256: "35c2c54181850123456789abcdef".into(),
        last_state: Some(serde_json::from_value(state).unwrap()),
        ..Credentials::default()
    }
}

fn find<'a>(rep: &'a Report, id: &str) -> &'a Check {
    rep.checks.iter().find(|c| c.id == id).unwrap()
}

fn rfc(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).unwrap()
}

/// fixture と、同じ証拠から作った Rust の報告を照らす。`host.platform` の所見だけは比べない。版と、
/// Go のメモリのソフト上限の予測を含み、Rust はそれを持たないためである。
#[cfg(unix)]
fn assert_regenerates(fixture: &str, rep: &Report, dir: &Path) {
    let want_text = read(fixture);
    let want: JsonReport = serde_json::from_str(&want_text).unwrap();
    let mut b = Vec::new();
    write_json(&mut b, rep).unwrap();
    let got = String::from_utf8(b)
        .unwrap()
        .replace(&dir.display().to_string(), "/tmp/spec-agent-us");
    let mut got: JsonReport = serde_json::from_str(&got).unwrap();
    let platform = want
        .checks
        .iter()
        .find(|c| c.id == CHECK_PLATFORM)
        .unwrap()
        .detail
        .clone();
    for c in &mut got.checks {
        if c.id == CHECK_PLATFORM {
            c.detail.clone_from(&platform);
        }
    }
    for (g, w) in got.checks.iter().zip(&want.checks) {
        assert_eq!(g, w);
    }
    let got_text =
        String::from_utf8(wgft_proto::gojson::to_vec_indent(&got).unwrap()).unwrap() + "\n";
    assert_eq!(got_text, want_text);
}

/// 仕様の fixture は、Go の v1 の模型が知らないキー無しで読め、同じ byte 列に書き戻せる。
#[test]
fn spec_reports_round_trip_byte_for_byte() {
    for name in ["agent-doctor.json", "agent-doctor-stopped.json"] {
        let want = read(&format!("testdata/spec/control/{name}"));
        let rep: JsonReport = serde_json::from_str(&want).unwrap();
        let got =
            String::from_utf8(wgft_proto::gojson::to_vec_indent(&rep).unwrap()).unwrap() + "\n";
        assert_eq!(got, want, "{name}");
    }
}

#[cfg(unix)]
fn root_input(dir: &Path, generation: u64) -> Input {
    let p = dir.join("agent.json");
    registered(generation).save(&p).unwrap();
    let mut i = input(dir);
    i.euid = Box::new(|| 0);
    i.user = "running as root, uid 0".into();
    i
}

/// 止めた agent の fixture を、同じ証拠から作り直す。
#[cfg(unix)]
#[test]
fn regenerates_the_stopped_agent_fixture() {
    let d = tempfile::tempdir().unwrap();
    let mut i = root_input(d.path(), 5);
    i.now = rfc("2026-10-31T21:16:56Z");
    i.inspect = Box::new(|_| Ok(LockState::Unlocked));
    i.interfaces = Box::new(|| {
        Ok(vec![
            lo(),
            iface("eth0", "192.168.50.2/24"),
            iface("wgft0", "10.200.0.3/24"),
        ])
    });
    let rep = diagnose(&i).unwrap();
    assert_regenerates(
        "testdata/spec/control/agent-doctor-stopped.json",
        &rep,
        d.path(),
    );
    assert_eq!(exit(&rep).unwrap().code, 1);
}

/// 稼働中の agent の fixture を、その agent の制御ソケットの応答 (`doctor-reply.json`) から作り直す。
/// Go の CLI が Go の agent の応答から作った報告と、Rust の CLI が同じ応答から作る報告が同じである。
#[cfg(unix)]
#[test]
fn regenerates_the_running_agent_fixture_from_its_reply() {
    let d = tempfile::tempdir().unwrap();
    let mut i = root_input(d.path(), 4);
    i.now = rfc("2026-10-31T21:16:43.2Z");
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    i.dial = reply(&read("testdata/spec/control/doctor-reply.json"));
    let rep = diagnose(&i).unwrap();
    assert_regenerates("testdata/spec/control/agent-doctor.json", &rep, d.path());
    assert_eq!(verdict(&rep), status::FAILED);
}

/// 設計の表の 1 列目のバッククォートの値。表は最初の行の値で見つける (見出しの行は日本語で、
/// 製品のコードの文字列に日本語を置かない約束がある)。
fn design_column(file: &str, first: &str) -> Vec<String> {
    let text = read(&format!("docs/design/diagnosis/{file}"));
    let lines: Vec<&str> = text.lines().collect();
    let start = format!("| `{first}` |");
    let i = lines
        .iter()
        .position(|l| l.starts_with(&start))
        .unwrap_or_else(|| panic!("{file} has no table starting with {first}"));
    // 見出しと区切りの行が直前にあることを確かめる
    assert!(
        lines[i - 1].starts_with("|---"),
        "{file}: {first} does not open a table"
    );
    lines[i..]
        .iter()
        .take_while(|r| r.starts_with("| `"))
        .map(|r| {
            let cell = &r[3..];
            cell[..cell.find('`').unwrap()].to_owned()
        })
        .collect()
}

#[test]
fn check_ids_match_the_design() {
    let design = design_column("agent-evidence.md", CHECK_PLATFORM);
    assert_eq!(design, CHECK_ORDER);
}

/// カーネルモードの検査だけが使う符号。このビルドはカーネルモードの agent を診断しないので持たない。
const KERNEL_ONLY_REASONS: &[&str] = &[
    "kernel_mode",
    "needs_cap_net_admin",
    "agent_lacks_cap_net_admin",
    "kernel_unreadable",
    "interface_missing",
    "interface_not_ours",
    "interface_down",
    "peer_missing",
    "interface_differs",
    "route_not_via_interface",
    "table_missing",
    "table_rows_missing",
    "guard_rows_missing",
    "table_changed",
    "publish_failed",
    "ip_forward_off",
    "ip_forward_unreadable",
    "forward_policy_drop",
    "rp_filter_strict",
];

#[test]
fn reasons_match_the_design() {
    let design = design_column("agent-output.md", reason::NOT_RUNNING);
    let mut seen = std::collections::HashSet::new();
    for r in reason::ALL {
        assert!(seen.insert(*r), "{r} is held twice");
        assert!(
            design.iter().any(|d| d == r),
            "{r} is not in the design table"
        );
    }
    for d in &design {
        assert!(
            reason::ALL.contains(&d.as_str()) || KERNEL_ONLY_REASONS.contains(&d.as_str()),
            "the design lists {d}, which this build neither has nor leaves to kernel mode"
        );
    }
    for k in KERNEL_ONLY_REASONS {
        assert!(
            design.iter().any(|d| d == k),
            "{k} is not in the design table"
        );
    }
}

#[test]
fn a_missing_credentials_file_fails_with_exit_one() {
    let d = tempfile::tempdir().unwrap();
    let rep = diagnose(&input(d.path())).unwrap();
    let c = find(&rep, CHECK_CREDENTIALS);
    assert_eq!(
        (c.status, c.reason),
        (status::FAILED, reason::CREDENTIALS_MISSING)
    );
    assert_eq!(
        find(&rep, CHECK_HOST_RESOLVE).reason,
        reason::CREDENTIALS_MISSING
    );
    assert_eq!(
        find(&rep, CHECK_DP_TABLE).reason,
        reason::CREDENTIALS_MISSING
    );
    assert_eq!(find(&rep, CHECK_ALLOW_TARGETS).status, status::UNKNOWN);
    let f = exit(&rep).unwrap();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.message,
        "this host's agent cannot forward traffic as it stands: credentials, process"
    );
}

#[test]
fn a_kernel_mode_record_is_refused_with_exit_three() {
    let d = tempfile::tempdir().unwrap();
    let mut c = registered(1);
    c.mode = "kernel".into();
    c.save(&d.path().join("agent.json")).unwrap();
    let e = diagnose(&input(d.path())).unwrap_err();
    assert_eq!(e.exit_code(), 3);
    assert_eq!(
        e.to_string(),
        "cannot continue [prerequisite WGFT_MODE]: this build does not include the agent's kernel mode yet, so it cannot diagnose a kernel-mode agent; use a build that includes it"
    );
}

#[test]
fn an_unknown_recorded_mode_is_refused_by_name() {
    let d = tempfile::tempdir().unwrap();
    let mut c = registered(1);
    c.mode = "turbo".into();
    c.save(&d.path().join("agent.json")).unwrap();
    let e = diagnose(&input(d.path())).unwrap_err();
    assert_eq!(e.exit_code(), 3);
    assert_eq!(
        e.to_string(),
        "cannot continue [prerequisite WGFT_MODE]: agent.json records the mode \"turbo\", which this build does not know, so it cannot diagnose this agent; use a build that knows it"
    );
}

/// 長すぎて開けない制御ソケットのパスは、繋げない場合と分けて `control_socket_path_too_long` にする。
#[test]
fn a_control_socket_path_over_the_limit_is_named_as_such() {
    let d = tempfile::tempdir().unwrap();
    let long = d.path().join("x".repeat(120));
    std::fs::create_dir_all(&long).unwrap();
    registered(1).save(&long.join("agent.json")).unwrap();
    let mut i = input(&long);
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    i.dial = Box::new(|_| Err(io::Error::from(io::ErrorKind::InvalidInput)));
    let rep = diagnose(&i).unwrap();
    let c = find(&rep, CHECK_CONTROL);
    assert_eq!(
        (c.status, c.reason),
        (status::FAILED, reason::CONTROL_PATH_TOO_LONG)
    );
    assert!(!c.evidence_unreachable);
    assert_eq!(
        find(&rep, CHECK_TUNNEL_LOCAL).reason,
        reason::CONTROL_PATH_TOO_LONG
    );
    // 同じ誤りでも、パスが上限の内なら繋げない場合である
    let short = d.path();
    registered(1).save(&short.join("agent.json")).unwrap();
    let mut i = input(short);
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    i.dial = Box::new(|_| Err(io::Error::from(io::ErrorKind::InvalidInput)));
    let rep = diagnose(&i).unwrap();
    assert_eq!(
        find(&rep, CHECK_CONTROL).reason,
        reason::CONTROL_UNREACHABLE
    );
}

/// ルールの並びは先頭のいくつかだけを示し、残りを数で示す。
#[test]
fn long_rule_lists_end_with_the_count_of_the_rest() {
    let d = tempfile::tempdir().unwrap();
    registered(1).save(&d.path().join("agent.json")).unwrap();
    let mut i = input(d.path());
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    let rules: Vec<String> = (0..7)
        .map(|n| {
            format!(
                "{{\"id\":\"r_{n}\",\"state\":\"error\",\"reason\":\"x\",\"proto\":\"tcp\",\"listeners\":1,\"listening\":0,\"bind_errors\":1,\"bind_error\":\"tcp/{n}: in use\",\"target_errors\":0,\"sessions\":0,\"flows\":0}}"
            )
        })
        .collect();
    i.dial = reply(&format!(
        "{{{NO_ALLOWLIST},{STREAM_UP},\"runtime_state\":{{\"generation\":1,\"tunnel\":{{\"present\":true,\"state\":\"ok\",\"endpoint\":\"203.0.113.1:51820\",\"last_handshake\":\"2027-01-15T08:00:00Z\",\"rx_bytes\":1,\"tx_bytes\":2,\"started_at\":\"2027-01-15T07:59:00Z\",\"watchdog\":{{\"rebuild_interval\":300000000000,\"retry_at\":\"0001-01-01T00:00:00Z\"}}}},\"rules\":[{}],\"budgets\":[{{\"proto\":\"tcp\",\"total\":2048,\"in_use\":0,\"rule_cap\":1024,\"reserve\":4,\"rules\":7}}],\"refusals_since\":\"2027-01-15T07:59:00Z\",\"agent_disabled\":false}}}}\n",
        rules.join(",")
    ));
    let rep = diagnose(&i).unwrap();
    let l = find(&rep, CHECK_LISTENERS);
    assert_eq!(l.reason, reason::LISTENER_ERROR);
    assert!(
        l.detail.starts_with("7 of 7 rules cannot serve: r_0 tcp"),
        "{}",
        l.detail
    );
    assert!(l.detail.ends_with("; and 3 more"), "{}", l.detail);
    assert!(!l.detail.contains("r_4"), "{}", l.detail);
    let s = find(&rep, CHECK_SESSIONS);
    assert!(s.detail.ends_with("; and 3 more"), "{}", s.detail);
}

#[test]
fn a_running_kernel_mode_agent_is_refused_too() {
    let d = tempfile::tempdir().unwrap();
    registered(1).save(&d.path().join("agent.json")).unwrap();
    let mut i = input(d.path());
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    i.dial = reply(&read("testdata/spec/control/doctor-reply-kernel.json"));
    assert_eq!(diagnose(&i).unwrap_err().exit_code(), 3);
}

#[test]
fn a_control_socket_refused_by_permissions_is_exit_two() {
    let d = tempfile::tempdir().unwrap();
    registered(1).save(&d.path().join("agent.json")).unwrap();
    let mut i = input(d.path());
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    i.dial = Box::new(|_| Err(io::Error::from(io::ErrorKind::PermissionDenied)));
    let rep = diagnose(&i).unwrap();
    let c = find(&rep, CHECK_CONTROL);
    assert!(c.evidence_unreachable);
    assert_eq!(c.reason, reason::CONTROL_UNREACHABLE);
    for c in &rep.checks {
        if c.id != CHECK_CONTROL {
            assert!(!c.evidence_unreachable, "{}", c.id);
        }
    }
    assert_eq!(find(&rep, CHECK_TUNNEL_LOCAL).status, status::SKIPPED);
    assert_eq!(verdict(&rep), status::UNKNOWN);
    assert_eq!(exit(&rep).unwrap().code, 2);
}

const STREAM_UP: &str = "\"stream\":{\"connected\":true,\"disconnected_at\":\"0001-01-01T00:00:00Z\",\"retry_at\":\"0001-01-01T00:00:00Z\",\"last_ping_at\":\"0001-01-01T00:00:00Z\",\"last_pong_at\":\"0001-01-01T00:00:00Z\",\"awaiting_pong\":false}";
const NO_ALLOWLIST: &str = "\"allow_targets\":{\"set\":false,\"env\":\"WGFT_AGENT_ALLOW_TARGETS\"}";

#[test]
fn an_old_agent_and_a_busy_agent_are_told_apart() {
    let d = tempfile::tempdir().unwrap();
    registered(1).save(&d.path().join("agent.json")).unwrap();
    let mut i = input(d.path());
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    i.dial = reply("error: unknown command\n");
    let rep = diagnose(&i).unwrap();
    assert_eq!(find(&rep, CHECK_CONTROL).reason, reason::DOCTOR_UNSUPPORTED);
    assert_eq!(
        find(&rep, CHECK_STREAM_CONN).reason,
        reason::DOCTOR_UNSUPPORTED
    );

    i.dial = reply(&format!(
        "{{{NO_ALLOWLIST},{STREAM_UP},\"runtime_state_timeout\":2000000000}}\n"
    ));
    let rep = diagnose(&i).unwrap();
    assert_eq!(find(&rep, CHECK_CONTROL).status, status::OK);
    assert_eq!(find(&rep, CHECK_STREAM_CONN).status, status::OK);
    let t = find(&rep, CHECK_TUNNEL_LOCAL);
    assert_eq!(t.reason, reason::RUNTIME_BUSY);
    assert!(t.detail.contains("within 2s"), "{}", t.detail);
}

#[test]
fn a_rust_agent_reply_without_budgets_skips_the_relay_lines() {
    let d = tempfile::tempdir().unwrap();
    registered(1).save(&d.path().join("agent.json")).unwrap();
    let mut i = input(d.path());
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    // 今の Rust の agent の応答の形: トンネルはあり、予算と測った値は無い
    i.dial = reply(&format!(
        "{{{NO_ALLOWLIST},{STREAM_UP},\"process\":{{\"uid\":999,\"user\":\"wgft\",\"cap_net_admin\":false}},\"runtime_state\":{{\"generation\":1,\"tunnel\":{{\"present\":true,\"state\":\"ok\",\"endpoint\":\"203.0.113.1:51820\",\"last_handshake\":\"2027-01-15T08:00:00Z\",\"rx_bytes\":1,\"tx_bytes\":2,\"started_at\":\"2027-01-15T07:59:00Z\",\"watchdog\":{{\"rebuild_interval\":300000000000,\"retry_at\":\"0001-01-01T00:00:00Z\"}}}},\"rules\":[{{\"id\":\"r_0\",\"state\":\"ok\",\"proto\":\"tcp\",\"listeners\":1,\"listening\":1,\"bind_errors\":0,\"target_errors\":0,\"sessions\":0,\"flows\":0}}],\"refusals_since\":\"2027-01-15T07:59:00Z\",\"agent_disabled\":false}}}}\n"
    ));
    let rep = diagnose(&i).unwrap();
    assert_eq!(find(&rep, CHECK_TUNNEL_LOCAL).status, status::OK);
    assert_eq!(
        find(&rep, CHECK_SOCKET_BUFS).reason,
        reason::SOCKET_BUFFERS_NOT_REPORTED
    );
    assert_eq!(
        find(&rep, CHECK_UDP_ACCT).reason,
        reason::UDP_ACCOUNTING_NOT_REPORTED
    );
    assert_eq!(find(&rep, CHECK_LISTENERS).reason, reason::NO_RELAY);
    assert_eq!(verdict(&rep), status::OK);
}

#[test]
fn json_and_human_output_agree_on_every_check() {
    let d = tempfile::tempdir().unwrap();
    let rep = diagnose(&input(d.path())).unwrap();
    let j = json_report(&rep);
    let mut human = Vec::new();
    write_report(&mut human, &rep).unwrap();
    let human = String::from_utf8(human).unwrap();
    for c in &j.checks {
        let word = match c.status.as_str() {
            "ok" => "OK",
            "failed" => "FAILED",
            "unknown" => "UNKNOWN",
            "skipped" => "SKIPPED",
            _ => "NOT TESTED",
        };
        let line = human
            .lines()
            .find(|l| l.starts_with(&format!("  {:<18} ", c.label)))
            .unwrap_or_else(|| panic!("no line for {}", c.label));
        // 値だけの検査は UNKNOWN の語を出さない
        let value_only = rep.checks.iter().any(|x| x.id == c.id && x.value_only);
        if !(c.status == "unknown" && value_only) {
            assert!(line.contains(word), "{line} for {}", c.id);
        }
    }
    assert!(human.contains("\nNot tested by this command\n"));
    assert!(j.checked_at.ends_with('Z') && !j.checked_at.contains('.'));
}

#[test]
fn checked_at_is_utc_without_fractions() {
    assert_eq!(
        output::rfc3339(rfc("2026-09-23T21:00:00.123456789+09:00")),
        "2026-09-23T12:00:00Z"
    );
}

#[test]
fn text_from_the_agent_is_escaped_before_output() {
    let d = tempfile::tempdir().unwrap();
    registered(1).save(&d.path().join("agent.json")).unwrap();
    let mut i = input(d.path());
    i.inspect = Box::new(|_| Ok(LockState::Locked));
    i.dial = reply("{\"error\":\"boom\\u001b[2J\"}\n");
    let rep = diagnose(&i).unwrap();
    let j = json_report(&rep);
    let c = j.checks.iter().find(|c| c.id == CHECK_CONTROL).unwrap();
    assert!(c.detail.ends_with("boom\\x1b[2J"), "{}", c.detail);
    let mut human = Vec::new();
    write_report(&mut human, &rep).unwrap();
    assert!(!String::from_utf8(human).unwrap().contains('\u{1b}'));
}

/// `wgft agent doctor <args>` を解釈して実行する。標準出力と、失敗の終了コードを返す。
fn run_command(args: &[&str], env: &[(&str, &str)]) -> (String, u8) {
    let mut argv: Vec<std::ffi::OsString> = ["wgft", "agent", "doctor"]
        .map(std::ffi::OsString::from)
        .to_vec();
    argv.extend(args.iter().map(std::ffi::OsString::from));
    let Ok(crate::cli::Parsed::AgentDoctor { global, args }) = crate::cli::parse(argv) else {
        panic!("arguments do not parse as agent doctor");
    };
    let env: std::collections::HashMap<String, std::ffi::OsString> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).into()))
        .collect();
    let mut out = Vec::new();
    let code = match command::run(&global, &args, &env, &mut out) {
        Ok(()) => 0,
        Err(f) => f.code,
    };
    (String::from_utf8(out).unwrap(), code)
}

#[test]
fn the_command_refuses_bad_settings_before_writing_a_report() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().to_str().unwrap();
    let env_file = d.path().join("agent.env");
    std::fs::write(&env_file, "not a line\n").unwrap();
    let cfg = env_file.to_str().unwrap();
    let (out, code) = run_command(&["--data-dir", dir, "--config", cfg], &[]);
    assert_eq!((out.as_str(), code), ("", 3));
    let none = d.path().join("none.env");
    let none = none.to_str().unwrap();
    let (out, code) = run_command(&["--config", none], &[("WGFT_DATA_DIR", " ")]);
    assert_eq!((out.as_str(), code), ("", 3));
    let (out, code) = run_command(
        &["--data-dir", dir, "--config", none, "--max-udp-flows", "5"],
        &[],
    );
    assert_eq!((out.as_str(), code), ("", 3));
    // 報告を書いてから、総合判定の終了コードを返す
    let (out, code) = run_command(&["--data-dir", dir, "--config", none, "--json"], &[]);
    assert_eq!(code, 1);
    let j: JsonReport = serde_json::from_str(&out).unwrap();
    assert_eq!(j.status, "failed");
    assert_eq!(j.checks.len(), CHECK_ORDER.len());
}

/// Windows では新しいファイルを作れるかを判定しないので、`host.privileges` は判定できない側に倒れる。
#[cfg(windows)]
#[test]
fn windows_privileges_are_not_determined() {
    let d = tempfile::tempdir().unwrap();
    let mut i = input(d.path());
    i.euid = Box::new(|| -1);
    i.dir_create_access = Box::new(os::dir_create_access);
    let rep = diagnose(&i).unwrap();
    let c = find(&rep, CHECK_PRIVILEGES);
    assert_eq!(
        (c.status, c.reason),
        (status::UNKNOWN, reason::PERMISSION_NOT_DETERMINED)
    );
}
