//! 3 節の口の server です。標準入力で要求を受け、標準出力で応答を返します (`docs/design/v2/test-tooling.md` の 3 節)。
//!
//! 最初の要求は `HELLO` で、その後の要求は [`answer`] が adapter の呼び出しに写します。口の誤り (壊れた frame、
//! 知らない種類、最初の要求が `HELLO` でない、知らない handle、2 回目の `HELLO`) では `ERROR` を書いて終了
//! コード 2 で終わり、標準入力が frame の境目で閉じたら 0 で終わります。`dutserve` と同じ規則です。

use std::io::{BufReader, BufWriter, Read, Write};

use wgft_tcpharness::dut::{DutError, answer};
use wgft_tcpharness::frame::{self, ErrKind, FrameError, Kind, Msg, VERSION};

use crate::dut::{ENGINE, WgstackDut};

/// 口の誤りの終了コードです。
pub const EXIT_PROTOCOL: u8 = 2;

fn fail(out: &mut impl Write, log: &mut impl Write, msg: &str) -> u8 {
    let _ = writeln!(log, "wgstack-dut: {msg}");
    let _ = frame::write_msg(
        out,
        &Msg::Error {
            err: ErrKind::Other,
            msg: msg.to_owned(),
        },
    );
    let _ = out.flush();
    EXIT_PROTOCOL
}

/// 1 つの要求を読みます。流れが frame の境目で終わったら `None` です。
pub(crate) fn read_request(r: &mut impl Read) -> Result<Option<Msg>, String> {
    let (k, body) = match frame::read_frame(r) {
        Ok(f) => f,
        Err(FrameError::Eof) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    match Kind::from_byte(k) {
        Some(kind) if kind.is_request() => {}
        Some(kind) => return Err(format!("{kind} is not a request")),
        None => return Err(format!("unknown frame kind {k:#04x}")),
    }
    Msg::decode(k, &body).map(Some).map_err(|e| e.to_string())
}

/// 口を出し、終了コードを返します。
pub fn serve(input: impl Read, output: impl Write, mut log: impl Write) -> u8 {
    let mut r = BufReader::new(input);
    let mut w = BufWriter::new(output);
    let hello = match read_request(&mut r) {
        Ok(None) => return 0,
        Ok(Some(Msg::Hello(h))) => h,
        Ok(Some(m)) => {
            return fail(
                &mut w,
                &mut log,
                &format!("the first request is {}, not HELLO", m.kind()),
            );
        }
        Err(e) => return fail(&mut w, &mut log, &e),
    };
    let mut dut = match WgstackDut::new(&hello) {
        Ok(d) => d,
        Err(e) => return fail(&mut w, &mut log, &format!("HELLO: {e}")),
    };
    let ok = Msg::HelloOk {
        engine: ENGINE.to_owned(),
        version: VERSION,
    };
    if frame::write_msg(&mut w, &ok).is_err() || w.flush().is_err() {
        let _ = writeln!(log, "wgstack-dut: cannot write the HELLO answer");
        return EXIT_PROTOCOL;
    }
    loop {
        let req = match read_request(&mut r) {
            Ok(None) => return 0,
            Ok(Some(Msg::Hello(_))) => return fail(&mut w, &mut log, "a second HELLO"),
            Ok(Some(m)) => m,
            Err(e) => return fail(&mut w, &mut log, &e),
        };
        let resp = match req {
            // dutserve と同じ文で、実時間の要求を engine の誤りとして答える
            Msg::RtoAt { .. } | Msg::ConnSocket { .. } => Msg::Error {
                err: ErrKind::Other,
                msg: format!(
                    "{} needs --clock real; wgstack-dut runs only the fake clock",
                    req.kind()
                ),
            },
            _ => match answer(&mut dut, &req) {
                Ok(m) => m,
                Err(DutError::Broken(m)) => return fail(&mut w, &mut log, &m),
                Err(DutError::Engine(e)) => Msg::Error {
                    err: e.kind,
                    msg: e.msg,
                },
            },
        };
        // dutserve と同じく、応答を書けなければ口の誤りとして終わる
        if frame::write_msg(&mut w, &resp).is_err() || w.flush().is_err() {
            let _ = writeln!(
                log,
                "wgstack-dut: cannot write the answer to {}",
                req.kind()
            );
            return EXIT_PROTOCOL;
        }
    }
}
