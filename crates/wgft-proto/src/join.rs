//! 接続文字列 `wgft://host:port/token#sha256:<hex 64 桁>` (Go の `internal/agent/enroll` の `ParseJoin`)。
//!
//! 誤りは固定の 7 つの値のどれかで、入力のどの部分も引用しない。トークンは秘密であり、形の崩れた入力では
//! トークンがどの断片に入り込むか判別できないためである。解釈は Go の `url.Parse` と
//! `net.SplitHostPort` の振る舞いのうち、接続文字列に関わる部分を写す。

use std::fmt;

/// 接続文字列の誤り。どれも入力を引用しない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// scheme が `wgft` でないか、URL として読めない。
    Scheme,
    /// host にポートが無い。
    NoPort,
    /// host が空。
    NoHost,
    /// ポートが 1 から 65535 の数でない。
    PortRange,
    /// トークンが無いか、`/` を含む。
    NoToken,
    /// `#sha256:` のピンが無い。
    NoPin,
    /// ピンが 64 桁の hex でない。
    BadPin,
}

impl fmt::Display for JoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JoinError::Scheme => "join string must look like wgft://host:port/token#sha256:HASH",
            JoinError::NoPort => "join string host has no port",
            JoinError::NoHost => "join string has no host",
            JoinError::PortRange => "join string port must be a number from 1 to 65535",
            JoinError::NoToken => "join string has no token",
            JoinError::NoPin => "join string has no #sha256 certificate hash",
            JoinError::BadPin => "join string certificate hash is invalid",
        })
    }
}

impl std::error::Error for JoinError {}

/// 接続文字列の中身。
#[derive(Clone, PartialEq, Eq)]
pub struct Join {
    /// エージェント用 API の `host:port`。IPv6 のアドレスは角括弧を含む。
    pub endpoint: String,
    /// `endpoint` の host の部分。角括弧を除く。
    pub host: String,
    /// `endpoint` のポート。
    pub port: u16,
    /// 1 回限りの登録トークン。秘密。捨てるときに 0 で消す。
    pub token: zeroize::Zeroizing<String>,
    /// エージェント用 API の leaf の証明書の DER の SHA-256。
    pub pin: [u8; 32],
}

// トークンを Debug の出力に出さない
impl fmt::Debug for Join {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Join")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("pin", &hex(&self.pin))
            .finish()
    }
}

impl Join {
    /// 接続文字列を解釈する。scheme、host、ポート、sha256 のピンをすべて要求する。
    ///
    /// # Errors
    ///
    /// 形が崩れていれば [`JoinError`] のどれかを返す。
    pub fn parse(s: &str) -> Result<Join, JoinError> {
        let u = parse_url(trim_go_space(s)).ok_or(JoinError::Scheme)?;
        if u.scheme != b"wgft" {
            return Err(JoinError::Scheme);
        }
        let (host, port) = split_host_port(&u.host).ok_or(JoinError::NoPort)?;
        if host.is_empty() {
            return Err(JoinError::NoHost);
        }
        let port = parse_port(port).ok_or(JoinError::PortRange)?;
        let tok = u.path.strip_prefix(b"/").unwrap_or(&u.path);
        if tok.is_empty() || tok.contains(&b'/') {
            return Err(JoinError::NoToken);
        }
        let Some(colon) = u.fragment.iter().position(|&c| c == b':') else {
            return Err(JoinError::NoPin);
        };
        if &u.fragment[..colon] != b"sha256" {
            return Err(JoinError::NoPin);
        }
        let pin = decode_hex32_bytes(&u.fragment[colon + 1..]).ok_or(JoinError::BadPin)?;
        // Go の文字列は不正な UTF-8 を持てるので、%XX が作る不正な UTF-8 の host とトークンも受ける。
        // Rust の String は持てないので拒む。Go が受け Rust が拒む、意図した差である
        let utf8 = |b: &[u8]| {
            str::from_utf8(b)
                .map(str::to_owned)
                .map_err(|_| JoinError::Scheme)
        };
        Ok(Join {
            endpoint: utf8(&u.host)?,
            host: utf8(host)?,
            port,
            token: zeroize::Zeroizing::new(utf8(tok)?),
            pin,
        })
    }

    /// ピンの hex (小文字)。
    #[must_use]
    pub fn pin_hex(&self) -> String {
        hex(&self.pin)
    }
}

/// バイト列を小文字の hex にする。
#[must_use]
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// 64 桁の hex を 32 byte にする。Go の `hex.DecodeString` と同じく大文字も受け付ける。
#[must_use]
pub fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    decode_hex32_bytes(s.as_bytes())
}

fn decode_hex32_bytes(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Go の `strings.TrimSpace` と同じく、両端の Unicode の空白を除く。
fn trim_go_space(s: &str) -> &str {
    s.trim_matches(char::is_whitespace)
}

/// Go の `strconv.ParseUint(port, 10, 32)` と範囲の検査。
fn parse_port(p: &[u8]) -> Option<u16> {
    if p.is_empty() || !p.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n: u64 = str::from_utf8(p).ok()?.parse().ok()?;
    if n > u64::from(u32::MAX) || !(1..=65535).contains(&n) {
        return None;
    }
    u16::try_from(n).ok()
}

struct Url {
    scheme: Vec<u8>,
    host: Vec<u8>,
    path: Vec<u8>,
    fragment: Vec<u8>,
}

/// path はトークンを持つので、捨てるときに 0 で消す。
impl Drop for Url {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.path);
    }
}

/// Go の `url.Parse`。`ParseJoin` が見る scheme、host、path、fragment を、Go の文字列と同じく
/// UTF-8 とは限らないバイト列で返す。Go が誤りにする入力は `None` にする。
fn parse_url(raw: &str) -> Option<Url> {
    let (rest, frag) = match raw.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (raw, None),
    };
    let mut u = parse(rest)?;
    if let Some(f) = frag
        && !f.is_empty()
    {
        u.fragment = unescape(f, Mode::Other)?;
    }
    Some(u)
}

/// Go の `parse(rawURL, false)`。
fn parse(raw: &str) -> Option<Url> {
    if raw.bytes().any(|c| c < 0x20 || c == 0x7f) {
        return None;
    }
    let mut u = Url {
        scheme: Vec::new(),
        host: Vec::new(),
        path: Vec::new(),
        fragment: Vec::new(),
    };
    if raw == "*" {
        u.path = b"*".to_vec();
        return Some(u);
    }
    let (scheme, rest) = get_scheme(raw)?;
    u.scheme = scheme.to_ascii_lowercase().into_bytes();
    let rest = if rest.ends_with('?') && rest.matches('?').count() == 1 {
        &rest[..rest.len() - 1]
    } else {
        rest.split_once('?').map_or(rest, |(r, _)| r)
    };
    if !rest.starts_with('/') {
        if !u.scheme.is_empty() {
            // rootless の path は opaque で、host も path も持たない
            return Some(u);
        }
        let segment = rest.split_once('/').map_or(rest, |(s, _)| s);
        if segment.contains(':') {
            return None;
        }
    }
    let mut path = rest;
    if (!u.scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let auth_and_path = &rest[2..];
        let (authority, p) = match auth_and_path.find('/') {
            Some(i) => auth_and_path.split_at(i),
            None => (auth_and_path, ""),
        };
        u.host = parse_authority(&u.scheme, authority)?;
        path = p;
    }
    u.path = unescape(path, Mode::Other)?;
    Some(u)
}

/// Go の `getScheme`。scheme が無ければ空の scheme と入力の全体を返す。
fn get_scheme(raw: &str) -> Option<(&str, &str)> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Some(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return None; // missing protocol scheme
                }
                return Some((&raw[..i], &raw[i + 1..]));
            }
            _ => return Some(("", raw)),
        }
    }
    Some(("", raw))
}

/// Go の `parseAuthority`。host を返す。userinfo は確かめてから捨てる。
fn parse_authority(scheme: &[u8], authority: &str) -> Option<Vec<u8>> {
    let Some(i) = authority.rfind('@') else {
        return parse_host(scheme, authority);
    };
    let host = parse_host(scheme, &authority[i + 1..])?;
    let userinfo = &authority[..i];
    if !valid_userinfo(userinfo) {
        return None;
    }
    let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    unescape(user, Mode::Other)?;
    unescape(pass, Mode::Other)?;
    Some(host)
}

/// Go の `validUserinfo`。
fn valid_userinfo(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '.'
                    | '_'
                    | ':'
                    | '~'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | '%'
                    | '@'
            )
    })
}

/// Go の `parseHost`。
fn parse_host(scheme: &[u8], host: &str) -> Option<Vec<u8>> {
    match host.rfind('[') {
        Some(i) if i > 0 => None, // invalid IP-literal
        Some(_) => {
            let close = host.rfind(']')?;
            let colon_port = &host[close + 1..];
            if !valid_optional_port(colon_port) {
                return None;
            }
            let colon_port = unescape(colon_port, Mode::Host)?;
            let hostname = &host[1..close];
            let unescaped = match hostname.find("%25") {
                Some(z) => {
                    let mut h = unescape(&hostname[..z], Mode::Host)?;
                    h.extend(unescape(&hostname[z..], Mode::Zone)?);
                    h
                }
                None => unescape(hostname, Mode::Host)?,
            };
            // 角括弧に入れてよいのは IPv6 のアドレスだけ (IPv4 に写した IPv6 は入れてよい)
            if !is_ipv6_literal(&unescaped) {
                return None;
            }
            let mut out = Vec::with_capacity(unescaped.len() + colon_port.len() + 2);
            out.push(b'[');
            out.extend(unescaped);
            out.push(b']');
            out.extend(colon_port);
            Some(out)
        }
        None => {
            if let Some(first) = host.find(':') {
                let last = host.rfind(':').unwrap_or(first);
                // Go は http と https でだけ host の中の複数のコロンを拒む。wgft は該当しない
                let i = if last != first && (scheme == b"http" || scheme == b"https") {
                    first
                } else {
                    last
                };
                if !valid_optional_port(&host[i..]) {
                    return None;
                }
            }
            unescape(host, Mode::Host)
        }
    }
}

/// Go の `netip.ParseAddr` が受け、`Is4` でない値。zone は空でないバイト列で、IPv6 にだけ付く。
fn is_ipv6_literal(s: &[u8]) -> bool {
    let (addr, zone) = match s.iter().position(|&c| c == b'%') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    if zone.is_some_and(<[u8]>::is_empty) || !addr.contains(&b':') {
        return false;
    }
    str::from_utf8(addr).is_ok_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok())
}

/// Go の `validOptionalPort`。
fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    let Some(digits) = port.strip_prefix(':') else {
        return false;
    };
    digits.bytes().all(|c| c.is_ascii_digit())
}

/// Go の `net.SplitHostPort`。
pub(crate) fn split_host_port(hostport: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = hostport.iter().rposition(|&c| c == b':')?;
    let (host, j, k) = if hostport.first() == Some(&b'[') {
        let end = hostport.iter().position(|&c| c == b']')?;
        if end + 1 != i {
            return None; // ']' の直後が最後のコロンでない
        }
        (&hostport[1..end], 1, end + 1)
    } else {
        let h = &hostport[..i];
        if h.contains(&b':') {
            return None;
        }
        (h, 0, 0)
    };
    if hostport[j..].contains(&b'[') || hostport[k..].contains(&b']') {
        return None;
    }
    Some((host, &hostport[i + 1..]))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Host,
    Zone,
    /// path、fragment、userinfo。`%XX` の形だけを確かめる。
    Other,
}

/// Go の `unescape`。
fn unescape(s: &str, mode: Mode) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    // 入力はトークンと userinfo を含みうるので、途中で断ったときも書いた分を 0 で消す。容量を先に取るので
    // 伸ばして前の領域を残すことはない
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = hex_val(*b.get(i + 1)?)?;
            let lo = hex_val(*b.get(i + 2)?)?;
            let v = (hi << 4) | lo;
            let is25 = hi == 2 && lo == 5;
            // host の %XX は非 ASCII のバイトと %25 だけ
            if mode == Mode::Host && hi < 8 && !is25 {
                return None;
            }
            // zone の %XX は、そのまま書ける host のバイトと空白と %25 だけ
            if mode == Mode::Zone && !is25 && v != b' ' && host_must_escape(v) {
                return None;
            }
            out.push(v);
            i += 3;
        } else {
            if matches!(mode, Mode::Host | Mode::Zone) && b[i] < 0x80 && host_must_escape(b[i]) {
                return None;
            }
            out.push(b[i]);
            i += 1;
        }
    }
    Some(std::mem::take(&mut *out))
}

/// Go の `shouldEscape(c, encodeHost)` (encodeZone も同じ)。0x80 以上は常に真。
fn host_must_escape(c: u8) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    !matches!(
        c,
        b'-' | b'_'
            | b'.'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'"'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn ok(s: &str) -> Join {
        Join::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn parses_the_form_the_server_issues() {
        let j = ok(&format!("wgft://203.0.113.1:8443/tok_ABC-def#sha256:{PIN}"));
        assert_eq!(j.endpoint, "203.0.113.1:8443");
        assert_eq!(j.host, "203.0.113.1");
        assert_eq!(j.port, 8443);
        assert_eq!(*j.token, "tok_ABC-def");
        assert_eq!(j.pin_hex(), PIN);
    }

    #[test]
    fn trims_space_and_accepts_upper_case_scheme_and_hex() {
        let j = ok(&format!(
            "  WGFT://vps.example:8443/t#sha256:{}\n",
            PIN.to_uppercase()
        ));
        assert_eq!(j.endpoint, "vps.example:8443");
        assert_eq!(j.pin_hex(), PIN);
    }

    #[test]
    fn ipv6_host_keeps_brackets_in_endpoint() {
        let j = ok(&format!("wgft://[2001:db8::1]:8443/t#sha256:{PIN}"));
        assert_eq!(j.endpoint, "[2001:db8::1]:8443");
        assert_eq!(j.host, "2001:db8::1");
    }

    #[test]
    fn rejects_with_fixed_errors() {
        let cases = [
            ("http://h:1/t#sha256:".to_owned() + PIN, JoinError::Scheme),
            ("wgft://h/t#sha256:".to_owned() + PIN, JoinError::NoPort),
            ("wgft://:8443/t#sha256:".to_owned() + PIN, JoinError::NoHost),
            (
                "wgft://h:0/t#sha256:".to_owned() + PIN,
                JoinError::PortRange,
            ),
            (
                "wgft://h:65536/t#sha256:".to_owned() + PIN,
                JoinError::PortRange,
            ),
            ("wgft://h:1/#sha256:".to_owned() + PIN, JoinError::NoToken),
            (
                "wgft://h:1/a/b#sha256:".to_owned() + PIN,
                JoinError::NoToken,
            ),
            ("wgft://h:1/t".to_owned(), JoinError::NoPin),
            ("wgft://h:1/t#md5:".to_owned() + PIN, JoinError::NoPin),
            ("wgft://h:1/t#sha256:abcd".to_owned(), JoinError::BadPin),
            (
                "wgft://h:1/t%zz#sha256:".to_owned() + PIN,
                JoinError::Scheme,
            ),
            ("wgft://h h:1/t#sha256:".to_owned() + PIN, JoinError::Scheme),
            ("wgft://<token>".to_owned(), JoinError::NoPort),
        ];
        for (s, want) in cases {
            assert_eq!(Join::parse(&s), Err(want), "{s}");
        }
    }

    #[test]
    fn errors_never_quote_the_input() {
        for s in [
            "wgft://secret-token",
            "wgft://h:1/secret-token#sha256:zz",
            "secret-token",
        ] {
            let msg = Join::parse(s).unwrap_err().to_string();
            assert!(!msg.contains("secret"), "{msg}");
        }
    }

    #[test]
    fn debug_hides_the_token() {
        let j = ok(&format!("wgft://h:1/hidden#sha256:{PIN}"));
        assert!(!format!("{j:?}").contains("hidden"));
    }
}
