//! 登録 API の呼び出しと、証明書のピンで server を確かめる TLS の接続。
//!
//! Go の agent と同じく、証明書の通常の検証 (CA、ホスト名、期限) は行わず、leaf の証明書の DER の
//! SHA-256 がピンと一致するときだけ通す。ハンドシェイクの署名は検証するので、相手が証明書の秘密鍵を
//! 持つことは確かめる。TLS は 1.2 以上、ALPN は送らず HTTP/1.1 で話す。

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use wgft_proto::join::hex;
use wgft_proto::{Join, REGISTER_RESPONSE_LIMIT, RegisterRequest, RegisterResponse};

use crate::error::{AgentError, Refusal};

/// 登録の要求の全体の期限。Go の agent の pinned client の `Timeout` と同じ。
const REGISTER_DEADLINE: Duration = Duration::from_secs(15);

/// 証明書がピンと一致しないことを示す文言の始まり。
pub const PIN_MISMATCH: &str = "server certificate does not match the pinned hash";

/// SHA-256。
#[must_use]
pub fn sha256(b: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, b);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// トークンの SHA-256 の hex。Go の `Join.TokenHash` と同じ値で、使用済みの記録に使う。
#[must_use]
pub fn token_hash(j: &Join) -> String {
    hex(&sha256(j.token.as_bytes()))
}

#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = sha256(end_entity.as_ref());
        if got == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "{PIN_MISMATCH}: got sha256 {}",
                hex(&got[..4])
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// ピンで確かめる TLS の接続を張る。`endpoint` は `host:port`。
///
/// # Errors
///
/// 接続できないか、ハンドシェイクに失敗するか、証明書がピンと一致しなければ誤りを返す。
/// ピンの不一致の文言は [`PIN_MISMATCH`] で始まる。
pub async fn connect_pinned(
    endpoint: &str,
    pin: [u8; 32],
    timeout: Duration,
) -> Result<TlsStream<TcpStream>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let config =
        rustls::ClientConfig::builder_with_provider(Arc::clone(&provider) as Arc<CryptoProvider>)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, algs }))
            .with_no_client_auth();
    let host = host_of(endpoint);
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| format!("{host} is not a valid server name"))?;
    let fut = async {
        let tcp = TcpStream::connect(endpoint)
            .await
            .map_err(|e| format!("dial tcp {endpoint}: {e}"))?;
        TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|e| {
                let s = e.to_string();
                if s.contains(PIN_MISMATCH) {
                    // rustls の誤りの前置きを外し、Go の agent と同じ文言から始める
                    s[s.find(PIN_MISMATCH).unwrap_or(0)..].to_owned()
                } else {
                    format!("tls handshake with {endpoint}: {s}")
                }
            })
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| format!("connecting to {endpoint} timed out"))?
}

/// `host:port` の host。IPv6 の角括弧を外す。
#[must_use]
pub fn host_of(endpoint: &str) -> &str {
    let h = endpoint.rsplit_once(':').map_or(endpoint, |(h, _)| h);
    h.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(h)
}

/// 登録 API を呼ぶ。401、400、409 は再試行で直らないので起動の拒否にする。
///
/// # Errors
///
/// 登録できなければ誤りを返す。
pub async fn register(j: &Join, name: &str) -> Result<RegisterResponse, AgentError> {
    // 本文は登録トークンを含むので、送った後に 0 で消す。容量を先に取り、書く途中で伸ばして前の領域を
    // 消さずに手放さないようにする
    let mut body =
        zeroize::Zeroizing::new(Vec::with_capacity(64 + 6 * (name.len() + j.token.len())));
    serde_json::to_writer(
        &mut *body,
        &RegisterRequest {
            name: name.to_owned(),
            token: j.token.clone(),
        },
    )
    .map_err(|e| AgentError::Other(e.to_string()))?;
    // Go の agent の pinned client の 15 秒の期限が、接続から本文の読みまでの全体にかかる。
    // 接続を回すタスクは、期限で打ち切った後も残らないよう最後に止める
    let mut conn_task = None;
    let fut = async {
        let tls = connect_pinned(&j.endpoint, j.pin, REGISTER_DEADLINE)
            .await
            .map_err(|e| AgentError::Other(format!("cannot reach the registration API: {e}")))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| AgentError::Other(format!("cannot reach the registration API: {e}")))?;
        conn_task = Some(tokio::spawn(conn));
        let req = hyper::Request::post("/api/v1/agents/register")
            .header(hyper::header::HOST, j.endpoint.as_str())
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_owner(body)))
            .map_err(|e| AgentError::Other(e.to_string()))?;
        let resp = send
            .send_request(req)
            .await
            .map_err(|e| AgentError::Other(format!("cannot reach the registration API: {e}")))?;
        let status = resp.status().as_u16();
        // 4096 byte まで読む。超える応答は Go の agent と同じく先頭だけを見る
        let data = read_prefix(resp.into_body(), REGISTER_RESPONSE_LIMIT).await;
        Ok::<_, AgentError>((status, data))
    };
    let done = tokio::time::timeout(REGISTER_DEADLINE, fut).await;
    if let Some(t) = conn_task {
        t.abort();
    }
    let (status, data) = done
        .map_err(|_| AgentError::Other("cannot reach the registration API: timed out".into()))??;
    // 応答の本文は恒久トークンを含みうるので、誤りの文に使うときだけ写す
    let text = || String::from_utf8_lossy(&data).trim().to_owned();
    match status {
        401 => Err(Refusal::conflict(
            "WGFT_JOIN",
            "registration rejected: join string already used or expired, or the name differs. Issue a new join string on the VPS with wgft agent join-string, and replace WGFT_JOIN",
        )
        .into()),
        400 => Err(Refusal::config(
            "WGFT_NAME",
            format!(
                "the registration API rejected the request: HTTP 400, {}; an agent name may hold only lowercase letters, digits and hyphens, at most 32 of them, and may not begin or end with a hyphen",
                text()
            ),
        )
        .into()),
        409 => Err(Refusal::conflict(
            "WGFT_JOIN",
            format!(
                "an agent is already registered under the name this join string carries: HTTP 409, {}. If that agent is running, on this host with another data directory or on another host, point WGFT_DATA_DIR at its directory instead; revoking it on the VPS cuts it off. Otherwise revoke it with wgft agent revoke <name>, or issue a join string for another name",
                text()
            ),
        )
        .into()),
        200 => {
            let out: RegisterResponse = serde_json::from_slice(&data)
                .map_err(|_| AgentError::Other("registration API returned an invalid response".into()))?;
            if out.permanent_token.is_empty() || out.name.is_empty() {
                return Err(AgentError::Other("registration API returned an invalid response".into()));
            }
            Ok(out)
        }
        s => Err(AgentError::Other(format!("registration API: HTTP {s}: {}", text()))),
    }
}

/// 本文の先頭 `limit` byte。恒久トークンを含みうるので捨てるときに 0 で消し、容量を先に取って伸ばさない。
async fn read_prefix(body: hyper::body::Incoming, limit: usize) -> zeroize::Zeroizing<Vec<u8>> {
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(limit));
    let mut body = body;
    while out.len() < limit {
        match body.frame().await {
            Some(Ok(f)) => {
                if let Ok(d) = f.into_data() {
                    let take = d.len().min(limit - out.len());
                    out.extend_from_slice(&d[..take]);
                }
            }
            _ => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_port_and_brackets() {
        assert_eq!(host_of("203.0.113.1:8443"), "203.0.113.1");
        assert_eq!(host_of("[2001:db8::1]:8443"), "2001:db8::1");
        assert_eq!(host_of("vps.example:8443"), "vps.example");
    }

    #[test]
    fn token_hash_matches_go() {
        // Go: sha256.Sum256([]byte("t")) の hex
        let j = Join::parse(
            "wgft://h:1/t#sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .unwrap();
        assert_eq!(
            token_hash(&j),
            "e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"
        );
    }
}
