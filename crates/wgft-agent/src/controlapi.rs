//! 制御ソケットの形と定数。契約は `docs/design/spec/control-socket.md` で、形は Go の
//! `internal/agent/controlapi` と同じにする。
//!
//! 稼働中の agent が応答を組み (`ctlserver`)、CLI の `agent doctor` と `agent rotate-key` が読む。
//! キーの順は Go の構造体の宣言の順で、省く規則は Go の `omitempty` に合わせる。時間の値は Go の
//! `time.Duration` と同じナノ秒の整数、時刻は [`GoTime`] である。Go の v1 の CLI はこの応答を読むので、
//! Rust の agent と Go の CLI を組ませても同じ報告になる。
//!
//! 読むときは Go の `encoding/json` と同じく知らないキーを読み飛ばす。新しい agent が足したキーで古い CLI
//! が読めなくならないためである (仕様の加算の規則)。知らないキーを拒むのは fixture の照合の試験だけである。

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wgft_proto::GoTime;

/// `doctor` の要求の 1 行 (改行を除く)。
pub const DOCTOR_COMMAND: &str = "doctor";

/// `rotate-key` の要求の 1 行 (改行を除く)。
pub const ROTATE_KEY_COMMAND: &str = "rotate-key";

/// 知らない要求への応答 (改行を除く)。新しい CLI と古い agent を組ませた場合の印でもある。
pub const UNKNOWN_COMMAND_REPLY: &str = "error: unknown command";

/// どの OS でも `sun_path` に収まるパスの長さ (byte)。
pub const CONTROL_PATH_LIMIT: usize = 103;

/// `agent doctor` が読む応答の上限 (byte)。
pub const DOCTOR_REPLY_MAX_BYTES: u64 = 4 << 20;

/// `agent rotate-key` が読む応答の上限 (byte)。
pub const ROTATE_KEY_REPLY_MAX_BYTES: u64 = 64 << 10;

/// 応答の中の 1 つの文字列の上限 (byte)。
pub const DOCTOR_TEXT_MAX_BYTES: usize = 512;

/// 実行時の排他を待つ期限。取れなければ `runtime_state` を欠いた応答を返す。
pub const DOCTOR_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// トンネルはあるがハンドシェイクがまだ済んでいないときの理由。
pub const REASON_HANDSHAKE_PENDING: &str = "handshake not established";
/// カーネルモードの agent が wg の設定を拒んだときの理由の書き出し。
pub const REASON_WG_REFUSED: &str = "refused the wg configuration";
/// トンネルが無いときの理由。
pub const REASON_NO_TUNNEL: &str = "no tunnel";
/// トンネルの作成が試し直さない失敗で終わったときの理由。
pub const REASON_NO_TUNNEL_BUILD_FAILED: &str = "no tunnel; building it failed";
/// トンネルの作成に失敗して試し直しを待っているときの理由。
pub const REASON_NO_TUNNEL_BUILD_RETRYING: &str =
    "no tunnel; building it failed and will be retried";
/// 全体状態をまだ受け取っていないことを表す句。
pub const REASON_FULL_STATE_NOT_RECEIVED: &str = "full state not received";
/// 全体状態をまだ受け取っていないためにトンネルが無いときの理由。
pub const REASON_NO_TUNNEL_FULL_STATE_PENDING: &str = "no tunnel; full state not received";

/// 認証情報ファイルに対応する制御ソケットの場所。
#[must_use]
pub fn control_path(credentials: &Path) -> PathBuf {
    let mut s = credentials.as_os_str().to_owned();
    s.push(".sock");
    PathBuf::from(s)
}

/// 応答の文字列を上限で切る。
#[must_use]
pub fn clip_text(s: &str) -> String {
    wgft_proto::textsafe::clip_text(s, DOCTOR_TEXT_MAX_BYTES)
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_false(v: &bool) -> bool {
    !*v
}

/// `doctor` の応答。`error` があれば他のキーは無い。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorResponse {
    /// 応答を組む処理の失敗。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// 宛先の許可一覧。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_targets: Option<DoctorAllowTargets>,
    /// 制御の stream の観測。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<DoctorStream>,
    /// agent のプロセスの実行主体。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<DoctorProcess>,
    /// 実行時の排他の下で 1 回に読んだ状態。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_state: Option<DoctorRuntimeState>,
    /// 実行時の排他を取れなかったときに待った長さ (ナノ秒)。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub runtime_state_timeout: i64,
}

/// 宛先の許可一覧。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorAllowTargets {
    /// 一覧を持っているか。
    #[serde(default)]
    pub set: bool,
    /// 正規化した一覧。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub list: String,
    /// 一覧を渡す設定の名前。
    #[serde(default)]
    pub env: String,
}

/// agent のプロセスの実行主体。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorProcess {
    /// 実 uid。Windows では -1。
    #[serde(default)]
    pub uid: i64,
    /// uid の利用者名。引けなければ空。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// 実効の `CAP_NET_ADMIN` を持つか。Linux の外と読めなかった場合は `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_net_admin: Option<bool>,
}

/// 制御の stream の観測。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the wire shape of Go's controlapi"
)]
pub struct DoctorStream {
    /// 今つながっているか。
    #[serde(default)]
    pub connected: bool,
    /// 直近の接続か試みが終わった時刻。
    #[serde(default)]
    pub disconnected_at: GoTime,
    /// その理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disconnect_reason: String,
    /// 直近の終わりが証明書のピンとの不一致だったか。
    #[serde(default, skip_serializing_if = "is_false")]
    pub pin_mismatch: bool,
    /// 直近の試みが server の鍵の変更の頻度の上限で拒まれたか。
    #[serde(default, skip_serializing_if = "is_false")]
    pub key_change_limited: bool,
    /// 直近に待った再接続の間隔 (ナノ秒)。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub backoff: i64,
    /// 次に試す時刻。待っていなければ零。
    #[serde(default)]
    pub retry_at: GoTime,
    /// 直近に ping を送った時刻。
    #[serde(default)]
    pub last_ping_at: GoTime,
    /// 直近に pong が返った時刻。
    #[serde(default)]
    pub last_pong_at: GoTime,
    /// pong を待っているか。
    #[serde(default)]
    pub awaiting_pong: bool,
}

/// 実行時の排他の下で 1 回に読んだ状態。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorRuntimeState {
    /// 転送の方式。ユーザー空間モードでは書かない。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    /// 最後に処理した全体状態の世代。
    #[serde(default)]
    pub generation: u64,
    /// トンネルの状態。
    #[serde(default)]
    pub tunnel: DoctorTunnel,
    /// ルールごとの状態。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DoctorRule>,
    /// プロトコルごとのフロー数の予算。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budgets: Vec<DoctorBudget>,
    /// 拒否の累計の起点。
    #[serde(default)]
    pub refusals_since: GoTime,
    /// server がこの agent を無効にしているか。
    #[serde(default)]
    pub agent_disabled: bool,
    /// カーネルモードの dataplane を読んだ結果。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<DoctorKernel>,
    /// 公開できずに試し直している全体状態の誤り。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub publish_error: String,
    /// カーネルモードの直前の見直しの誤り。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub check_error: String,
}

/// トンネルの状態。`state` と `reason` はハートビートと同じ値。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorTunnel {
    /// トンネルがあるか。
    #[serde(default)]
    pub present: bool,
    /// `ok` か `error`。
    #[serde(default)]
    pub state: String,
    /// 理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// 解決済みのエンドポイント。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// 今の device の最終ハンドシェイク。
    #[serde(default)]
    pub last_handshake: GoTime,
    /// 受けた byte 数。
    #[serde(default)]
    pub rx_bytes: i64,
    /// 送った byte 数。
    #[serde(default)]
    pub tx_bytes: i64,
    /// 今のトンネルを立てた時刻。
    #[serde(default)]
    pub started_at: GoTime,
    /// 作り直しの判定の状態。
    #[serde(default)]
    pub watchdog: DoctorWatchdog,
    /// WireGuard の UDP のソケットのバッファ。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_buffers: Option<DoctorSocketBuffers>,
    /// UDP の受信の会計。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_accounting: Option<DoctorUdpAccounting>,
}

/// UDP の受信の会計の状態。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorUdpAccounting {
    /// 不変条件の違反でトンネルの UDP を止めたか。
    #[serde(default)]
    pub stopped: bool,
    /// 検出した違反。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// WireGuard の UDP のソケットのバッファを測った結果。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorSocketBuffers {
    /// 測る手段を持つか。Linux だけが真。
    #[serde(default)]
    pub supported: bool,
    /// 測った listen port。
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub port: u16,
    /// 測れたソケットの数。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub sockets: i64,
    /// 最も小さい実効の受信バッファ (byte)。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub recv: i64,
    /// 最も小さい実効の送信バッファ (byte)。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub send: i64,
    /// 条件の値 (byte)。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub required: i64,
    /// 測れなかった理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// トンネルを作り直す判定の状態。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorWatchdog {
    /// 作り直しの間隔の実効値 (ナノ秒)。
    #[serde(default)]
    pub rebuild_interval: i64,
    /// 試し直しの予定の時刻。
    #[serde(default)]
    pub retry_at: GoTime,
}

/// ルール 1 本の状態。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorRule {
    /// ルールの ID。
    #[serde(default)]
    pub id: String,
    /// ハートビートと同じ状態。
    #[serde(default)]
    pub state: String,
    /// ハートビートと同じ理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// `tcp` か `udp`。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proto: String,
    /// リスナーの数。
    #[serde(default)]
    pub listeners: i64,
    /// 待ち受けを開けている数。
    #[serde(default)]
    pub listening: i64,
    /// 開けなかった数。
    #[serde(default)]
    pub bind_errors: i64,
    /// その 1 つの理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bind_error: String,
    /// 宛先に届かない数。
    #[serde(default)]
    pub target_errors: i64,
    /// その 1 つの理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_error: String,
    /// 中継が持つ接続の数。
    #[serde(default)]
    pub sessions: i64,
    /// フロー数の予算が数える数。
    #[serde(default)]
    pub flows: i64,
    /// カーネルモードの宣言のポートの数。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub ports: i64,
    /// そのうち DNAT を置いた数。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub dnat_ports: i64,
}

/// 1 つのプロトコルのフロー数の予算。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorBudget {
    /// `tcp` か `udp`。
    #[serde(default)]
    pub proto: String,
    /// 予算。
    #[serde(default)]
    pub total: i64,
    /// 今のフロー数。
    #[serde(default)]
    pub in_use: i64,
    /// ルール 1 本の上限。
    #[serde(default)]
    pub rule_cap: i64,
    /// ルールごとの最低分。
    #[serde(default)]
    pub reserve: i64,
    /// 受け付けているルールの数。
    #[serde(default)]
    pub rules: i64,
    /// 拒否の累計。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<DoctorRefusal>,
}

/// ルール 1 本の 1 つの理由の拒否の累計。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorRefusal {
    /// ルールの ID。
    #[serde(default)]
    pub rule_id: String,
    /// `budget`、`rule_cap`、`reserve`、`floor`、`spare` のどれか。
    #[serde(default)]
    pub reason: String,
    /// 数。
    #[serde(default)]
    pub count: u64,
}

/// カーネルモードの dataplane の 3 つの面。Rust の agent は書かず、Go の agent の応答を読むときだけ使う。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorKernel {
    /// WireGuard のインタフェース。
    #[serde(default)]
    pub interface: DoctorKernelInterface,
    /// `table inet wgft_agent`。
    #[serde(default)]
    pub table: DoctorKernelTable,
    /// ホストの転送の設定。
    #[serde(default)]
    pub forwarding: DoctorKernelForwarding,
}

/// カーネルモードの WireGuard のインタフェース。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the wire shape of Go's controlapi"
)]
pub struct DoctorKernelInterface {
    /// 名前。
    #[serde(default)]
    pub name: String,
    /// リンクを読めなかった理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub read_error: String,
    /// あるか。
    #[serde(default)]
    pub exists: bool,
    /// リンクの種類。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// up か。
    #[serde(default)]
    pub up: bool,
    /// 鍵とピアを `CAP_NET_ADMIN` なしに読めなかったか。
    #[serde(default, skip_serializing_if = "is_false")]
    pub needs_net_admin: bool,
    /// 鍵とピアを権限以外の理由で読めなかった理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_error: String,
    /// 持ち主の判定。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ownership: String,
    /// MTU。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub mtu: i64,
    /// アドレス。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// ピア。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<DoctorKernelPeer>,
    /// 比べる宣言があったか。
    #[serde(default)]
    pub declared: bool,
    /// server のトンネルアドレス。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_address: String,
    /// server のピアがあるか。
    #[serde(default)]
    pub peer_ok: bool,
    /// 宣言と違う点。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub differs: Vec<String>,
    /// server のトンネルアドレスへの経路のインタフェース。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub route_interface: String,
    /// 経路を読めなかった理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub route_error: String,
}

/// カーネルモードのインタフェースのピア 1 つ。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorKernelPeer {
    /// 公開鍵。
    #[serde(default)]
    pub public_key: String,
    /// AllowedIPs。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    /// エンドポイント。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// keepalive (ナノ秒)。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub keepalive: i64,
    /// 最終ハンドシェイク。
    #[serde(default)]
    pub last_handshake: GoTime,
    /// 受けた byte 数。
    #[serde(default)]
    pub rx_bytes: i64,
    /// 送った byte 数。
    #[serde(default)]
    pub tx_bytes: i64,
}

/// `table inet wgft_agent` と、直近の公開の記録との比較。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorKernelTable {
    /// 読めなかった理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub read_error: String,
    /// それが `CAP_NET_ADMIN` の不足によるか。
    #[serde(default, skip_serializing_if = "is_false")]
    pub needs_net_admin: bool,
    /// あるか。
    #[serde(default)]
    pub present: bool,
    /// 比べた材料。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// 記録の元にした世代。
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub generation: u64,
    /// 欠けると転送が止まるもの。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    /// その全体の数。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub missing_count: i64,
    /// 欠けた守りの行。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_missing: Vec<String>,
    /// その全体の数。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub guard_missing_count: i64,
    /// 開きうる面。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_effects: Vec<String>,
    /// まだ閉じている面。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_closed: Vec<String>,
    /// 別の位置にある行。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub moved: Vec<String>,
    /// その全体の数。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub moved_count: i64,
    /// 記録に無いのにある行。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unexpected: Vec<String>,
    /// その全体の数。
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub unexpected_count: i64,
    /// 記録か宣言から読んだルールごとの状態。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DoctorRule>,
}

/// ホストの転送の設定。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorKernelForwarding {
    /// `net.ipv4.ip_forward` の値。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip_forward: String,
    /// 読めなかった理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip_forward_error: String,
    /// `rp_filter` が 1 の設定の名前。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rp_filter_strict: Vec<String>,
    /// 既定で落とす他のテーブルの forward のチェーン。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_drops: Vec<String>,
    /// 他のテーブルを読めなかった理由。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_error: String,
    /// それが `CAP_NET_ADMIN` の不足によるか。
    #[serde(default, skip_serializing_if = "is_false")]
    pub policy_needs_net_admin: bool,
}

impl DoctorResponse {
    /// 改行で終わる 1 行にする。Go の `json.Marshal` と同じ byte 列である。書けなければ理由だけの行を返す。
    #[must_use]
    pub fn to_line(&self) -> Vec<u8> {
        match wgft_proto::gojson::to_vec_compact(self) {
            Ok(mut b) => {
                b.push(b'\n');
                b
            }
            Err(e) => error_line(&format!(
                "the agent state could not be encoded as JSON: {e}"
            )),
        }
    }
}

/// 理由だけを載せた応答の 1 行。
#[must_use]
pub fn error_line(msg: &str) -> Vec<u8> {
    let r = DoctorResponse {
        error: clip_text(msg),
        ..DoctorResponse::default()
    };
    match wgft_proto::gojson::to_vec_compact(&r) {
        Ok(mut b) => {
            b.push(b'\n');
            b
        }
        // 固定の形なので届かないが、ここでも 1 行の JSON を返す
        Err(_) => b"{\"error\":\"the agent could not describe its own failure\"}\n".to_vec(),
    }
}

/// 応答の 1 行を `max` byte まで読む。改行を含めて返す。上限に届いても改行が来なければ、上限を名指す
/// 誤りにする。改行の前に閉じられれば `UnexpectedEof` の誤りである。
///
/// # Errors
///
/// 読みの誤り、上限、改行の前の終わりを返す。
pub fn read_control_reply(r: impl Read, max: u64) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut limited = r.take(max);
    let mut byte = [0u8; 4096];
    loop {
        let n = limited.read(&mut byte)?;
        if n == 0 {
            if buf.len() as u64 >= max {
                return Err(io::Error::other(format!(
                    "the agent's reply exceeded the {max}-byte limit without a newline"
                )));
            }
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if let Some(i) = byte[..n].iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&byte[..=i]);
            break;
        }
        buf.extend_from_slice(&byte[..n]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str) -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/spec/control")
            .join(name);
        std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
            .replace("\r\n", "\n")
    }

    /// 仕様の fixture を読んで同じ 1 行に書き戻す。型が知らないキーは書き戻しで落ちるので、値として
    /// 比べることで、fixture のすべてのキーを型が持つことも確かめる。
    #[test]
    fn spec_doctor_replies_round_trip_byte_for_byte() {
        for name in ["doctor-reply.json", "doctor-reply-kernel.json"] {
            let want = spec(name);
            let r: DoctorResponse =
                serde_json::from_str(&want).unwrap_or_else(|e| panic!("{name}: {e}"));
            let got = String::from_utf8(r.to_line()).unwrap();
            let as_value = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
            assert_eq!(as_value(&got), as_value(&want), "{name}: keys");
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn spec_constants() {
        assert_eq!(
            control_path(Path::new("/d/agent.json")),
            Path::new("/d/agent.json.sock")
        );
        assert_eq!(CONTROL_PATH_LIMIT, 103);
        assert_eq!(DOCTOR_REPLY_MAX_BYTES, 4 << 20);
        assert_eq!(DOCTOR_TEXT_MAX_BYTES, 512);
        assert_eq!(DOCTOR_COMMAND, "doctor");
    }

    /// Go の v1 の CLI と同じく、知らないキーは読み飛ばす。
    #[test]
    fn unknown_keys_are_ignored() {
        let r: DoctorResponse = serde_json::from_str(
            r#"{"surprise":1,"stream":{"connected":true,"later":"x"},"runtime_state_timeout":5}"#,
        )
        .unwrap();
        assert!(r.stream.is_some_and(|s| s.connected));
        assert_eq!(r.runtime_state_timeout, 5);
    }

    #[test]
    fn the_error_line_carries_nothing_else_and_is_clipped() {
        let l = String::from_utf8(error_line(&"x".repeat(600))).unwrap();
        assert!(
            l.starts_with(r#"{"error":"xxx"#) && l.ends_with("... truncated\"}\n"),
            "{l}"
        );
        assert_eq!(
            String::from_utf8(DoctorResponse::default().to_line()).unwrap(),
            "{}\n"
        );
    }

    #[test]
    fn a_reply_without_a_newline_names_the_limit() {
        let e = read_control_reply(&b"0123456789"[..], 10).unwrap_err();
        assert!(e.to_string().contains("10-byte limit"), "{e}");
        let e = read_control_reply(&b"short"[..], 10).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            read_control_reply(&b"ok key\nmore"[..], 64).unwrap(),
            "ok key\n"
        );
    }
}
