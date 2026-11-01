//! wgft の wire の版 1 の型 (agent と server の間)。
//!
//! Go の v1 の `proto` パッケージと `internal/agent/enroll` の接続文字列の解釈を写したもので、
//! 形は Go の `encoding/json` が書き読みするものに合わせる。合わせ方と、合わせていない細部は
//! `docs/design/v2/agent-control.md` に書く。

pub mod gojson;
pub mod gotime;
pub mod join;
pub mod register;
pub mod state;
pub mod stream;
pub mod textsafe;
pub mod version;

pub use gotime::GoTime;
pub use join::{Join, JoinError};
pub use register::{REGISTER_RESPONSE_LIMIT, RegisterRequest, RegisterResponse};
pub use state::{AgentRule, PortRange, Proto, State, WgConfig};
pub use stream::{
    CLOSE_POLICY_VIOLATION, CloseCode, DecodeError, Heartbeat, Message, MessageType,
    REASON_MAX_BYTES, RECONNECT_BACKOFF_MAX, RuleStatus, STATE_HELD_FACTOR, STATUS_ERROR,
    STATUS_OK, STREAM_READ_LIMIT, TunnelStatus,
};
pub use version::{
    ProtocolRange, SUPPORTED_CAPABILITIES, SUPPORTED_PROTOCOL, select_protocol_version,
};
