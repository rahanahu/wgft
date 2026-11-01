//! 作成の時の設定と表の大きさ。

use core::fmt;
use core::net::Ipv4Addr;

/// 受け付ける MTU の下限です。
pub const MIN_MTU: usize = 576;
/// 受け付ける MTU の上限です。server が送る範囲に合わせた値です。
pub const MAX_MTU: usize = 9216;

/// 表の大きさです。本番は [`Limits::with_max_flows`] の値で、試験だけが小さな値を渡します。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// 同時に確立できる接続の数 K です (`WGFT_MAX_TCP_FLOWS`)。
    pub max_flows: usize,
    /// accept の待ち行列の全体の数 Q です。接続の枠の数は K + Q です。
    pub accept_queue: usize,
    /// 握手の途中の表の行の数 N_syn です。
    pub syn_rows: usize,
    /// TIME_WAIT と FIN_WAIT_2 の行の数 M です。
    pub tw_rows: usize,
    /// 制御の出力の輪の枠の数 Q_ctl です。
    pub ctl_slots: usize,
    /// 再組み立ての表の項目の数です。
    pub frag_entries: usize,
    /// 再組み立ての表の断片の枠の数です。
    pub frag_pieces: usize,
}

impl Limits {
    /// K の既定値です (`WGFT_MAX_TCP_FLOWS` の既定値と同じ)。
    pub const DEFAULT_MAX_FLOWS: usize = 2048;

    /// K を `max_flows` にした本番の表の大きさです。0 は既定値です。
    pub const fn with_max_flows(max_flows: usize) -> Self {
        Self {
            max_flows: if max_flows == 0 {
                Self::DEFAULT_MAX_FLOWS
            } else {
                max_flows
            },
            accept_queue: 512,
            syn_rows: 1024,
            tw_rows: 65536,
            ctl_slots: 256,
            frag_entries: crate::frag::LIMITS.entries,
            frag_pieces: crate::frag::LIMITS.fragments,
        }
    }

    /// 接続の枠の数 N_c = K + Q です。
    pub const fn conns(&self) -> usize {
        self.max_flows + self.accept_queue
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::with_max_flows(0)
    }
}

/// 作成の時の設定です。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// 受け付ける宛先です。agent ではトンネルのアドレスの /32 の 1 つだけです。
    pub addr: Ipv4Addr,
    /// トンネルの MTU です。[`MIN_MTU`] から [`MAX_MTU`] を受け付けます。
    pub mtu: usize,
    /// 表の大きさです。
    pub limits: Limits,
}

impl Config {
    /// 既定の表の大きさの設定です。
    pub const fn new(addr: Ipv4Addr, mtu: usize) -> Self {
        Self {
            addr,
            mtu,
            limits: Limits::with_max_flows(0),
        }
    }
}

/// 設定の誤りです。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// MTU が範囲の外です。
    Mtu(usize),
    /// 表の大きさが範囲の外です。
    Limits,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mtu(m) => write!(f, "MTU {m} is out of range {MIN_MTU} to {MAX_MTU}"),
            Self::Limits => f.write_str("the table sizes are out of range"),
        }
    }
}

impl Config {
    /// 設定を確かめます。
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err(ConfigError::Mtu(self.mtu));
        }
        let l = &self.limits;
        let fits = |n: usize| u32::try_from(n).is_ok_and(|n| n < u32::MAX / 8);
        if l.max_flows == 0
            || l.tw_rows == 0
            || l.ctl_slots == 0
            || !fits(l.conns())
            || !fits(l.syn_rows + l.tw_rows)
            || l.ctl_slots > 1 << 16
            || l.max_flows.checked_add(l.accept_queue).is_none()
            || (crate::frag::Limits {
                entries: l.frag_entries,
                fragments: l.frag_pieces,
                ..crate::frag::LIMITS
            })
            .base_cost()
            .is_err()
        {
            return Err(ConfigError::Limits);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_mtu_and_limits() {
        let c = Config::new(Ipv4Addr::new(10, 9, 0, 1), 1420);
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.limits.conns(), 2560);
        assert_eq!(
            Limits::default(),
            Limits::with_max_flows(Limits::DEFAULT_MAX_FLOWS)
        );
        for mtu in [575, 9217] {
            assert_eq!(Config { mtu, ..c }.validate(), Err(ConfigError::Mtu(mtu)));
        }
        assert_eq!(Config { mtu: 576, ..c }.validate(), Ok(()));
        assert_eq!(Config { mtu: 9216, ..c }.validate(), Ok(()));
        let bad = Config {
            limits: Limits {
                tw_rows: 0,
                ..c.limits
            },
            ..c
        };
        assert_eq!(bad.validate(), Err(ConfigError::Limits));
        let zero_syn = Config {
            limits: Limits {
                syn_rows: 0,
                accept_queue: 0,
                ..c.limits
            },
            ..c
        };
        assert_eq!(
            zero_syn.validate(),
            Ok(()),
            "the dial side has no half-open rows and no accept queue"
        );
    }
}
