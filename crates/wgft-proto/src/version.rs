//! wire の版と capability の交渉 (Go の `proto/version.go`)。

/// 対応する版の範囲 (両端を含む)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolRange {
    /// 下端。
    pub min: i64,
    /// 上端。
    pub max: i64,
}

impl ProtocolRange {
    /// 番号の付いた版の範囲として意味を持つか。版は 1 から始まる。
    #[must_use]
    pub fn valid(&self) -> bool {
        self.min >= 1 && self.min <= self.max
    }

    /// `v` が範囲に入るか。
    #[must_use]
    pub fn contains(&self, v: i64) -> bool {
        self.min <= v && v <= self.max
    }
}

/// この build が対応する版。Rust のエージェントは版 1 だけを話す。
pub const SUPPORTED_PROTOCOL: ProtocolRange = ProtocolRange { min: 1, max: 1 };

/// この build が持つ capability の語彙。今は空。
pub const SUPPORTED_CAPABILITIES: &[&str] = &[];

/// 2 つの範囲の共通部分のうち最大の版を選ぶ。どちらかが無効か、共通部分が無ければ `None`。
#[must_use]
pub fn select_protocol_version(local: ProtocolRange, remote: ProtocolRange) -> Option<i64> {
    if !local.valid() || !remote.valid() {
        return None;
    }
    let lo = local.min.max(remote.min);
    let hi = local.max.min(remote.max);
    (lo <= hi).then_some(hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection() {
        let r = |min, max| ProtocolRange { min, max };
        assert_eq!(select_protocol_version(r(1, 1), r(1, 3)), Some(1));
        assert_eq!(select_protocol_version(r(1, 2), r(2, 3)), Some(2));
        assert_eq!(select_protocol_version(r(1, 1), r(2, 3)), None);
        assert_eq!(select_protocol_version(r(0, 1), r(1, 1)), None);
        assert_eq!(select_protocol_version(r(2, 1), r(1, 1)), None);
    }
}
