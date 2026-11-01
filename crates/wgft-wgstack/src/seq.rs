//! シーケンス番号の比較 (RFC 9293 3.4、Go の `index.go` の写し)。

#![expect(
    clippy::cast_possible_wrap,
    reason = "the comparison reads the 32-bit difference as signed, as RFC 9293 3.4 does"
)]

pub(crate) fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub(crate) fn le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

pub(crate) fn gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

pub(crate) fn ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// `a` と `b` の前の方を返します。
pub(crate) fn min(a: u32, b: u32) -> u32 {
    if lt(a, b) { a } else { b }
}

/// `a` と `b` の後ろの方を返します。
pub(crate) fn max(a: u32, b: u32) -> u32 {
    if gt(a, b) { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_around() {
        assert!(lt(u32::MAX, 0) && gt(0, u32::MAX));
        assert!(le(5, 5) && ge(5, 5) && !lt(5, 5) && !gt(5, 5));
        assert!(lt(0x7fff_ffff, 0x8000_0000));
        assert_eq!(min(u32::MAX - 1, 3), u32::MAX - 1);
        assert_eq!(max(u32::MAX - 1, 3), 3);
    }
}
