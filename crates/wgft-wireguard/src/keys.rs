//! WireGuard の鍵を wgft の型で持つ。
//!
//! agent.json の `wg_private_key` は標準の base64 で 32 バイトを書いた文字列で、Go の
//! `wgtypes.ParseKey` と同じ形を読む。公開鍵の導出だけは `protocol` の module が sanstun で行う。

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

/// The length of a WireGuard key in bytes.
pub const KEY_LEN: usize = 32;

/// A key could not be read from its text form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The text is not standard padded base64.
    NotBase64,
    /// The text decodes to a length other than 32 bytes.
    WrongLength(usize),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::NotBase64 => f.write_str("key is not standard base64"),
            KeyError::WrongLength(n) => write!(f, "key decodes to {n} bytes, want {KEY_LEN}"),
        }
    }
}

impl std::error::Error for KeyError {}

fn decode(text: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, KeyError> {
    let bytes = Zeroizing::new(STANDARD.decode(text).map_err(|_| KeyError::NotBase64)?);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    if bytes.len() != KEY_LEN {
        return Err(KeyError::WrongLength(bytes.len()));
    }
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// A Curve25519 public key of a WireGuard peer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// Wraps the raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Reads a key in the standard base64 form that WireGuard tools and agent.json use.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] when the text is not base64 of exactly 32 bytes.
    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        decode(text).map(|k| Self(*k))
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The standard base64 form.
    #[must_use]
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

/// A Curve25519 private key. The bytes are zeroed when the key is dropped.
#[derive(Clone)]
pub struct PrivateKey(Zeroizing<[u8; KEY_LEN]>);

impl PrivateKey {
    /// Wraps the raw key bytes as they are stored, without clamping.
    ///
    /// X25519 clamps the scalar when it uses it, so stored keys that were not clamped still
    /// work, as with wireguard-go and Linux. The key is copied from `bytes`, which the caller
    /// zeroes when it owns them; taking them by reference leaves no copy behind on the way in.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(bytes);
        Self(key)
    }

    /// Makes a new key from 32 bytes of fresh entropy, clamped as `wg genkey` does.
    ///
    /// The caller supplies the entropy, from the operating system in production and from a
    /// fixed seed in tests. The entropy is taken by reference, so no copy of it is left behind
    /// unzeroed; the caller zeroes its own.
    #[must_use]
    pub fn generate(entropy: &[u8; KEY_LEN]) -> Self {
        let mut key = Self::from_bytes(entropy);
        key.0[0] &= 0b1111_1000;
        key.0[31] = (key.0[31] & 0b0111_1111) | 0b0100_0000;
        key
    }

    /// Reads a key in the standard base64 form, the form of `wg_private_key` in agent.json.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] when the text is not base64 of exactly 32 bytes.
    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        decode(text).map(Self)
    }

    /// The standard base64 form. The returned string is zeroed when dropped.
    #[must_use]
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(&self.0[..]))
    }

    /// The raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The public key that belongs to this private key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        crate::protocol::derive_public_key(self)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 公開鍵は別の X25519 の実装 (Python の cryptography) で求めた値。
    const PRIVATE: &str = "eFQyKJtWZ2cVgGc7r9HFtmZ+ivoO9Djzs4wn9HDQS3s=";
    const PUBLIC: &str = "5EJBg3pcah/JARvqqlNdIzhBeWhGfDKLNIq9E8kcBCI=";

    #[test]
    fn public_key_matches_wg_pubkey() {
        let private = PrivateKey::from_base64(PRIVATE).unwrap();
        assert_eq!(private.public_key().to_base64(), PUBLIC);
        assert_eq!(&*private.to_base64(), PRIVATE);
    }

    #[test]
    fn rejects_bad_text() {
        assert_eq!(
            PublicKey::from_base64("not base64!").unwrap_err(),
            KeyError::NotBase64
        );
        assert_eq!(
            PublicKey::from_base64("AAAA").unwrap_err(),
            KeyError::WrongLength(3)
        );
        assert!(PrivateKey::from_base64("").is_err());
    }

    #[test]
    fn generate_clamps() {
        let key = PrivateKey::generate(&[0xff; KEY_LEN]);
        assert_eq!(key.as_bytes()[0] & 7, 0);
        assert_eq!(key.as_bytes()[31] & 0xc0, 0x40);
    }

    #[test]
    fn debug_hides_the_private_key() {
        let key = PrivateKey::from_bytes(&[7; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "PrivateKey(..)");
    }
}
