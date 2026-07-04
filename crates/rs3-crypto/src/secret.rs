//! Secret memory containers.

use crate::CryptoError;
use std::fmt;
use zeroize::Zeroizing;

/// Secret bytes that are zeroized when dropped.
#[derive(Clone)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Minimum accepted secret length in bytes.
    pub const MIN_LEN: usize = 32;

    /// Creates a secret byte container.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        Self::from_zeroizing(Zeroizing::new(bytes))
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(CryptoError::SecretTooShort {
                minimum_len: Self::MIN_LEN,
            });
        }

        Ok(Self(bytes))
    }

    /// Exposes the secret to cryptographic code inside this crate.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretBytes")
            .field(&"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn rejects_short_secret() {
        assert!(SecretBytes::new(vec![1; 8]).is_err());
    }

    #[test]
    fn debug_output_is_redacted() {
        let secret = match SecretBytes::new(vec![171; SecretBytes::MIN_LEN]) {
            Ok(secret) => secret,
            Err(error) => panic!("{error}"),
        };

        let debug = format!("{secret:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("171"));
    }
}
