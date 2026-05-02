//! Secret memory containers.

use crate::CryptoError;
use zeroize::Zeroizing;

/// Secret bytes that are zeroized when dropped.
#[derive(Clone, Debug)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Minimum accepted secret length in bytes.
    pub const MIN_LEN: usize = 32;

    /// Creates a secret byte container.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(CryptoError::SecretTooShort {
                minimum_len: Self::MIN_LEN,
            });
        }

        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Exposes the secret to cryptographic code inside this crate.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::SecretBytes;

    #[test]
    fn rejects_short_secret() {
        assert!(SecretBytes::new(vec![1; 8]).is_err());
    }
}
