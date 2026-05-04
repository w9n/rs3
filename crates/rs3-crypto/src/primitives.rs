//! Low-level domain-separated MAC helpers.

use crate::{CryptoError, SecretBytes};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derives bytes using HMAC with an explicit domain separator.
pub(crate) fn derive_hmac(
    repository_secret: &SecretBytes,
    domain: &[u8],
    material: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut mac = HmacSha256::new_from_slice(repository_secret.expose())
        .map_err(|_| CryptoError::InvalidHmacKey)?;
    mac.update(domain);
    mac.update(&[0]);
    mac.update(material);
    Ok(mac.finalize().into_bytes().to_vec())
}
