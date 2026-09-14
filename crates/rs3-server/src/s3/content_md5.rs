//! Canonical S3 `Content-MD5` request transport parsing.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::HeaderMap;
use rs3_types::Md5Digest;
use s3s::dto::{PutObjectInput, UploadPartInput};

const CONTENT_MD5: &str = "content-md5";

/// Stable request-side MD5 transport failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContentMd5Error {
    /// The request carries more than one Content-MD5 header.
    InvalidRequest,
    /// The declared MD5 is not canonical Base64 for exactly 128 bits.
    InvalidDigest,
}

impl ContentMd5Error {
    /// Maps a transport error to its S3-visible form without echoing digest bytes.
    pub(super) fn into_s3_error(self) -> s3s::S3Error {
        match self {
            Self::InvalidRequest => s3s::s3_error!(InvalidRequest, "invalid Content-MD5 request"),
            Self::InvalidDigest => s3s::s3_error!(InvalidDigest, "invalid Content-MD5 request"),
        }
    }
}

/// Parses an optional PUT Content-MD5 fact before any body consumer starts.
pub(super) fn put_expected_md5(
    input: &PutObjectInput,
    headers: &HeaderMap,
) -> Result<Option<Md5Digest>, ContentMd5Error> {
    expected_md5(input.content_md5.as_deref(), headers)
}

/// Parses an optional UploadPart Content-MD5 fact before accepting a replacement.
pub(super) fn upload_part_expected_md5(
    input: &UploadPartInput,
    headers: &HeaderMap,
) -> Result<Option<Md5Digest>, ContentMd5Error> {
    expected_md5(input.content_md5.as_deref(), headers)
}

fn expected_md5(
    dto_value: Option<&str>,
    headers: &HeaderMap,
) -> Result<Option<Md5Digest>, ContentMd5Error> {
    let header_value = unique_header(headers)?
        .map(|value| value.to_str().map_err(|_| ContentMd5Error::InvalidDigest))
        .transpose()?;
    let dto = dto_value.map(parse_md5).transpose()?;
    let header = header_value.map(parse_md5).transpose()?;
    if let (Some(dto), Some(header)) = (&dto, &header)
        && dto != header
    {
        return Err(ContentMd5Error::InvalidRequest);
    }
    Ok(dto.or(header))
}

fn unique_header(headers: &HeaderMap) -> Result<Option<&http::HeaderValue>, ContentMd5Error> {
    let mut values = headers.get_all(CONTENT_MD5).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(ContentMd5Error::InvalidRequest);
    }
    Ok(first)
}

fn parse_md5(encoded: &str) -> Result<Md5Digest, ContentMd5Error> {
    if encoded.len() != 24 {
        return Err(ContentMd5Error::InvalidDigest);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| ContentMd5Error::InvalidDigest)?;
    let bytes: [u8; 16] = decoded
        .try_into()
        .map_err(|_| ContentMd5Error::InvalidDigest)?;
    if STANDARD.encode(bytes) != encoded {
        return Err(ContentMd5Error::InvalidDigest);
    }
    Ok(Md5Digest::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                CONTENT_MD5,
                http::HeaderValue::from_str(value).expect("header"),
            );
        }
        headers
    }

    #[test]
    fn accepts_only_canonical_128_bit_base64() {
        let encoded = STANDARD.encode([0_u8; 16]);
        assert!(parse_md5(&encoded).is_ok());
        for malformed in [
            "",
            "AAAAAA",
            "AAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAB==",
            "%%%%%%%%%%%%%%%%%%%%%%%%",
        ] {
            assert_eq!(parse_md5(malformed), Err(ContentMd5Error::InvalidDigest));
        }
    }

    #[test]
    fn rejects_duplicate_and_disagreeing_transport_values() {
        assert_eq!(
            expected_md5(
                None,
                &headers(&["AAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAAAAAAAA=="])
            ),
            Err(ContentMd5Error::InvalidRequest)
        );
        assert_eq!(
            expected_md5(
                Some("AAAAAAAAAAAAAAAAAAAAAA=="),
                &headers(&["/////////////////////w=="])
            ),
            Err(ContentMd5Error::InvalidRequest)
        );
    }
}
