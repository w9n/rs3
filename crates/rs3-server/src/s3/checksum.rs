//! S3 checksum transport parsing and streaming validation.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::Stream;
use http::HeaderMap;
use rs3_crypto::{ChecksumHasher, ct_eq};
use rs3_repository::UploadChecksum;
use rs3_types::{ChecksumAlgorithm, ChecksumType, ObjectChecksum};
use s3s::TrailingHeaders;
use s3s::dto::{
    ChecksumAlgorithm as S3ChecksumAlgorithm, PutObjectInput, StreamingBlob, UploadPartInput,
};
use s3s::stream::{ByteStream, RemainingLength};
use s3s::{Body, StdError};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

const CHECKSUM_ALGORITHM: &str = "x-amz-checksum-algorithm";
const SDK_CHECKSUM_ALGORITHM: &str = "x-amz-sdk-checksum-algorithm";
const CHECKSUM_TYPE: &str = "x-amz-checksum-type";
const TRAILER: &str = "x-amz-trailer";

/// A checksum failure that can be retained after a body reader reports an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChecksumFailure {
    /// The request checksum transport was malformed or incomplete.
    InvalidRequest,
    /// The algorithm or digest did not agree with the transmitted body.
    BadDigest,
}

impl ChecksumFailure {
    /// Converts the stable failure class to the client-visible S3 error.
    pub(super) fn into_s3_error(self) -> s3s::S3Error {
        match self {
            Self::InvalidRequest => s3s::s3_error!(InvalidRequest, "invalid checksum request"),
            Self::BadDigest => s3s::s3_error!(BadDigest, "checksum did not match request body"),
        }
    }
}

/// A reusable handoff for checksum errors emitted by a wrapped body.
#[derive(Clone, Debug, Default)]
pub(super) struct ChecksumFailureHandle(Arc<Mutex<Option<ChecksumFailure>>>);

impl ChecksumFailureHandle {
    /// Replaces a downstream body error only when checksum validation failed.
    pub(super) fn map_error(&self, error: s3s::S3Error) -> s3s::S3Error {
        match self.get() {
            Some(failure) => failure.into_s3_error(),
            None => error,
        }
    }

    /// Returns the checksum error recorded at validated EOF, if any.
    pub(super) fn get(&self) -> Option<ChecksumFailure> {
        self.0.lock().ok().and_then(|value| *value)
    }

    fn record(&self, failure: ChecksumFailure) {
        if let Ok(mut value) = self.0.lock() {
            let _ = value.get_or_insert(failure);
        }
    }
}

/// Wraps an optional request body without buffering or changing its length facts.
pub(super) fn validate_body(
    body: Option<StreamingBlob>,
    request: ChecksumRequest,
    handoff: UploadChecksum,
) -> (StreamingBlob, ChecksumFailureHandle) {
    let failure = ChecksumFailureHandle::default();
    let body = body.unwrap_or_else(|| StreamingBlob::from(Body::from(Bytes::new())));
    (
        StreamingBlob::new(ChecksumBody {
            body,
            validator: Some(request.into_validator(handoff)),
            failure: failure.clone(),
            terminal: false,
        }),
        failure,
    )
}

struct ChecksumBody {
    body: StreamingBlob,
    validator: Option<ChecksumValidator>,
    failure: ChecksumFailureHandle,
    terminal: bool,
}

impl Unpin for ChecksumBody {}

impl Stream for ChecksumBody {
    type Item = Result<Bytes, StdError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.terminal {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.body).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(bytes))) => {
                let Some(validator) = this.validator.as_mut() else {
                    this.terminal = true;
                    return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                        "checksum body state is unavailable",
                    )))));
                };
                validator.update(&bytes);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.terminal = true;
                this.validator = None;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.terminal = true;
                let Some(validator) = this.validator.take() else {
                    return Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                        "checksum body state is unavailable",
                    )))));
                };
                match validator.finish() {
                    Ok(_) => Poll::Ready(None),
                    Err(failure) => {
                        this.failure.record(failure);
                        Poll::Ready(Some(Err(Box::new(std::io::Error::other(
                            "checksum body validation failed",
                        )))))
                    }
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.body.size_hint()
    }
}

impl ByteStream for ChecksumBody {
    fn remaining_length(&self) -> RemainingLength {
        self.body.remaining_length()
    }
}

#[derive(Clone, Copy)]
struct ChecksumFields<'a> {
    algorithm: Option<&'a S3ChecksumAlgorithm>,
    crc32: Option<&'a str>,
    crc32c: Option<&'a str>,
    crc64_nvme: Option<&'a str>,
    sha1: Option<&'a str>,
    sha256: Option<&'a str>,
}

impl<'a> ChecksumFields<'a> {
    fn from_put(input: &'a PutObjectInput) -> Self {
        Self {
            algorithm: input.checksum_algorithm.as_ref(),
            crc32: input.checksum_crc32.as_deref(),
            crc32c: input.checksum_crc32c.as_deref(),
            crc64_nvme: input.checksum_crc64nvme.as_deref(),
            sha1: input.checksum_sha1.as_deref(),
            sha256: input.checksum_sha256.as_deref(),
        }
    }

    fn from_upload_part(input: &'a UploadPartInput) -> Self {
        Self {
            algorithm: input.checksum_algorithm.as_ref(),
            crc32: input.checksum_crc32.as_deref(),
            crc32c: input.checksum_crc32c.as_deref(),
            crc64_nvme: input.checksum_crc64nvme.as_deref(),
            sha1: input.checksum_sha1.as_deref(),
            sha256: input.checksum_sha256.as_deref(),
        }
    }
}

/// Parsed, bounded checksum facts for one S3 request body.
pub(super) struct ChecksumRequest {
    algorithm: ChecksumAlgorithm,
    expected_header: Option<Vec<u8>>,
    expected_trailer: Option<ChecksumHeader>,
    trailing_headers: Option<TrailingHeaders>,
}

impl ChecksumRequest {
    /// Parses a PUT checksum, defaulting absent client intent to CRC64/NVME.
    pub(super) fn from_put(
        input: &PutObjectInput,
        headers: &HeaderMap,
        trailing_headers: Option<TrailingHeaders>,
    ) -> Result<Self, ChecksumFailure> {
        validate_full_object_type(headers)?;
        Self::from_fields(
            ChecksumFields::from_put(input),
            headers,
            trailing_headers,
            ChecksumAlgorithm::Crc64Nvme,
        )
    }

    /// Parses a multipart part checksum using its creation algorithm as fallback.
    pub(super) fn from_upload_part(
        input: &UploadPartInput,
        headers: &HeaderMap,
        trailing_headers: Option<TrailingHeaders>,
        creation_algorithm: ChecksumAlgorithm,
    ) -> Result<Self, ChecksumFailure> {
        validate_full_object_type(headers)?;
        Self::from_fields(
            ChecksumFields::from_upload_part(input),
            headers,
            trailing_headers,
            creation_algorithm,
        )
    }

    /// Returns the selected algorithm for multipart creation binding.
    pub(super) const fn algorithm(&self) -> ChecksumAlgorithm {
        self.algorithm
    }

    /// Starts streaming validation and connects its successful EOF to publication.
    pub(super) fn into_validator(self, handoff: UploadChecksum) -> ChecksumValidator {
        ChecksumValidator {
            hasher: ChecksumHasher::new(self.algorithm),
            algorithm: self.algorithm,
            expected_header: self.expected_header,
            expected_trailer: self.expected_trailer,
            trailing_headers: self.trailing_headers,
            handoff,
        }
    }

    fn from_fields(
        fields: ChecksumFields<'_>,
        headers: &HeaderMap,
        trailing_headers: Option<TrailingHeaders>,
        fallback_algorithm: ChecksumAlgorithm,
    ) -> Result<Self, ChecksumFailure> {
        validate_request_headers(headers)?;
        let concrete = checksum_header_from_fields(fields)?;
        let trailer = checksum_trailer_declaration(headers)?;
        if concrete.is_some() && trailer.is_some() {
            return Err(ChecksumFailure::InvalidRequest);
        }
        if trailer.is_some() && trailing_headers.is_none() {
            return Err(ChecksumFailure::InvalidRequest);
        }

        let dto_algorithm = fields.algorithm.map(parse_algorithm).transpose()?;
        let request_algorithm = algorithm_header(headers, CHECKSUM_ALGORITHM)?;
        let sdk_algorithm = algorithm_header(headers, SDK_CHECKSUM_ALGORITHM)?;
        let concrete_algorithm = concrete.as_ref().map(|(header, _)| header.algorithm());
        let trailer_algorithm = trailer.map(ChecksumHeader::algorithm);
        let selected = dto_algorithm
            .or(request_algorithm)
            .or(sdk_algorithm)
            .or(concrete_algorithm)
            .or(trailer_algorithm)
            .unwrap_or(fallback_algorithm);
        if [
            dto_algorithm,
            request_algorithm,
            sdk_algorithm,
            concrete_algorithm,
            trailer_algorithm,
        ]
        .into_iter()
        .flatten()
        .any(|algorithm| algorithm != selected)
        {
            return Err(ChecksumFailure::BadDigest);
        }
        if (dto_algorithm.is_some() || request_algorithm.is_some() || sdk_algorithm.is_some())
            && concrete.is_none()
            && trailer.is_none()
        {
            return Err(ChecksumFailure::InvalidRequest);
        }
        Ok(Self {
            algorithm: selected,
            expected_header: concrete
                .map(|(_, value)| decode_digest(selected, value))
                .transpose()?,
            expected_trailer: trailer,
            trailing_headers,
        })
    }
}

/// No-buffer state driven by the request body's actual stream.
pub(super) struct ChecksumValidator {
    hasher: ChecksumHasher,
    algorithm: ChecksumAlgorithm,
    expected_header: Option<Vec<u8>>,
    expected_trailer: Option<ChecksumHeader>,
    trailing_headers: Option<TrailingHeaders>,
    handoff: UploadChecksum,
}

impl ChecksumValidator {
    /// Adds an already-delivered body chunk without retaining it.
    pub(super) fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// Finishes at exact EOF, including verified SigV4 trailer validation.
    pub(super) fn finish(self) -> Result<ObjectChecksum, ChecksumFailure> {
        let digest = self.hasher.finalize();
        if let Some(expected) = self.expected_header
            && !ct_eq(&digest, &expected)
        {
            return Err(ChecksumFailure::BadDigest);
        }
        if let Some(header) = self.expected_trailer {
            let trailers = self
                .trailing_headers
                .as_ref()
                .and_then(|value| value.read(Clone::clone))
                .ok_or(ChecksumFailure::InvalidRequest)?;
            validate_trailer_headers(&trailers)?;
            let encoded = unique_header(&trailers, header.name())?
                .ok_or(ChecksumFailure::InvalidRequest)?
                .to_str()
                .map_err(|_| ChecksumFailure::BadDigest)?;
            let expected = decode_digest(self.algorithm, encoded)?;
            if !ct_eq(&digest, &expected) {
                return Err(ChecksumFailure::BadDigest);
            }
        }
        let checksum = ObjectChecksum::new(self.algorithm, ChecksumType::FullObject, digest)
            .map_err(|_| ChecksumFailure::InvalidRequest)?;
        self.handoff
            .finish(checksum.clone())
            .map_err(|_| ChecksumFailure::InvalidRequest)?;
        Ok(checksum)
    }
}

/// Maps a stored checksum into the generated S3 response DTO shape.
pub(super) fn checksum_output(checksum: Option<&ObjectChecksum>) -> s3s::dto::Checksum {
    let mut output = s3s::dto::Checksum::default();
    let Some(checksum) = checksum else {
        return output;
    };
    let (_, value) = checksum_response_value(checksum);
    match checksum.algorithm() {
        ChecksumAlgorithm::Crc32 => output.checksum_crc32 = Some(value),
        ChecksumAlgorithm::Crc32c => output.checksum_crc32c = Some(value),
        ChecksumAlgorithm::Crc64Nvme => output.checksum_crc64nvme = Some(value),
        ChecksumAlgorithm::Sha1 => output.checksum_sha1 = Some(value),
        ChecksumAlgorithm::Sha256 => output.checksum_sha256 = Some(value),
    }
    output.checksum_type = Some(match checksum.kind() {
        ChecksumType::FullObject => {
            s3s::dto::ChecksumType::from_static(s3s::dto::ChecksumType::FULL_OBJECT)
        }
        ChecksumType::Composite { .. } => {
            s3s::dto::ChecksumType::from_static(s3s::dto::ChecksumType::COMPOSITE)
        }
    });
    output
}

/// Returns the canonical wire header name and S3 response checksum value.
pub(super) fn checksum_response_value(checksum: &ObjectChecksum) -> (&'static str, String) {
    let header = match checksum.algorithm() {
        ChecksumAlgorithm::Crc32 => ChecksumHeader::Crc32,
        ChecksumAlgorithm::Crc32c => ChecksumHeader::Crc32c,
        ChecksumAlgorithm::Crc64Nvme => ChecksumHeader::Crc64Nvme,
        ChecksumAlgorithm::Sha1 => ChecksumHeader::Sha1,
        ChecksumAlgorithm::Sha256 => ChecksumHeader::Sha256,
    };
    let encoded = STANDARD.encode(checksum.digest());
    let value = match checksum.kind() {
        ChecksumType::FullObject => encoded,
        ChecksumType::Composite { parts } => format!("{encoded}-{parts}"),
    };
    (header.name(), value)
}

/// Maps generated S3 algorithm strings to trusted checksum types.
pub(super) fn parse_algorithm(
    value: &S3ChecksumAlgorithm,
) -> Result<ChecksumAlgorithm, ChecksumFailure> {
    parse_algorithm_name(value.as_str())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChecksumHeader {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
}

impl ChecksumHeader {
    const ALL: [Self; 5] = [
        Self::Crc32,
        Self::Crc32c,
        Self::Crc64Nvme,
        Self::Sha1,
        Self::Sha256,
    ];

    const fn algorithm(self) -> ChecksumAlgorithm {
        match self {
            Self::Crc32 => ChecksumAlgorithm::Crc32,
            Self::Crc32c => ChecksumAlgorithm::Crc32c,
            Self::Crc64Nvme => ChecksumAlgorithm::Crc64Nvme,
            Self::Sha1 => ChecksumAlgorithm::Sha1,
            Self::Sha256 => ChecksumAlgorithm::Sha256,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|header| header.name() == name)
    }
}

fn parse_algorithm_name(value: &str) -> Result<ChecksumAlgorithm, ChecksumFailure> {
    match value {
        S3ChecksumAlgorithm::CRC32 => Ok(ChecksumAlgorithm::Crc32),
        S3ChecksumAlgorithm::CRC32C => Ok(ChecksumAlgorithm::Crc32c),
        S3ChecksumAlgorithm::CRC64NVME => Ok(ChecksumAlgorithm::Crc64Nvme),
        S3ChecksumAlgorithm::SHA1 => Ok(ChecksumAlgorithm::Sha1),
        S3ChecksumAlgorithm::SHA256 => Ok(ChecksumAlgorithm::Sha256),
        _ => Err(ChecksumFailure::InvalidRequest),
    }
}

fn checksum_header_from_fields(
    fields: ChecksumFields<'_>,
) -> Result<Option<(ChecksumHeader, &str)>, ChecksumFailure> {
    let mut values = [
        (ChecksumHeader::Crc32, fields.crc32),
        (ChecksumHeader::Crc32c, fields.crc32c),
        (ChecksumHeader::Crc64Nvme, fields.crc64_nvme),
        (ChecksumHeader::Sha1, fields.sha1),
        (ChecksumHeader::Sha256, fields.sha256),
    ]
    .into_iter()
    .filter_map(|(header, value)| value.map(|value| (header, value)));
    let first = values.next();
    if values.next().is_some() {
        return Err(ChecksumFailure::InvalidRequest);
    }
    Ok(first)
}

/// Rejects duplicate and unsupported checksum request headers.
pub(super) fn validate_request_headers(headers: &HeaderMap) -> Result<(), ChecksumFailure> {
    for name in [
        CHECKSUM_ALGORITHM,
        SDK_CHECKSUM_ALGORITHM,
        CHECKSUM_TYPE,
        TRAILER,
    ] {
        unique_header(headers, name)?;
    }
    for header in ChecksumHeader::ALL {
        unique_header(headers, header.name())?;
    }
    validate_checksum_header_names(headers)
}

/// Rejects unsupported request checksum headers without interpreting operation-specific values.
pub(super) fn validate_checksum_header_names(headers: &HeaderMap) -> Result<(), ChecksumFailure> {
    for name in headers.keys() {
        let name = name.as_str();
        if let Some(suffix) = name.strip_prefix("x-amz-checksum-")
            && !matches!(
                suffix,
                "algorithm"
                    | "crc32"
                    | "crc32c"
                    | "crc64nvme"
                    | "sha1"
                    | "sha256"
                    | "mode"
                    | "type"
            )
        {
            return Err(ChecksumFailure::InvalidRequest);
        }
    }
    Ok(())
}

fn validate_full_object_type(headers: &HeaderMap) -> Result<(), ChecksumFailure> {
    let header_value = unique_header(headers, CHECKSUM_TYPE)?
        .map(|value| value.to_str().map_err(|_| ChecksumFailure::InvalidRequest))
        .transpose()?;
    if header_value.is_some_and(|value| value != s3s::dto::ChecksumType::FULL_OBJECT) {
        return Err(ChecksumFailure::InvalidRequest);
    }
    Ok(())
}

fn checksum_trailer_declaration(
    headers: &HeaderMap,
) -> Result<Option<ChecksumHeader>, ChecksumFailure> {
    let Some(value) = unique_header(headers, TRAILER)? else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ChecksumFailure::InvalidRequest)?;
    let mut found = None;
    for name in value.split(',').map(str::trim) {
        if name.is_empty() {
            return Err(ChecksumFailure::InvalidRequest);
        }
        let name = name.to_ascii_lowercase();
        if name.starts_with("x-amz-checksum-") {
            let header = ChecksumHeader::from_name(&name).ok_or(ChecksumFailure::InvalidRequest)?;
            if found.replace(header).is_some() {
                return Err(ChecksumFailure::InvalidRequest);
            }
        }
    }
    Ok(found)
}

fn algorithm_header(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<ChecksumAlgorithm>, ChecksumFailure> {
    unique_header(headers, name)?
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ChecksumFailure::InvalidRequest)
                .and_then(parse_algorithm_name)
        })
        .transpose()
}

fn validate_trailer_headers(headers: &HeaderMap) -> Result<(), ChecksumFailure> {
    validate_checksum_header_names(headers)?;
    let mut found = None;
    for header in ChecksumHeader::ALL {
        if unique_header(headers, header.name())?.is_some() && found.replace(header).is_some() {
            return Err(ChecksumFailure::InvalidRequest);
        }
    }
    found.ok_or(ChecksumFailure::InvalidRequest).map(|_| ())
}

fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a http::HeaderValue>, ChecksumFailure> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(ChecksumFailure::InvalidRequest);
    }
    Ok(first)
}

fn decode_digest(algorithm: ChecksumAlgorithm, encoded: &str) -> Result<Vec<u8>, ChecksumFailure> {
    let digest = STANDARD
        .decode(encoded)
        .map_err(|_| ChecksumFailure::BadDigest)?;
    if digest.len() != algorithm.digest_len() || STANDARD.encode(&digest) != encoded {
        return Err(ChecksumFailure::BadDigest);
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    fn input(algorithm: Option<&'static str>, crc32: Option<&str>) -> PutObjectInput {
        PutObjectInput {
            checksum_algorithm: algorithm.map(S3ChecksumAlgorithm::from_static),
            checksum_crc32: crc32.map(str::to_owned),
            ..Default::default()
        }
    }

    fn input_for(algorithm: ChecksumAlgorithm, digest: String) -> PutObjectInput {
        let mut input = PutObjectInput {
            checksum_algorithm: Some(S3ChecksumAlgorithm::from_static(match algorithm {
                ChecksumAlgorithm::Crc32 => S3ChecksumAlgorithm::CRC32,
                ChecksumAlgorithm::Crc32c => S3ChecksumAlgorithm::CRC32C,
                ChecksumAlgorithm::Crc64Nvme => S3ChecksumAlgorithm::CRC64NVME,
                ChecksumAlgorithm::Sha1 => S3ChecksumAlgorithm::SHA1,
                ChecksumAlgorithm::Sha256 => S3ChecksumAlgorithm::SHA256,
            })),
            ..Default::default()
        };
        match algorithm {
            ChecksumAlgorithm::Crc32 => input.checksum_crc32 = Some(digest),
            ChecksumAlgorithm::Crc32c => input.checksum_crc32c = Some(digest),
            ChecksumAlgorithm::Crc64Nvme => input.checksum_crc64nvme = Some(digest),
            ChecksumAlgorithm::Sha1 => input.checksum_sha1 = Some(digest),
            ChecksumAlgorithm::Sha256 => input.checksum_sha256 = Some(digest),
        }
        input
    }

    fn algorithm_name(algorithm: ChecksumAlgorithm) -> &'static str {
        match algorithm {
            ChecksumAlgorithm::Crc32 => S3ChecksumAlgorithm::CRC32,
            ChecksumAlgorithm::Crc32c => S3ChecksumAlgorithm::CRC32C,
            ChecksumAlgorithm::Crc64Nvme => S3ChecksumAlgorithm::CRC64NVME,
            ChecksumAlgorithm::Sha1 => S3ChecksumAlgorithm::SHA1,
            ChecksumAlgorithm::Sha256 => S3ChecksumAlgorithm::SHA256,
        }
    }

    fn checksum_header(algorithm: ChecksumAlgorithm) -> &'static str {
        match algorithm {
            ChecksumAlgorithm::Crc32 => "x-amz-checksum-crc32",
            ChecksumAlgorithm::Crc32c => "x-amz-checksum-crc32c",
            ChecksumAlgorithm::Crc64Nvme => "x-amz-checksum-crc64nvme",
            ChecksumAlgorithm::Sha1 => "x-amz-checksum-sha1",
            ChecksumAlgorithm::Sha256 => "x-amz-checksum-sha256",
        }
    }

    fn headers(entries: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in entries {
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                http::HeaderValue::try_from(*value).expect("header value"),
            );
        }
        headers
    }

    #[test]
    fn defaults_put_to_crc64_and_resolves_handoff() {
        let request = ChecksumRequest::from_put(&input(None, None), &HeaderMap::new(), None)
            .expect("default request");
        assert_eq!(request.algorithm(), ChecksumAlgorithm::Crc64Nvme);
        let handoff = UploadChecksum::pending();
        let mut validator = request.into_validator(handoff.clone());
        validator.update(b"body");
        assert!(validator.finish().is_ok());
        assert!(handoff.get().is_ok());
    }

    #[test]
    fn rejects_malformed_duplicate_and_disagreeing_headers() {
        let digest = STANDARD.encode([0_u8; 4]);
        assert!(matches!(
            ChecksumRequest::from_put(
                &input(None, Some("%%%")),
                &headers(&[("x-amz-checksum-crc32", "%%%")]),
                None,
            ),
            Err(ChecksumFailure::BadDigest)
        ));
        assert!(matches!(
            ChecksumRequest::from_put(
                &input(None, Some(&digest)),
                &headers(&[
                    ("x-amz-checksum-crc32", &digest),
                    ("x-amz-checksum-crc32", &digest),
                ]),
                None,
            ),
            Err(ChecksumFailure::InvalidRequest)
        ));
        assert!(matches!(
            ChecksumRequest::from_put(
                &input(None, Some(&digest)),
                &headers(&[
                    (SDK_CHECKSUM_ALGORITHM, S3ChecksumAlgorithm::SHA256),
                    ("x-amz-checksum-crc32", &digest),
                ]),
                None,
            ),
            Err(ChecksumFailure::BadDigest)
        ));
    }

    #[test]
    fn parses_and_validates_every_pinned_algorithm() {
        for algorithm in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32c,
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumAlgorithm::Sha1,
            ChecksumAlgorithm::Sha256,
        ] {
            let mut hasher = ChecksumHasher::new(algorithm);
            hasher.update(b"body");
            let digest = STANDARD.encode(hasher.finalize());
            let input = input_for(algorithm, digest.clone());
            let request = ChecksumRequest::from_put(
                &input,
                &headers(&[
                    (CHECKSUM_ALGORITHM, algorithm_name(algorithm)),
                    (checksum_header(algorithm), &digest),
                ]),
                None,
            )
            .expect("canonical checksum request");
            assert_eq!(request.algorithm(), algorithm);

            let short = STANDARD.encode(vec![0_u8; algorithm.digest_len() - 1]);
            let invalid = input_for(algorithm, short);
            assert!(matches!(
                ChecksumRequest::from_put(&invalid, &HeaderMap::new(), None),
                Err(ChecksumFailure::BadDigest)
            ));
        }
    }

    #[test]
    fn rejects_noncanonical_checksum_and_non_full_put_checksum_type() {
        let noncanonical = "AAAAAA";
        assert!(matches!(
            ChecksumRequest::from_put(
                &input(None, Some(noncanonical)),
                &headers(&[("x-amz-checksum-crc32", noncanonical)]),
                None,
            ),
            Err(ChecksumFailure::BadDigest)
        ));
        for value in ["COMPOSITE", "unknown"] {
            assert!(matches!(
                ChecksumRequest::from_put(
                    &input(None, None),
                    &headers(&[(CHECKSUM_TYPE, value)]),
                    None,
                ),
                Err(ChecksumFailure::InvalidRequest)
            ));
            assert!(matches!(
                ChecksumRequest::from_upload_part(
                    &UploadPartInput::default(),
                    &headers(&[(CHECKSUM_TYPE, value)]),
                    None,
                    ChecksumAlgorithm::Crc32,
                ),
                Err(ChecksumFailure::InvalidRequest)
            ));
        }
    }

    #[test]
    fn rejects_unavailable_and_duplicate_checksum_trailer_declarations() {
        assert!(matches!(
            ChecksumRequest::from_put(
                &input(Some(S3ChecksumAlgorithm::CRC32), None),
                &headers(&[
                    (CHECKSUM_ALGORITHM, S3ChecksumAlgorithm::CRC32),
                    (TRAILER, "x-amz-checksum-crc32"),
                ]),
                None,
            ),
            Err(ChecksumFailure::InvalidRequest)
        ));
        assert!(matches!(
            ChecksumRequest::from_put(
                &input(None, None),
                &headers(&[
                    (TRAILER, "x-amz-checksum-crc32"),
                    (TRAILER, "x-amz-checksum-crc32"),
                ]),
                None,
            ),
            Err(ChecksumFailure::InvalidRequest)
        ));
    }

    #[test]
    fn response_value_includes_composite_part_count() {
        let checksum = ObjectChecksum::new(
            ChecksumAlgorithm::Crc32,
            ChecksumType::Composite { parts: 2 },
            vec![0; 4],
        )
        .expect("valid composite checksum");
        let (header, value) = checksum_response_value(&checksum);
        assert_eq!(header, "x-amz-checksum-crc32");
        assert_eq!(value, "AAAAAA==-2");
        let output = checksum_output(Some(&checksum));
        assert_eq!(output.checksum_crc32.as_deref(), Some("AAAAAA==-2"));
        assert_eq!(
            output.checksum_type.as_ref().map(|kind| kind.as_str()),
            Some(s3s::dto::ChecksumType::COMPOSITE)
        );
    }

    #[tokio::test]
    async fn wrapper_only_resolves_at_verified_eof() {
        let mut hasher = ChecksumHasher::new(ChecksumAlgorithm::Crc32);
        hasher.update(b"body");
        let digest = STANDARD.encode(hasher.finalize());
        let request = ChecksumRequest::from_put(
            &input(Some(S3ChecksumAlgorithm::CRC32), Some(&digest)),
            &headers(&[
                (CHECKSUM_ALGORITHM, S3ChecksumAlgorithm::CRC32),
                ("x-amz-checksum-crc32", &digest),
            ]),
            None,
        )
        .expect("request");
        let handoff = UploadChecksum::pending();
        let (mut body, failure) = validate_body(
            Some(StreamingBlob::from(Body::from(Bytes::from_static(b"body")))),
            request,
            handoff.clone(),
        );
        assert!(body.next().await.expect("body chunk").is_ok());
        assert!(handoff.get().is_err());
        assert!(body.next().await.is_none());
        assert!(failure.get().is_none());
        assert!(handoff.get().is_ok());
    }

    #[tokio::test]
    async fn wrapper_records_bad_digest_without_resolving_handoff() {
        let digest = STANDARD.encode([0_u8; 4]);
        let request = ChecksumRequest::from_put(
            &input(None, Some(&digest)),
            &headers(&[("x-amz-checksum-crc32", &digest)]),
            None,
        )
        .expect("request");
        let handoff = UploadChecksum::pending();
        let (mut body, failure) = validate_body(
            Some(StreamingBlob::from(Body::from(Bytes::from_static(b"body")))),
            request,
            handoff.clone(),
        );
        assert!(body.next().await.expect("body chunk").is_ok());
        assert!(body.next().await.expect("failure item").is_err());
        assert_eq!(failure.get(), Some(ChecksumFailure::BadDigest));
        assert_eq!(
            failure
                .map_error(s3s::s3_error!(InternalError))
                .code()
                .as_str(),
            "BadDigest"
        );
        assert!(handoff.get().is_err());
    }

    #[tokio::test]
    async fn source_error_is_terminal_and_never_resolves_handoff() {
        let request = ChecksumRequest::from_put(&input(None, None), &HeaderMap::new(), None)
            .expect("request");
        let source = futures_util::stream::iter(vec![Err::<Bytes, _>(std::io::Error::other(
            "source failed",
        ))]);
        let handoff = UploadChecksum::pending();
        let (mut body, failure) =
            validate_body(Some(StreamingBlob::wrap(source)), request, handoff.clone());
        assert!(body.next().await.expect("source error").is_err());
        assert!(body.next().await.is_none());
        assert!(failure.get().is_none());
        assert!(handoff.get().is_err());
    }
}
